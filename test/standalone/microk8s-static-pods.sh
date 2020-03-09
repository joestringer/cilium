#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/microk8s-utils.bash"

POD_MANIFESTS_PATH="${SNAP_COMMON}/etc/kubelet.d"
STATIC_POD_PATH="${POD_MANIFESTS_PATH}/static-web.yaml"

function cfg_kubelet {
    if ! grep -q "pod-manifest-path" $KUBELET_CONF; then
        echo "--pod-manifest-path=${POD_MANIFESTS_PATH}" >> $KUBELET_CONF
        systemctl restart snap.microk8s.daemon-apiserver.service
    fi
}

function cfg_static_pod {
    mkdir -p $POD_MANIFESTS_PATH
    cat <<EOF >$STATIC_POD_PATH
apiVersion: v1
kind: Pod
metadata:
  name: static-web
  labels:
    role: myrole
spec:
  containers:
    - name: web
      image: nginx
      ports:
        - name: web
          containerPort: 80
          protocol: TCP
EOF
}

function check_pod_labels {
    static_pod_labels="$(cilium endpoint list -o json \
        | jq '.[].status.labels."security-relevant"
              | select(any(.[]; contains("k8s"))|not)
              | select(any(.[]; contains("health"))|not)')"
    log "$static_pod_labels"
    [ "$(echo "$static_pod_labels" | jq 'length')" = "" ]
}

function cleanup {
    rm -rf $STATIC_POD_PATH
}

trap cleanup EXIT

function main {
    log "Configuring the test"
    cleanup
    cfg_kubelet
    apiserver stop
    cfg_static_pod
    sleep 2
    apiserver start

    # Initial logging status
    log "Gathering initial state from cilium"
    log "$(cilium status)"
    log "$(cilium endpoint list)"

    log "Running test..."
    if ! check_pod_labels; then
        # Sleep for up to 50 seconds, checking that the pod labels get properly updated from apiserver
        for i in {1..10}; do
            if check_pod_labels; then
                break
            fi
            log "Static pod labels don't contain kubernetes labels"
            sleep 5
        done
        if ! check_pod_labels; then
            abort "Static pod labels don't contain kubernetes labels after timeout"
        fi
    fi

    test_succeeded "${TEST_NAME}"
}

main "$@"
