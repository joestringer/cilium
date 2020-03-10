#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/microk8s-utils.bash"

HTTP_APP="$dir/../../examples/minikube/http-sw-app.yaml"
N_EPS="5"
N_EPS_IDLE="1"

function main {
    log "Configuring the test"
    microk8s.kubectl delete -f $HTTP_APP || true 2>&1 > /dev/null

    log "Gathering initial state from cilium"
    cilium status --brief

    log "Running test..."
    microk8s.kubectl apply -f $HTTP_APP
    until [[ $(cilium endpoint list -o json | jq '. | length') == $N_EPS ]]; do
        sleep 0.2
    done
    sleep 0.2

    log "Killing cilium-agent"
    killall cilium-agent

    log "Waiting for cilium-agent to restart"
    until cilium status --brief 2>&1 ; do
        echo -n "."
        sleep 1
    done 2>&1 >/dev/null
    until cilium endpoint list ; do
        echo -n "."
        sleep 1
    done 2>&1 >/dev/null

    if [[ $(cilium endpoint list -o json | jq '. | length') != $N_EPS ]]; then
        abort "Wrong number of endpoints in Cilium after restart"
    fi

    microk8s.kubectl delete -f $HTTP_APP 2>&1 >/dev/null || true
    test_succeeded "${TEST_NAME}"
}

main "$@"
