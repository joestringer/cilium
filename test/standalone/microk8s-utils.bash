SNAP_COMMON=${SNAP_COMMON:-"/var/snap/microk8s/common"}
KUBELET_CONF="/var/snap/microk8s/current/args/kubelet"
TEST_NAME="$0"

set -eo pipefail

function log {
    echo "=> $@" >&2
}

function abort {
    log "$@"
    return 1
}

function test_succeeded {
    log "$@"
    echo "Success"
}

function cilium {
    microk8s.cilium "$@"
}

# $1 - start / stop / restart
function apiserver {
    systemctl "$1" snap.microk8s.daemon-apiserver.service
}

if [ $UID != 0 ]; then
    echo "Script must be run as root"
    exit
fi
