#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

CILIUM_IMAGE=${CILIUM_IMAGE:-"quay.io/cilium/cilium:stable"}
CILIUM_OPTS=${CILIUM_OPTS:-""}
HOST_IP=${HOST_IP:-""}
RETRIES=${RETRIES:-5}
DNS_RETRIES=${DNS_RETRIES:-24}

set -e
shopt -s extglob

# Run without sudo if not available (e.g., running as root)
SUDO=

uninstall() {
    set +e
    if [ -n "$(${SUDO} docker ps -a -q -f name=cilium)" ]; then
        echo "Shutting down running Cilium agent"
        ${SUDO} docker rm -f cilium
    fi
    if [ -e /usr/bin/cilium ]; then
        echo "Removing /usr/bin/cilium"
        ${SUDO} rm /usr/bin/cilium
    fi
    if [ -e /usr/bin/cilium-dbg ] ; then
        echo "Removing /usr/bin/cilium-dbg"
        ${SUDO} rm /usr/bin/cilium-dbg
    fi
    pushd /etc
    if [ -f resolv.conf.orig ] ; then
        echo "Restoring /etc/resolv.conf"
        ${SUDO} mv -f resolv.conf.orig resolv.conf
    elif [ -f resolv.conf.link ] && [ -f "$(cat resolv.conf.link)" ] ; then
        echo "Restoring systemd resolved config..."
        if [ -f /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf ] ; then
	    ${SUDO} rm /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf
        fi
        ${SUDO} systemctl daemon-reload
        ${SUDO} systemctl reenable systemd-resolved.service
        ${SUDO} service systemd-resolved restart
        ${SUDO} ln -fs "$(cat resolv.conf.link)" resolv.conf
        ${SUDO} rm resolv.conf.link
    fi
    popd
}

CILIUM_OPTS+=" --enable-endpoint-health-checking=false"
if [ -n "$HOST_IP" ] ; then
    CILIUM_OPTS+=" --ipv4-node $HOST_IP"
fi

DOCKER_OPTS=" -d --log-driver local --restart always"
DOCKER_OPTS+=" --privileged --network host --cap-add NET_ADMIN --cap-add SYS_MODULE"
# Run cilium agent in the host's cgroup namespace so that
# socket-based load balancing works as expected.
# See https://github.com/cilium/cilium/pull/16259 for more details.
DOCKER_OPTS+=" --cgroupns=host"
DOCKER_OPTS+=" --volume /var/lib/cilium/etcd:/var/lib/cilium/etcd"
DOCKER_OPTS+=" --volume /var/run/cilium:/var/run/cilium"
DOCKER_OPTS+=" --volume /var/run/cilium/netns:/var/run/cilium/netns"
DOCKER_OPTS+=" --volume /boot:/boot"
DOCKER_OPTS+=" --volume /lib/modules:/lib/modules"
DOCKER_OPTS+=" --volume /sys/fs/bpf:/sys/fs/bpf"
DOCKER_OPTS+=" --volume /run/xtables.lock:/run/xtables.lock"

install() {
    cilium_started=false
    retries=${RETRIES}
    while [ $cilium_started = false ]; do
        if [ -n "$(${SUDO} docker ps -a -q -f name=cilium)" ]; then
            echo "Shutting down running Cilium agent"
            ${SUDO} docker rm -f cilium || true
        fi

        echo "Launching Cilium agent $CILIUM_IMAGE..."
        ${SUDO} docker run \
            --name cilium \
            "$DOCKER_OPTS" \
            "$CILIUM_IMAGE" \
            cilium-agent "$CILIUM_OPTS"

        # Copy Cilium CLI
        ${SUDO} docker cp -L cilium:/usr/bin/cilium /usr/bin/cilium-dbg
        ${SUDO} ln -fs /usr/bin/cilium-dbg /usr/bin/cilium

        # Wait for cilium agent to become available
        for ((i = 0 ; i < 12; i++)); do
            if ${SUDO} cilium-dbg status --brief > /dev/null 2>&1; then
                cilium_started=true
                break
            fi
            sleep 5s
            echo "Waiting for Cilium daemon to come up..."
        done

        echo "Cilium status:"
        ${SUDO} cilium-dbg status || true

        if [ "$cilium_started" = true ] ; then
            echo 'Cilium successfully started!'
        else
            if [ "$retries" -eq 0 ]; then
                >&2 echo 'Timeout waiting for Cilium to start, retries exhausted.'
                exit 1
            fi
            ((retries--))
            echo "Restarting Cilium..."
        fi
    done
}

setup_kube_dns() {
    # Wait for kube-dns service to become available
    kubedns=""
    for ((i = 0 ; i < "$DNS_RETRIES"; i++)); do
        kubedns=$(${SUDO} cilium-dbg service list get -o jsonpath='{[?(@.spec.frontend-address.port==53)].spec.frontend-address.ip}')
        if [ -n "$kubedns" ] ; then
            break
        fi
        sleep 5s
        echo "Waiting for kube-dns service to come available..."
    done

    namespace=$(${SUDO} cilium-dbg endpoint get -l reserved:host -o jsonpath='{$[0].status.identity.labels}' | tr -d "[]\"" | tr "," "\n" | grep io.kubernetes.pod.namespace | cut -d= -f2)

    if [ -n "$kubedns" ] ; then
        if grep "nameserver $kubedns" /etc/resolv.conf ; then
            echo "kube-dns IP $kubedns already in /etc/resolv.conf"
            else
            linkval="$(readlink /etc/resolv.conf || true)"
            echo "$linkval" | ${SUDO} tee /etc/resolv.conf.link
            if [[ "$linkval" == *"/systemd/"* ]] ; then
                echo "updating systemd resolved with kube-dns IP $kubedns"
                ${SUDO} mkdir -p /usr/lib/systemd/resolved.conf.d
                ${SUDO} tee /usr/lib/systemd/resolved.conf.d/cilium-kube-dns.conf <<EOF >/dev/null
# This file is installed by Cilium to use kube dns server from a non-k8s node.
[Resolve]
DNS=$kubedns
Domains=${namespace}.svc.cluster.local svc.cluster.local cluster.local
EOF
            ${SUDO} systemctl daemon-reload
            ${SUDO} systemctl reenable systemd-resolved.service
            ${SUDO} service systemd-resolved restart
            ${SUDO} ln -fs /run/systemd/resolve/resolv.conf /etc/resolv.conf
            else
                echo "Adding kube-dns IP $kubedns to /etc/resolv.conf"
                ${SUDO} cp /etc/resolv.conf /etc/resolv.conf.orig
                resolvconf="nameserver $kubedns\n$(cat /etc/resolv.conf)\nsearch ${namespace}.svc.cluster.local svc.cluster.local cluster.local\n"
                printf '%s' "$resolvconf" | ${SUDO} tee /etc/resolv.conf
            fi
        fi
    else
        >&2 echo "kube-dns not found."
        exit 1
    fi
}

main() {
    if [ ! "$(whoami)" = "root" ] ; then
        SUDO=sudo
    fi

    if [ "$1" = "uninstall" ] ; then
        uninstall
        exit 0
    fi

    install
    setup_kube_dns
}

main "$@"
