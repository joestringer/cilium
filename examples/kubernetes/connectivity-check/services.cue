package connectivity_check

deployment: [ID=_]: {
	if ID =~ "^[-_a-zA-Z0-9]*-headless$" {
		_probeTarget: "echo-b-headless"
	}
}

_serviceDeployment: {
	metadata: labels: component: "services-check"
}

// 'pod-to-b' implies probing echo-b via defaults.cue.

// '*-to-b-multi-node' implies echo-b antiAffinity via defaults.cue.
deployment: "pod-to-b-multi-node-clusterip": _serviceDeployment & {}
deployment: "pod-to-b-multi-node-headless":  _serviceDeployment & {}

// '*-to-b-intra-node' implies echo-b affinity via defaults.cue.
deployment: "pod-to-b-intra-node-clusterip": _serviceDeployment & {}
deployment: "pod-to-b-intra-node-headless":  _serviceDeployment & {}

// Deployments for testing hostport service should be separate to allow us to
// later generate separate connectivity-check YAMLs to either include/exclude
// these checks.
_hostPortDeployment: {
	metadata: labels: component: "hostport-check"
	_probeTarget: "echo-b-host-headless:40000"
}
deployment: "pod-to-b-multi-node-hostport": _hostPortDeployment & {}
deployment: "pod-to-b-intra-node-hostport": _hostPortDeployment & {}

_hostnetDeployment: _serviceDeployment & {
	spec: template: spec: {
		hostNetwork: true
		dnsPolicy:   "ClusterFirstWithHostNet"
	}
}
deployment: "host-to-b-multi-node-clusterip": _hostnetDeployment & {}
deployment: "host-to-b-multi-node-headless":  _hostnetDeployment & {}
