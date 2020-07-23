package connectivity_check

_networkCheck: {
	metadata: labels: component: "network-check"
}

// 'pod-to-a' implies probing echo-a via defaults.cue.
// No policy
deployment: "pod-to-a":             _networkCheck & {}
deployment: "pod-to-external-1111": _networkCheck & {
	_probeTarget: "1.1.1.1"
	_probePath:   "/"
}

_policyResource: {
	metadata: labels: component: "policy-check"
}

// L3 connectivity check with egress L3+L4 policy
deployment: "pod-to-a-allowed-cnp": _policyResource & {}
egressCNP: "pod-to-a-allowed-cnp":  _policyResource & {
	_allow: "echo-a"
}

// L3 policy check with egress deny
deployment: "pod-to-a-denied-cnp": _policyResource & {}
egressCNP: "pod-to-a-denied-cnp":  _policyResource & {}

// FQDN policy check to world. _allowFQDN implies DNS visibility policy.
deployment: "pod-to-external-fqdn-allow-google-cnp": _policyResource & {
	_probeTarget: "www.google.com"
	_probePath:   ""
}
egressCNP: "pod-to-external-fqdn-allow-google-cnp": _policyResource & {
	_allowFQDN: "*.google.com"
}
