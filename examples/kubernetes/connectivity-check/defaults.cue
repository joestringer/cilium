package connectivity_check

// Default parameters for echo clients (may be overridden).
deployment: [ID=_]: {
	// General pod parameters
	if ID =~ "^pod-to-[-_a-zA-Z0-9]*$" || ID =~ "^host-to-[-_a-zA-Z0-9]*$" {
		_image:        "docker.io/byrnedo/alpine-curl:0.1.8"
		_sleepCommand: true
	}

	// readinessProbe target name
	if ID =~ "^pod-to-a.*$" || ID =~ "^host-to-a.*$" {
		_probeTarget: *"echo-a" | string
	}
	if ID =~ "^pod-to-b.*$" || ID =~ "^host-to-b.*$" {
		_probeTarget: *"echo-b" | string
	}
	if ID =~ "^pod-to-c.*$" || ID =~ "^host-to-c.*$" {
		_probeTarget: *"echo-c" | string
	}

	// Topology
	if ID =~ "^[-_a-zA-Z0-9]*intra-node[-_a-zA-Z0-9]*$" {
		metadata: labels: topology: "intra-node"
	}
	if ID =~ "^[-_a-zA-Z0-9]*multi-node[-_a-zA-Z0-9]*$" {
		metadata: labels: topology: "multi-node"
	}

	// Affinity
	if ID =~ "^[-_a-zA-Z0-9]*to-a-intra-node-[-_a-zA-Z0-9]*$" {
		_affinity: "echo-a"
	}
	if ID =~ "^[-_a-zA-Z0-9]*to-a-multi-node-[-_a-zA-Z0-9]*$" {
		_antiAffinity: "echo-a"
	}
	if ID =~ "^[-_a-zA-Z0-9]*to-b-intra-node-[-_a-zA-Z0-9]*$" {
		_affinity: "echo-b"
	}
	if ID =~ "^[-_a-zA-Z0-9]*to-b-multi-node-[-_a-zA-Z0-9]*$" {
		_antiAffinity: "echo-b"
	}
	if ID =~ "^[-_a-zA-Z0-9]*to-c-intra-node-[-_a-zA-Z0-9]*$" {
		_affinity: "echo-c"
	}

	if ID =~ "^to-c-multi-node-[-_a-zA-Z0-9]*$"
	// TODO: Proxy container handling
	{
		_antiAffinity: "echo-c"
	}
}
