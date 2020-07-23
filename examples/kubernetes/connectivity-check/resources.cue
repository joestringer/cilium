package connectivity_check

_spec: {
	_name:               string
	_image:              string
	_serverPort:         *"" | string
	_affinity:           *"" | string
	_antiAffinity:       *"" | string
	_probeTarget:        string
	_probePath:          *"/public" | string
	_probeForbiddenPath: *false | true
	_probeCommand: [...string]
	if _probeForbiddenPath {
		_probePath: "/private"
		_probeCommand: [ "ash", "-c", "! curl -sS --fail --connect-timeout 5 -o /dev/null \(_probeTarget)\(_probePath)"]
	}
	if !_probeForbiddenPath {
		// Assume /public can always be accessed
		_probeCommand: [ "curl", "-sS", "--fail", "-o", "/dev/null", "\(_probeTarget)\(_probePath)"]
	}

	apiVersion: "apps/v1"
	kind:       "Deployment"
	metadata: {
		name: _name
		labels: {
			name:      _name
			topology:  *"any" | string
			component: *"invalid" | string
		}
	}
	spec: {
		selector: matchLabels: name: _name
		template: {
			metadata: labels: name: _name
			spec: containers: [...{
				name:            "echo-container"
				image:           _image
				imagePullPolicy: "IfNotPresent"
				if _serverPort != "" {
					env: [{
						name:  "PORT"
						value: _serverPort
					}]
				}
				ports: [...{
					_expose: *false | true
				}]
				readinessProbe: exec: command: _probeCommand
			}]
			if _affinity != "" {
				spec: affinity: podAffinity: requiredDuringSchedulingIgnoredDuringExecution: [{
					labelSelector: matchExpressions: [{
						key:      "name"
						operator: "In"
						values: [
							_affinity,
						]
					}]
					topologyKey: "kubernetes.io/hostname"
				}]
			}
			if _antiAffinity != "" {
				spec: affinity: podAntiAffinity: requiredDuringSchedulingIgnoredDuringExecution: [{
					labelSelector: matchExpressions: [{
						key:      "name"
						operator: "In"
						values: [
							_antiAffinity,
						]
					}]
					topologyKey: "kubernetes.io/hostname"
				}]
			}
		}
	}
}

deployment: [ID=_]: _spec & {
	_name:         ID
	_image:        string
	_sleepCommand: *false | true // Run a sleep command instead of regular pod CMD.

	// Expose services
	_exposeClusterIP: *false | true
	_exposeNodePort:  *false | true
	_exposeHeadless:  *false | true

	// Pod ports
	_serverPort: *"" | string
	if _serverPort != "" {
		_probeTarget: "localhost:\(_serverPort)"
	}

	spec: {
		replicas: *1 | int
		template: spec: {
			hostNetwork: *false | true
			containers: [{
				if _sleepCommand {
					command: ["/bin/ash", "-c", "sleep 1000000000"]
				}
			}]
		}
	}
}

service: [ID=_]: {
	_name:     ID
	_selector: ID | string

	apiVersion: "v1"
	kind:       "Service"
	metadata: {
		name: ID
		labels: {
			name:      _name
			topology:  *"any" | string
			component: *"invalid" | string
		}
	}
	spec: {
		type: *"ClusterIP" | string
		selector: name: _selector
	}
}

_cnp: {
	_name: string

	apiVersion: "cilium.io/v2"
	kind:       "CiliumNetworkPolicy"
	metadata: {
		name: _name
		labels: {
			name:      _name
			topology:  *"any" | string
			component: *"invalid" | string
		}
	}
	spec: endpointSelector: matchLabels: name: _name
}

egressCNP: [ID=_]: _cnp & {
	_name:      ID
	_allow:     *"" | string
	_allowFQDN: *"" | string
	_port:      *"80" | string
	_proto:     *"TCP" | "TCP" | "UDP"
	_httpAllow: *false | true

	_endpointRule: {}
	if _allow != "" {
		_endpointRule: {
			toEndpoints: [{
				matchLabels: {
					name: _allow
				}
			}]
			toPorts: [{
				ports: [{
					port:     _port
					protocol: _proto
				}]
				if _httpAllow {
					rules:
						http: [{
							method: "GET"
							path:   "/public$"
						}]
				}
			}]
		}
	}

	_fqdnRule: {}
	if _allowFQDN != "" {
		_fqdnRule: {
			toFQDNs: [{matchPattern: _allowFQDN}]
		}
	}

	spec: egress: [
		_endpointRule,
		_fqdnRule,
		{
			toEndpoints: [{
				matchLabels: {
					"k8s:io.kubernetes.pod.namespace": " kube-system"
					"k8s:k8s-app":                     " kube-dns"
				}
			}]
			toPorts: [{
				ports: [{
					port:     "53"
					protocol: "UDP"
				}]
				if _allowFQDN != "" {
					rules: dns: matchPattern: "*"
				}
			}]
		},
		{
			toEndpoints: [{
				matchLabels: {
					"k8s:io.kubernetes.pod.namespace":             "openshift-dns"
					"k8s:dns.operator.openshift.io/daemonset-dns": "default"
				}
			}]
			toPorts: [{
				ports: [{
					port:     "5353"
					protocol: "UDP"
				}]
				if _allowFQDN != "" {
					rules: dns: matchPattern: "*"
				}
			}]
		},
	]
}

ingressCNP: [ID=_]: _cnp & {
	_name:      ID
	_port:      *"80" | string
	_proto:     *"TCP" | "TCP" | "UDP"
	_httpAllow: *false | true

	spec: ingress: [{
		toPorts: [{
			ports: [{
				port:     _port
				protocol: _proto
			}]
			if _httpAllow {
				rules:
					http: [{
						method: "GET"
						path:   "/public$"
					}]
			}
		}]
	}]
}

// Create services for each deployment that have relevant configuration.
for x in [deployment] for k, v in x {
	if v._exposeClusterIP || v._exposeNodePort {
		service: "\(k)": {
			metadata: v.metadata
			spec: selector: v.spec.template.metadata.labels
			if v._exposeNodePort {
				spec: type: "NodePort"
			}
			spec: ports: [
				for c in v.spec.template.spec.containers
				for p in c.ports
				if p._expose {
					let Port = p.containerPort // Port is an alias
					port: *Port | int
					if v._exposeNodePort {
						nodePort: v._nodePort
					}
				},
			]
		}
	}
	if v._exposeHeadless {
		service: "\(k)-headless": {
			_selector: k
			metadata: name: "\(v.metadata.name)-headless"
			metadata: labels: name:      "\(v.metadata.name)-headless"
			metadata: labels: component: v.metadata.labels.component
			spec: selector:  v.spec.template.metadata.labels
			spec: clusterIP: "None"
			spec: ports: [
				for c in v.spec.template.spec.containers
				for p in c.ports
				if p._expose {
					let Port = p.containerPort // Port is an alias
					port: *Port | int
				},
			]
		}
	}
}
