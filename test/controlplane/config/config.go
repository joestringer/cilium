// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var (
	podCIDR         = cidr.MustParseCIDR("10.0.1.0/24")
	localNodeObject = &corev1.Node{
		TypeMeta: metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "minimal",
			Labels: map[string]string{
				"foo": "bar",
			},
			Annotations: map[string]string{
				"cilium.io/baz": "quux",
			},
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR.String(),
			PodCIDRs: []string{podCIDR.String()},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeExternalIP, Address: "20.0.0.2"},
				{Type: corev1.NodeHostName, Address: "minimal"},
			},
		},
	}
)

func validateConfig(cmd *cobra.Command) error {
	m := map[string]interface{}{
		//TODO add things in here
	}
	return option.ValidateConfigMap(cmd, m)
}

func init() {
	// AgentConfig validates that input flags provided by the user on the
	// daemon commandline are properly parsed and ingested into the
	// DaemonConfig.
	suite.AddTestCase("AgentConfig", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		// We only need to test the last k8s version
		test := suite.NewControlPlaneTest(t, "minimal", k8sVersions[len(k8sVersions)-1])
		test.
			UpdateObjects(localNodeObject).
			SetupEnvironment().
			StartAgent(func(*option.DaemonConfig) {}).
			ValidateAgentConfig(validateConfig).
			StopAgent().
			ClearEnvironment()
	})
}
