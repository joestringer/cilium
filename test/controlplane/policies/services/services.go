// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodeport

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var repeatPeriod = 50 * time.Microsecond

func init() {
	suite.AddTestCase("Policies/ToServices", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}

		modConfig := func(c *option.DaemonConfig) {}

		for _, version := range []string{"1.26"} {
			abs := func(f string) string { return path.Join(cwd, "policies", "services", "v"+version, f) }

			t.Run("v"+version, func(t *testing.T) {
				test := suite.NewControlPlaneTest(t, "policies-control-plane", version)

				// Feed in initial state and start the agent.
				test.
					UpdateObjectsFromFile(abs("init.yaml")).
					StartAgent(modConfig).
					// TODO: New "Eventually()" but it accounts for tests that hang / deadlock and errors out
					Eventually(func() error { return validate(test, cwd) }).
					StopAgent()
			})
		}
	})
}

func validate(test *suite.ControlPlaneTest, cwd string) error {
	// TODO: Do we need this?
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return stressServicesAndPolicies(ctx, test, cwd)
}

func stressServicesAndPolicies(ctx context.Context, test *suite.ControlPlaneTest, cwd string) error {
	svcChan := make(chan struct{})
	// TODO: Factor out? reuse code?
	go func(ctx context.Context) {
		for {
			svcFile := path.Join(cwd, "policies", "services", "manifests", "services.yaml")
			test.UpdateObjectsFromFile(svcFile)
			time.Sleep(repeatPeriod)
			test.DeleteObjectsFromFile(svcFile)
			time.Sleep(repeatPeriod)
			select {
			case <-ctx.Done():
				close(svcChan)
				return
			default:
				fmt.Println("Time to add more services... 🎣")
				continue
			}
		}
	}(ctx)
	policyChan := make(chan struct{})
	go func(ctx context.Context) {
		for {
			svcFile := path.Join(cwd, "policies", "services", "manifests", "policies.yaml")
			test.UpdateObjectsFromFile(svcFile)
			time.Sleep(repeatPeriod)
			test.DeleteObjectsFromFile(svcFile)
			time.Sleep(repeatPeriod)
			select {
			case <-ctx.Done():
				close(policyChan)
				return
			default:
				fmt.Println("Time to add more policies... 🎣")
				continue
			}
		}
	}(ctx)

	<-ctx.Done()

	err := context.DeadlineExceeded
	svcOK := false
	policyOK := false
	timeout := time.After(1 * time.Second)
loop:
	for {
		select {
		case <-svcChan:
			svcOK = true
		case <-policyChan:
			policyOK = true
		case <-timeout:
			break loop
		}
	}
	if svcOK && policyOK {
		err = nil
	} else {
		fmt.Println("Fishy 🎣")
	}

	return err
}
