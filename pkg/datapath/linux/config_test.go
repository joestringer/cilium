// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package linux

import (
	"bytes"
	"errors"
	"io"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/cache"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

type DatapathSuite struct{}

var (
	_ = Suite(&DatapathSuite{})

	dummyNodeCfg = datapath.LocalNodeConfiguration{}
	dummyDevCfg  = testutils.NewTestEndpoint()
	dummyEPCfg   = testutils.NewTestEndpoint()
)

func (s *DatapathSuite) SetUpTest(c *C) {
	node.InitDefaultPrefix("")
}

type badWriter struct{}

func (b *badWriter) Write(p []byte) (int, error) {
	return 0, errors.New("bad write :(")
}

type testCase struct {
	description string
	output      io.Writer
	expResult   Checker
}

type writeFn func(io.Writer, datapath.Datapath) error

func writeConfig(c *C, header string, write writeFn) {
	tests := []testCase{
		{
			description: "successful write to an in-memory buffer",
			output:      &bytes.Buffer{},
			expResult:   IsNil,
		},
		{
			description: "write to a failing writer",
			output:      &badWriter{},
			expResult:   NotNil,
		},
	}
	for _, test := range tests {
		c.Logf("  Testing %s configuration: %s", header, test.description)
		dp := NewDatapath(DatapathConfiguration{})
		c.Assert(write(test.output, dp), test.expResult)
	}
}

func (s *DatapathSuite) TestWriteNodeConfig(c *C) {
	writeConfig(c, "node", func(w io.Writer, dp datapath.Datapath) error {
		return dp.WriteNodeConfig(w, &dummyNodeCfg)
	})
}

func (s *DatapathSuite) TestWriteNetdevConfig(c *C) {
	writeConfig(c, "netdev", func(w io.Writer, dp datapath.Datapath) error {
		return dp.WriteNetdevConfig(w, &dummyDevCfg)
	})
}

func (s *DatapathSuite) TestWriteEndpointConfig(c *C) {
	writeConfig(c, "endpoint", func(w io.Writer, dp datapath.Datapath) error {
		return dp.WriteEndpointConfig(w, &dummyEPCfg, true)
	})
}

// TestHashDatapath is done in this package just for easy access to dummy
// configuration objects.
func (s *DatapathSuite) TestHashDatapath(c *C) {
	dp := NewDatapath(DatapathConfiguration{})
	h := cache.NewHash(dp)
	baseHash := h.String()

	// Ensure we get different hashes when config is added
	h = cache.HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &dummyEPCfg)
	dummyHash := h.String()
	c.Assert(dummyHash, Not(Equals), baseHash)

	// Ensure we get the same base hash when config is removed via Reset()
	h.Reset()
	c.Assert(h.String(), Equals, baseHash)
	c.Assert(h.String(), Not(Equals), dummyHash)

	// Ensure that with a copy of the endpoint config we get the same hash
	newEPCfg := dummyEPCfg
	h = cache.HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Equals, dummyHash)

	// Even with different endpoint IDs, we get the same hash
	//
	// This is the key to avoiding recompilation per endpoint; static
	// data substitution is performed via pkg/elf instead.
	newEPCfg.id++
	h = cache.HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Equals, dummyHash)

	// But when we configure the endpoint differently, it's different
	newEPCfg = newDummyEP()
	newEPCfg.opts.SetBool("foo", true)
	h = cache.HashDatapath(dp, &dummyNodeCfg, &dummyDevCfg, &newEPCfg)
	c.Assert(h.String(), Not(Equals), baseHash)
	c.Assert(h.String(), Not(Equals), dummyHash)
}
