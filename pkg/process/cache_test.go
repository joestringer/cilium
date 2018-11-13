// Copyright 2018 Authors of Cilium
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

package process

import (
	"bufio"
	"bytes"
	"net"
	"strings"

	. "gopkg.in/check.v1"
)

var (
	c1 = ConnectContext{
		SrcIP:   net.ParseIP("192.0.2.3"),
		DstIP:   net.ParseIP("192.0.2.4"),
		DstPort: 0xcafe,
		Socket:  0x4a11,
	}
	c2 = ConnectContext{
		SrcIP:   net.ParseIP("192.0.2.3"),
		DstIP:   net.ParseIP("192.0.2.5"),
		DstPort: 0xcafe,
		Socket:  0xcafe4a11,
	}
)

func (p *ProcessTestSuite) TestLookupOrCreate(c *C) {
	cache := newCache()

	proc, created, err := cache.lookupOrCreateLocked(currentPID)
	c.Assert(err, IsNil)
	c.Assert(proc, NotNil)
	c.Assert(created, Equals, true)

	proc, created, err = cache.lookupOrCreateLocked(currentPID)
	c.Assert(err, IsNil)
	c.Assert(proc, NotNil)
	c.Assert(created, Equals, false)
}

func dumpCache(cache *cache) string {
	buf := bytes.Buffer{}
	writer := bufio.NewWriter(&buf)
	cache.Dump(writer)
	writer.Flush()
	return buf.String()
}

func (p *ProcessTestSuite) TestDump(c *C) {
	cache := newCache()

	proc, err := cache.LookupOrCreate(currentPID)
	c.Assert(err, IsNil)
	c.Assert(proc, NotNil)

	dump := dumpCache(cache)
	c.Assert(dump, Not(Equals), "")
	c.Assert(strings.Contains(dump, currentPID.String()), Equals, true)
	c.Assert(strings.Contains(dump, proc.Binary), Equals, true)

	// Add some connections, look for them in the dump output
	cache.AddConnection(currentPID, c1)
	cache.AddConnection(currentPID, c2)
	dump = dumpCache(cache)
	c.Assert(strings.Contains(dump, currentPID.String()), Equals, true)
	c.Assert(strings.Contains(dump, c1.String()), Equals, true)
	c.Assert(strings.Contains(dump, c2.String()), Equals, true)
}

func (p *ProcessTestSuite) TestDelete(c *C) {
	cache := newCache()

	_, err := cache.LookupOrCreate(currentPID)
	c.Assert(err, IsNil)

	cache.Delete(currentPID)
	c.Assert(len(cache.byPID), Equals, 0)
	c.Assert(len(cache.byContainerID), Equals, 0)

	_, created, err := cache.lookupOrCreateLocked(currentPID)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
}
