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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

var (
	currentPID = PID(os.Getpid())
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ProcessTestSuite struct{}

var _ = Suite(&ProcessTestSuite{})

func (p *ProcessTestSuite) TestExtractContainerID(c *C) {
	dockerID := "a043f02cf1a1ae11116e2110be401541f07293f67eab4b9584682078773c79c7"
	fileInput := fmt.Sprintf("6:cpu:/docker/%s", dockerID)
	c.Assert(extractContainerID(fileInput), Equals, dockerID)
}

// TestNewProcessContext reads the proc file for the process running this test
// and checks that the resulting ProcessContext has valid values (ie, matching
// what we can access directly via Golang libraries).
func (p *ProcessTestSuite) TestNewProcessContext(c *C) {
	nosuchPID := PID(-1)
	proc, err := newProcessContext(nosuchPID)
	c.Assert(err, NotNil)

	expProcess := &ProcessContext{
		HostPID:     currentPID,
		Binary:      os.Args[0],
		CmdLine:     strings.Join(os.Args, " "),
		Name:        filepath.Base(os.Args[0]),
		connections: map[string]ConnectContext{},
	}
	proc, err = newProcessContext(currentPID)
	c.Assert(err, IsNil)
	c.Assert(proc, checker.DeepEquals, expProcess)
	procString := proc.String()
	c.Assert(strings.Contains(procString, currentPID.String()), Equals, true)
	c.Assert(strings.Contains(procString, os.Args[0]), Equals, true)
}
