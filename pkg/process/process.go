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

package process

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "process")
)

// ProcessContext is a collection of information about a Process.
type ProcessContext struct {
	// HostPID is the PID of the process in the root PID namespace.
	HostPID PID

	// ContainerPID is the PID of the process inside a child PID namespace.
	ContainerPID PID

	// Binary is the first argument used to run this process.
	Binary string

	// CmdLine is the full set of arguments used to run this process.
	CmdLine string

	// Name is the name of the process.
	Name string

	// DockerContainerID is the ContainerID that Docker associates with
	// this process.
	DockerContainerID string

	// Expiry is the time that this entry will be forgotten by the cache.
	// If nil, the proccessContext is live.
	Expiry time.Time

	connections map[string]ConnectContext
}

func newProcessContext(hostPID PID) (*ProcessContext, error) {
	context := &ProcessContext{
		HostPID:     hostPID,
		connections: map[string]ConnectContext{},
	}

	if err := context.readPIDProcFile(); err != nil {
		return nil, err
	}

	p, err := process.NewProcess(int32(hostPID))
	if err != nil {
		return nil, err
	} else {
		context.Binary, _ = p.Exe()
		context.CmdLine, _ = p.Cmdline()
		context.Name, _ = p.Name()
	}

	return context, nil
}

func extractContainerID(s string) string {
	return path.Base(s)
}

// String returns a human-readable representation of the ProcessContext.
func (p *ProcessContext) String() string {
	binary := p.Binary
	if binary == "" {
		binary = fmt.Sprintf("[%s]", p.Name)
	}
	return fmt.Sprintf("%-5s %5d %5d %20s %s %s %s",
		"host", p.HostPID, p.ContainerPID, p.Expiry.Format(time.RFC3339), p.DockerContainerID, binary, p.CmdLine)
}

func (p *ProcessContext) readPIDProcFile() error {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", p.HostPID)
	file, err := os.Open(cgroupPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		if strings.Contains(s, "/docker/") && strings.Contains(s, ":cpu") {
			p.DockerContainerID = extractContainerID(s)
			log.WithFields(logrus.Fields{
				logfields.ContainerID: p.DockerContainerID,
				logfields.PID:         p.HostPID,
			}).Debugf("Extracting from /proc: %s", s)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
