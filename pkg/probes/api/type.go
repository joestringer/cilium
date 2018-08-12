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

package api

import (
	"fmt"
)

// ProbeType defines the type of probe.
type ProbeType uint16

// String returns the human readable form of a probe type.
func (p ProbeType) String() string {
	switch p {
	case ProbeEnterConnect:
		return "kprobe_connect"
	case ProbeReturnConnect:
		return "kretprobe_connect"
	case ProbeEnterExecute:
		return "kprobe_execve"
	case ProbeEnterExit:
		return "kprobe_exit"
	default:
		return fmt.Sprintf("unknown:%d", uint16(p))
	}
}

// IsKProbe returns true if the recieved ProbeType represents a KProbe.
func (p ProbeType) IsKProbe() bool {
	switch p {
	case ProbeEnterConnect, ProbeEnterExecute, ProbeEnterExit:
		return true
	}
	return false
}

// IsKRetProbe returns true if the recieved ProbeType represents a KRetProbe.
func (p ProbeType) IsKRetProbe() bool {
	switch p {
	case ProbeReturnConnect:
		return true
	}
	return false
}

// AttachType returns the string representing the BPF attachment type for
// the received ProbeType.
func (p ProbeType) AttachType() string {
	switch {
	case p.IsKProbe():
		return "kprobe"
	case p.IsKRetProbe():
		return "kretprobe"
	}
	return p.String()
}

const (
	// These types must be kept in sync with <bpf/lib/probes/comm.h>

	// ProbeUnknown is a dummy value for unhandled probe types
	ProbeUnknown ProbeType = iota
	// ProbeEnterConnect is invoked when entering tcp_v4_connect()
	ProbeEnterConnect
	// ProbeReturnConnect is invoked when tcp_v4_connect() returns
	ProbeReturnConnect
	// ProbeEnterExecute is invoked when entering sys_execve()
	ProbeEnterExecute
	// ProbeEnterExit is invoked when entering sys_exit() or sys_exit_group()
	ProbeEnterExit
)
