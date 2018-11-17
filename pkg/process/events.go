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
	"fmt"
	"net"
)

const MaxPort = ^uint16(0)

// TODO: UDP?
type ConnectContext struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Socket  uint64
}

// ParseConnection creates a connection from the specified IP address strings
// and ports.
func ParseConnection(localIP, remoteIP string, localPort, remotePort uint32) (ConnectContext, error) {
	if remotePort > uint32(MaxPort) {
		return ConnectContext{}, fmt.Errorf("invalid remote port %d", remotePort)
	}
	if localPort > uint32(MaxPort) {
		return ConnectContext{}, fmt.Errorf("invalid local port %d", localPort)
	}
	srcIP := net.ParseIP(localIP)
	if srcIP == nil {
		return ConnectContext{}, fmt.Errorf("invalid local IP %s", localIP)
	}
	dstIP := net.ParseIP(remoteIP)
	if dstIP == nil {
		return ConnectContext{}, fmt.Errorf("invalid remote IP %s", remoteIP)
	}

	return ConnectContext{
		SrcIP: srcIP,
		DstIP: dstIP,
		// TODO: Use full 4-tuple
		//SrcPort: uint16(localPort),
		DstPort: uint16(remotePort),
	}, nil
}

func (c *ConnectContext) StringID() string {
	return fmt.Sprintf("%s:%d -> %s:%d", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
}

func (c *ConnectContext) String() string {
	return fmt.Sprintf("%16s:%-5d -> %s:%-5d", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
}

func (p *ProcessContext) AddConnection(ctx ConnectContext) {
	p.connections[ctx.StringID()] = ctx
}

func (p *ProcessContext) AddExecveEvent(comm string) {
	p.KernelCommand = comm
}
