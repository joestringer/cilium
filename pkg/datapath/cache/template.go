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

package cache

import (
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
)

// templateCfg wraps a real configuration from an endpoint to pass through its
// configuration of conditional branches in the datapath, but to mock out dummy
// values for static data.
//
// Note that the static data dummy values must be non-zero in every 32-bit
// section of the data to ensure that during compilation, the compiler reserves
// space in the .data section of the ELF for the value of the data, rather than
// generating a reference to the .bss section (which is what it will typically
// do if a static integer is initialized to zero).
//
// Ideally we also statically configure the values used in the template in such
// a way that if ever someone managed to inadvertently attach the template
// program directly to a device, that there are no unintended consequences such
// as allowing traffic to leak out with routable addresses.
type templateCfg struct {
	datapath.EndpointConfiguration
	stats *SpanStat
}

// GetID returns a uint64, but in practice on the datapath side it is
// guaranteed to be 16-bit; it is used to generate map names, so we need to
// ensure that the template generates map names that are as long as the longest
// possible name, which would be guaranteed with a 5-digit output.
//
// By using 65536, (0x10000 in hex), the ID would be zero if truncated to 16
// bits, and when read in decimal it is an obviously nonsense endpoint ID.
func (t *templateCfg) GetID() uint64 { return 65536 }

// StringID returns the string form of the ID returned by GetID().
func (t *templateCfg) StringID() string { return "65536" }

// GetIdentity should ideally return a security ID that will never be allocated
// for an actual set of labels, so use UINT32_MAX here.
func (t *templateCfg) GetIdentity() identity.NumericIdentity { return 0xFFFFFFFF }

func (t *templateCfg) GetNodeMAC() mac.MAC {
	return mac.MAC([]byte{0x02, 0x00, 0x60, 0x0D, 0xF0, 0x0D})
}

// IPv4Address always returns an IP in the documentation prefix (RFC5737) as
// a nonsense address that should typically not be routable.
func (t *templateCfg) IPv4Address() addressing.CiliumIPv4 {
	return addressing.CiliumIPv4([]byte{192, 0, 2, 3})
}

// IPv6Address returns an IP in the documentation prefix (RFC3849) to ensure
// that each 32-bit segment of the address is non-zero as per the requirements
// described in the structure definition. This can't be guaranteed while using
// a more appropriate prefix such as the discard prefix (RFC6666).
func (t *templateCfg) IPv6Address() addressing.CiliumIPv6 {
	return addressing.CiliumIPv6([]byte{0x20, 0x01, 0xdb, 0x8, 0x0b, 0xad, 0xca, 0xfe, 0x60, 0x0d, 0xbe, 0xe2, 0x0b, 0xad, 0xca, 0xfe})
}

// wrap takes an endpoint configuration and optional stats tracker and wraps
// it inside a templateCfg which hides static data from callers that wish to
// generate header files based on the configuration, substituting it for
// template data.
func wrap(cfg datapath.EndpointConfiguration, stats *SpanStat) *templateCfg {
	if stats == nil {
		stats = &SpanStat{}
	}
	return &templateCfg{
		EndpointConfiguration: cfg,
		stats:                 stats,
	}
}
