// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"fmt"
	"path"
	"reflect"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	datapathcache "github.com/cilium/cilium/pkg/datapath/cache"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	bpfconfig "github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// epInfoCache describes the set of lxcmap entries necessary to describe an Endpoint
// in the BPF maps. It is generated while holding the Endpoint lock, then used
// after releasing that lock to push the entries into the datapath.
// Functions below implement the EndpointFrontend interface with this cached information.
type epInfoCache struct {
	// revision is used by the endpoint regeneration code to determine
	// whether this cache is out-of-date wrt the underlying endpoint.
	revision uint64

	// For lxcmap.EndpointFrontend
	keys  []*lxcmap.EndpointKey
	value *lxcmap.EndpointInfo

	// For datapath.loader.endpoint
	epdir       string
	id          uint64
	ifName      string
	graftToLoad bool

	// For datapath.EndpointConfiguration
	identity                               identity.NumericIdentity
	mac                                    mac.MAC
	ipv4                                   addressing.CiliumIPv4
	ipv6                                   addressing.CiliumIPv6
	conntrackLocal                         bool
	cidr4PrefixLengths, cidr6PrefixLengths []int
	options                                option.IntOptions

	// endpoint is used to get the endpoint's logger.
	//
	// Do NOT use this for fetching endpoint data directly; this structure
	// is intended as a safe cache of endpoint data that is assembled while
	// holding the endpoint lock, for use beyond the holding of that lock.
	// Dereferencing fields in this endpoint is not guaranteed to be safe.
	endpoint *Endpoint
}

// Must be called when endpoint is still locked.
func (e *Endpoint) createEpInfoCache(epdir string) *epInfoCache {
	cidr6, cidr4 := e.GetCIDRPrefixLengths()

	ep := &epInfoCache{
		revision:           e.nextPolicyRevision,
		endpoint:           e,
		epdir:              epdir,
		id:                 e.GetID(),
		identity:           e.GetIdentity(),
		ipv4:               e.IPv4Address(),
		ipv6:               e.IPv6Address(),
		ifName:             e.IfName,
		keys:               e.GetBPFKeys(),
		graftToLoad:        e.MustGraft(),
		conntrackLocal:     e.ConntrackLocalLocked(),
		cidr4PrefixLengths: cidr4,
		cidr6PrefixLengths: cidr6,
		options:            *e.Options,
	}

	var err error
	ep.value, err = e.GetBPFValue()
	if err != nil {
		log.WithField(logfields.EndpointID, e.ID).WithError(err).Error("getBPFValue failed")
		return nil
	}
	return ep
}

// InterfaceName returns the name of the link-layer interface used for
// communicating with the endpoint.
func (ep *epInfoCache) InterfaceName() string {
	return ep.ifName
}

// MapPath returns tail call map path
func (ep *epInfoCache) MapPath() string {
	return ep.endpoint.BPFIpvlanMapPath()
}

// GetID returns the endpoint's ID.
func (ep *epInfoCache) GetID() uint64 {
	return ep.id
}

// StringID returns the endpoint's ID in a string.
func (ep *epInfoCache) StringID() string {
	return fmt.Sprintf("%d", ep.id)
}

// GetIdentity returns the security identity of the endpoint.
func (ep *epInfoCache) GetIdentity() identity.NumericIdentity {
	return ep.identity
}

// Logger returns the logger for the endpoint that is being cached.
func (ep *epInfoCache) Logger(subsystem string) *logrus.Entry {
	return ep.endpoint.Logger(subsystem)
}

// MustGraft returns whether we need full replacement or grafting of object file.
func (ep *epInfoCache) MustGraft() bool {
	return ep.graftToLoad
}

// IPv4Address returns the cached IPv4 address for the endpoint.
func (ep *epInfoCache) IPv4Address() addressing.CiliumIPv4 {
	return ep.ipv4
}

// IPv6Address returns the cached IPv6 address for the endpoint.
func (ep *epInfoCache) IPv6Address() addressing.CiliumIPv6 {
	return ep.ipv6
}

// StateDir returns the directory for the endpoint's (next) state.
func (ep *epInfoCache) StateDir() string    { return ep.epdir }
func (ep *epInfoCache) GetNodeMAC() mac.MAC { return ep.mac }

// GetBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func (ep *epInfoCache) GetBPFKeys() []*lxcmap.EndpointKey {
	return ep.keys
}

// GetBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
// Must only be called if init() succeeded.
func (ep *epInfoCache) GetBPFValue() (*lxcmap.EndpointInfo, error) {
	return ep.value, nil
}

func (ep *epInfoCache) ConntrackLocalLocked() bool {
	return ep.conntrackLocal
}

// sliceToBe32 converts the input slice of four bytes to a big-endian uint32.
func sliceToBe32(input []byte) uint32 {
	result := uint32(0)
	result |= uint32(input[0]) << 24
	result |= uint32(input[1]) << 16
	result |= uint32(input[2]) << 8
	result |= uint32(input[3])
	return byteorder.HostToNetwork(result).(uint32)
}

// staticDataToMap converts the cached endpoints info which should be
// represented in BPF as static data variables into a map from the name of the
// variable to its value.
func (ep *epInfoCache) staticDataToMap() map[string]uint32 {
	result := make(map[string]uint32)

	// TODO: This seems to kinda duplicate bits of WriteEndpointConfig()

	// TODO: Double-check the byte-ordering here
	log.Debugf("%+v", ep)
	if ipv6 := ep.IPv6Address(); ipv6 != nil {
		// Corresponds to DEFINE_IPV6() in bpf/lib/utils.h
		result["LXC_IP_1"] = sliceToBe32(ipv6[0:4])
		result["LXC_IP_2"] = sliceToBe32(ipv6[4:8])
		result["LXC_IP_3"] = sliceToBe32(ipv6[8:12])
		result["LXC_IP_4"] = sliceToBe32(ipv6[12:16])
	}
	if ipv4 := ep.IPv4Address(); ipv4 != nil {
		result["LXC_IPV4"] = byteorder.HostSliceToNetwork(ipv4, reflect.Uint32).(uint32)
	}
	// TODO: MAC
	//result["NODE_MAC"] =
	result["LXC_ID"] = uint32(ep.GetID())
	identity := ep.GetIdentity().Uint32()
	result["SECLABEL"] = identity
	result["SECLABEL_NB"] = byteorder.HostToNetwork(identity).(uint32)

	return result
}

// stringsToMap converts the cached endpoints info which should be represented
// in the BPF ELF as strings into a map from the name of the string to its
// value.
func (ep *epInfoCache) stringsToMap() map[string]string {
	result := make(map[string]string)

	// The keys here must match templateCfg!
	mapNames := []string{
		policymap.MapName,
		"cilium_calls_",
		bpfconfig.MapNamePrefix,
	}
	for _, name := range mapNames {
		templateStr := path.Base(bpf.MapPath(fmt.Sprintf("%s%05d", name, datapathcache.TemplateID)))
		desiredStr := path.Base(bpf.MapPath(fmt.Sprintf("%s%05d", name, ep.GetID())))
		result[templateStr] = desiredStr
	}
	result[fmt.Sprintf("1/%#04x", datapathcache.TemplateID)] = fmt.Sprintf("1/%#04x", ep.GetID())
	return result
}

// ToBPFData converts the endpoint cache's static data (consistent with
// WriteEndpointConfig() in pkg/datapath/linux), into two maps:
// * The first represents static 32-bit data held in the ELF .data section
// * The second represents string values held in the ELF .strtab section
func (ep *epInfoCache) ToBPFData() (map[string]uint32, map[string]string) {
	return ep.staticDataToMap(), ep.stringsToMap()
}

func (ep *epInfoCache) GetCIDRPrefixLengths() ([]int, []int) {
	return ep.cidr6PrefixLengths, ep.cidr4PrefixLengths
}

func (ep *epInfoCache) GetOptions() *option.IntOptions {
	return &ep.options
}
