// Copyright 2018-2019 Authors of Cilium
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

package policy

import (
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

// selectorPolicy is a structure which contains the resolved policy for a
// particular Identity across all layers (L3, L4, and L7), with the policy
// still determined in terms of EndpointSelectors.
type selectorPolicy struct {
	// Revision is the revision of the policy repository used to generate
	// this selectorPolicy.
	Revision uint64

	// SelectorCache managing selectors in L4Policy
	SelectorCache *SelectorCache

	// L4Policy contains the computed L4 and L7 policy.
	L4Policy *L4Policy

	// CIDRPolicy contains the L3 (not L4) CIDR-based policy.
	CIDRPolicy *CIDRPolicy

	// IngressPolicyEnabled specifies whether this policy contains any policy
	// at ingress.
	IngressPolicyEnabled bool

	// EgressPolicyEnabled specifies whether this policy contains any policy
	// at egress.
	EgressPolicyEnabled bool
}

func (p *selectorPolicy) Attach() {
	if p.L4Policy != nil {
		p.L4Policy.Attach()
	}
}

// EndpointPolicy is a structure which contains the resolved policy across all
// layers (L3, L4, and L7), distilled against a set of identities.
type EndpointPolicy struct {
	// Note that all Endpoints sharing the same identity will be
	// referring to a shared selectorPolicy!
	*selectorPolicy

	// PolicyMapState contains the state of this policy as it relates to the
	// datapath. In the future, this will be factored out of this object to
	// decouple the policy as it relates to the datapath vs. its userspace
	// representation.
	// It maps each Key to the proxy port if proxy redirection is needed.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the Key and the proxy port must be in host byte-order.
	PolicyMapState MapState

	// PolicyMapChanges collects pending changes to the PolicyMapState
	PolicyMapChanges MapChanges

	// PolicyOwner describes any type which consumes this EndpointPolicy object.
	PolicyOwner PolicyOwner
}

// PolicyOwner is anything which consumes a EndpointPolicy.
type PolicyOwner interface {
	LookupRedirectPort(l4 *L4Filter) uint16
	FetchVisibilityPolicy(trafficdirection.TrafficDirection) L4PolicyMap
}

// newSelectorPolicy returns an empty selectorPolicy stub.
func newSelectorPolicy(revision uint64, selectorCache *SelectorCache) *selectorPolicy {
	return &selectorPolicy{
		Revision:      revision,
		SelectorCache: selectorCache,
	}
}

// insertUser adds a user to the L4Policy so that incremental
// updates of the L4Policy may be fowarded.
func (p *selectorPolicy) insertUser(user *EndpointPolicy) {
	if p.L4Policy != nil {
		p.L4Policy.insertUser(user)
	}
}

// Detach releases resources held by a selectorPolicy to enable
// successful eventual GC.  Note that the selectorPolicy itself if not
// modified in any way, so that it can be used concurrently.
func (p *selectorPolicy) Detach() {
	if p.L4Policy != nil {
		p.L4Policy.Detach(p.SelectorCache)
	}
}

// DistillPolicy filters down the specified selectorPolicy (which acts
// upon selectors) into a set of concrete map entries based on the
// SelectorCache. These can subsequently be plumbed into the datapath.
//
// Must be performed while holding the Repository lock.
func (p *selectorPolicy) DistillPolicy(policyOwner PolicyOwner) *EndpointPolicy {
	calculatedPolicy := &EndpointPolicy{
		selectorPolicy: p,
		PolicyMapState: make(MapState),
		PolicyOwner:    policyOwner,
	}

	if !p.IngressPolicyEnabled || !p.EgressPolicyEnabled {
		calculatedPolicy.PolicyMapState.AllowAllIdentities(
			!p.IngressPolicyEnabled, !p.EgressPolicyEnabled)
	}

	// Register the new EndpointPolicy as a receiver of delta
	// updates.  Any updates happening after this, but before
	// computeDesiredL4PolicyMapEntires() call finishes may
	// already be applied to the PolicyMapState, specifically:
	//
	// - PolicyMapChanges may contain an addition of an entry that
	//   is already added to the PolicyMapState
	//
	// - PolicyMapChanges may congtain a deletion of an entry that
	//   has already been deleted from PolicyMapState
	p.insertUser(calculatedPolicy)

	// Must come after the 'insertUser()' above to guarantee
	// PolicyMapCanges will contain all changes that are applied
	// after the computation of PolicyMapState has started.
	calculatedPolicy.computeDesiredL4PolicyMapEntries()
	calculatedPolicy.PolicyMapState.DetermineAllowLocalhostIngress(p.L4Policy)

	return calculatedPolicy
}

// computeDesiredL4PolicyMapEntries transforms the EndpointPolicy.L4Policy into
// the datapath-friendly format inside EndpointPolicy.PolicyMapState.
func (p *EndpointPolicy) computeDesiredL4PolicyMapEntries() {

	if p.L4Policy == nil {
		return
	}
	p.computeDirectionL4PolicyMapEntries(p.L4Policy.Ingress, trafficdirection.Ingress)
	p.computeDirectionL4PolicyMapEntries(p.L4Policy.Egress, trafficdirection.Egress)
}

func (p *EndpointPolicy) computeDirectionL4PolicyMapEntries(l4PolicyMap L4PolicyMap, direction trafficdirection.TrafficDirection) {
	// Derive map entries from the selector policy
	for _, filter := range l4PolicyMap {
		keysFromFilter := filter.ToKeys(direction)
		for _, keyFromFilter := range keysFromFilter {
			var proxyPort uint16
			// Preserve the already-allocated proxy ports for redirects that
			// already exist.
			if filter.IsRedirect() {
				proxyPort = p.PolicyOwner.LookupRedirectPort(filter)
				// If the currently allocated proxy port is 0, this is a new
				// redirect, for which no port has been allocated yet. Ignore
				// it for now. This will be configured by
				// e.addNewRedirectsFromMap once the port has been allocated.
				if proxyPort == 0 {
					continue
				}
			}
			p.PolicyMapState[keyFromFilter] = MapStateEntry{ProxyPort: proxyPort}
		}
	}

	// Derive L7 visibility overrides from the PolicyOwner
	//vp := p.PolicyOwner.FetchVisibilityPolicy(direction)
	//allowAll := p.PolicyMapState.AllowsAll(direction)
	//for _, filter := range vp {
	//	for _, k := range filter.ToKeys(direction) {
	// TODO: Check that the traffic is already allowed
	// TODO: If allowed, lookup redirect and insert

	// TODO: It's likely that the specified 'filter' is
	//       not l3-dependent, but it could be applied to
	//       an endpoint with l3-dependent policy, in which
	//       case we should:
	//       - Check for L4 policy. We can just introspect
	//         into the 'p.selectorPolicy' using the same
	//         "port/protocol" that identifies 'filter'.
	//         + If there's already L7-only policy, continue 'vp'.
	//         + If there's L4-only policy, get a port and
	//           stuff it in there. Presumably means
	//           deleting the existing map key in
	//           'p.PolicyMapState' and inserting an L7 one.
	//           ADDENDUM: This shouldn't be overridden by
	//                     incremental policy calculation..
	//         + If the L4 policy is l3-dependent, we need
	//           to do something similar to the above two
	//           steps, except considering each l3 peer.
	//       - Check for L3-only policy. Can be done via
	//         the "0/0" port/proto filter in 'p.selectorPolicy's
	//         L4PolicyMap.
	//         + If wildcards L3, easy, just inject the L7
	//           policymap entries.
	//         + Otherwise iterate each L3 peer that's
	//           allowed and generate the entry for that.
	//
	//       May also want to consider whether saving the
	//       results / changes from the above is useful for
	//       later; either in the following L7 rule gen
	//       piece, or potentially even later again if we
	//       want to cache and/or rely upon this for
	//       incremental policy calc.
	//	}
	//}

	// TODO: Apparently we shouldn't need to generate L7 policy because
	//       the proxy is automatically allow-all unless an l7 policy is
	//       configured, in which case we will rely on that enforcement
	//       policy to perform the right L7 forwarding. Either way,
	//       directing traffic to the proxy will have the effect of
	//       providing visibility and will follow the enforcement policy.
	//
	//       Just need to validate that we didn't miss anything with the
	//       above; hopefully it's a no-op.
}

// NewEndpointPolicy returns an empty EndpointPolicy stub.
func NewEndpointPolicy(repo *Repository) *EndpointPolicy {
	return &EndpointPolicy{
		selectorPolicy: newSelectorPolicy(0, repo.GetSelectorCache()),
	}
}
