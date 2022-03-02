// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcachetypes

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/identity/cache"
)

type PolicyHandler interface {
	UpdateIdentities(added, deleted cache.IdentityCache, wg *sync.WaitGroup)
}

type DatapathHandler interface {
	UpdatePolicyMaps(context.Context, *sync.WaitGroup) *sync.WaitGroup
}
