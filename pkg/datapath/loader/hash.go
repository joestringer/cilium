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

package loader

import (
	"crypto/sha1"
	"hash"
	"io"

	"github.com/cilium/cilium/pkg/datapath"
)

var (
	// DatapathSHA is set during build to the SHA generated from bindata.sh
	// which is hashed across all datapath template code, excluding the
	// node, netdev, lxc and sockops header files (see daemon/Makefile).
	DatapathSHA string
)

// NewHash creates a new datapath hash based on the contents of the datapath
// template files under bpf/, generated by contrib/scripts/bindata.sh.
func NewHash() hash.Hash {
	h := sha1.New()
	io.WriteString(h, DatapathSHA)
	return h
}

// HashDatapath returns a new datapath hash based on the specified datapath.
func HashDatapath(dp datapath.Datapath, nodeCfg *datapath.LocalNodeConfiguration, netdevCfg datapath.DeviceConfiguration, epCfg datapath.EndpointConfiguration) hash.Hash {
	h := NewHash()

	// Writes won't fail; it's an in-memory hash.
	_ = dp.WriteNodeConfig(h, nodeCfg)
	_ = dp.WriteNetdevConfig(h, netdevCfg)
	_ = dp.WriteEndpointConfig(h, epCfg)

	return h
}
