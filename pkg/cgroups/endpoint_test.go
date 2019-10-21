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

// +build !privileged_tests

package cgroups

import (
	"gopkg.in/check.v1"
)

var (
	testContainerID = "abcdef01234567890"
)

func (s *CGroupsTestSuite) TestsanitizeEndpointPath(c *check.C) {
	tests := []struct {
		input  string
		result string
	}{
		{
			input:  "/",
			result: "/abcdef01234567890",
		},
		{
			input:  "/abcdef01234567890",
			result: "/abcdef01234567890",
		},
		{
			input:  "/system.slice/containerd.service/",
			result: "/system.slice/containerd.service/abcdef01234567890",
		},
	}

	for _, tt := range tests {
		result := sanitizeEndpointPath(tt.input, testContainerID)
		c.Assert(result, check.Equals, tt.result)
	}
}
