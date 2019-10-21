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
	"bufio"
	"strings"

	"github.com/cilium/cilium/pkg/checker"

	"gopkg.in/check.v1"
)

var (
	sampleCGroupOutput = `
12:freezer:/kubepods/besteffort/podbdd4c994-081e-4f19-b213-38cd9b37b78d/d9087097fb775b02cb6375bd884a52251fae9d65836274e609806eff1427e689
11:memory:/system.slice/snap.microk8s.daemon-containerd.service
10:pids:/system.slice/snap.microk8s.daemon-containerd.service
9:rdma:/
8:hugetlb:/kubepods/besteffort/podbdd4c994-081e-4f19-b213-38cd9b37b78d/d9087097fb775b02cb6375bd884a52251fae9d65836274e609806eff1427e689
7:blkio:/system.slice/snap.microk8s.daemon-containerd.service
6:cpuset:/kubepods/besteffort/podbdd4c994-081e-4f19-b213-38cd9b37b78d/d9087097fb775b02cb6375bd884a52251fae9d65836274e609806eff1427e689
5:cpu,cpuacct:/system.slice/snap.microk8s.daemon-containerd.service
4:net_cls,net_prio:/kubepods/besteffort/podbdd4c994-081e-4f19-b213-38cd9b37b78d/d9087097fb775b02cb6375bd884a52251fae9d65836274e609806eff1427e689
3:devices:/system.slice/snap.microk8s.daemon-containerd.service
2:perf_event:/kubepods/besteffort/podbdd4c994-081e-4f19-b213-38cd9b37b78d/d9087097fb775b02cb6375bd884a52251fae9d65836274e609806eff1427e689
1:name=systemd:/kubepods/besteffort/podbdd4c994-081e-4f19-b213-38cd9b37b78d/d9087097fb775b02cb6375bd884a52251fae9d65836274e609806eff1427e689
0::/system.slice/snap.microk8s.daemon-containerd.service/xwing
`
	sampleCgroup2Path   = "/system.slice/snap.microk8s.daemon-containerd.service/xwing"
	sampleCgroupNetPath = "/kubepods/besteffort/podbdd4c994-081e-4f19-b213-38cd9b37b78d/d9087097fb775b02cb6375bd884a52251fae9d65836274e609806eff1427e689"
)

func (s *CGroupsTestSuite) Testcgroup2Path(c *check.C) {
	tests := []struct {
		name   string
		input  string
		check  check.Checker
		result string
	}{
		{
			name:  "Empty input",
			input: "",
			check: check.NotNil,
		},
		{
			name:  "Invalid input",
			input: "abcdefg",
			check: check.NotNil,
		},
		{
			name:   "Valid input",
			input:  sampleCGroupOutput,
			check:  check.IsNil,
			result: sampleCgroup2Path,
		},
	}

	for _, tt := range tests {
		c.Log(tt.name)
		scanner := bufio.NewScanner(strings.NewReader(tt.input))
		ch, err := parseCgroups(scanner)
		c.Assert(err, tt.check)
		result, err := ch.cgroup2Path()
		c.Assert(err, tt.check)
		if tt.result != "" {
			c.Assert(result, checker.DeepEquals, tt.result)
		}
	}
}
