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

package cgroups

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var (
	// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#organizing-processes-and-threads
	cgroupSeparator = ":"
	cgroup2Name     = "" // "0::$PATH"
)

// cgroup is formed by parsing a line from /proc/$$/cgroup and
// splitting it by the cgroup separator.
type cgroup []string

func (ch cgroup) index() string {
	if len(ch) > 0 {
		return ch[0]
	}
	return ""
}

func (ch cgroup) name() string {
	if len(ch) > 1 {
		return ch[1]
	}
	return ""
}

func (ch cgroup) path() string {
	if len(ch) > 2 {
		return ch[2]
	}
	return ""
}

func (ch cgroup) isNet() bool {
	switch ch.name() {
	case "net_cls":
	case "net_cls,net_prio":
	case "net_prio":
	default:
		return false
	}
	return true
}

func (ch cgroup) isUnified() bool {
	if len(ch) < 3 {
		return false
	}
	return ch.name() == ""
}

// parseCgroup converts a line like "0::/path" into a cgroup type.
func parseCgroup(line string) (cgroup, error) {
	cgroup := strings.Split(line, cgroupSeparator)
	if len(cgroup) != 3 {
		return nil, fmt.Errorf("unparseable cgroup specification %q", cgroup[0])
	}
	return cgroup, nil
}

type cgroups []cgroup

// parseCgroups converts a scanner over a buffer of individual cgroup definitions
// into a native type for easy manipulation.
func parseCgroups(scanner *bufio.Scanner) (cgroups, error) {
	var cgroups cgroups
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		cgroup, err := parseCgroup(line)
		if err != nil {
			return nil, err
		}
		cgroups = append(cgroups, cgroup)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(cgroups) == 0 {
		return nil, fmt.Errorf("no cgroups found")
	}

	return cgroups, nil
}

func (ch cgroups) cgroup2Path() (string, error) {
	for _, cg := range ch {
		if cg.isUnified() {
			// There's only one cgroup2 hierarchy.
			return cg.path(), nil
		}
	}

	return "", fmt.Errorf("cgroup2 prefix not found")
}

// parseCgroupHierarchyForPID takes a PID and attempts to determine the
// set of cgroup hierarchies that apply to the PID.
func parseCgroupHierarchyForPID(pid string) (cgroups, error) {
	procPath := fmt.Sprintf("/proc/%s/cgroup", pid)
	cgFile, err := os.Open(procPath)
	if err != nil {
		return nil, fmt.Errorf("could not read cgroup from path %s: %s", procPath, err)
	}
	defer cgFile.Close()

	scanner := bufio.NewScanner(cgFile)
	return parseCgroups(scanner)
}
