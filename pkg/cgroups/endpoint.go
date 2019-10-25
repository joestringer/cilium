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
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	// https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#core-interface-files
	procsBaseName = "cgroup.procs"

	datapathClsPrefix = uint32(0xC1110000)

	checkCgroupV2Once   sync.Once
	cgroupV2PerEndpoint bool
)

// EndpointCgroup is the representation of a Cgroup corresponding to a Cilium
// Endpoint.
type EndpointCgroup struct {
	id   uint64
	path string // relative path under unified cgroup v2 filesystem
}

// Open returns a handle for manipulating cgroups for an endpoint,
// based upon a specified cgroup v2 relative path.
func Open(path string) (*EndpointCgroup, error) {
	id, err := GetCgroupID(path)
	if err != nil {
		return nil, err
	}

	return &EndpointCgroup{
		path: path,
		id:   id,
	}, nil
}

// Create a cgroup for the container sandbox identified by the specified
// sandbox PID and containerID.
func Create(pid, containerID string) (*EndpointCgroup, error) {
	// TODO: What if the mount fails...?
	CheckOrMountCgrpFS("")

	cgroups, err := parseCgroupHierarchyForPID(pid)
	if err != nil {
		return nil, err
	}

	cg2Path, err := cgroups.cgroup2Path()
	if err != nil {
		return nil, fmt.Errorf("could not read cgroup for pid %s: %s", pid, err)
	}

	newPath := sanitizeEndpointPath(cg2Path, containerID)
	if newPath != cg2Path {
		fullPath := path.Join(GetCgroupRoot(), newPath)
		_ = fullPath
		if err := os.Mkdir(fullPath, 0755); err != nil {
			return nil, err
		}

		procsPath := path.Join(fullPath, procsBaseName)
		if err := ioutil.WriteFile(procsPath, []byte(pid), 0755); err != nil {
			err2 := os.RemoveAll(fullPath)
			if err2 != nil {
				log.WithField("path", fullPath).WithError(err2).Warning("Failed to clean up cgroup after pid write failure")
			}
			return nil, err
		}
	}

	cg, err := Open(newPath)
	if err != nil {
		return nil, err
	}

	// Best effort. Complain if it doesn't work but allow connectivity bootstrap.
	_ = cg.disableConflictingCgroups(cgroups, pid)

	return cg, nil
}

// Path returns the relative path in the cgroup hierarchy for this cgroup.
func (cg *EndpointCgroup) Path() string {
	return cg.path
}

// ID returns the kernel ID for this cgroup.
func (cg *EndpointCgroup) ID() uint64 {
	return cg.id
}

func (cg *EndpointCgroup) disableConflictingCgroups(cgroups cgroups, pid string) (err error) {
	for _, cg := range cgroups {
		if !cg.isNet() {
			continue
		}

		scopedLog := log.WithFields(logrus.Fields{
			logfields.PID:  pid,
			logfields.Path: cg.path(),
		})
		basePath, mounted := getCgroupNetMounts()[cg.name()]
		if !mounted || cg.path() == "/" {
			scopedLog.Debugf("Skipping cgroup net hierarchy move")
			continue
		}

		scopedLog.WithField("cgroup", basePath).Debugf("Configuring cgroup net hierarchy")
		procsPath := path.Join(basePath, procsBaseName)
		if err2 := ioutil.WriteFile(procsPath, []byte(pid), 0755); err2 != nil {
			scopedLog.WithError(err2).Warning("Failed to move process to root net cgroup")
			err = err2
		}
	}
	return err
}

// GetCgroupIDByPath converts a filesystem path into a cgroup ID.
func GetCgroupIDByPath(fullPath string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, fullPath, 0)
	if err != nil {
		return 0, &os.PathError{
			Op:   "failed to convert cgroup path to handle",
			Path: fullPath,
			Err:  err,
		}
	}

	var result uint64
	rawID := bytes.NewBuffer(handle.Bytes()[:])
	if err := binary.Read(rawID, byteorder.Native, &result); err != nil {
		return 0, &os.PathError{
			Op:   "failed to decode cgroup handle",
			Path: fullPath,
			Err:  err,
		}
	}
	return result, nil
}

// GetCgroupID converts a cgroup v2 path into a cgroup ID.
func GetCgroupID(relativePath string) (uint64, error) {
	fullPath := path.Join(GetCgroupRoot(), relativePath)
	return GetCgroupIDByPath(fullPath)
}

// sanitizeEndpointPath idempotently converts a path for a cgroup into a path
// that is suffixed by the containerID.
//
// sanitizeEndpointPath(path/cid, cid) -> path/cid
// sanitizeEndpointPath(path/foo, cid) -> path/foo/cid
func sanitizeEndpointPath(cgPath, containerID string) string {
	if strings.HasSuffix(cgPath, containerID) {
		return cgPath
	}
	return path.Join(cgPath, containerID)
}

// perEndpointIDExists returns true if the cgroup v2 id appears to be available
// for use in the datapath. If not available, we assume that cgroup v1 net_cls
// controller is available for each endpoint.
func perEndpointIDExists() bool {
	checkCgroupV2Once.Do(func() {
		path := fmt.Sprintf("%s/kubepods", GetCgroupRoot())
		if _, err := os.Stat(path); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Path: path,
			}).Debugf("Cgroup v2 per pod not found")
			cgroupV2PerEndpoint = false
			return
		}
		cgroupV2PerEndpoint = true
	})
	return cgroupV2PerEndpoint
}

type endpoint interface {
	Cgroup() string
	GetID16() uint16
}

func ConfigureEndpoint(ep endpoint) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.EndpointID: ep.GetID16(),
	})
	if perEndpointIDExists() {
		scopedLog.Debug("Skipping configuration of endpoint classid")
		return nil
	}

	classID := fmt.Sprintf("%#08x", datapathClsPrefix|uint32(ep.GetID16()))
	for _, mount := range getCgroupNetMounts() {
		fullPath := path.Join(mount, ep.Cgroup(), "net_cls.classid")
		scopedLog.WithFields(logrus.Fields{
			"classid":      classID,
			logfields.Path: fullPath,
		}).Debug("Configuring cgroup")
		if err := ioutil.WriteFile(fullPath, []byte(classID), 0755); err != nil {
			return err
		}
	}
	return nil
}
