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

package notify

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/process"

	"github.com/shirou/gopsutil/net"
	"github.com/sirupsen/logrus"
)

const (
	procPath = "/proc"
)

var (
	log             = logging.DefaultLogger.WithField(logfields.LogSubsys, "process-notify")
	defaultInterval = 100 * time.Millisecond
	gcInterval      = 1 * time.Second
)

type ProcessListener interface {
	Learn(pid process.PID) error
	Forget(pid process.PID)
	AddConnection(pid process.PID, ctx process.ConnectContext)
}

type pidConn struct {
	pid  process.PID
	conn string
}

// processWatcher provides abstraction over the DirectoryWatcher to notify a
// ProcessListener when processes are created or killed.
type processWatcher struct {
	listener     ProcessListener
	pollInterval time.Duration
	stop         chan struct{}

	// PIDs and Conns map from seen PID/connections to whether
	// that PID/connection was seen in the recent dump.
	PIDs  map[process.PID]bool
	Conns map[pidConn]bool
}

func newProcessWatcher(path string, listener ProcessListener) *processWatcher {
	procWatcher := &processWatcher{
		listener:     listener,
		pollInterval: defaultInterval,
		stop:         make(chan struct{}),
		PIDs:         make(map[process.PID]bool),
		Conns:        make(map[pidConn]bool),
	}

	return procWatcher
}

// NewProcessWatcher creates a watcher on the process filesystem and updates
// the cache in pkg/process whenever processes exec or stop.
func NewProcessWatcher() *processWatcher {
	return newProcessWatcher(procPath, process.Cache)
}

// discoverConnections learns about the connections for the specified PID and
// socket type (tcp, udp, etc), and if successful returns
func (pw *processWatcher) discoverConnections(pid process.PID, kind string) ([]process.ConnectContext, error) {
	conns, err := net.ConnectionsPid(kind, int32(pid))
	if err != nil {
		log.WithFields(logrus.Fields{
			"kind":        kind,
			logfields.PID: pid,
		}).WithError(err).Warn("Failed to discover connections for process")
		return nil, err
	}

	// Look for connections and validate
	connsToAdd := make([]process.ConnectContext, len(conns))
	for i, c := range conns {
		if err := pw.listener.Learn(pid); err != nil {
			log.WithField("connection", c).WithError(err).Debug("Failed to fetch process context")
			return nil, err
		}

		connCtx, err := process.ParseConnection(c.Laddr.IP, c.Raddr.IP, c.Laddr.Port, c.Raddr.Port)
		if err != nil {
			log.WithField("connection", c).WithError(err).Warn("Failed to parse addresses for connection")
			continue
		}
		connsToAdd[i] = connCtx
	}

	// Add the connections to the listener only if we can guarantee we have
	// a ProcessContext corresponding to the pid.
	for _, c := range connsToAdd {
		pw.listener.AddConnection(pid, c)
	}

	return connsToAdd, nil
}

type connSweepInfo struct {
	pid  process.PID
	seen bool
}

func (pw *processWatcher) mark() {
	for p := range pw.PIDs {
		pw.PIDs[p] = false
	}
	for c := range pw.Conns {
		pw.Conns[c] = false
	}
}

func (pw *processWatcher) dump() error {
	pids, err := net.Pids()
	if err != nil {
		return fmt.Errorf("Failed to fetch PIDs: %s", err)
	}
nextProcess:
	for _, p := range pids {
		pid := process.PID(p)
		for _, kind := range []string{"tcp"} {
			cts, err := pw.discoverConnections(pid, kind)
			if err != nil {
				continue nextProcess
			}

			for _, c := range cts {
				pidConn := pidConn{
					pid:  pid,
					conn: c.String(),
				}
				pw.Conns[pidConn] = true
			}
		}
		pw.PIDs[pid] = true
	}

	return nil
}

func (pw *processWatcher) sweep() {
	for p, seen := range pw.PIDs {
		if !seen {
			pw.listener.Forget(process.PID(p))
			delete(pw.PIDs, p)
		}
	}
	for c, seen := range pw.Conns {
		// Sweep connections for live processes.
		if pw.PIDs[c.pid] && !seen {
			// TODO: Connection cleanup for long-lived processes
			//pw.listener.RemoveConnection(info.pid)
			delete(pw.Conns, c)
		}
	}
}

func (pw *processWatcher) Watch() error {
	go process.Cache.GarbageCollect(gcInterval)

	for {
		select {
		case <-time.After(pw.pollInterval):
			pw.mark()
			if err := pw.dump(); err != nil {
				return err
			}
			pw.sweep()
		case <-pw.stop:
			return nil
		}
	}
}

func (pw *processWatcher) Stop() {
	process.Cache.StopGC()
	close(pw.stop)
}
