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

package process

import (
	"fmt"
	"io"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var (
	Cache     = newCache()
	ghostTime = 10 * time.Second
)

type cache struct {
	mutex         lock.Mutex
	byPID         map[PID]*ProcessContext
	byContainerID map[string]*ProcessContext
	byConnection  map[string]*ProcessContext

	// deleted is a priority queue of ProcessContexts to be removed from
	// the cache, ordered by their expiry time.
	deleted []PID

	gcStop chan struct{}
}

func newCache() *cache {
	return &cache{
		byPID:         map[PID]*ProcessContext{},
		byContainerID: map[string]*ProcessContext{},
		byConnection:  map[string]*ProcessContext{},
		deleted:       []PID{},
		gcStop:        make(chan struct{}),
	}
}

func (c *cache) UpdateReferences(endpoint *endpoint.Endpoint) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	context, ok := c.byContainerID[endpoint.GetContainerID()]
	if ok {
		log.WithFields(logrus.Fields{
			logfields.ContainerID: endpoint.GetContainerID(),
		}).Debug("Updating process cache entry for endpoint")
		context.endpoint = endpoint
	} else {
		log.WithFields(logrus.Fields{
			logfields.ContainerID: endpoint.GetContainerID(),
		}).Warning("Couldn't find process cache entry for endpoint")
	}
}

func (c *cache) LookupOrCreate(pid PID) (*ProcessContext, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	context, ok := c.byPID[pid]
	if !ok {
		var err error

		context, err = newProcessContext(pid)
		if err != nil {
			return nil, false, err
		}
		c.byPID[pid] = context
		if context.DockerContainerID != "" {
			c.byContainerID[context.DockerContainerID] = context
		}
	}

	return context, !exists, nil
}

// LookupOrCreate attempts to find a ProcessContext associated with the
// specified host PID in the cache, and returns it. If the process is not yet
// in the cache, create a ProcessContext for it.
func (c *cache) LookupOrCreate(pid PID) (*ProcessContext, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	ctx, _, err := c.lookupOrCreateLocked(pid)
	return ctx, err
}

// Learn attempts to create a ProcessContext for the specified PID. Returns
// an error if the context cannot be established for the process.
func (c *cache) Learn(pid PID) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	_, _, err := c.lookupOrCreateLocked(pid)
	return err
}

// AddConnection adds a mapping between the specified PID and connection to the
// cache. If the PID does not yet exist, it will be created.
func (c *cache) AddConnection(pid PID, connection ConnectContext) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	proc, _, err := c.lookupOrCreateLocked(pid)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.PID: pid,
			"connection":  connection,
		}).WithError(err).Debug("Failed to find connection")
		return
	}

	// TODO: Handle overlapping addresses
	proc.AddConnection(connection)
	c.byConnection[connection.StringID()] = proc
}

// IndexByConnection returns the ProcessContext corresponding to the specified
// connection, or nil and false.
func (c *cache) IndexByConnection(connection ConnectContext) (*ProcessContext, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	proc, ok := c.byConnection[connection.String()]
	return proc, ok
}

// Dump prints a vaguely human-readable form of all cached PIDs with their
// connections.
func (c *cache) Dump(writer io.Writer) {
	c.mutex.Lock()
	for _, p := range c.byPID {
		fmt.Fprintln(writer, p.String())
		for _, conn := range p.connections {
			fmt.Fprintf(writer, "  %s\n", conn.String())
		}
	}
	c.mutex.Unlock()
}

func (c *cache) deleteLocked(pid PID) {
	context := c.byPID[pid]
	for ct := range context.connections {
		delete(c.byConnection, ct)
	}
	delete(c.byPID, pid)
	if context != nil && context.DockerContainerID != "" {
		delete(c.byContainerID, context.DockerContainerID)
	}
}

func (c *cache) Delete(pid PID) {
	c.mutex.Lock()
	c.deleteLocked(pid)
	c.mutex.Unlock()
}

// Forget queues up the process associated with the specified PID to be
// deleted from the cache after a grace period.
func (c *cache) Forget(pid PID) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if proc, ok := c.byPID[pid]; ok {
		proc.Expiry = time.Now().Add(ghostTime)
		c.byPID[pid] = proc
		c.deleted = append(c.deleted, pid)
	}
}

func (c *cache) garbageCollect(interval time.Duration) time.Duration {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var nextExpiry time.Time
	for _, pid := range c.deleted {
		if proc, ok := c.byPID[pid]; ok {
			if time.Now().After(proc.Expiry) {
				c.deleteLocked(pid)
			}
		}
	}
	if len(c.deleted) > 0 {
		for _, pid := range c.deleted {
			if nextProc, ok := c.byPID[pid]; ok {
				nextExpiry = nextProc.Expiry
				break
			}
		}
	}

	if nextExpiry.IsZero() {
		return interval
	}
	return nextExpiry.Sub(time.Now())
}

// GarbageCollect launches the garbage collector for process entries.
// It will block forever, garbage collecting as many processes as it can, then
// sleeping until the soonest of 'interval' or the next process expiry time.
func (c *cache) GarbageCollect(interval time.Duration) {
	for {
		duration := c.garbageCollect(interval)
		select {
		case <-time.After(duration):
		case <-c.gcStop:
			return
		}
	}
}

// StopGC stops the garbagecollector.
func (c *cache) StopGC() {
	c.gcStop <- struct{}{}
}
