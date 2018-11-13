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

// +build !privileged_tests

package notify

import (
	"bufio"
	"os"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/process"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

var (
	failTimeout = 100 * time.Millisecond
	testTime    = 2 * gcInterval
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type NotifyTestSuite struct{}

var _ = Suite(&NotifyTestSuite{})

func (nts *NotifyTestSuite) TestWatch(c *C) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	watcher := NewProcessWatcher()
	go func() {
		c.Assert(watcher.Watch(), IsNil)
	}()
	defer watcher.Stop()

	go func() {
		writer := bufio.NewWriter(os.Stdout)
		for {
			process.Cache.Dump(writer)
			writer.Flush()
			time.Sleep(10 * time.Second)
		}
	}()

	time.Sleep(testTime)
}
