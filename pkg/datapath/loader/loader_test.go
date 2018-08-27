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

package loader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LoaderTestSuite struct{}

var (
	_              = Suite(&LoaderTestSuite{})
	contextTimeout = 5 * time.Minute
)

func Test(t *testing.T) {
	TestingT(t)
}

type testEP struct {
}

func (ep *testEP) InterfaceName() string {
	return "cilium_test"
}

func (ep *testEP) Logger() *logrus.Entry {
	return log
}

func (ep *testEP) StateDir() string {
	return "test_loader"
}

func (ep *testEP) StringID() string {
	return "test_loader"
}

func prepareEnv(ep *testEP) (string, func() error, error) {
	link := netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: ep.InterfaceName(),
		},
	}
	if err := netlink.LinkAdd(&link); err != nil {
		if !os.IsExist(err) {
			return "", nil, fmt.Errorf("Failed to add link: %s", err)
		}
	}
	cleanupFn := func() error {
		if err := netlink.LinkDel(&link); err != nil {
			return fmt.Errorf("Failed to delete link: %s", err)
		}
		return nil
	}

	wd, err := os.Getwd()
	if err != nil {
		cleanupFn()
		return "", nil, fmt.Errorf("Failed to get working directory: %s", err)
	}
	bpfdir := filepath.Join(wd, "..", "..", "..", "bpf")

	return bpfdir, cleanupFn, nil
}

// TestCompileAndLoad checks that the basic CompileAndLoad functionality works
// from the testsuite.
func (s *LoaderTestSuite) TestCompileAndLoad(c *C) {
	if os.Getuid() != 0 {
		c.Skip("Test requires root privileges")
	}

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	ep := &testEP{}
	dirs, cleanup, err := prepareEnv(ep)
	c.Assert(err, IsNil)
	defer cleanup()

	c.Assert(joinEP(ctx, ep, dirs, dirs, dirs, "true"), IsNil)
}

// BenchmarkCompileAndLoad benchmarks the entire compilation + loading process.
func BenchmarkCompileAndLoad(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	ep := &testEP{}
	dirs, cleanup, err := prepareEnv(ep)
	if err != nil {
		b.Fatal(err)
	}
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := joinEP(ctx, ep, dirs, dirs, dirs, "true"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplaceDatapath compiles the datapath program, then benchmarks only
// the loading of the program into the kernel.
func BenchmarkReplaceDatapath(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	ep := &testEP{}
	dirs, cleanup, err := prepareEnv(ep)
	if err != nil {
		b.Fatal(err)
	}
	defer cleanup()

	if err := joinEP(ctx, ep, dirs, dirs, dirs, "true"); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := joinEP(ctx, ep, dirs, dirs, dirs, "false"); err != nil {
			b.Fatal(err)
		}
	}
}
