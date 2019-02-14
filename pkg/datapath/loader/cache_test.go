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

// +build privileged_tests

package loader

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

var (
	bpfDir     = filepath.Join("..", "..", "..", "bpf")
	sourceName = "bpf_lxc.c"
)

func (s *LoaderTestSuite) TestObjectCache(c *C) {
	tmpDir, err := ioutil.TempDir("", "cilium_test")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	cache := newObjectCache(linux.NewDatapath(linux.DatapathConfiguration{}), nil, tmpDir)
	realEP := testutils.NewTestEndpoint()

	// First run should compile and generate the object.
	_, isNew, err := cache.FetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)

	// Same EP should not be compiled twice.
	_, isNew, err = cache.FetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	// Changing the ID should not generate a new object.
	realEP.Id++
	_, isNew, err = cache.FetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	// Changing a setting on the EP should generate a new object.
	realEP.Opts.SetBool("foo", true)
	_, isNew, err = cache.FetchOrCompile(ctx, &realEP, nil)
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
}

type buildResult struct {
	goroutine int
	path      string
	compiled  bool
	err       error
}

func receiveResult(c *C, results chan buildResult) (*buildResult, error) {
	select {
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		return &result, nil
	case <-time.After(contextTimeout):
		return nil, fmt.Errorf("Timed out waiting for goroutines to return")
	}
}

func (s *LoaderTestSuite) TestObjectCacheParallel(c *C) {
	tmpDir, err := ioutil.TempDir("", "cilium_test")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	tests := []struct {
		description string
		builds      int
		divisor     int
	}{
		{
			description: "One build, multiple blocking goroutines",
			builds:      8,
			divisor:     8,
		},
		{
			description: "Eight builds, half compile, half block",
			builds:      8,
			divisor:     2,
		},
		{
			description: "Eight unique builds",
			builds:      8,
			divisor:     1,
		},
	}

	for _, t := range tests {
		c.Logf("  %s", t.description)

		results := make(chan buildResult, t.builds)
		cache := newObjectCache(linux.NewDatapath(linux.DatapathConfiguration{}), nil, tmpDir)
		for i := 0; i < t.builds; i++ {
			go func(i int) {
				ep := testutils.NewTestEndpoint()
				opt := fmt.Sprintf("OPT%d", i/t.divisor)
				ep.Opts.SetBool(opt, true)
				path, isNew, err := cache.FetchOrCompile(ctx, &ep, nil)
				results <- buildResult{
					goroutine: i,
					path:      path,
					compiled:  isNew,
					err:       err,
				}
			}(i)
		}

		// First result will always be a compilation for the new set of options
		compiled := make(map[int]string, t.builds)
		for i := 0; i < t.builds; i++ {
			result, err := receiveResult(c, results)
			c.Assert(err, IsNil)

			opt := result.goroutine / t.divisor
			basePath, exists := compiled[opt]
			if exists {
				c.Assert(result.compiled, Equals, false)
				c.Assert(result.path, Equals, basePath)
			} else {
				c.Assert(result.compiled, Equals, true)
				compiled[opt] = result.path
			}
		}
	}
}
