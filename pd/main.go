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
package main

import (
	"bufio"
	"io/ioutil"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/process"
	"github.com/cilium/cilium/pkg/process/notify"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "pd")

func main() {
	pw := notify.NewProcessWatcher()
	controller.NewManager().UpdateController("proc-poller",
		controller.ControllerParams{
			DoFunc: func() error {
				return pw.Watch()
			},
		},
	)
	processFile, err := ioutil.TempFile("", "cilium_pd_")
	if err != nil {
		log.WithError(err).Fatal("Failed to generate temp file")
	}
	for {
		if _, err := processFile.Seek(0, 0); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Path: processFile.Name(),
			}).Fatalf("Failed to seek file")
		}
		writer := bufio.NewWriter(processFile)
		process.Cache.Dump(writer)
		if err := writer.Flush(); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Path: processFile.Name(),
			}).Fatalf("Failed to flush file")
		}
		if err := processFile.Sync(); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Path: processFile.Name(),
			}).Fatalf("Failed to sync file")
		}
		time.Sleep(10 * time.Second)
	}
}
