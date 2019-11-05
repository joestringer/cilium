// MIT License
//
// Copyright (c) 2017-2019 Nathan Sweet
// Copyright (c) 2018-2019, 2019 Cloudflare
// Copyright (c) 2019 Authors of Cilium
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Adapted from https://github.com/cilium/ebpf/perf/reader_test.go

// +build privileged_tests

package bpf

import (
	"os"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	. "gopkg.in/check.v1"
)

func outputSamplesProg(sampleSizes ...int) (*ebpf.Program, *ebpf.Map, error) {
	const bpfFCurrentCPU = 0xffffffff

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
	})
	if err != nil {
		return nil, nil, err
	}

	var maxSampleSize int
	for _, sampleSize := range sampleSizes {
		if sampleSize > maxSampleSize {
			maxSampleSize = sampleSize
		}
	}

	// Fill a buffer on the stack, and stash context somewhere
	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0x0102030404030201, asm.DWord),
		asm.Mov.Reg(asm.R9, asm.R1),
	}

	bufDwords := (maxSampleSize / 8) + 1
	for i := 0; i < bufDwords; i++ {
		insns = append(insns,
			asm.StoreMem(asm.RFP, int16(i+1)*-8, asm.R0, asm.DWord),
		)
	}

	for _, sampleSize := range sampleSizes {
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R9),
			asm.LoadMapPtr(asm.R2, events.FD()),
			asm.LoadImm(asm.R3, bpfFCurrentCPU, asm.DWord),
			asm.Mov.Reg(asm.R4, asm.RFP),
			asm.Add.Imm(asm.R4, int32(bufDwords*-8)),
			asm.Mov.Imm(asm.R5, int32(sampleSize)),
			asm.FnPerfEventOutput.Call(),
		)
	}

	insns = append(insns, asm.Return())

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		License:      "GPL",
		Type:         ebpf.XDP,
		Instructions: insns,
	})
	if err != nil {
		events.Close()
		return nil, nil, err
	}

	return prog, events, nil
}

func mustOutputSamplesProg(tb *C, sampleSizes ...int) (*ebpf.Program, *ebpf.Map) {
	//tb.Helper()

	prog, events, err := outputSamplesProg(sampleSizes...)
	if err != nil {
		tb.Fatal(err)
	}

	return prog, events
}

func (s *BPFPrivilegedTestSuite) BenchmarkReader(c *C) {
	prog, events := mustOutputSamplesProg(c, 80)
	defer prog.Close()
	defer events.Close()

	mapName := "cilium_test_events"
	mapPath := MapPath(mapName)
	if err := events.Pin(mapPath); err != nil {
		c.Fatal(err)
	}
	defer os.RemoveAll(mapPath)

	config := PerfEventConfig{
		MapName:      mapName,
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   PERF_SAMPLE_RAW,
		NumPages:     1,
		WakeupEvents: 1,
		NumCpus:      runtime.NumCPU(),
	}

	rd, err := NewPerCpuEvents(&config)
	if err != nil {
		c.Fatal(err)
	}
	defer rd.CloseAll()

	buf := make([]byte, 14)

	rcvFn := func(msg *PerfEventSample, cpu int) {}
	lostFn := func(msg *PerfEventLost, cpu int) {}
	errFn := func(msg *PerfEvent) {}

	c.ResetTimer()
	//c.ReportAllocs()
	for i := 0; i < c.N; i++ {
		ret, _, err := prog.Test(buf)
		if err != nil {
			c.Fatal(err)
		} else if errno := syscall.Errno(-int32(ret)); errno != 0 {
			c.Fatal("Expected 0 as return value, got", errno)
		}

		if _, err = rd.Poll(-1); err != nil {
			c.Fatal(err)
		}
		if err = rd.ReadAll(rcvFn, lostFn, errFn); err != nil {
			c.Fatal(err)
		}
	}
}
