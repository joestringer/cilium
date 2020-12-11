// Copyright 2017-2020 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go LXC ../../bpf/bpf_lxc.c -- -D__NR_CPUS__=1 -I../../bpf/  -I../../bpf/include/ -O2 -g

func main() {
	fmt.Printf("OK")
}
