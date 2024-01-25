# eBPF DashDays

- [eBPF DashDays](#ebpf-dashdays)
- [Prerequisites](#prerequisites)
- [Goals](#goals)
- [List Tracepoints](#list-tracepoints)

## Prerequisites

- Install [`bpftool`](https://github.com/libbpf/bpftool/blob/main/README.md)

```bash
cargo generate https://github.com/aya-rs/aya-template
```
## Goals


- Endgoal is to have a JSON configurable eBPF controller deployable to Kubernetes that can be used to monitor the network traffic of a container/Kernel and file paths of the Kernel. 


## bpftool

```bash
bpftool prog list

1291: kprobe  name kprobe_controll  tag 30a22350f2c5b6d5  gpl
	loaded_at 2024-01-25T15:27:50-0500  uid 0
	xlated 1776B  jited 969B  memlock 4096B  map_ids 443,442,444
	pids kprobe-controll(84855)

```

```bash
bpftool prog dump xlated id 1291
```

```bash
sudo bpftool prog show id 1291 --pretty
{
    "id": 1291,
    "type": "kprobe",
    "name": "kprobe_controll",
    "tag": "30a22350f2c5b6d5",
    "gpl_compatible": true,
    "loaded_at": 1706214470,
    "uid": 0,
    "bytes_xlated": 1776,
    "jited": true,
    "bytes_jited": 969,
    "bytes_memlock": 4096,
    "map_ids": [443,442,444
    ],
    "pids": [{
            "pid": 84855,
            "comm": "kprobe-controll"
        }
    ]
}
```

```bash
bpftool prog show id 1291 --json
```

```json
{
    "id": 1291,
    "type": "kprobe",
    "name": "kprobe_controll",
    "tag": "30a22350f2c5b6d5",
    "gpl_compatible": true,
    "loaded_at": 1706214470,
    "uid": 0,
    "bytes_xlated": 1776,
    "jited": true,
    "bytes_jited": 969,
    "bytes_memlock": 4096,
    "map_ids": [443,442,444
    ],
    "pids": [{
            "pid": 84855,
            "comm": "kprobe-controll"
        }
    ]
}
```

```bash
bpftool prog show id 1291 --json 
sudo bpftool prog show name kprobe_controll --pretty

sudo bpftool map list 
sudo bpftool map dump name AYA_LOG_BUF

```

## List Tracepoints

```bash
 sudo cat /sys/kernel/debug/tracing/available_events | grep open 
 # out
hda_controller:azx_pcm_open
syscalls:sys_exit_pidfd_open
syscalls:sys_enter_pidfd_open
syscalls:sys_exit_perf_event_open
syscalls:sys_enter_perf_event_open
syscalls:sys_exit_openat2
syscalls:sys_enter_openat2
syscalls:sys_exit_openat
syscalls:sys_enter_openat
syscalls:sys_exit_open
syscalls:sys_enter_open
syscalls:sys_exit_open_tree
syscalls:sys_enter_open_tree
syscalls:sys_exit_fsopen
syscalls:sys_enter_fsopen
syscalls:sys_exit_open_by_handle_at
syscalls:sys_enter_open_by_handle_at
syscalls:sys_exit_mq_open
syscalls:sys_enter_mq_open

cargo generate https://github.com/aya-rs/aya-template
⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
🤷   Project Name: file-controller
🔧   Destination: /Users/cmwylie19/eBPF-DashDays/eBPF_controller/file-controller ...
🔧   project-name: file-controller ...
🔧   Generating template ...
✔ 🤷   Which type of eBPF program? · tracepoint
🤷   Which tracepoint name? (e.g sched_switch, net_dev_queue): sys_enter_open
🤷   Which tracepoint category? (e.g sched, net etc...): syscalls
🔧   Moving generated files into: `/Users/cmwylie19/eBPF-DashDays/eBPF_controller/file-controller`...
🔧   Initializing a fresh Git repository
```
