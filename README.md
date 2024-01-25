# eBPF DashDays

- [eBPF DashDays](#ebpf-dashdays)
- [Prerequisites](#prerequisites)
- [Goals](#goals)

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
