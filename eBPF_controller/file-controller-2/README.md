# file-controller-2

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`
```
⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
🤷   Project Name: file_controller_2
⚠️   Renaming project called `file_controller_2` to `file-controller-2`...
🔧   Destination: /Users/cmwylie19/eBPF-DashDays/eBPF_controller/file-controller-2 ...
🔧   project-name: file-controller-2 ...
🔧   Generating template ...
✔ 🤷   Which type of eBPF program? · tracepoint
🤷   Which tracepoint name? (e.g sched_switch, net_dev_queue): sys_enter_openat
🤷   Which tracepoint category? (e.g sched, net etc...): syscalls
🔧   Moving generated files into: `/Users/cmwylie19/eBPF-DashDays/eBPF_controller/file-controller-2`...
🔧   Initializing a fresh Git repository
✨   Done! New project created /Users/cmwylie19/eBPF-DashDays/eBPF_controller/file-controller-2
```

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
