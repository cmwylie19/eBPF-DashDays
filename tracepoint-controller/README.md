# tracepoint-controller

## Prerequisites
```
┌─[cmwylie19@Cases-MacBook-Pro] - [~/eBPF-DashDays] - [2024-01-26 05:19:19]
└─[0] <git:(case fa2af32) > cargo generate https://github.com/aya-rs/aya-template
⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
🤷   Project Name: tracepoint-controller
🔧   Destination: /Users/cmwylie19/eBPF-DashDays/tracepoint-controller ...
🔧   project-name: tracepoint-controller ...
🔧   Generating template ...
✔ 🤷   Which type of eBPF program? · tracepoint
🤷   Which tracepoint name? (e.g sched_switch, net_dev_queue): sys_enter_execve
🤷   Which tracepoint category? (e.g sched, net etc...): syscalls
```
1. Install bpf-linker: `cargo install bpf-linker`

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
