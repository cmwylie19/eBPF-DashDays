# file-controller-3
```
cargo generate https://github.com/aya-rs/aya-template
⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
🤷   Project Name: file-controller-3
🔧   Destination: /Users/cmwylie19/eBPF-DashDays/file-controller-3 ...
🔧   project-name: file-controller-3 ...
🔧   Generating template ...
✔ 🤷   Which type of eBPF program? · kprobe
🤷   Where to attach the (k|kret)probe? (e.g try_to_wake_up): syscalls:sys_enter_execv
🔧   Moving generated files into: `/Users/cmwylie19/eBPF-DashDays/file-controller-3`...
🔧   Initializing a fresh Git repository
✨   Done! New project created /Users/cmwylie19/eBPF-DashDays/file-controller-3
```
## Prerequisites

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
