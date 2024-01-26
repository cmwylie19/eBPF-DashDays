#![no_std]
#![no_main]

use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn file_controller_3(ctx: ProbeContext) -> u32 {
    match try_file_controller_3(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_controller_3(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function syscalls:sys_enter_execv called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
