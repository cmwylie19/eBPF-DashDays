#![no_std]
#![no_main]

use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn kprobe_controller(ctx: ProbeContext) -> u32 {
    match try_kprobe_controller(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kprobe_controller(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function execve called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
