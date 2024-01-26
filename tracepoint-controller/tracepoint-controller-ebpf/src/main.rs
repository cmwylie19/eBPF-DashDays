#![no_std]
#![no_main]

use aya_bpf::{
    
    cty::c_long,
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_probe_read_user_str_bytes,
    },
};

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn tracepoint_controller(ctx: TracePointContext) -> c_long {
    match try_tracepoint_controller(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint_controller(ctx: TracePointContext) -> Result<c_long, c_long>  {
    info!(&ctx, "tracepoint sys_enter_execve called");

    const FILENAME_OFFSET: usize = 16;
    let filename_addr: u64 =
        unsafe { ctx.read_at(FILENAME_OFFSET)? };

    const BUF_SIZE: usize = 128;
    let mut buf = [0u8; BUF_SIZE];
    // read the filename
    let filename = unsafe {
        core::str::from_utf8_unchecked(
            bpf_probe_read_user_str_bytes(
                filename_addr as *const u8,
                &mut buf,
            )?,
        )
    };
    

    let pid = bpf_get_current_pid_tgid() as u32;
    
    info!(&ctx, "{} {}", pid, filename);


    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
