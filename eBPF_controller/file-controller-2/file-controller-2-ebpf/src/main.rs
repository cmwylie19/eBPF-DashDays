#![no_std]
#![no_main]

use aya_bpf::helpers::bpf_get_current_uid_gid;
use aya_bpf::helpers::bpf_ktime_get_ns;
use aya_bpf::helpers::bpf_probe_read_user_str_bytes;
use aya_bpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_bpf::{
    helpers::bpf_probe_read_user, macros::tracepoint, maps::HashMap, programs::TracePointContext,
};
use aya_bpf::BpfContext;
use aya_log_ebpf::info;
use core::convert::TryInto;
use file_controller_2_common::FileLog;

#[aya_bpf::macros::map]
static EVENTS: HashMap<u64, FileLog> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn file_controller_2(ctx: TracePointContext) -> u32 {
    match try_file_controller_2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_controller_2(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter_openat called");
    let mut dest = [0u8; 256];
    // // Get the current user ID
    let uid = bpf_get_current_uid_gid() as u64;
    info!(&ctx, "uid: {}", uid);

    let user = unsafe {
        bpf_probe_read_user_str_bytes(ctx.as_ptr() as *const u8, &mut dest));
    };
    info!(&ctx, "user ",user );
    // let mut dest = [0u8; 256];
    
    // let r = unsafe {
    //     bpf_probe_read_kernel_str_bytes((ctx.as_ptr() as *const u8).add(16), &mut dest)
    // };
 
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
