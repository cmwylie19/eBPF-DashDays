#![no_std]
#![no_main]

use aya_bpf::helpers::bpf_get_current_uid_gid;
use aya_bpf::helpers::bpf_ktime_get_ns;
use aya_bpf::{
    helpers::bpf_probe_read_user, macros::tracepoint, maps::HashMap, programs::TracePointContext,
};
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
    info!(
        ctx.args(),
        "tracepoint sys_enter_openat called with args",
        )
    ;
    info!( bpf_get_current_uid_gid() & 0xFFFFFFFF ,"uid");

    
  
 
   

    // // Generate a unique key for this event
    // // You can use a counter, timestamp, or any other method that suits your use case
    // let key = bpf_ktime_get_ns(); // Using the current timestamp as a key

    // // Insert the log entry into the map
    // EVENTS.insert(&key, &log_entry, 0).map_err(|_| 1u32)?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
