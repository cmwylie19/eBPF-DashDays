#![no_std]
#![no_main]

use aya_bpf::helpers::bpf_ktime_get_ns;
use aya_bpf::{
    helpers::bpf_probe_read_user, macros::tracepoint, maps::HashMap, programs::TracePointContext,
};
use aya_log_ebpf::info;
use core::convert::TryInto;
use file_controller_common::FileLog;
use aya_bpf::helpers::bpf_get_current_uid_gid;
|
use aya_bpf::helpers::gen::bpf_get_current_uid_gid;
#[map]
static EVENTS: HashMap<u32, FileLog> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn file_controller_2(ctx: TracePointContext) -> u32 {
    match try_file_controller_2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_controller_2(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter_openat called");

    // Access the registers to get the filename pointer
    let regs = ctx.regs();
    let filename_ptr = regs.rcx as *const u8; // Modify as per your architecture and syscall

    // Buffer to store the filename
    let mut filename_buf = [0u8; 256];
    let filename_len =
        bpf_probe_read_user(&mut filename_buf, filename_ptr as *const _).map_err(|_| 1u32)?;
    let filename = &filename_buf[..filename_len];

    // Assuming you have a way to get file_location and action
    let file_location = [0u8; 256]; // Placeholder, fetch the actual data
    let action = 0; // Placeholder, fetch the actual data

    // Get the UID from the current task
    let uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // Lower 32 bits

    // Create an instance of FileLog
    let log_entry = FileLog {
        file_name: filename_buf,
        file_location,
        uid,
        action: action.try_into().unwrap_or(0),
    };

    // Generate a unique key for this event
    // You can use a counter, timestamp, or any other method that suits your use case
    let key = bpf_ktime_get_ns(); // Using the current timestamp as a key

    // Insert the log entry into the map
    EVENTS.insert(&key, &log_entry, 0).map_err(|_| 1u32)?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
