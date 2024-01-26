#![no_std]
#![no_main]
use core::ffi::c_char;
use aya_bpf::helpers::bpf_get_current_uid_gid;
use aya_bpf::helpers::bpf_ktime_get_ns;
use aya_bpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_bpf::helpers::bpf_probe_read_user_str_bytes;
use aya_bpf::BpfContext;
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
    let mut dest = [0u8; 16];
    let mut buf = [0u8; 16];


    let uid = bpf_get_current_uid_gid() as u64;
    info!(&ctx, "uid: {}", uid);

    let node: *const c_char
    let user = unsafe {
        unsafe { bpf_probe_read_user_str_bytes(node as *const u8, &mut buf).map_err(|e| e as u32)? };
    };
    match user {
        Ok(len) => {
            // `len` is the length of the string. Use it to slice `dest` and convert to a str
            if let Ok(str_slice) = core::str::from_utf8(&dest[..len]) {
                // `str_slice` is a `&str`, log it directly
                info!(&ctx, "user: {}", str_slice);
            } else {
                // Handle invalid UTF-8
                info!(&ctx, "user: [Invalid UTF-8]");
            }
        }
        Err(err) => {
            // Handle the error, for example, you might want to return an error code from your eBPF program
            info!(&ctx, "Failed to read user string: {}", err);
            return Err(err as u32);
        }
    }
    info!(&ctx, "user:  {}",user );




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
