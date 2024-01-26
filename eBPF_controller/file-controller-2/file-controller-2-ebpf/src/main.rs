#![no_std]
#![no_main]
use aya_bpf::helpers::*;
use aya_bpf::{bpf_printk, helpers::bpf_get_current_comm};
use aya_bpf::{
    helpers::bpf_probe_read_user, macros::tracepoint, maps::HashMap, programs::TracePointContext,
};
use aya_log_ebpf::info;
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

    let uid = bpf_get_current_uid_gid() as u64;
    info!(&ctx, "uid: {}", uid);

    let tsig = unsafe {
        ctx.read_at::<u64>(24).unwrap() as u32;
    };
    if tsig == 0 {
        return Ok(0);
    }
    let tpid = unsafe {ctx.read_at::<i64>(16).unwrap() as i32; }

    let tid = bpf_get_current_pid_tgid() as u32;
    let comm = bpf_get_current_comm().unwrap();

    info!(
        &ctx,
        "tracepoint sys_enter_openat called: , tid: {}, tpid: {}, tsig: {}", tid, tpid, tsig
    );
    //  let fname_ptr: usize = ctx.read_at(24).unwrap();
    // unsafe {
    //     let comm = bpf_get_current_comm().unwrap();
    //     let fname_ptr: usize = ctx.read_at(24).unwrap();
    //     bpf_printk!(
    //         b"---------------- command: %s openfile: %s",
    //         comm.as_ptr() as usize,
    //         fname_ptr
    //     );
    // }

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
