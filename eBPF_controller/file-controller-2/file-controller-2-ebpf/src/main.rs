#![no_std]
#![no_main]
use aya_bpf::helpers::bpf_get_current_uid_gid;
use aya_bpf::helpers::bpf_ktime_get_ns;
use aya_bpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_bpf::helpers::bpf_probe_read_user_str_bytes;
use aya_bpf::BpfContext;
use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_buf,
    bpf_probe_read_user_str_bytes,
};
use aya_bpf::{
    macros::{map, tracepoint}, maps::HashMap, programs::TracePointContext,
};
use aya_log_ebpf::info;
use core::convert::TryInto;
use core::ffi::c_char;
use common::{ArgType, STR_MAX_LENGTH};
use core::cmp::min;
use file_controller_2_common::FileLog;

#[map]
static mut SYSCALL_ARG_TABLE: HashMap<u64, [u16; 6]> = HashMap::with_max_entries(512, 0);
#[map]
pub static mut RECORD_LOGS: PerfEventByteArray = PerfEventByteArray::new(0);

#[map]
static mut CONTEXT: HashMap<u32, [usize; 6]> = HashMap::with_max_entries(64, 0);

#[map]
static mut TRAGET_PID: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
#[map]
static mut TRAGET_TID: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
#[map]
static mut TRAGET_UID: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
static mut FLAG: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

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
    let pid_tid = bpf_get_current_pid_tgid();
    let pid = (pid_tid >> 32) as u32;
    let tid = pid_tid as u32;
    if unsafe {
        FLAG.get(&0).is_some()
            ^ (TRAGET_PID.get(&pid).is_none()
                && TRAGET_TID.get(&tid).is_none()
                && TRAGET_UID
                    .get(&(bpf_get_current_uid_gid() as u32))
                    .is_none())
    } {
        return Ok(());
    }
    let mut send_byte = [0u8; 19 + STR_MAX_LENGTH];
    let syscall_number = unsafe { ctx.read_at::<u64>(8)? };
    send_byte[1..9].copy_from_slice(&pid_tid.to_le_bytes());
    send_byte[9..17].copy_from_slice(&syscall_number.to_le_bytes());
    unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19], 0) };
    let arg_table = unsafe { SYSCALL_ARG_TABLE.get(&syscall_number).ok_or(0) }?;
    let args: [usize; 6] = unsafe { ctx.read_at(16) }?;
    let _ = unsafe { CONTEXT.insert(&tid, &args, 0) };
    for (i, ty_size) in arg_table.iter().enumerate() {
        let ty: ArgType = ArgType::from_bits_retain((*ty_size >> 8) as u8);
        let size_info: u8 = *ty_size as u8;
        if !ty.contains(ArgType::record_before) {
            continue;
        }
        send_byte[0] = 0x10 | (i as u8);
        send_byte[1..9].copy_from_slice(&pid_tid.to_le_bytes());
        send_byte[9..17].copy_from_slice(&args[i].to_le_bytes());
        let mut additional_size = 0;
        if ty.contains(ArgType::is_ptr) {
            if ty.contains(ArgType::is_str) {
                let slice = unsafe {
                    bpf_probe_read_user_str_bytes(
                        args[i] as *const u8,
                        &mut send_byte[19..19 + STR_MAX_LENGTH],
                    )
                };
                // additional_size = slice.map_or(0, |s|s.len());
                additional_size = if let Ok(slice) = slice {
                    slice.len()
                } else {
                    send_byte[17] = 0;
                    send_byte[18] = 0;
                    unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19], 0) };
                    continue;
                }
            } else {
                if ty.contains(ArgType::is_const) {
                    additional_size = size_info as usize;
                } else {
                    let index = size_info as usize;
                    additional_size = if index >= 6 { 0 } else { args[index] }
                }
                additional_size = min(additional_size, STR_MAX_LENGTH);
                if additional_size > 0 {
                    let r = unsafe {
                        bpf_probe_read_buf(
                            args[i] as *const u8,
                            &mut send_byte[19..19 + additional_size],
                        )
                    };
                    if r.is_err() {
                        additional_size = 0;
                    }
                }
            }
        }
        send_byte[17..19].copy_from_slice(&(additional_size as u16).to_le_bytes());
        unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19 + additional_size], 0) };
    }
    // Ok(())
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
