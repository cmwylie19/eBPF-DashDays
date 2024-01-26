#![no_std]
#![no_main]

use aya_bpf::helpers::*;
use aya_bpf::macros::*;

use aya_bpf::maps::HashMap;
use aya_bpf::BpfContext;
use aya_bpf::PtRegs;
use aya_bpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;
use file_controller_3_common::Filename;

#[map(name = "PIDS")]
static mut PIDS: HashMap<u32, Filename> = HashMap::with_max_entries(10240000, 0);

#[kprobe]
pub fn file_controller_3(ctx: ProbeContext) -> u32 {
    match try_file_controller_3(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_controller_3(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function syscalls:sys_enter_execv called");
    unsafe {
        let pid = ctx.pid();
        //  info!(&ctx, "args: {} ",ctx.arg(0).unwrap());

        if PIDS.get(&pid).is_none() {
            let regs = PtRegs::new(ctx.arg(0).unwrap());
            let filename_addr: *const u8 = regs.arg(0).unwrap();

            let mut buf = [0u8; 127];
            let filename_len = bpf_probe_read_user_str(filename_addr as *const u8, &mut buf)
                .map_err(|e| e as u32)? as u8;

            let log_entry = Filename {
                filename: buf,
                filename_len,
            };
            PIDS.insert(&pid, &log_entry, 0).unwrap();
        }
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
