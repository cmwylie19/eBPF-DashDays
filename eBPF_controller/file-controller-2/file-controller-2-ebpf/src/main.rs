#![no_std]
#![no_main]
use aya_bpf::{bpf_printk, helpers::bpf_get_current_comm};
use aya_bpf::helpers::bpf_get_current_uid_gid;
use aya_bpf::{
    macros::{map, tracepoint, xdp}, 
    helpers::bpf_probe_read_user,  maps::HashMap, programs::TracePointContext,
};
use aya_log_ebpf::info;
use file_controller_2_common::FileLog;
#[map(name = "EXECVE_EVENTS")]
static mut EXECVE_EVENTS: PerfEventArray<ExecveCalls> = PerfEventArray::<ExecveCalls>::with_max_entries(1024, 0);

#[map(name = "IP_RECORDS")]
static mut IP_RECORDS: PerfEventArray<IpRecord> = PerfEventArray::<IpRecord>::with_max_entries(1024, 0);


#[aya_bpf::macros::map]
static EVENTS: HashMap<u64, FileLog> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn file_controller_2(ctx: TracePointContext) -> u32 {
    match try_file_controller_2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
unsafe fn try_syspection(ctx: &TracePointContext) -> Result<i32, i64> {

    // Get the process that is executing the command
    let mut exec_buf = [0u8; 42];
    let exec = bpf_get_current_comm().unwrap_or_default();

    // Get the command that is being executed and stores it in exec_comm
    let exec_comm = ctx.read_at::<*const u8>(16)?;
    _ = bpf_probe_read_user_str_bytes(exec_comm, &mut exec_buf);

    // Create a buffer for the arguments of the command
    let mut arg_buf = [[0u8; ARG_SIZE]; ARG_COUNT];
    
    // Get the arguments of the command
    let argv = ctx.read_at::<*const *const u8>(24)?;
    for i in 0..ARG_COUNT {
        let arg_ptr = bpf_probe_read_user(argv.offset(i as isize))?;

        if arg_ptr.is_null() {
            break;
        }

        bpf_probe_read_user_str_bytes(arg_ptr, &mut arg_buf[i as usize]).unwrap_or_default();
    }

    let execve_calls = ExecveCalls {
        caller: exec,
        command: exec_buf,
        args: arg_buf,
    };

    EXECVE_EVENTS.output(ctx, &execve_calls, 0);

    info!(
        ctx, "curr_comm: {}, exec_comm: {}", from_utf8_unchecked(&execve_calls.caller), from_utf8_unchecked(&execve_calls.command)
    );

    Ok(0)
}
fn try_file_controller_2(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter_openat called");


    let uid = bpf_get_current_uid_gid() as u64;
    info!(&ctx, "uid: {}", uid);
    unsafe {
        let comm = bpf_get_current_comm().unwrap();
        let fname_ptr: usize = ctx.read_at(24).unwrap();
        bpf_printk!(
            b"---------------- command: %s openfile: %s",
            comm.as_ptr() as usize,
            fname_ptr
        );
    }

    match unsafe {try_syspection(&ctx)} {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }

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
