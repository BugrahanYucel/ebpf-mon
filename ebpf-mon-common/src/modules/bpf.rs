use crate::{co_re::{core_read_kernel, nsproxy, task_struct}, path::MAX_PATH_DEPTH};
use aya_ebpf::{helpers::bpf_ktime_get_ns, macros::map, maps::PerfEventByteArray, EbpfContext};
use super::{EventRaw, EventInfo, Namespaces, ProcessInfo, Type};

impl EventInfo{
    pub(crate) unsafe fn new(&mut self, t: Type, task: task_struct) -> Result<(), u32>{
        self.timestamp = bpf_ktime_get_ns();
        self.event_type = t;

        if !task.is_null(){
            let _ = self.process.init_from_task(task);
            let _ = self.parent.init_from_task(task.real_parent().ok_or(1u32)?);
        }
        Ok(())
    }
}

impl<T> EventRaw<T> {
    pub unsafe fn init(&mut self, event_type: Type, ts: task_struct) -> Result<(), u32> {
        self.header.new(event_type, ts)?;
        Ok(())
    }
}
impl ProcessInfo{
    #[inline(always)]
    pub unsafe fn init_from_task(&mut self, ts: task_struct) -> Result<u32, u32>{

        self.comm = ts.comm_array().ok_or(1u32)?;
        self.start_time = ts.start_boottime().ok_or(1u32)?;
        self.tgid = ts.tgid().ok_or(1u32)?;
        self.pid = ts.pid().ok_or(1u32)?;

        if let Some(nsproxy) = core_read_kernel!(ts, nsproxy){
            if !nsproxy.is_null(){
                self.parse_namespace(nsproxy)?;
            }
        }

        if let Some(linux_binprm) = core_read_kernel!(ts, mm, exe_file){
            self.executable.core_resolve_file(&linux_binprm, MAX_PATH_DEPTH)?;
        }

        if let Some(cgroup) = ts.get_cgroup_handle(){
            self.cgroup.resolve(cgroup)?;
        }
        // could not read currently running workloads arguments as they are probably paged out after execution and minor page fault occurs which makes it impossible
        // for our ebpf program to read arguments for the current_task_struct
        if let Some(mm) = core_read_kernel!(ts, mm){
            let arg_start = mm.arg_start().ok_or(1u32)?;
            let arg_len = mm.arg_len().ok_or(1u32)?;
            self.args.read_user_memory(arg_start as *const u8, arg_len as u32)?
        }

        Ok(0)
    }

    pub unsafe fn parse_namespace(&mut self, nsproxy: nsproxy) -> Result<(), u32>{
        self.namespaces = Some(
            Namespaces{
                mnt: core_read_kernel!(nsproxy, mnt_ns, ns, inum).ok_or(1u32)?,
            }
        );

        return Ok(());
    }
}

#[map]
static mut EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);

pub unsafe fn pipe_event<C: EbpfContext, T>(ctx: &C, e: &EventRaw<T>) {
    EVENTS.output(ctx, e.encode(), 0);
}
