use std::ffi::{c_char, CString, OsStr};
use std::fs::{create_dir, read, remove_dir, write, File};
use std::mem::{self, size_of_val};
use std::os::fd::AsRawFd;
use std::os::unix::prelude::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use libc::c_ulonglong;

use nix::sys::resource::Usage;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, Signal};
use nix::sys::signalfd::SigSet;
use tempfile::tempdir_in;

use color_eyre::eyre::{eyre, ContextCompat, Result, WrapErr};
use color_eyre::{Help, Report};
use thiserror::Error;

#[derive(Debug)]
struct Meta {
    cg_fs_dir: PathBuf,
    cg_pdir: PathBuf,
    cg_dir: PathBuf,
    child_argv: Vec<String>,
    delim: char,
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let meta = Meta::new_from_args()?;

    join_errors(vec![real_main(&meta), meta.tear_down()])
}

fn real_main(meta: &Meta) -> Result<()> {
    meta.precheck()?;
    meta.setup_cgroup()?;

    //meta.execute()?;

    Ok(())
}

impl Meta {
    fn new_from_args() -> Result<Self> {
        // TODO: use clap
        let mut meta = Meta {
            cg_fs_dir: PathBuf::from("/sys/fs/cgroup"),
            cg_pdir: PathBuf::new(),
            cg_dir: PathBuf::new(),
            child_argv: vec![String::from("sleep"), String::from("1")],
            delim: ';',
        };

        if let Some("") = meta.cg_pdir.to_str() {
            // Create a temp cgroup under the current user's cgroup root (e.g. /user.slice/user-1000.slice/user@1000.service).
            // Otherwise, the current per process cgroup might disallow users to enable a specific
            // (i.e. memory) controller.
            let bs = read("/proc/self/cgroup").wrap_err("reading per process cgroup file")?;
            let my_cgroup = bs
                .strip_prefix("0::".as_bytes())
                .wrap_err("failed to read the current cgroup")?;

            // The sub-slicing here is meant to remove the prefixng slash and the trailing newline
            let my_cgroup = OsStr::from_bytes(&my_cgroup[1..my_cgroup.len() - 1])
                .to_str()
                .wrap_err_with(|| format!("converting {:?} to &str", my_cgroup))?;
            let user_cgroup = &my_cgroup[..my_cgroup
                .find(".service")
                .wrap_err_with(|| format!(r#"finding the ".service" in {}"#, my_cgroup))?
                + ".service".len()];
            let user_cgroup_dir = meta.cg_fs_dir.join(Path::new(user_cgroup));
            meta.cg_pdir = tempdir_in(user_cgroup_dir)
                .wrap_err("creating the parent cgroup dir")?
                .into_path();
            meta.cg_dir = meta.cg_pdir.join("leaf");
        }

        Ok(meta)
    }

    fn precheck(&self) -> Result<()> {
        // TODO: probably should check the user cgroup dir
        let path = self.cg_fs_dir.as_path();
        OsStr::from_bytes(read(path.join("cgroup.controllers"))?.as_slice())
            .to_str()
            .wrap_err("failed to convert from OsStr to Rust str")?
            .find("memory")
            .wrap_err(r#""memory" controller not defined"#)?;
        OsStr::from_bytes(read(path.join("cgroup.subtree_control"))?.as_slice())
            .to_str()
            .wrap_err("failed to convert from OsStr to Rust str")?
            .find("memory")
            .wrap_err(r#""memory" controller not defined"#)?;
        Ok(())
    }

    fn setup_cgroup(&self) -> Result<()> {
        write(self.cg_pdir.join("cgroup.subtree_control"), "+memory")
            .wrap_err("enabling the memory controller for the parent cgroup")?;

        // See: https://docs.kernel.org/admin-guide/cgroup-v2.html#no-internal-process-constraint
        create_dir(self.cg_dir.as_path()).wrap_err("creating the real cgroup")?;
        Ok(())
    }

    fn execute(&self) -> Result<()> {
        let cgroup_file =
            File::open(self.cg_dir.as_path()).wrap_err("openning the cgroup for execution")?;
        let mut pid_fd: c_ulonglong = 0;

        let ca = libc::clone_args {
            flags: (libc::CLONE_NEWCGROUP | libc::CLONE_PIDFD | libc::CLONE_VFORK)
                as libc::c_ulonglong,
            pidfd: &mut pid_fd as *mut c_ulonglong as c_ulonglong,
            exit_signal: libc::SIGCHLD as libc::c_ulonglong,
            cgroup: cgroup_file.as_raw_fd() as c_ulonglong,
            child_tid: 0,
            parent_tid: 0,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
        };

        let start = SystemTime::now();

        // Safety: we'll wait on the pidfd later
        let mut pid: libc::pid_t = -1;
        unsafe {
            pid = libc::syscall(libc::SYS_clone3, &ca, size_of_val(&ca)) as libc::pid_t;
        }

        // failed to clone
        if pid == -1 {
            let err_msg = "failed to call clone3";
            unsafe {
                // Safety: just printing the error
                libc::perror(CString::new(err_msg)?.as_ptr() as *const c_char);
            }
            return Err(eyre!(err_msg));
        }

        // child
        if pid == 0 {
            let mut cmd = Command::new(&self.child_argv[0]);
            let err = cmd.args(&self.child_argv[1..]).exec();
            return Err(err).wrap_err("executing the child process");
        }

        // parent

        // Ignore SIGINT and SIGQUIT for the cgmemtime parent process, as otherwise, Ctrl+C/+] also kill cgmemtime before it has a chance printing its summary
        let sa = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        unsafe {
            sigaction(Signal::SIGINT, &sa)?;
            sigaction(Signal::SIGQUIT, &sa)?;
        }

        let mut usg = mem::MaybeUninit::<libc::rusage>::uninit();

        let mut ret: libc::c_long = 0;

        // Safety: calling the raw syscall to wait pidfd of the child process
        unsafe {
            ret = libc::syscall(
                libc::SYS_waitid,
                pid_fd as libc::idtype_t,
                0 as libc::uintptr_t,
                libc::WEXITED,
                usg.as_mut_ptr(),
            );
        }
        if ret == -1 {
            let err_msg = "failed to wait child";
            unsafe {
                // Safety: just printing the error
                libc::perror(CString::new(err_msg)?.as_ptr() as *const c_char);
            }
            return Err(eyre!(err_msg));
        }

        let wall_duration = SystemTime::now().duration_since(start)?;
        Ok(())
    }

    fn tear_down(&self) -> Result<()> {
        let cg_dir = self.cg_dir.as_path();
        let cg_pdir = self.cg_pdir.as_path();
        if cg_dir.is_dir() {
            remove_dir(cg_dir).wrap_err("removing the real cgroup")?;
        }
        if cg_pdir.is_dir() {
            remove_dir(cg_pdir).wrap_err("removing the parent cgroup")?;
        }
        Ok(())
    }
}

fn join_errors(results: Vec<Result<(), Report>>) -> Result<(), Report> {
    #[derive(Debug, Error)]
    #[error("{0}")]
    struct StrError(String);

    if results.iter().all(|r| r.is_ok()) {
        return Ok(());
    }

    let results: Vec<Result<(), Report>> = results.into_iter().filter(Result::is_err).collect();

    if results.len() == 1 {
        return results.into_iter().next().unwrap();
    }

    results.into_iter().map(Result::unwrap_err).fold(
        Err(eyre!("encountered multiple errors")),
        |report, e| {
            let e = StrError(format!("{:#}", e));
            report.error(e)
        },
    )
}
