use color_eyre::{Help, Report};
use libc::{c_ulong, c_ulonglong, syscall};
use std::ffi::{c_char, CStr, CString, OsStr, OsString};
use std::fs::{self, create_dir, remove_dir, write, File};
use std::io::Read;
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::prelude::{FileExt, OsStrExt};
use std::path::Path;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::read, path::PathBuf};
use tempfile::tempdir_in;

use color_eyre::eyre::{self, eyre, ContextCompat, Result, WrapErr};

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

    if let Err(err) = real_main(&meta) {
        // TODO: how to handle multiple error via eyre?
        meta.tear_down();
        return Err(err);
    }
    meta.tear_down()?;
    Ok(())
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
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as libc::c_ulonglong,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: cgroup_file.as_raw_fd() as c_ulonglong,
        };

        let start = SystemTime::now();

        // Safety: we'll wait on the pidfd later
        let mut pid: libc::pid_t = -1;
        unsafe {
            pid = libc::syscall(libc::SYS_clone3, &ca, size_of_val(&ca)) as libc::pid_t;
        }

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
            // TODO: Use https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#tymethod.exec instead of unsafe syscall
            let cmd_ptr = CString::new(self.child_argv[0].as_str())?.as_ptr();
            let args: Vec<*const c_char> = self.child_argv[1..]
                .iter()
                .map(|s| {
                    CString::new(s.as_str())
                        .wrap_err_with(|| format!("converting to CString for {}", s))
                        .unwrap()
                        .as_ptr() as *const c_char
                }) // TODO: how to pop up error here?
                .collect();
            let args_ptr = args.as_ptr() as *const *const c_char;

            // Safety: executing a command won't leak any memory, or?
            unsafe {
                libc::execv(cmd_ptr, args_ptr);
            }
            let err_msg = "failed to exec child";
            unsafe {
                // Safety: just printing the error
                libc::perror(CString::new(err_msg)?.as_ptr() as *const c_char);
            }
            exit(1);
        }

        // parent
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

fn join_errors(
    results: Vec<Result<(), impl std::error::Error + Send + Sync + 'static>>,
) -> Result<(), Report> {
    if results.iter().all(|r| r.is_ok()) {
        return Ok(());
    }

    results
        .into_iter()
        .filter(Result::is_err)
        .map(Result::unwrap_err)
        .fold(Err(eyre!("encountered multiple errors")), |report, e| {
            report.error(e)
        })
}
