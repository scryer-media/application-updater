//! Stopping a product's own Windows processes, wherever they came from.
//!
//! Waiting on one recorded process id is not enough before an installer runs:
//! a server orphaned by an earlier, interrupted upgrade still holds the
//! installed executables open, and nothing records its id. This module finds
//! every running process whose image is one of the product's executables in
//! the installation directory, asks each to exit, and terminates whatever is
//! still running once a bounded wait runs out. That is the same
//! ask-then-kill-by-name sequence established Windows installers and in-app
//! updaters use, bounded so a process that ignores the request cannot stall an
//! upgrade.
//!
//! Matching is deliberately narrow: the image file name must be one the host
//! listed in [`crate::ProductDescriptor::windows_product_process_names`] *and*
//! the image must live directly in the installation directory. A process the
//! caller cannot attribute (its image path is unreadable, or it runs from
//! somewhere else) is never touched.

use std::path::Path;
use std::time::Duration;

/// How a stop request is paced.
///
/// The defaults ask, then poll `ask_attempts` times `ask_interval` apart
/// (twenty half-second polls, ten seconds in all) before terminating, and then
/// wait up to `terminate_wait` for the terminated processes to disappear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopPolicy {
    pub ask_attempts: u32,
    pub ask_interval: Duration,
    pub terminate_wait: Duration,
}

impl StopPolicy {
    /// Twenty polls half a second apart, then five seconds after termination.
    pub const DEFAULT: Self = Self {
        ask_attempts: 20,
        ask_interval: Duration::from_millis(500),
        terminate_wait: Duration::from_secs(5),
    };

    /// The longest a stop following this policy can take.
    pub fn budget(&self) -> Duration {
        self.ask_interval
            .saturating_mul(self.ask_attempts)
            .saturating_add(self.terminate_wait)
    }
}

impl Default for StopPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a stop did. Process ids only; the caller already knows the names.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StopReport {
    /// Processes that matched and were asked to exit.
    pub found: Vec<u32>,
    /// Processes that had to be terminated because they ignored the request.
    pub terminated: Vec<u32>,
    /// Processes still running when the policy's budget ran out.
    pub remaining: Vec<u32>,
}

impl StopReport {
    /// Whether nothing the stop matched is still running.
    pub fn all_stopped(&self) -> bool {
        self.remaining.is_empty()
    }
}

/// Normalize a Windows path for comparison: no extended-length prefix, one
/// separator, no trailing separator, ASCII case folded.
///
/// Windows paths are case-insensitive, and the same directory reaches this
/// code both as `QueryFullProcessImageNameW` reports it and as
/// `std::fs::canonicalize` reports it (with `\\?\`).
pub fn normalize_windows_path(path: &str) -> String {
    let path = path.replace('/', "\\");
    let path = if let Some(rest) = path.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = path.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        path
    };
    path.trim_end_matches('\\').to_ascii_lowercase()
}

/// Whether a running image is one of the product's processes in this
/// installation: its file name is one of `names` and it lives directly in one
/// of the `install_dirs` spellings.
pub fn image_is_product_process(image: &str, names: &[&str], install_dirs: &[String]) -> bool {
    let image = normalize_windows_path(image);
    let Some((parent, file_name)) = image.rsplit_once('\\') else {
        return false;
    };
    names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(file_name))
        && install_dirs
            .iter()
            .any(|install_dir| normalize_windows_path(install_dir) == parent)
}

/// The spellings an installation directory may be reported under: as given,
/// and canonicalized (which on Windows resolves junctions and adds `\\?\`).
pub fn install_dir_spellings(install_dir: &Path) -> Vec<String> {
    let mut spellings = vec![install_dir.to_string_lossy().into_owned()];
    if let Ok(canonical) = std::fs::canonicalize(install_dir) {
        let canonical = canonical.to_string_lossy().into_owned();
        if normalize_windows_path(&canonical) != normalize_windows_path(&spellings[0]) {
            spellings.push(canonical);
        }
    }
    spellings
}

#[cfg(windows)]
pub use self::windows::{
    find_product_processes, request_console_interrupt, request_window_close,
    stop_product_processes, terminate_process,
};

#[cfg(windows)]
mod windows {
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Instant;

    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Console::{
        AttachConsole, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
    };
    use windows_sys::core::BOOL;

    use super::{StopPolicy, StopReport, image_is_product_process, install_dir_spellings};

    /// Every running process whose image is one of `names` directly inside
    /// `install_dir`, except the ids in `exclude`.
    pub fn find_product_processes(names: &[&str], install_dir: &Path, exclude: &[u32]) -> Vec<u32> {
        let install_dirs = install_dir_spellings(install_dir);
        let mut matches = Vec::new();
        // SAFETY: A process snapshot takes plain flags and returns a handle this
        // function owns, or INVALID_HANDLE_VALUE.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return matches;
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        // SAFETY: `entry` is a valid, size-initialized PROCESSENTRY32W.
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            let process_id = entry.th32ProcessID;
            let exe_len = entry
                .szExeFile
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(entry.szExeFile.len());
            let exe = String::from_utf16_lossy(&entry.szExeFile[..exe_len]);
            // The snapshot's name is only the file name; it is the cheap
            // filter, and the full image path is the real test.
            if process_id != 0
                && !exclude.contains(&process_id)
                && names.iter().any(|name| name.eq_ignore_ascii_case(&exe))
                && process_image(process_id)
                    .is_some_and(|image| image_is_product_process(&image, names, &install_dirs))
            {
                matches.push(process_id);
            }
            // SAFETY: As above; the snapshot handle is still open.
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        // SAFETY: This function owns the snapshot handle.
        unsafe { CloseHandle(snapshot) };
        matches
    }

    /// The full Win32 image path of a process, when this process may read it.
    fn process_image(process_id: u32) -> Option<String> {
        let handle = OwnedProcess::open(process_id, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut buffer = vec![0_u16; 32_768];
        let mut size = buffer.len() as u32;
        // SAFETY: The handle is open with query rights, and `buffer` holds `size`
        // writable UTF-16 units.
        let ok = unsafe {
            QueryFullProcessImageNameW(handle.0, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size)
        };
        (ok != 0).then(|| String::from_utf16_lossy(&buffer[..size as usize]))
    }

    struct OwnedProcess(HANDLE);

    impl OwnedProcess {
        fn open(process_id: u32, access: u32) -> Option<Self> {
            // SAFETY: OpenProcess takes plain integers and returns a handle this
            // value owns, or null.
            let handle = unsafe { OpenProcess(access, 0, process_id) };
            (!handle.is_null()).then_some(Self(handle))
        }
    }

    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            // SAFETY: This value owns the handle returned by OpenProcess.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Whether a process is still running. A process that cannot be opened at
    /// all is gone (or its id was recycled into one this caller cannot touch).
    fn is_running(process_id: u32) -> bool {
        let Some(handle) = OwnedProcess::open(process_id, PROCESS_SYNCHRONIZE) else {
            return false;
        };
        // SAFETY: The handle is open with SYNCHRONIZE rights.
        unsafe { WaitForSingleObject(handle.0, 0) != WAIT_OBJECT_0 }
    }

    /// Post `WM_CLOSE` to every top-level window a process owns. Returns
    /// whether it owned any.
    pub fn request_window_close(process_id: u32) -> bool {
        struct Search {
            process_id: u32,
            posted: bool,
        }
        unsafe extern "system" fn visit(window: HWND, lparam: LPARAM) -> BOOL {
            // SAFETY: `lparam` is the `Search` below, alive for the whole
            // enumeration and touched only on this thread.
            let search = unsafe { &mut *(lparam as *mut Search) };
            let mut owner = 0_u32;
            // SAFETY: `window` came from EnumWindows and `owner` is writable.
            unsafe { GetWindowThreadProcessId(window, &mut owner) };
            if owner == search.process_id {
                // SAFETY: Posting a close request to a window of the process
                // being stopped; the message carries no pointers.
                if unsafe { PostMessageW(window, WM_CLOSE, 0, 0) } != 0 {
                    search.posted = true;
                }
            }
            1
        }
        let mut search = Search {
            process_id,
            posted: false,
        };
        // SAFETY: The callback only reads the `Search` passed through lparam,
        // which outlives the call.
        unsafe { EnumWindows(Some(visit), &mut search as *mut Search as LPARAM) };
        search.posted
    }

    static CONSOLE_LOCK: Mutex<()> = Mutex::new(());

    /// Deliver `CTRL_C_EVENT` to the console a process is attached to, which is
    /// how a windowless console server is asked to shut down gracefully.
    ///
    /// The caller temporarily joins that console to raise the event. Any
    /// console this process had is released first, because a process may be
    /// attached to only one.
    ///
    /// Group 0 delivers the event to this process too, so it first sets the
    /// process-wide ignore flag with `SetConsoleCtrlHandler(NULL, TRUE)`. A
    /// registered handler that returns `TRUE` does not protect the sender:
    /// measured on Windows, the sender still exited with
    /// `STATUS_CONTROL_C_EXIT`, and only the ignore flag kept it alive.
    ///
    /// The flag is left set: the event reaches this process asynchronously, so
    /// clearing it afterwards could race the delivery and kill the caller. The
    /// calling process therefore ignores Ctrl+C for the rest of its lifetime,
    /// and every child process it starts afterwards INHERITS the flag. Callers
    /// that later start a console child which must answer Ctrl+C (a relaunched
    /// server, for example) must clear the flag first, or the child must clear
    /// it itself at startup.
    ///
    /// Returns whether the event was raised. A process started without a
    /// console (`DETACHED_PROCESS`) cannot be reached this way.
    pub fn request_console_interrupt(process_id: u32) -> bool {
        let _guard = CONSOLE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: A null handler with TRUE only sets this process's
        // ignore-Ctrl+C flag.
        unsafe { SetConsoleCtrlHandler(None, 1) };
        // SAFETY: Releasing this process's console, if it has one, is always
        // permitted; failure only means it had none.
        unsafe { FreeConsole() };
        // SAFETY: AttachConsole takes a plain process id.
        if unsafe { AttachConsole(process_id) } == 0 {
            return false;
        }
        // SAFETY: Group 0 addresses every process attached to the console this
        // process just joined; this process ignores its own copy above.
        let raised = unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) } != 0;
        // SAFETY: Leave the borrowed console again.
        unsafe { FreeConsole() };
        raised
    }

    /// Terminate a process outright. Returns whether the call succeeded or the
    /// process was already gone.
    pub fn terminate_process(process_id: u32) -> bool {
        let Some(handle) = OwnedProcess::open(process_id, PROCESS_TERMINATE) else {
            return !is_running(process_id);
        };
        // SAFETY: The handle is open with TERMINATE rights.
        unsafe { TerminateProcess(handle.0, 1) != 0 }
    }

    /// Stop every product process in `install_dir`: ask each one to exit
    /// (window close, then console interrupt), poll as the policy says, then
    /// terminate whatever is still running and wait for it to disappear.
    ///
    /// Processes that start during the stop are not chased; callers that need
    /// a quiet installation call this again after their own next step.
    pub fn stop_product_processes(
        names: &[&str],
        install_dir: &Path,
        exclude: &[u32],
        policy: StopPolicy,
    ) -> StopReport {
        let mut exclude = exclude.to_vec();
        exclude.push(std::process::id());
        let found = find_product_processes(names, install_dir, &exclude);
        let mut report = StopReport {
            found: found.clone(),
            ..StopReport::default()
        };
        if found.is_empty() {
            return report;
        }
        // Both requests go to every process: a windowed process ignores the
        // console interrupt it cannot receive, and a console server ignores a
        // close posted to a hidden window it happens to own.
        for &process_id in &found {
            request_window_close(process_id);
            request_console_interrupt(process_id);
        }
        let mut running: Vec<u32> = found;
        for _ in 0..policy.ask_attempts {
            running.retain(|&process_id| is_running(process_id));
            if running.is_empty() {
                return report;
            }
            std::thread::sleep(policy.ask_interval);
        }
        running.retain(|&process_id| is_running(process_id));
        for &process_id in &running {
            if terminate_process(process_id) {
                report.terminated.push(process_id);
            }
        }
        let deadline = Instant::now() + policy.terminate_wait;
        loop {
            running.retain(|&process_id| is_running(process_id));
            if running.is_empty() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        report.remaining = running;
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMES: [&str; 2] = ["exampleapp.exe", "exampleapp-tray.exe"];

    #[test]
    fn a_product_executable_in_the_install_directory_matches_in_any_spelling() {
        let install = vec!["C:\\Program Files\\ExampleApp".to_string()];
        assert!(image_is_product_process(
            "C:\\Program Files\\ExampleApp\\exampleapp.exe",
            &NAMES,
            &install
        ));
        assert!(image_is_product_process(
            "\\\\?\\c:\\program files\\exampleapp\\ExampleApp-Tray.EXE",
            &NAMES,
            &install
        ));
        assert!(image_is_product_process(
            "C:/Program Files/ExampleApp/exampleapp.exe",
            &NAMES,
            &["\\\\?\\C:\\Program Files\\ExampleApp\\".to_string()]
        ));
    }

    #[test]
    fn other_executables_and_other_directories_never_match() {
        let install = vec!["C:\\Program Files\\ExampleApp".to_string()];
        // Same name, different installation.
        assert!(!image_is_product_process(
            "D:\\portable\\exampleapp.exe",
            &NAMES,
            &install
        ));
        // A sibling directory that merely shares the prefix.
        assert!(!image_is_product_process(
            "C:\\Program Files\\ExampleApp Other\\exampleapp.exe",
            &NAMES,
            &install
        ));
        // Nested below the installation is not the installation.
        assert!(!image_is_product_process(
            "C:\\Program Files\\ExampleApp\\tools\\exampleapp.exe",
            &NAMES,
            &install
        ));
        // The temporary upgrade helper and unrelated programs are left alone.
        assert!(!image_is_product_process(
            "C:\\Program Files\\ExampleApp\\exampleapp-upgrade-helper.exe",
            &NAMES,
            &install
        ));
        assert!(!image_is_product_process(
            "exampleapp.exe",
            &NAMES,
            &install
        ));
    }

    #[test]
    fn unc_extended_paths_normalize_to_their_plain_form() {
        assert_eq!(
            normalize_windows_path("\\\\?\\UNC\\server\\share\\ExampleApp\\"),
            "\\\\server\\share\\exampleapp"
        );
    }

    #[test]
    fn the_default_policy_asks_for_ten_seconds_and_stays_well_inside_an_installer_wait() {
        let policy = StopPolicy::default();
        assert_eq!(
            policy.ask_interval * policy.ask_attempts,
            Duration::from_secs(10)
        );
        assert_eq!(policy.budget(), Duration::from_secs(15));
    }

    #[test]
    fn a_stop_that_left_nothing_running_reports_all_stopped() {
        let report = StopReport {
            found: vec![10, 11],
            terminated: vec![11],
            remaining: Vec::new(),
        };
        assert!(report.all_stopped());
        let report = StopReport {
            remaining: vec![11],
            ..report
        };
        assert!(!report.all_stopped());
    }
}
