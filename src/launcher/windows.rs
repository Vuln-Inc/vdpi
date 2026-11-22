use super::{Choice, INSTALL_HINT, RUN_HINT, TITLE};
use std::{mem, ptr};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetConsoleProcessList, GetStdHandle, SetConsoleMode,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_FLAGS, USEROBJECTFLAGS,
};
#[cfg(target_env = "msvc")]
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDNO, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MB_YESNOCANCEL, WSF_VISIBLE,
};

pub fn has_own_console() -> bool {
    let mut processes = [0; 2];
    unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) == 1 }
}

pub fn enable_terminal_color() -> bool {
    let mut mode = 0;
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        GetConsoleMode(handle, &mut mode) != 0
            && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
                || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0)
    }
}

fn visible_window_station() -> bool {
    let mut flags = USEROBJECTFLAGS::default();
    let mut len = 0;
    unsafe {
        GetUserObjectInformationW(
            GetProcessWindowStation(),
            UOI_FLAGS,
            (&mut flags as *mut USEROBJECTFLAGS).cast(),
            mem::size_of_val(&flags) as u32,
            &mut len,
        ) != 0
            && flags.dwFlags & WSF_VISIBLE as u32 != 0
    }
}

pub fn desktop_choice() -> Option<Choice> {
    if !visible_window_station() {
        return None;
    }
    #[cfg(target_env = "msvc")]
    if let Some(choice) = task_dialog() {
        return Some(choice);
    }

    let body = wide(&format!(
        "Yes: Run directly. {RUN_HINT}\n\nNo: Install. {INSTALL_HINT}"
    ));
    let button = unsafe {
        MessageBoxW(
            ptr::null_mut(),
            body.as_ptr(),
            wide(TITLE).as_ptr(),
            MB_YESNOCANCEL | MB_ICONINFORMATION,
        )
    };
    match button {
        IDYES => Some(Choice::Run),
        IDNO => Some(Choice::Install),
        0 => None,
        _ => Some(Choice::Cancel),
    }
}

#[cfg(target_env = "msvc")]
fn task_dialog() -> Option<Choice> {
    const RUN: i32 = 100;
    const INSTALL: i32 = 101;
    let title = wide(&format!("vdpi {}", env!("CARGO_PKG_VERSION")));
    let instruction = wide(TITLE);
    let run = wide(&format!("Run directly\n{RUN_HINT}"));
    let install =
        wide("Install for automatic startup\nRun in the background as a Windows service.");
    let footer = wide("You can install later with vdpi install.");
    let buttons = [
        TASKDIALOG_BUTTON {
            nButtonID: RUN,
            pszButtonText: run.as_ptr(),
        },
        TASKDIALOG_BUTTON {
            nButtonID: INSTALL,
            pszButtonText: install.as_ptr(),
        },
    ];
    let config = TASKDIALOGCONFIG {
        cbSize: mem::size_of::<TASKDIALOGCONFIG>() as u32,
        dwFlags: TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT,
        dwCommonButtons: TDCBF_CANCEL_BUTTON,
        pszWindowTitle: title.as_ptr(),
        pszMainInstruction: instruction.as_ptr(),
        pButtons: buttons.as_ptr(),
        cButtons: buttons.len() as u32,
        nDefaultButton: RUN,
        pszFooter: footer.as_ptr(),
        ..Default::default()
    };
    let mut button = 0;
    let result =
        unsafe { TaskDialogIndirect(&config, &mut button, ptr::null_mut(), ptr::null_mut()) };
    (result >= 0).then_some(match button {
        RUN => Choice::Run,
        INSTALL => Choice::Install,
        _ => Choice::Cancel,
    })
}

pub fn install_finished(result: &anyhow::Result<()>) {
    if !visible_window_station() {
        return;
    }
    let (message, icon) = match result {
        Ok(()) => (
            "vdpi is installed and starts automatically.".to_string(),
            MB_ICONINFORMATION,
        ),
        Err(e) => (
            format!("vdpi could not finish installation.\n\n{e:#}"),
            MB_ICONERROR,
        ),
    };
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            wide(&message).as_ptr(),
            wide("vdpi installation").as_ptr(),
            MB_OK | icon,
        )
    };
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
