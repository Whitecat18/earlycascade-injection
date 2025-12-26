use windows_sys::Win32::System::Memory::RtlCompareMemory;

const MAX_PATTERN_SIZE: usize = 0x20;

pub fn encode_system_ptr(ptr: u64) -> u64 {
    let cookie: u32 = unsafe { *(0x7FFE0330 as *const u32) };
    ((ptr ^ cookie as u64).rotate_right((cookie & 0x3F) as u32)) as u64
}

pub fn find_pattern(buf: &[u8], pat: &[u8]) -> Option<usize> {
    if buf.len() < pat.len() {
        return None;
    }

    buf.windows(pat.len()).position(|window| unsafe {
        RtlCompareMemory(window.as_ptr() as _, pat.as_ptr() as _, pat.len()) == pat.len()
    })
}

#[repr(C)]
struct CascadePattern {
    data: [u8; MAX_PATTERN_SIZE],
    size: u8,
    pc_off: u8,
}

pub fn find_se_dll_loaded(ntdll_base: u64) -> Option<(u64, u64)> {
    let patterns = [CascadePattern {
        data: [
            0x8B, 0x14, 0x25, 0x30, 0x03, 0xFE, 0x7F, 0x8B, 0xC2, 0x48, 0x8B, 0x3D, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        size: 12,
        pc_off: 4,
    }];

    let dos = ntdll_base as *const u8;
    let e_lfanew = unsafe { *(dos.offset(0x3C) as *const i32) } as isize;
    let nt = (ntdll_base as isize + e_lfanew) as *const u8;

    let num_sections = unsafe { *(nt.offset(6) as *const u16) } as usize;
    let opt_size = unsafe { *(nt.offset(20) as *const u16) } as isize;

    let sec_start = unsafe { nt.offset(24 + opt_size) };

    let mut text_va = 0u64;
    let mut text_size = 0u64;
    let mut mrdata_va = 0u64;
    let mut mrdata_size = 0u64;

    for i in 0..num_sections {
        let sec = unsafe { sec_start.offset((i * 40) as isize) };
        let name_arr = unsafe { *(sec as *const [u8; 8]) };

        if name_arr == *b".text\0\0\0" {
            text_va = unsafe { *(sec.offset(12) as *const u32) } as u64;
            text_size = unsafe { *(sec.offset(8) as *const u32) } as u64;
        }
        if name_arr == *b".mrdata\0" {
            mrdata_va = unsafe { *(sec.offset(12) as *const u32) } as u64;
            mrdata_size = unsafe { *(sec.offset(8) as *const u32) } as u64;
        }
    }

    let text_start = ntdll_base + text_va;

    for pat in patterns {
        let mut pos = text_start as usize;
        let mem =
            unsafe { std::slice::from_raw_parts(text_start as *const u8, text_size as usize) };

        while let Some(off) = find_pattern(
            &mem[(pos - text_start as usize)..],
            &pat.data[..pat.size as usize],
        ) {
            pos = text_start as usize + (pos - text_start as usize) + off + pat.size as usize;
            if unsafe { *((pos as *const u8).offset(3)) } != 0 {
                continue;
            }

            let rel = unsafe { *(pos as *const i32) };
            let addr = (pos as u64)
                .wrapping_add(rel as u64)
                .wrapping_add(pat.pc_off as u64);

            if addr >= ntdll_base + mrdata_va && addr < ntdll_base + mrdata_va + mrdata_size {
                return Some((addr, pos as u64 - pat.size as u64));
            }
        }
    }
    None
}

pub fn find_shims_enabled(ntdll_base: u64, offset_addr: u64) -> Option<u64> {
    let patterns = [
        CascadePattern {
            data: [
                0xc6, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
            size: 2,
            pc_off: 5,
        },
        CascadePattern {
            data: [
                0x44, 0x38, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ],
            size: 3,
            pc_off: 4,
        },
        
        // win11 variant for cmp [rel], r13b
        CascadePattern {
            data: [
                0x44, 0x38, 0x2D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0,
            ],
            size: 3,
            pc_off: 4,
        },
    ];

    let search_start = offset_addr.saturating_sub(0xFF);
    let search_end = offset_addr + 0xFF;
    let mem = unsafe {
        std::slice::from_raw_parts(
            search_start as *const u8,
            (search_end - search_start) as usize,
        )
    };

    let dos = ntdll_base as *const u8;
    let e_lfanew = unsafe { *(dos.offset(0x3C) as *const i32) } as isize;
    let nt = (ntdll_base as isize + e_lfanew) as *const u8;
    let num_sections = unsafe { *(nt.offset(6) as *const u16) } as usize;
    let opt_size = unsafe { *(nt.offset(20) as *const u16) } as isize;

    let sec_start = unsafe { nt.offset(24 + opt_size) };

    let mut data_va = 0u64;
    let mut data_size = 0u64;

    for i in 0..num_sections {
        let sec = unsafe { sec_start.offset((i * 40) as isize) };
        let name_arr = unsafe { *(sec as *const [u8; 8]) };
        if name_arr == *b".data\0\0\0" {
            data_va = unsafe { *(sec.offset(12) as *const u32) } as u64;
            data_size = unsafe { *(sec.offset(8) as *const u32) } as u64;
        }
    }

    for pat in patterns {
        let mut cur = 0usize;
        while let Some(off) = find_pattern(&mem[cur..], &pat.data[..pat.size as usize]) {
            cur += off + pat.size as usize;
            let ptr = search_start + cur as u64;
            if unsafe { *((ptr + 3) as *const u8) } != 0 {
                continue;
            }

            let rel = unsafe { *(ptr as *const i32) };
            let addr = ptr.wrapping_add(rel as u64).wrapping_add(pat.pc_off as u64);

            if addr >= ntdll_base + data_va && addr < ntdll_base + data_va + data_size {
                return Some(addr);
            }
        }
    }
    None
}
