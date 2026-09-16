// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    ffi::CStr,
    io::{BufRead, Cursor},
    sync::{Arc, Mutex},
};

use goblin::{
    elf::{Elf, Reloc, Sym},
    elf64::{
        program_header::PT_LOAD,
        reloc::{R_386_RELATIVE, R_AARCH64_RELATIVE, R_ARM_RELATIVE, R_X86_64_RELATIVE},
    },
    Object,
};
#[cfg(not(target_arch = "wasm32"))]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::ParallelSlice;
use regex::Regex;

use coeus_macros::{iterator, windows};
use coeus_models::models::BinaryObject;

use super::{ByteEvidence, ConfidenceLevel, Context, Evidence, Location, StringEvidence};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinaryContent {
    Char(char),
    Byte(u8),
    Wildcard,
}

pub fn find_binary_pattern_in_elf<'a>(
    pattern: &'a [BinaryContent],
    files: &'a HashMap<String, Arc<BinaryObject>>,
) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|(file_name, object)| {
        let obj_data = object.data();
        let the_matches: Vec<Evidence> = windows!(obj_data, pattern.len())
            .enumerate()
            .filter(|(_, data)| {
                for i in 0..data.len() {
                    match pattern[i] {
                        BinaryContent::Char(c) => {
                            if c as u8 != data[i] {
                                return false;
                            }
                        }
                        BinaryContent::Byte(b) => {
                            if b != data[i] {
                                return false;
                            }
                        }
                        BinaryContent::Wildcard => continue,
                    }
                }
                true
            })
            .map(|(index, _)| {
                Evidence::BytePattern(ByteEvidence {
                    pattern: pattern.to_vec(),
                    place: Location::NativePattern(file_name.to_string(), index as usize),
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(the_matches);
        }
    });
    matches
}

pub fn find_string_matches_in_elf(
    reg: &Regex,
    files: &HashMap<String, Arc<BinaryObject>>,
    only_symbols: bool,
) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|(file_name, object)| {
        match object.object_no_cache() {
            Some(Object::Elf(elf)) => {
                let lib_matches: Vec<_> = iterator!(elf.libraries)
                    .filter(|&&lib| reg.is_match(lib))
                    .map(|&lib| {
                        Evidence::String(StringEvidence {
                            content: lib.to_string(),
                            context: Context::NativeLib(
                                object.clone(),
                                file_name.to_string(),
                                0,
                                false,
                                Sym::default(),
                            ),
                            confidence_level: ConfidenceLevel::Medium,
                            place: Location::NativeLibLoad,
                        })
                    })
                    .collect();

                let symbol_matches: Vec<_> = elf
                    .dynsyms
                    .iter()
                    .filter(|&sym| match elf.strtab.get_at(sym.st_name) {
                        Some(symbol_name) => reg.is_match(symbol_name),
                        _ => false,
                    })
                    .filter_map(|sym| {
                        Some(Evidence::String(StringEvidence {
                            content: elf.strtab.get_at(sym.st_name)?.to_string(),
                            context: Context::NativeSymbol(object.clone(), file_name.to_string()),
                            confidence_level: ConfidenceLevel::Medium,
                            place: Location::NativeSymbol,
                        }))
                    })
                    .collect();

                if let Ok(mut lock) = vec_lock.lock() {
                    lock.extend(lib_matches);
                    lock.extend(symbol_matches);
                }
            }
            Some(_) if !only_symbols => {
                let mut tmp_matches: Vec<Evidence> = vec![];
                let str_lossy = object.get_utf8_lossy();
                for mat in reg.find_iter(&str_lossy) {
                    tmp_matches.push(Evidence::String(StringEvidence {
                        content: mat.as_str().to_string(),
                        confidence_level: ConfidenceLevel::Low,
                        context: Context::Binary(object.clone(), file_name.to_string()),
                        place: Location::Unknown,
                    }));
                }
                if let Ok(mut lock) = vec_lock.lock() {
                    lock.extend(tmp_matches);
                }
            }
            _ => {}
        };
    });
    matches
}

pub fn find_exported_functions(reg: &Regex, bin_elf: Arc<BinaryObject>) -> Vec<Evidence> {
    let elf = if let Some(Object::Elf(elf)) = bin_elf.object_no_cache() {
        elf
    } else {
        return vec![];
    };
    let mut evidences = vec![];
    for sym in elf
        .dynsyms
        .into_iter()
        .filter(|a| a.is_function() && !a.is_import())
    {
        let sym_name = if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            sym_name
        } else {
            continue;
        };
        if reg.is_match(sym_name) {
            let evidence = StringEvidence {
                content: sym_name.to_string(),
                place: Location::NativeLibLoad,
                context: Context::NativeLib(
                    bin_elf.clone(),
                    sym_name.to_string(),
                    sym.st_value,
                    true,
                    sym,
                ),
                confidence_level: ConfidenceLevel::Medium,
            };
            evidences.push(Evidence::String(evidence));
        }
    }
    evidences
}

pub fn find_imported_functions(reg: &Regex, bin_elf: Arc<BinaryObject>) -> Vec<Evidence> {
    let elf = if let Some(Object::Elf(elf)) = bin_elf.object_no_cache() {
        elf
    } else {
        return vec![];
    };
    let mut evidences = vec![];
    let mask = match elf.header.e_machine {
        goblin::elf::header::EM_ARM => !1,
        _ => !0,
    };
    for sym in elf
        .dynsyms
        .into_iter()
        .filter(|a| a.is_function() && a.is_import())
    {
        let sym_name = if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            sym_name
        } else {
            continue;
        };
        if reg.is_match(sym_name) {
            let evidence = StringEvidence {
                content: sym_name.to_string(),
                place: Location::NativeLibLoad,
                context: Context::NativeLib(
                    bin_elf.clone(),
                    sym_name.to_string(),
                    sym.st_value & mask,
                    false,
                    sym,
                ),
                confidence_level: ConfidenceLevel::Medium,
            };
            evidences.push(Evidence::String(evidence));
        }
    }
    evidences
}

pub fn find_strings(reg: &Regex, bin_elf: Arc<BinaryObject>) -> Vec<Evidence> {
    let elf = if let Some(Object::Elf(elf)) = bin_elf.object_no_cache() {
        elf
    } else {
        return vec![];
    };
    let strings = if let Ok(strings) = elf.strtab.to_vec() {
        strings
    } else {
        return vec![];
    };
    let mut evidences = vec![];
    let regex = regex::bytes::Regex::new(r"(?-u)(?P<cstr>[^\x00]+)\x00").expect("REGEX IS WRONG");
    for h in &elf.section_headers {
        let name = if let Some(name) = elf.shdr_strtab.get_at(h.sh_name) {
            name
        } else {
            continue;
        };
        if name == ".rodata" {
            let cstrs: Vec<(usize, String)> = regex
                .captures_iter(
                    &bin_elf.data()[h.sh_offset as usize..(h.sh_offset + h.sh_size) as usize],
                )
                .filter_map(|c| {
                    if let Ok(cstr) = String::from_utf8(c.name("cstr")?.as_bytes().to_vec()) {
                        Some((c.name("cstr")?.start(), cstr))
                    } else {
                        None
                    }
                })
                .collect();
            for (offset, string) in cstrs {
                if reg.is_match(&string) {
                    let evidence = StringEvidence {
                        content: string.clone(),
                        place: Location::NativeLibLoad,
                        context: Context::NativeLib(
                            bin_elf.clone(),
                            string,
                            h.sh_offset + offset as u64,
                            false,
                            Sym::default(),
                        ),
                        confidence_level: ConfidenceLevel::Medium,
                    };
                    evidences.push(Evidence::String(evidence));
                }
            }
        }
    }
    // let relocs = elf.dynrelas.iter().find(|a| a.)

    for str in strings {
        if reg.is_match(str) {
            let evidence = StringEvidence {
                content: str.to_string(),
                place: Location::NativeLibLoad,
                context: Context::NativeSymbol(bin_elf.clone(), str.to_string()),
                confidence_level: ConfidenceLevel::Medium,
            };
            evidences.push(Evidence::String(evidence));
        }
    }
    evidences
}

#[derive(Debug)]
pub enum CpuArch {
    ArmV7,
    Arm64,
    X86,
    X86_64,
}
/// Find structs, which resemble the NativeFunction struct for the JNIRegisterNative call.
/// This means, there are three pointers where the first is a string pointer to the function name
/// and the last pointer is a function pointer (dynamic symbol)
fn find_jni_register_native(
    symbol_pos: usize,
    offset: i64,
    base_address: u64,
    file_bytes: &[u8],
    elf: &Elf,
) -> Option<Sym> {
    // We need the endianness to figure out, how to interpret the value
    let little_endian = matches!(
        elf.header.endianness().unwrap(),
        goblin::container::Endian::Little
    );
    // We only care about the android subset for now
    let platform = match elf.header.e_machine {
        0x28 => CpuArch::ArmV7,
        0xB7 => CpuArch::Arm64,
        0x03 => CpuArch::X86,
        0x3e => CpuArch::X86_64,
        ty => panic!("{}", ty),
    };
    // We check all relocation tables for a relocation pointing to our found symbol
    let mut register_native_start = 0;
    // adjust pointer offset for cpu architecture (32 bit has 4byte pointers 64bit 8byte pointers)
    let offset_from_start = if elf.is_64 { 16 } else { 8 };
    for r in &elf.dynrelas {
        let sym = elf.dynsyms.get(r.r_sym).unwrap();
        if let Some(native_start) = check_reloc_for_symbol(
            symbol_pos,
            file_bytes,
            little_endian,
            offset,
            base_address,
            &platform,
            &r,
        ) {
            register_native_start = native_start;
        }
        // if this is a function pointer, then we most likely have a NativeFunction struct
        if register_native_start > 0 && r.r_offset == register_native_start + offset_from_start {
            return Some(sym);
        }
    }
    for r in &elf.pltrelocs {
        let sym = elf.dynsyms.get(r.r_sym).unwrap();
        if let Some(native_start) = check_reloc_for_symbol(
            symbol_pos,
            file_bytes,
            little_endian,
            offset,
            base_address,
            &platform,
            &r,
        ) {
            register_native_start = native_start;
        }
        // if this is a function pointer, then we most likely have a NativeFunction struct
        if register_native_start > 0 && r.r_offset == register_native_start + offset_from_start {
            return Some(sym);
        }
    }
    for r in &elf.dynrels {
        let sym = elf.dynsyms.get(r.r_sym).unwrap();
        if let Some(native_start) = check_reloc_for_symbol(
            symbol_pos,
            file_bytes,
            little_endian,
            offset,
            base_address,
            &platform,
            &r,
        ) {
            register_native_start = native_start;
        }
        // if this is a function pointer, then we most likely have a NativeFunction struct
        if register_native_start > 0 && r.r_offset == register_native_start + offset_from_start {
            return Some(sym);
        }
    }
    None
}

/// Do the basic loader relocation (for now only the relative relocations), to see if we find a relocation matching
/// the string symbol position we are seeking for
fn check_reloc_for_symbol(
    symbol_pos: usize,
    file_bytes: &[u8],
    little_endian: bool,
    offset: i64,
    base_address: u64,
    platform: &CpuArch,
    r: &Reloc,
) -> Option<u64> {
    // we do not actually check elf architecture, but assume that arm64 and x86_64 are 64bit
    // we probably could use the elf value
    let is_64 = matches!(platform, CpuArch::Arm64 | CpuArch::X86_64);
    // check for architecture
    // if we have the symbol undefined, the relocation is not based on a symbol, but a direct offset to the string
    match platform {
        CpuArch::ArmV7 => {
            if !(r.r_type == R_ARM_RELATIVE && r.r_sym == 0) {
                return None;
            }
        }
        CpuArch::Arm64 => {
            if !(r.r_type == R_AARCH64_RELATIVE && r.r_sym == 0) {
                return None;
            }
        }
        CpuArch::X86 => {
            if !(r.r_type == R_386_RELATIVE && r.r_sym == 0) {
                return None;
            }
        }
        CpuArch::X86_64 => {
            if !(r.r_type == R_X86_64_RELATIVE && r.r_sym == 0) {
                return None;
            }
        }
    }
    // read the value we need to relocate
    // depending on the architecture and the endianness, we interpret the bytes differently
    let ptr_value = {
        if is_64 {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(
                &file_bytes[(r.r_offset as i64 + offset) as usize
                    ..(r.r_offset as i64 + offset) as usize + 8],
            );
            if little_endian {
                u64::from_le_bytes(bytes)
            } else {
                u64::from_be_bytes(bytes)
            }
        } else {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(
                &file_bytes[(r.r_offset as i64 + offset) as usize
                    ..(r.r_offset as i64 + offset) as usize + 4],
            );
            if little_endian {
                u32::from_le_bytes(bytes) as u64
            } else {
                u32::from_be_bytes(bytes) as u64
            }
        }
    };
    // for 32bit architecture we just adjust the value for the program base. We might need to adjust the
    // calculation of it, since it should be truncated to a multiple of the page size.
    // For 64bit architecture we use the base value and the addended to calculate the location.
    match platform {
        CpuArch::ArmV7 => {
            if ptr_value as i64 - base_address as i64 == symbol_pos as i64 {
                return Some(r.r_offset);
            }
        }
        CpuArch::Arm64 => {
            if r.r_addend.unwrap_or(0) as i64 - base_address as i64 == symbol_pos as i64 {
                return Some(r.r_offset);
            }
        }
        CpuArch::X86 => {
            if ptr_value as i64 - base_address as i64 == symbol_pos as i64 {
                return Some(r.r_offset);
            }
        }
        CpuArch::X86_64 => {
            if r.r_addend.unwrap_or(0) as i64 + base_address as i64 == symbol_pos as i64 {
                return Some(r.r_offset);
            }
        }
    }
    None
}

// We parse the rodata section for strings, matching the name of our function from Java. We use the
// found symbol position, to find relocations, where this string is used, as this is most likely a
// NativeFunction struct.
fn find_symbol(name: &Regex, bytes: &[u8], elf: &Elf) -> Option<usize> {
    let mut sym_pos = None;
    for s in &elf.section_headers {
        // check the name of the section
        let section_header_name = &elf.shdr_strtab[s.sh_name];
        if section_header_name == ".rodata" {
            // we know that rodata has a file_range
            let file_range = s.file_range().unwrap();
            // we create a cursor, operating on the rodata section.
            let bytes_to_search = &bytes[file_range.clone()];
            let mut cursor = Cursor::new(bytes_to_search);
            let mut string_buffer = vec![];
            loop {
                // we read until we can read no more. Since we are looking for arrays of data, we look for 0x00
                // terminated data.
                let str_length = cursor.read_until(0x00, &mut string_buffer).unwrap();
                if str_length == 0 {
                    break;
                }
                // our function name should be a cstring
                if let Ok(the_string) = CStr::from_bytes_with_nul(&string_buffer[..str_length]) {
                    if let Ok(the_string) = the_string.to_str() {
                        if name.is_match(&the_string) {
                            sym_pos = file_range
                                .start
                                .checked_add(cursor.position() as usize - str_length);
                        }
                    }
                }
                string_buffer.clear();
            }
        }
    }
    sym_pos
}

pub fn find_dynamically_registered_function(
    reg: &Regex,
    bin_elf: Arc<BinaryObject>,
) -> Vec<Evidence> {
    let elf = if let Some(Object::Elf(elf)) = bin_elf.object_no_cache() {
        elf
    } else {
        return vec![];
    };
    let mut evidences = vec![];

    let mut base_address = u64::MAX;
    let mut file_offset = 0;
    for p in &elf.program_headers {
        if p.p_type == PT_LOAD {
            if p.p_vaddr < base_address {
                base_address = p.p_vaddr;
            }
            if p.p_vaddr > 0 && p.p_offset != p.p_vaddr {
                file_offset = p.p_offset as i64 - p.p_vaddr as i64
            }
        }
    }
    let sym_pos = find_symbol(reg, bin_elf.data(), &elf);
    if let Some(sym_pos) = sym_pos {
        let native_symbol =
            find_jni_register_native(sym_pos, file_offset, base_address, &bin_elf.data(), &elf);
        if let Some(native_symbol) = native_symbol {
            let sym_name = &elf.dynstrtab[native_symbol.st_name];
            let evidence = StringEvidence {
                content: sym_name.to_string(),
                place: Location::NativeLibLoad,
                context: Context::NativeLib(
                    bin_elf.clone(),
                    sym_name.to_string(),
                    native_symbol.st_value,
                    true,
                    native_symbol,
                ),
                confidence_level: ConfidenceLevel::Medium,
            };

            evidences.push(Evidence::String(evidence));
        }
    }
    evidences
}
