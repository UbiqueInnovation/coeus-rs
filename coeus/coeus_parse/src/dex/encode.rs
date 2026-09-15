//! DEX code-unit encoding and loss-minimal patching.
//!
//! The parser keeps the original DEX as an opaque payload.  This is important
//! for round-tripping annotations, debug information, map items, and newer
//! DEX sections that the analysis model does not expose yet.  Edits therefore
//! patch a code item in place and repair the DEX checksum/signature.

use super::{parse_dex_buf, ArrayView};
use coeus_models::models::{DexFile, Instruction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexEncodeError {
    MissingRawData,
    MethodNotFound(u32),
    MethodHasNoCode(u32),
    InstructionNotFound,
    InstructionSizeChanged { expected: usize, actual: usize },
    MethodHasTryHandlers,
    MethodHasPayload,
    MethodClassDataNotFound,
    RegisterUnavailable { register: u8, available: u16 },
    InvalidCodeItem,
}

impl std::fmt::Display for DexEncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRawData => write!(formatter, "DEX has no retained raw bytes"),
            Self::MethodNotFound(index) => write!(formatter, "method not found: {index}"),
            Self::MethodHasNoCode(index) => write!(formatter, "method has no code: {index}"),
            Self::InstructionNotFound => write!(formatter, "instruction not found"),
            Self::InstructionSizeChanged { expected, actual } => write!(
                formatter,
                "instruction size changed from {expected} to {actual} code units; use a same-size patch",
            ),
            Self::MethodHasTryHandlers => write!(formatter, "method try/catch handlers are not yet supported for code insertion"),
            Self::MethodHasPayload => write!(formatter, "method switch/array payloads are not yet supported for code insertion"),
            Self::MethodClassDataNotFound => write!(formatter, "method class_data_item not found"),
            Self::RegisterUnavailable { register, available } => write!(
                formatter,
                "register v{register} is not a local register; available local registers: v0..v{}",
                available.saturating_sub(1)
            ),
            Self::InvalidCodeItem => write!(formatter, "invalid DEX code item"),
        }
    }
}

impl std::error::Error for DexEncodeError {}

/// Return a valid copy of the original DEX.
pub fn encode_dex(dex: &DexFile) -> Result<Vec<u8>, DexEncodeError> {
    if dex.raw_data().is_empty() {
        return Err(DexEncodeError::MissingRawData);
    }
    let mut output = dex.raw_data().to_vec();
    repair_checksums(&mut output)?;
    Ok(output)
}

/// Replace one decoded instruction without moving any DEX sections.
pub fn replace_method_instruction(
    dex: &DexFile,
    method_idx: u32,
    instruction_index: usize,
    replacement: &Instruction,
) -> Result<Vec<u8>, DexEncodeError> {
    let code_units = replacement
        .to_code_units()
        .map_err(|_| DexEncodeError::InvalidCodeItem)?;
    replace_method_instruction_units(dex, method_idx, instruction_index, &code_units)
}

/// Replace one instruction using already encoded DEX code units.
///
/// The replacement must have the same width as the original instruction.  A
/// fixed-width edit is the safe primitive until the model includes all DEX
/// offset-bearing structures needed for arbitrary code insertion.
pub fn replace_method_instruction_units(
    dex: &DexFile,
    method_idx: u32,
    instruction_index: usize,
    replacement: &[u16],
) -> Result<Vec<u8>, DexEncodeError> {
    let code = dex
        .classes
        .iter()
        .flat_map(|class| class.codes.iter())
        .find(|method| method.method_idx == method_idx)
        .ok_or(DexEncodeError::MethodNotFound(method_idx))?
        .code
        .as_ref()
        .ok_or(DexEncodeError::MethodHasNoCode(method_idx))?;
    let (size, offset, _) = code
        .insns
        .get(instruction_index)
        .ok_or(DexEncodeError::InstructionNotFound)?;
    // The parser stores InstructionSize in bytes, while the editing API
    // accepts the DEX format's 16-bit code units.
    let expected = (size.0 / 2) as usize;
    if expected != replacement.len() {
        return Err(DexEncodeError::InstructionSizeChanged {
            expected,
            actual: replacement.len(),
        });
    }

    let start = (code.code_off as usize)
        .checked_add(16)
        .and_then(|value| value.checked_add(offset.0 as usize * 2))
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let end = start
        .checked_add(replacement.len() * 2)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    if end > dex.raw_data().len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }

    let mut output = dex.raw_data().to_vec();
    for (index, unit) in replacement.iter().enumerate() {
        let position = start + index * 2;
        output[position..position + 2].copy_from_slice(&unit.to_le_bytes());
    }
    repair_checksums(&mut output)?;
    Ok(output)
}

/// Inject a `System.loadLibrary(library_name)` call at the beginning of a
/// method. Missing DEX references are added to rebuilt ID/data sections and
/// the edited DEX is reparsed before the new code item is installed.
pub fn inject_load_library(
    dex: &DexFile,
    method_idx: u32,
    library_name: &str,
    register: u8,
) -> Result<Vec<u8>, DexEncodeError> {
    let (referenced_dex, string_idx, load_library_idx) =
        ensure_load_library_references(dex, library_name)?;
    let edited = parse_dex_buf(
        &dex.file_name,
        &ArrayView::new(&referenced_dex),
        false,
    )
    .ok_or(DexEncodeError::InvalidCodeItem)?;
    let code = edited
        .classes
        .iter()
        .flat_map(|class| class.codes.iter())
        .find(|method| method.method_idx == method_idx)
        .and_then(|method| method.code.as_ref())
        .ok_or(DexEncodeError::MethodHasNoCode(method_idx))?;
    let available = code.register_size.saturating_sub(code.ins_size);
    if register as u16 >= available {
        return Err(DexEncodeError::RegisterUnavailable { register, available });
    }
    let prefix = load_library_prefix(string_idx, load_library_idx, register);
    prepend_method_code(&edited, method_idx, &prefix)
}

/// Encode the two instructions needed for the common Frida Gadget loader:
/// `const-string vN, <library>` followed by
/// `invoke-static {vN}, System.loadLibrary(String)`.  The indices are DEX
/// string/method IDs, not resource IDs.
pub fn load_library_prefix(string_idx: u32, method_idx: u32, register: u8) -> Vec<u16> {
    vec![
        u16::from_le_bytes([0x1a, register]),
        string_idx as u16,
        u16::from_le_bytes([0x71, 0x10]),
        method_idx as u16,
        u16::from(register),
    ]
}

fn ensure_load_library_references(
    dex: &DexFile,
    library_name: &str,
) -> Result<(Vec<u8>, u32, u32), DexEncodeError> {
    if dex.raw_data().is_empty() {
        return Err(DexEncodeError::MissingRawData);
    }
    let mut strings = dex
        .strings
        .iter()
        .map(|entry| entry.to_str().map(str::to_string))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DexEncodeError::InvalidCodeItem)?;
    let old_string_count = strings.len();
    let ensure_string = |strings: &mut Vec<String>, value: &str| -> u32 {
        if let Some(index) = strings.iter().position(|current| current == value) {
            index as u32
        } else {
            let index = strings.len() as u32;
            strings.push(value.to_string());
            index
        }
    };
    let library_string_idx = ensure_string(&mut strings, library_name);
    let load_name_idx = ensure_string(&mut strings, "loadLibrary");
    let system_descriptor_idx = ensure_string(&mut strings, "Ljava/lang/System;");
    let string_descriptor_idx = ensure_string(&mut strings, "Ljava/lang/String;");
    let void_descriptor_idx = ensure_string(&mut strings, "V");
    let shorty_idx = ensure_string(&mut strings, "VL");

    let mut type_additions = Vec::<u32>::new();
    let ensure_type = |descriptor_idx: u32, dex: &DexFile, additions: &mut Vec<u32>| {
        if let Some(index) = dex
            .types
            .iter()
            .position(|index| *index == descriptor_idx)
        {
            index as u32
        } else if let Some(index) = additions.iter().position(|index| *index == descriptor_idx) {
            dex.types.len() as u32 + index as u32
        } else {
            let index = dex.types.len() as u32 + additions.len() as u32;
            additions.push(descriptor_idx);
            index
        }
    };
    let system_type_idx = ensure_type(system_descriptor_idx, dex, &mut type_additions);
    let string_type_idx = ensure_type(string_descriptor_idx, dex, &mut type_additions);
    let void_type_idx = ensure_type(void_descriptor_idx, dex, &mut type_additions);

    let existing_proto_idx = dex.protos.iter().position(|proto| {
        proto.return_type_idx == void_type_idx
            && proto.arguments.as_slice() == [string_type_idx as u16]
    });
    let proto_idx = existing_proto_idx
        .map(|index| index as u32)
        .unwrap_or(dex.protos.len() as u32);
    let existing_method_idx = dex.methods.iter().position(|method| {
        method.class_idx as u32 == system_type_idx
            && method.proto_idx as u32 == proto_idx
            && method.name_idx == load_name_idx
    });
    if let Some(method_idx) = existing_method_idx {
        return Ok((dex.raw_data().to_vec(), library_string_idx, method_idx as u32));
    }

    let new_string_values = strings[old_string_count..].to_vec();
    let new_type_values = type_additions.clone();
    let new_proto = existing_proto_idx.is_none();
    let new_method_idx = dex.methods.len() as u32;
    let output = rebuild_dex_with_references(
        dex,
        &new_string_values,
        &new_type_values,
        new_proto,
        shorty_idx,
        void_type_idx,
        string_type_idx,
        system_type_idx,
        proto_idx,
        load_name_idx,
    )?;
    Ok((output, library_string_idx, new_method_idx))
}

fn append_dex_string_data(output: &mut Vec<u8>, value: &str) {
    append_uleb(output, value.encode_utf16().count() as u32);
    output.extend_from_slice(value.as_bytes());
    output.push(0);
}

fn append_uleb(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MapEntry {
    kind: u16,
    count: u32,
    offset: u32,
}

/// Rebuild the ID/class-data prefix while retaining all unmodelled data.
///
/// A DEX file requires the ID tables to precede class definitions and the data
/// section.  It is therefore not valid to append a new string/type/proto/
/// method table at EOF.  This rebuild keeps existing indices stable, grows the
/// tables in place, relocates the old data section, and repairs every
/// offset-bearing structure that can be encountered in that data section.
fn rebuild_dex_with_references(
    dex: &DexFile,
    new_strings: &[String],
    new_types: &[u32],
    new_proto: bool,
    shorty_idx: u32,
    return_type_idx: u32,
    parameter_type_idx: u32,
    method_class_idx: u32,
    method_proto_idx: u32,
    method_name_idx: u32,
) -> Result<Vec<u8>, DexEncodeError> {
    let raw = dex.raw_data();
    let old_map_off = dex.header.map_off as usize;
    let old_data_off = dex.header.data_off as usize;
    if old_map_off < old_data_off || old_map_off > raw.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    let map_entries = read_map_entries(raw, old_map_off)?;

    let mut output = Vec::with_capacity(raw.len() + 256);
    let old_string_off = dex.header.string_ids_off as usize;
    if old_string_off > raw.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    output.extend_from_slice(&raw[..old_string_off]);

    let string_ids_off = output.len() as u32;
    append_raw_table(&mut output, raw, old_string_off, dex.header.string_ids_size, 4)?;
    let new_string_slot_off = output.len();
    output.resize(output.len() + new_strings.len() * 4, 0);

    let type_ids_off = output.len() as u32;
    append_raw_table(
        &mut output,
        raw,
        dex.header.type_ids_off as usize,
        dex.header.type_ids_size,
        4,
    )?;
    for value in new_types {
        output.extend_from_slice(&value.to_le_bytes());
    }

    let proto_ids_off = output.len() as u32;
    append_raw_table(
        &mut output,
        raw,
        dex.header.proto_ids_off as usize,
        dex.header.proto_ids_size,
        12,
    )?;
    if new_proto {
        output.extend_from_slice(&shorty_idx.to_le_bytes());
        output.extend_from_slice(&return_type_idx.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
    }

    let field_ids_off = if dex.header.fields_ids_size == 0 {
        0
    } else {
        let offset = output.len() as u32;
        append_raw_table(
            &mut output,
            raw,
            dex.header.fields_ids_off as usize,
            dex.header.fields_ids_size,
            8,
        )?;
        offset
    };

    if method_class_idx > u16::MAX as u32 || method_proto_idx > u16::MAX as u32 {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    let method_ids_off = output.len() as u32;
    append_raw_table(
        &mut output,
        raw,
        dex.header.method_ids_off as usize,
        dex.header.method_ids_size,
        8,
    )?;
    output.extend_from_slice(&(method_class_idx as u16).to_le_bytes());
    output.extend_from_slice(&(method_proto_idx as u16).to_le_bytes());
    output.extend_from_slice(&method_name_idx.to_le_bytes());

    align_vec(&mut output, 4);
    let class_defs_off = if dex.header.class_defs_size == 0 {
        0
    } else {
        let offset = output.len() as u32;
        append_raw_table(
            &mut output,
            raw,
            dex.header.class_defs_off as usize,
            dex.header.class_defs_size,
            32,
        )?;
        offset
    };
    align_vec(&mut output, 4);
    let data_off = output.len() as u32;
    let shift = data_off
        .checked_sub(dex.header.data_off)
        .ok_or(DexEncodeError::InvalidCodeItem)?;

    // Existing string/proto/class references into data now point at the
    // relocated copy.  New references are filled in after the new data items
    // have been assigned their final offsets.
    patch_string_ids(&mut output, string_ids_off as usize, dex.header.string_ids_size, shift)?;
    patch_proto_ids(&mut output, proto_ids_off as usize, dex.header.proto_ids_size, shift)?;
    patch_class_defs(&mut output, class_defs_off as usize, dex.header.class_defs_size, shift)?;

    let old_data_copy_start = output.len();
    output.extend_from_slice(&raw[old_data_off..old_map_off]);
    let old_data_copy = &mut output[old_data_copy_start..];
    patch_data_offsets(old_data_copy, &map_entries, dex.header.data_off, shift)?;

    let mut new_string_offsets = Vec::with_capacity(new_strings.len());
    for value in new_strings {
        let offset = output.len() as u32;
        new_string_offsets.push(offset);
        append_dex_string_data(&mut output, value);
    }
    let parameters_off = if new_proto {
        align_vec(&mut output, 4);
        let offset = output.len() as u32;
        output.extend_from_slice(&1u32.to_le_bytes());
        output.extend_from_slice(&(parameter_type_idx as u16).to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        Some(offset)
    } else {
        None
    };

    for (index, offset) in new_string_offsets.iter().enumerate() {
        let position = new_string_slot_off + index * 4;
        write_u32_at(&mut output, position, *offset)?;
    }
    if let Some(parameters_off) = parameters_off {
        write_u32_at(
            &mut output,
            proto_ids_off as usize + dex.header.proto_ids_size as usize * 12 + 8,
            parameters_off,
        )?;
    }

    align_vec(&mut output, 4);
    let new_map_off = output.len() as u32;
    let mut new_map = Vec::with_capacity(map_entries.len() + 8);
    for entry in map_entries {
        if entry.kind == 0x1000 {
            continue;
        }
        let (count, offset) = match entry.kind {
            0x0001 => (
                dex.header.string_ids_size + new_strings.len() as u32,
                string_ids_off,
            ),
            0x0002 => (
                dex.header.type_ids_size + new_types.len() as u32,
                type_ids_off,
            ),
            0x0003 => (
                dex.header.proto_ids_size + u32::from(new_proto),
                proto_ids_off,
            ),
            0x0004 => (dex.header.fields_ids_size, field_ids_off),
            0x0005 => (dex.header.method_ids_size + 1, method_ids_off),
            0x0006 => (dex.header.class_defs_size, class_defs_off),
            0x1001 => (
                entry.count + u32::from(new_proto),
                entry.offset.checked_add(shift).ok_or(DexEncodeError::InvalidCodeItem)?,
            ),
            0x2002 => (
                entry.count + new_strings.len() as u32,
                entry.offset.checked_add(shift).ok_or(DexEncodeError::InvalidCodeItem)?,
            ),
            _ => (
                entry.count,
                entry.offset.checked_add(shift).ok_or(DexEncodeError::InvalidCodeItem)?,
            ),
        };
        new_map.push(MapEntry { kind: entry.kind, count, offset });
    }
    if new_proto && !new_map.iter().any(|entry| entry.kind == 0x1001) {
        // The map can legally omit empty optional sections, but a new proto
        // parameter list must be described by a type_list item.
        new_map.push(MapEntry {
            kind: 0x1001,
            count: 1,
            offset: parameters_off.ok_or(DexEncodeError::InvalidCodeItem)?,
        });
    }
    if !new_strings.is_empty() && !new_map.iter().any(|entry| entry.kind == 0x2002) {
        new_map.push(MapEntry {
            kind: 0x2002,
            count: new_strings.len() as u32,
            offset: *new_string_offsets.first().ok_or(DexEncodeError::InvalidCodeItem)?,
        });
    }
    new_map.sort_by_key(|entry| (entry.offset, entry.kind));
    let map_count = (new_map.len() + 1) as u32;
    output.extend_from_slice(&map_count.to_le_bytes());
    for entry in &new_map {
        append_map_entry(&mut output, *entry);
    }
    append_map_entry(
        &mut output,
        MapEntry {
            kind: 0x1000,
            count: 1,
            offset: new_map_off,
        },
    );

    write_u32_at(&mut output, 52, new_map_off)?;
    write_u32_at(&mut output, 56, dex.header.string_ids_size + new_strings.len() as u32)?;
    write_u32_at(&mut output, 60, string_ids_off)?;
    write_u32_at(&mut output, 64, dex.header.type_ids_size + new_types.len() as u32)?;
    write_u32_at(&mut output, 68, type_ids_off)?;
    write_u32_at(&mut output, 72, dex.header.proto_ids_size + u32::from(new_proto))?;
    write_u32_at(&mut output, 76, proto_ids_off)?;
    write_u32_at(&mut output, 80, dex.header.fields_ids_size)?;
    write_u32_at(&mut output, 84, field_ids_off)?;
    write_u32_at(&mut output, 88, dex.header.method_ids_size + 1)?;
    write_u32_at(&mut output, 92, method_ids_off)?;
    write_u32_at(&mut output, 96, dex.header.class_defs_size)?;
    write_u32_at(&mut output, 100, class_defs_off)?;
    let file_size = output.len() as u32;
    write_u32_at(&mut output, 104, file_size.saturating_sub(data_off))?;
    write_u32_at(&mut output, 108, data_off)?;
    write_u32_at(&mut output, 32, file_size)?;
    repair_checksums(&mut output)?;
    Ok(output)
}

fn append_raw_table(
    output: &mut Vec<u8>,
    raw: &[u8],
    offset: usize,
    count: u32,
    item_size: usize,
) -> Result<(), DexEncodeError> {
    let size = (count as usize)
        .checked_mul(item_size)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let end = offset.checked_add(size).ok_or(DexEncodeError::InvalidCodeItem)?;
    if end > raw.len() || (count != 0 && offset == 0) {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    output.extend_from_slice(&raw[offset..end]);
    Ok(())
}

fn read_map_entries(raw: &[u8], map_off: usize) -> Result<Vec<MapEntry>, DexEncodeError> {
    let count = read_u32_at(raw, map_off)? as usize;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = map_off
            .checked_add(4 + index * 12)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        entries.push(MapEntry {
            kind: read_u16_at(raw, offset)?,
            count: read_u32_at(raw, offset + 4)?,
            offset: read_u32_at(raw, offset + 8)?,
        });
    }
    Ok(entries)
}

fn append_map_entry(output: &mut Vec<u8>, entry: MapEntry) {
    output.extend_from_slice(&entry.kind.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&entry.count.to_le_bytes());
    output.extend_from_slice(&entry.offset.to_le_bytes());
}

fn patch_string_ids(
    output: &mut [u8],
    offset: usize,
    count: u32,
    shift: u32,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 4;
        let value = read_u32_at(output, position)?;
        write_u32_at(output, position, shift_offset(value, shift)?)?;
    }
    Ok(())
}

fn patch_proto_ids(
    output: &mut [u8],
    offset: usize,
    count: u32,
    shift: u32,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 12 + 8;
        let value = read_u32_at(output, position)?;
        if value != 0 {
            write_u32_at(output, position, shift_offset(value, shift)?)?;
        }
    }
    Ok(())
}

fn patch_class_defs(
    output: &mut [u8],
    offset: usize,
    count: u32,
    shift: u32,
) -> Result<(), DexEncodeError> {
    if count == 0 {
        return Ok(());
    }
    for index in 0..count as usize {
        let base = offset + index * 32;
        for field in [12, 20, 24, 28] {
            let position = base + field;
            let value = read_u32_at(output, position)?;
            if value != 0 {
                write_u32_at(output, position, shift_offset(value, shift)?)?;
            }
        }
    }
    Ok(())
}

fn patch_data_offsets(
    data: &mut [u8],
    entries: &[MapEntry],
    old_data_off: u32,
    shift: u32,
) -> Result<(), DexEncodeError> {
    for entry in entries {
        if entry.offset < old_data_off || entry.kind == 0x1000 {
            continue;
        }
        let base = (entry.offset - old_data_off) as usize;
        match entry.kind {
            0x1002 => {
                for index in 0..entry.count as usize {
                    patch_u32_reference(data, base + 4 + index * 4, shift)?;
                }
            }
            0x1003 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    cursor += patch_annotation_set_item(data, cursor, shift)?;
                }
            }
            0x2000 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    cursor += patch_class_data_item(data, cursor, shift)?;
                }
            }
            0x2001 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    patch_u32_reference(data, cursor + 8, shift)?;
                    cursor += code_item_size(data, cursor)?;
                    if cursor % 4 != 0 {
                        cursor += 4 - cursor % 4;
                    }
                }
            }
            0x2006 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    cursor += patch_annotations_directory(data, cursor, shift)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Relocate offsets when new data items are inserted into the data section.
///
/// The insertion points are offsets in the original DEX.  Both comparisons
/// therefore use the original value rather than the partially relocated one.
#[derive(Debug, Clone, Copy)]
struct OffsetRelocation {
    first_insert: u32,
    first_delta: u32,
    second_insert: u32,
    second_delta: u32,
}

impl OffsetRelocation {
    fn apply(self, value: u32) -> Result<u32, DexEncodeError> {
        let mut relocated = value;
        if value >= self.first_insert {
            relocated = relocated
                .checked_add(self.first_delta)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
        }
        if value >= self.second_insert {
            relocated = relocated
                .checked_add(self.second_delta)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
        }
        Ok(relocated)
    }
}

fn patch_string_ids_relocated(
    output: &mut [u8],
    offset: usize,
    count: u32,
    relocation: OffsetRelocation,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 4;
        let value = read_u32_at(output, position)?;
        write_u32_at(output, position, relocation.apply(value)?)?;
    }
    Ok(())
}

fn patch_proto_ids_relocated(
    output: &mut [u8],
    offset: usize,
    count: u32,
    relocation: OffsetRelocation,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 12 + 8;
        let value = read_u32_at(output, position)?;
        if value != 0 {
            write_u32_at(output, position, relocation.apply(value)?)?;
        }
    }
    Ok(())
}

fn patch_class_defs_relocated(
    output: &mut [u8],
    offset: usize,
    count: u32,
    relocation: OffsetRelocation,
) -> Result<(), DexEncodeError> {
    if count == 0 {
        return Ok(());
    }
    for index in 0..count as usize {
        let base = offset + index * 32;
        for field in [12, 20, 24, 28] {
            let position = base + field;
            let value = read_u32_at(output, position)?;
            if value != 0 {
                write_u32_at(output, position, relocation.apply(value)?)?;
            }
        }
    }
    Ok(())
}

fn patch_u32_reference_relocated(
    data: &mut [u8],
    offset: usize,
    relocation: OffsetRelocation,
) -> Result<(), DexEncodeError> {
    let value = read_u32_at(data, offset)?;
    if value != 0 {
        write_u32_at(data, offset, relocation.apply(value)?)?;
    }
    Ok(())
}

fn patch_annotation_set_item_relocated(
    data: &mut [u8],
    offset: usize,
    relocation: OffsetRelocation,
) -> Result<usize, DexEncodeError> {
    let count = read_u32_at(data, offset)? as usize;
    for index in 0..count {
        patch_u32_reference_relocated(data, offset + 4 + index * 4, relocation)?;
    }
    4usize
        .checked_add(count * 4)
        .ok_or(DexEncodeError::InvalidCodeItem)
}

fn patch_annotations_directory_relocated(
    data: &mut [u8],
    offset: usize,
    relocation: OffsetRelocation,
) -> Result<usize, DexEncodeError> {
    patch_u32_reference_relocated(data, offset, relocation)?;
    let field_count = read_u32_at(data, offset + 4)? as usize;
    let method_count = read_u32_at(data, offset + 8)? as usize;
    let parameter_count = read_u32_at(data, offset + 12)? as usize;
    let mut cursor = offset + 16;
    for _ in 0..field_count + method_count + parameter_count {
        patch_u32_reference_relocated(data, cursor + 4, relocation)?;
        cursor += 8;
    }
    Ok(cursor - offset)
}

fn patch_class_data_item_relocated(
    data: &mut [u8],
    offset: usize,
    relocation: OffsetRelocation,
) -> Result<usize, DexEncodeError> {
    let mut cursor = offset;
    let static_count = read_uleb_at(data, &mut cursor)?;
    let instance_count = read_uleb_at(data, &mut cursor)?;
    let direct_count = read_uleb_at(data, &mut cursor)?;
    let virtual_count = read_uleb_at(data, &mut cursor)?;
    for _ in 0..static_count + instance_count {
        read_uleb_at(data, &mut cursor)?;
        read_uleb_at(data, &mut cursor)?;
    }
    for _ in 0..direct_count + virtual_count {
        read_uleb_at(data, &mut cursor)?;
        read_uleb_at(data, &mut cursor)?;
        let code_position = cursor;
        let (code_off, width) = read_uleb_at_with_width(data, &mut cursor)?;
        if code_off != 0 {
            let relocated = relocation.apply(code_off)?;
            if uleb_width(relocated) != width {
                return Err(DexEncodeError::InvalidCodeItem);
            }
            write_fixed_uleb(data, code_position, relocated, width)?;
        }
    }
    Ok(cursor - offset)
}

/// Patch references in the original data items after section insertions.
///
/// The newly inserted code/class-data items are deliberately excluded from
/// this walk.  Their references are either copied from the original item and
/// patched explicitly, or point at the newly assigned code offset already.
fn patch_data_offsets_relocated(
    data: &mut [u8],
    entries: &[MapEntry],
    old_data_off: u32,
    relocation: OffsetRelocation,
) -> Result<(), DexEncodeError> {
    for entry in entries {
        if entry.offset < old_data_off || entry.kind == 0x1000 {
            continue;
        }
        let relocated_offset = relocation.apply(entry.offset)?;
        let base = relocated_offset
            .checked_sub(old_data_off)
            .ok_or(DexEncodeError::InvalidCodeItem)? as usize;
        match entry.kind {
            0x1002 => {
                for index in 0..entry.count as usize {
                    patch_u32_reference_relocated(data, base + 4 + index * 4, relocation)?;
                }
            }
            0x1003 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    cursor += patch_annotation_set_item_relocated(data, cursor, relocation)?;
                }
            }
            0x2000 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    cursor += patch_class_data_item_relocated(data, cursor, relocation)?;
                }
            }
            0x2001 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    patch_u32_reference_relocated(data, cursor + 8, relocation)?;
                    cursor += code_item_size(data, cursor)?;
                    if cursor % 4 != 0 {
                        cursor += 4 - cursor % 4;
                    }
                }
            }
            0x2006 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    cursor +=
                        patch_annotations_directory_relocated(data, cursor, relocation)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn shift_offset(value: u32, shift: u32) -> Result<u32, DexEncodeError> {
    value.checked_add(shift).ok_or(DexEncodeError::InvalidCodeItem)
}

fn patch_u32_reference(data: &mut [u8], offset: usize, shift: u32) -> Result<(), DexEncodeError> {
    let value = read_u32_at(data, offset)?;
    if value != 0 {
        write_u32_at(data, offset, shift_offset(value, shift)?)?;
    }
    Ok(())
}

fn patch_annotation_set_item(
    data: &mut [u8],
    offset: usize,
    shift: u32,
) -> Result<usize, DexEncodeError> {
    let count = read_u32_at(data, offset)? as usize;
    for index in 0..count {
        patch_u32_reference(data, offset + 4 + index * 4, shift)?;
    }
    4usize
        .checked_add(count * 4)
        .ok_or(DexEncodeError::InvalidCodeItem)
}

fn patch_annotations_directory(
    data: &mut [u8],
    offset: usize,
    shift: u32,
) -> Result<usize, DexEncodeError> {
    patch_u32_reference(data, offset, shift)?;
    let field_count = read_u32_at(data, offset + 4)? as usize;
    let method_count = read_u32_at(data, offset + 8)? as usize;
    let parameter_count = read_u32_at(data, offset + 12)? as usize;
    let mut cursor = offset + 16;
    for _ in 0..field_count + method_count + parameter_count {
        patch_u32_reference(data, cursor + 4, shift)?;
        cursor += 8;
    }
    Ok(cursor - offset)
}

fn patch_class_data_item(
    data: &mut [u8],
    offset: usize,
    shift: u32,
) -> Result<usize, DexEncodeError> {
    let mut cursor = offset;
    let static_count = read_uleb_at(data, &mut cursor)?;
    let instance_count = read_uleb_at(data, &mut cursor)?;
    let direct_count = read_uleb_at(data, &mut cursor)?;
    let virtual_count = read_uleb_at(data, &mut cursor)?;
    for _ in 0..static_count + instance_count {
        read_uleb_at(data, &mut cursor)?;
        read_uleb_at(data, &mut cursor)?;
    }
    for _ in 0..direct_count + virtual_count {
        read_uleb_at(data, &mut cursor)?;
        read_uleb_at(data, &mut cursor)?;
        let code_position = cursor;
        let (code_off, width) = read_uleb_at_with_width(data, &mut cursor)?;
        if code_off != 0 {
            let shifted = shift_offset(code_off, shift)?;
            if uleb_width(shifted) != width {
                return Err(DexEncodeError::InvalidCodeItem);
            }
            write_fixed_uleb(data, code_position, shifted, width)?;
        }
    }
    Ok(cursor - offset)
}

fn code_item_size(data: &[u8], offset: usize) -> Result<usize, DexEncodeError> {
    let tries_size = read_u16_at(data, offset + 6)? as usize;
    let insns_size = read_u32_at(data, offset + 12)? as usize;
    let mut cursor = offset
        .checked_add(16)
        .and_then(|value| value.checked_add(insns_size * 2))
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    if tries_size == 0 {
        return Ok(cursor - offset);
    }
    if cursor % 4 != 0 {
        cursor += 4 - cursor % 4;
    }
    cursor = cursor
        .checked_add(tries_size * 8)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let handler_count = read_uleb_at(data, &mut cursor)?;
    for _ in 0..handler_count {
        let (size, _) = read_sleb_at(data, &mut cursor)?;
        let typed_count = size.unsigned_abs() as u32;
        for _ in 0..typed_count {
            read_uleb_at(data, &mut cursor)?;
            read_uleb_at(data, &mut cursor)?;
        }
        if size <= 0 {
            read_uleb_at(data, &mut cursor)?;
        }
    }
    Ok(cursor - offset)
}

fn read_uleb_at(data: &[u8], cursor: &mut usize) -> Result<u32, DexEncodeError> {
    Ok(read_uleb_at_with_width(data, cursor)?.0)
}

fn read_uleb_at_with_width(
    data: &[u8],
    cursor: &mut usize,
) -> Result<(u32, usize), DexEncodeError> {
    let start = *cursor;
    let mut value = 0u32;
    let mut shift = 0;
    loop {
        if *cursor >= data.len() || shift > 28 {
            return Err(DexEncodeError::InvalidCodeItem);
        }
        let byte = data[*cursor];
        *cursor += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, *cursor - start));
        }
        shift += 7;
    }
}

fn read_sleb_at(data: &[u8], cursor: &mut usize) -> Result<(i32, usize), DexEncodeError> {
    let start = *cursor;
    let mut value = 0i32;
    let mut shift = 0;
    let mut byte;
    loop {
        if *cursor >= data.len() || shift > 28 {
            return Err(DexEncodeError::InvalidCodeItem);
        }
        byte = data[*cursor];
        *cursor += 1;
        value |= ((byte & 0x7f) as i32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if shift < 32 && byte & 0x40 != 0 {
        value |= !0i32 << shift;
    }
    Ok((value, *cursor - start))
}

fn uleb_width(mut value: u32) -> usize {
    let mut width = 1;
    while value >= 0x80 {
        value >>= 7;
        width += 1;
    }
    width
}

fn write_fixed_uleb(
    data: &mut [u8],
    offset: usize,
    mut value: u32,
    width: usize,
) -> Result<(), DexEncodeError> {
    if offset + width > data.len() || uleb_width(value) != width {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    for index in 0..width {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if index + 1 != width {
            byte |= 0x80;
        }
        data[offset + index] = byte;
    }
    Ok(())
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, DexEncodeError> {
    if offset + 2 > bytes.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, DexEncodeError> {
    if offset + 4 > bytes.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), DexEncodeError> {
    if offset + 4 > bytes.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Prepend code units to a method by inserting a new code_item at the end of
/// the existing code_item section and a copied class_data_item at the end of
/// the existing class_data_item section.
///
/// DEX map entries describe contiguous sections.  Appending new items after
/// the original map_list and merely increasing a section count makes ART walk
/// the following section as if it were another item of the previous type.  We
/// therefore insert both items before their next mapped section and relocate
/// all offset-bearing references in the shifted suffix.
pub fn prepend_method_code(
    dex: &DexFile,
    method_idx: u32,
    prefix: &[u16],
) -> Result<Vec<u8>, DexEncodeError> {
    if prefix.is_empty() {
        return encode_dex(dex);
    }
    let (class_idx, code) = dex
        .classes
        .iter()
        .flat_map(|class| class.codes.iter().map(move |method| (class.class_idx, method)))
        .find(|(_, method)| method.method_idx == method_idx)
        .ok_or(DexEncodeError::MethodNotFound(method_idx))?;
    let code = code.code.as_ref().ok_or(DexEncodeError::MethodHasNoCode(method_idx))?;
    if code.tries_size != 0 {
        return Err(DexEncodeError::MethodHasTryHandlers);
    }
    if !code.array_data.is_empty() || !code.switch_data.is_empty() {
        return Err(DexEncodeError::MethodHasPayload);
    }
    if code.code_off == 0 {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    let original_start = code.code_off as usize + 16;
    let original_end = original_start
        .checked_add(code.insns_size as usize * 2)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    if original_end > dex.raw_data().len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }

    let raw = dex.raw_data();
    let old_map_off = dex.header.map_off as usize;
    let map_entries = read_map_entries(raw, old_map_off)?;
    let old_map_end = old_map_off
        .checked_add(4 + map_entries.len() * 12)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    if old_map_end != raw.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }

    let code_insert = section_content_end(raw, &map_entries, 0x2001)? as usize;
    let class_data_insert = section_content_end(raw, &map_entries, 0x2000)? as usize;
    let old_data_off = dex.header.data_off as usize;
    if old_data_off > code_insert
        || code_insert > class_data_insert
        || class_data_insert > old_map_off
    {
        return Err(DexEncodeError::InvalidCodeItem);
    }

    let code_padding = (4 - code_insert % 4) % 4;
    let mut new_code = Vec::with_capacity(16 + (prefix.len() + code.insns_size as usize) * 2);
    new_code.extend_from_slice(&code.register_size.to_le_bytes());
    new_code.extend_from_slice(&code.ins_size.to_le_bytes());
    new_code.extend_from_slice(&code.outs_size.to_le_bytes());
    new_code.extend_from_slice(&0u16.to_le_bytes());
    new_code.extend_from_slice(&code.debug_info_off.to_le_bytes());
    new_code.extend_from_slice(&((code.insns_size as usize + prefix.len()) as u32).to_le_bytes());
    for unit in prefix {
        new_code.extend_from_slice(&unit.to_le_bytes());
    }
    new_code.extend_from_slice(&raw[original_start..original_end]);

    let code_insert_delta = code_padding
        .checked_add(new_code.len())
        .and_then(|size| size.checked_add((4 - size % 4) % 4))
        .ok_or(DexEncodeError::InvalidCodeItem)? as u32;

    let class_def_off = class_def_offset(dex, class_idx)?;
    let original_class_data_off = class_data_offset(dex, class_def_off)?;
    let class_data = rewrite_class_data(
        &raw[original_class_data_off..],
        method_idx,
        code_insert as u32 + code_padding as u32,
    )?;
    let class_data_insert_delta = (class_data.len() + (4 - class_data.len() % 4) % 4) as u32;

    let relocation = OffsetRelocation {
        first_insert: code_insert as u32,
        first_delta: code_insert_delta,
        second_insert: class_data_insert as u32,
        second_delta: class_data_insert_delta,
    };

    let mut output = Vec::with_capacity(
        raw.len()
            .checked_add(code_insert_delta as usize)
            .and_then(|size| size.checked_add(class_data_insert_delta as usize))
            .ok_or(DexEncodeError::InvalidCodeItem)?,
    );
    output.extend_from_slice(&raw[..code_insert]);
    output.resize(output.len() + code_padding, 0);
    let new_code_off = output.len() as u32;
    output.extend_from_slice(&new_code);
    output.resize(output.len() + (code_insert_delta as usize - code_padding - new_code.len()), 0);
    output.extend_from_slice(&raw[code_insert..class_data_insert]);
    let new_class_data_off = output.len() as u32;
    output.extend_from_slice(&class_data);
    output.resize(
        output.len() + (class_data_insert_delta as usize - class_data.len()),
        0,
    );
    output.extend_from_slice(&raw[class_data_insert..old_map_off]);

    align_vec(&mut output, 4);
    let new_map_off = output.len() as u32;

    patch_string_ids_relocated(
        &mut output,
        dex.header.string_ids_off as usize,
        dex.header.string_ids_size,
        relocation,
    )?;
    patch_proto_ids_relocated(
        &mut output,
        dex.header.proto_ids_off as usize,
        dex.header.proto_ids_size,
        relocation,
    )?;
    patch_class_defs_relocated(
        &mut output,
        dex.header.class_defs_off as usize,
        dex.header.class_defs_size,
        relocation,
    )?;
    patch_data_offsets_relocated(
        &mut output[old_data_off..new_map_off as usize],
        &map_entries,
        dex.header.data_off,
        relocation,
    )?;

    // The new code item copied the old debug_info_off.  It now points into
    // the shifted suffix and must be relocated as well.  The new class-data
    // item already contains the new code offset and is excluded from the
    // original-section walk above.
    patch_u32_reference_relocated(
        &mut output[old_data_off..new_map_off as usize],
        (new_code_off - dex.header.data_off) as usize + 8,
        relocation,
    )?;

    // The target class now uses the newly copied class_data_item rather than
    // the relocated original one.
    if class_def_off + 32 > output.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    output[class_def_off + 24..class_def_off + 28]
        .copy_from_slice(&new_class_data_off.to_le_bytes());

    let mut new_map = Vec::with_capacity(map_entries.len());
    for mut entry in map_entries {
        if entry.kind == 0x1000 {
            continue;
        }
        entry.offset = relocation.apply(entry.offset)?;
        if entry.kind == 0x2001 || entry.kind == 0x2000 {
            entry.count = entry
                .count
                .checked_add(1)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
        }
        new_map.push(entry);
    }
    new_map.sort_by_key(|entry| (entry.offset, entry.kind));
    let map_count = (new_map.len() + 1) as u32;
    output.extend_from_slice(&map_count.to_le_bytes());
    for entry in new_map {
        append_map_entry(&mut output, entry);
    }
    append_map_entry(
        &mut output,
        MapEntry {
            kind: 0x1000,
            count: 1,
            offset: new_map_off,
        },
    );

    let file_size = output.len() as u32;
    output[32..36].copy_from_slice(&file_size.to_le_bytes());
    output[52..56].copy_from_slice(&new_map_off.to_le_bytes());
    output[104..108].copy_from_slice(
        &file_size
            .checked_sub(dex.header.data_off)
            .ok_or(DexEncodeError::InvalidCodeItem)?
            .to_le_bytes(),
    );
    repair_checksums(&mut output)?;
    Ok(output)
}

fn section_content_end(
    raw: &[u8],
    entries: &[MapEntry],
    kind: u16,
) -> Result<u32, DexEncodeError> {
    let entry = entries
        .iter()
        .find(|entry| entry.kind == kind)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let mut cursor = entry.offset as usize;
    match kind {
        0x2001 => {
            for index in 0..entry.count as usize {
                let item_end = cursor
                    .checked_add(code_item_size(raw, cursor)?)
                    .ok_or(DexEncodeError::InvalidCodeItem)?;
                cursor = item_end;
                if index + 1 != entry.count as usize && cursor % 4 != 0 {
                    cursor += 4 - cursor % 4;
                }
            }
        }
        0x2000 => {
            for _ in 0..entry.count {
                cursor = cursor
                    .checked_add(class_data_item_size(raw, cursor)?)
                    .ok_or(DexEncodeError::InvalidCodeItem)?;
            }
        }
        _ => return Err(DexEncodeError::InvalidCodeItem),
    }
    if cursor > raw.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    Ok(cursor as u32)
}

fn class_data_item_size(data: &[u8], offset: usize) -> Result<usize, DexEncodeError> {
    let mut cursor = offset;
    let static_count = read_uleb_at(data, &mut cursor)?;
    let instance_count = read_uleb_at(data, &mut cursor)?;
    let direct_count = read_uleb_at(data, &mut cursor)?;
    let virtual_count = read_uleb_at(data, &mut cursor)?;
    for _ in 0..static_count + instance_count {
        read_uleb_at(data, &mut cursor)?;
        read_uleb_at(data, &mut cursor)?;
    }
    for _ in 0..direct_count + virtual_count {
        read_uleb_at(data, &mut cursor)?;
        read_uleb_at(data, &mut cursor)?;
        read_uleb_at(data, &mut cursor)?;
    }
    Ok(cursor - offset)
}

fn class_def_offset(dex: &DexFile, class_idx: u32) -> Result<usize, DexEncodeError> {
    let class_defs_off = dex.header.class_defs_off as usize;
    for index in 0..dex.header.class_defs_size as usize {
        let offset = class_defs_off
            .checked_add(index * 32)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        if offset + 4 > dex.raw_data().len() { break; }
        let current = u32::from_le_bytes([
            dex.raw_data()[offset], dex.raw_data()[offset + 1],
            dex.raw_data()[offset + 2], dex.raw_data()[offset + 3],
        ]);
        if current == class_idx { return Ok(offset); }
    }
    Err(DexEncodeError::MethodClassDataNotFound)
}

fn class_data_offset(dex: &DexFile, class_def_offset: usize) -> Result<usize, DexEncodeError> {
    let offset = class_def_offset
        .checked_add(24)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    if offset + 4 > dex.raw_data().len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    let class_data_off = u32::from_le_bytes([
        dex.raw_data()[offset], dex.raw_data()[offset + 1],
        dex.raw_data()[offset + 2], dex.raw_data()[offset + 3],
    ]) as usize;
    if class_data_off == 0 || class_data_off >= dex.raw_data().len() {
        return Err(DexEncodeError::MethodClassDataNotFound);
    }
    Ok(class_data_off)
}

fn rewrite_class_data(
    input: &[u8],
    target_method_idx: u32,
    new_code_off: u32,
) -> Result<Vec<u8>, DexEncodeError> {
    let mut reader = UlebReader { bytes: input, offset: 0 };
    let static_fields = reader.read()?;
    let instance_fields = reader.read()?;
    let direct_methods = reader.read()?;
    let virtual_methods = reader.read()?;
    let mut output = Vec::new();
    write_uleb(&mut output, static_fields);
    write_uleb(&mut output, instance_fields);
    write_uleb(&mut output, direct_methods);
    write_uleb(&mut output, virtual_methods);
    for _ in 0..static_fields {
        write_uleb(&mut output, reader.read()?);
        write_uleb(&mut output, reader.read()?);
    }
    for _ in 0..instance_fields {
        write_uleb(&mut output, reader.read()?);
        write_uleb(&mut output, reader.read()?);
    }
    let mut found = false;
    for count in [direct_methods, virtual_methods] {
        let mut previous_method = 0u32;
        for _ in 0..count {
            let method_diff = reader.read()?;
            let method = previous_method
                .checked_add(method_diff)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
            let flags = reader.read()?;
            let code_off = reader.read()?;
            write_uleb(&mut output, method_diff);
            write_uleb(&mut output, flags);
            if method == target_method_idx {
                write_uleb(&mut output, new_code_off);
                found = true;
            } else {
                write_uleb(&mut output, code_off);
            }
            previous_method = method;
        }
    }
    if !found {
        return Err(DexEncodeError::MethodClassDataNotFound);
    }
    Ok(output)
}

struct UlebReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> UlebReader<'a> {
    fn read(&mut self) -> Result<u32, DexEncodeError> {
        let mut value = 0u32;
        let mut shift = 0;
        loop {
            if self.offset >= self.bytes.len() || shift > 28 {
                return Err(DexEncodeError::InvalidCodeItem);
            }
            let byte = self.bytes[self.offset];
            self.offset += 1;
            value |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 == 0 { return Ok(value); }
            shift += 7;
        }
    }
}

fn write_uleb(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 { byte |= 0x80; }
        output.push(byte);
        if value == 0 { break; }
    }
}

fn align_vec(output: &mut Vec<u8>, alignment: usize) {
    while output.len() % alignment != 0 { output.push(0); }
}

fn repair_checksums(data: &mut [u8]) -> Result<(), DexEncodeError> {
    if data.len() < 32 || &data[0..3] != b"dex" {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    let signature = sha1_digest(&data[32..]);
    data[12..32].copy_from_slice(&signature);
    let checksum = adler32(&data[12..]);
    data[8..12].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + *byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

// Small dependency-free SHA-1 implementation for the DEX header signature.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 80];
        for index in 0..16 {
            let offset = index * 4;
            words[index] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) =
            (state[0], state[1], state[2], state[3], state[4]);
        for index in 0..80 {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(words[index]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut output = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn inject_load_library_adds_references_and_reparses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex = parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false)
            .expect("test DEX parses");
        let (method_idx, register) = dex
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .filter_map(|method| {
                let code = method.code.as_ref()?;
                let available = code.register_size.saturating_sub(code.ins_size);
                (code.tries_size == 0 && available > 0).then_some((method.method_idx, 0u8))
            })
            .next()
            .expect("test DEX has an injectable method");
        let edited = inject_load_library(&dex, method_idx, "frida-gadget", register)
            .expect("inject loadLibrary");
        let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("edited DEX reparses");
        assert_eq!(reparsed.find_string_index("frida-gadget").is_some(), true);
        assert!(reparsed.find_method_index(
            "Ljava/lang/System;",
            "loadLibrary",
            "(Ljava/lang/String;)V"
        ).is_some());
        let code = reparsed
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .find(|method| method.method_idx == method_idx)
            .and_then(|method| method.code.as_ref())
            .expect("injected method code");
        assert_eq!(code.insns_size, 5 + dex
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .find(|method| method.method_idx == method_idx)
            .and_then(|method| method.code.as_ref())
            .map(|code| code.insns_size)
            .unwrap());
    }

    #[test]
    fn replace_instruction_uses_code_unit_width() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex = parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false)
            .expect("test DEX parses");
        let (method_idx, instruction_index) = dex
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .filter_map(|method| {
                let code = method.code.as_ref()?;
                code.insns
                    .iter()
                    .position(|(_, _, instruction)| {
                        instruction.to_code_units().map(|units| units.len()) == Ok(1)
                    })
                    .map(|index| (method.method_idx, index))
            })
            .next()
            .expect("test DEX has a one-unit instruction");
        let edited = replace_method_instruction(&dex, method_idx, instruction_index, &Instruction::Nop)
            .expect("replace one-unit instruction");
        parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("edited DEX reparses");
    }

    #[test]
    fn prepend_method_rebuilds_aligned_map_list() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex = parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false)
            .expect("test DEX parses");
        let original_code_count = read_map_entries(
            &bytes,
            read_u32_at(&bytes, 52).expect("original map offset") as usize,
        )
        .expect("original map parses")
        .into_iter()
        .find(|entry| entry.kind == 0x2001)
        .map(|entry| entry.count)
        .expect("original DEX has code items");
        let method_idx = dex
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .filter_map(|method| {
                let code = method.code.as_ref()?;
                (code.tries_size == 0
                    && code.array_data.is_empty()
                    && code.switch_data.is_empty())
                    .then_some(method.method_idx)
            })
            .next()
            .expect("test DEX has a method without payloads");

        let edited = prepend_method_code(&dex, method_idx, &[0x0000])
            .expect("prepend one-unit instruction");
        parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("edited DEX reparses");

        let map_off = read_u32_at(&edited, 52).expect("map offset") as usize;
        let map_count = read_u32_at(&edited, map_off).expect("map count") as usize;
        let mut map_list_count = None;
        let mut code_item_count = None;
        for index in 0..map_count {
            let entry = map_off + 4 + index * 12;
            let kind = read_u16_at(&edited, entry).expect("map kind");
            let count = read_u32_at(&edited, entry + 4).expect("map item count");
            match kind {
                0x1000 => map_list_count = Some(count),
                0x2001 => code_item_count = Some(count),
                _ => {}
            }
        }
        assert_eq!(map_list_count, Some(1));
        assert_eq!(code_item_count, Some(original_code_count + 1));
    }
}
