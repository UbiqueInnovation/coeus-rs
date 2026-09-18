//! DEX code-unit encoding and loss-minimal patching.
//!
//! The parser keeps the original DEX as an opaque payload.  This is important
//! for round-tripping annotations, debug information, map items, and newer
//! DEX sections that the analysis model does not expose yet.  Edits therefore
//! patch a code item in place and repair the DEX checksum/signature.

use super::{parse_dex_buf, ArrayView};
use coeus_models::models::{DexFile, Instruction, TestFunction};
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
};

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
    InvalidStringIndex(u32),
    StringIndexWidthChanged { old: u32, new: u32 },
    ConflictingEdits,
    InvalidEditAnchor(u32),
    BranchTargetNotFound(u32),
    BranchOutOfRange,
    UnsupportedEditInstruction,
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
            Self::InvalidStringIndex(index) => write!(formatter, "invalid DEX string index: {index}"),
            Self::StringIndexWidthChanged { old, new } => write!(
                formatter,
                "string index relocation changed an encoded index width ({old} -> {new})"
            ),
            Self::ConflictingEdits => write!(formatter, "conflicting edits at the same instruction"),
            Self::InvalidEditAnchor(offset) => {
                write!(formatter, "edit anchor is not an executable instruction: {offset}")
            }
            Self::BranchTargetNotFound(offset) => {
                write!(formatter, "branch target is not an instruction boundary: {offset}")
            }
            Self::BranchOutOfRange => write!(formatter, "branch target is out of range"),
            Self::UnsupportedEditInstruction => {
                write!(formatter, "instruction cannot be used in a symbolic edit")
            }
        }
    }
}

impl std::error::Error for DexEncodeError {}

/// Which logical position an edit target refers to.
///
/// `Instruction` is the instruction itself, while `Before` and `After` are
/// explicit insertion points. Keeping these distinct means that a branch to
/// an existing instruction is not accidentally redirected in front of code
/// inserted with `insert_before`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetPosition {
    Before,
    Instruction,
    After,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeTarget {
    pub offset: u32,
    pub position: TargetPosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditPosition {
    Before,
    After,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchForm {
    Auto,
    Packed,
    Sparse,
}

/// An instruction used by the symbolic method rewriter.
///
/// The ordinary `Instruction` enum deliberately remains a low-level model
/// whose branch operands are relative offsets. This separate type lets the
/// editor express branches using logical targets until final layout is known.
#[derive(Debug, Clone)]
pub enum EditableInstruction {
    Concrete(Instruction),
    Branch {
        instruction: Instruction,
        target: CodeTarget,
    },
    Switch {
        register: u8,
        cases: BTreeMap<i32, CodeTarget>,
        default: Option<CodeTarget>,
        form: SwitchForm,
    },
    FillArray {
        register: u8,
        width: u16,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct MethodEdit {
    pub anchor: u32,
    pub position: EditPosition,
    pub instructions: Vec<EditableInstruction>,
}

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
    let edited = parse_dex_buf(&dex.file_name, &ArrayView::new(&referenced_dex), false)
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
        return Err(DexEncodeError::RegisterUnavailable {
            register,
            available,
        });
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
    let mut strings = read_string_pool_units(dex)?
        .into_iter()
        .map(|units| String::from_utf16(&units).map_err(|_| DexEncodeError::InvalidCodeItem))
        .collect::<Result<Vec<_>, _>>()?;
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
    ensure_string(&mut strings, library_name);
    ensure_string(&mut strings, "loadLibrary");
    ensure_string(&mut strings, "Ljava/lang/System;");
    ensure_string(&mut strings, "Ljava/lang/String;");
    ensure_string(&mut strings, "V");
    ensure_string(&mut strings, "VL");

    let string_plan = build_string_pool_plan(dex, &strings[old_string_count..], &[])?;
    let library_string_idx = string_plan
        .index_of(library_name)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let load_name_idx = string_plan
        .index_of("loadLibrary")
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let system_descriptor_idx = string_plan
        .index_of("Ljava/lang/System;")
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let string_descriptor_idx = string_plan
        .index_of("Ljava/lang/String;")
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let void_descriptor_idx = string_plan
        .index_of("V")
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let shorty_idx = string_plan
        .index_of("VL")
        .ok_or(DexEncodeError::InvalidCodeItem)?;

    let mut type_additions = Vec::<u32>::new();
    let ensure_type =
        |descriptor: &str, descriptor_idx: u32, dex: &DexFile, additions: &mut Vec<u32>| {
            if let Some(index) = dex
                .types
                .iter()
                .position(|index| dex.get_string(*index as usize) == Some(descriptor))
            {
                index as u32
            } else if let Some(index) = additions.iter().position(|index| *index == descriptor_idx)
            {
                dex.types.len() as u32 + index as u32
            } else {
                let index = dex.types.len() as u32 + additions.len() as u32;
                additions.push(descriptor_idx);
                index
            }
        };
    let system_type_idx = ensure_type(
        "Ljava/lang/System;",
        system_descriptor_idx,
        dex,
        &mut type_additions,
    );
    let string_type_idx = ensure_type(
        "Ljava/lang/String;",
        string_descriptor_idx,
        dex,
        &mut type_additions,
    );
    let void_type_idx = ensure_type("V", void_descriptor_idx, dex, &mut type_additions);

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
            && method.method_name == "loadLibrary"
    });

    let new_type_values = type_additions.clone();
    let new_proto = existing_proto_idx.is_none() && existing_method_idx.is_none();
    let new_method_idx = existing_method_idx.unwrap_or(dex.methods.len()) as u32;
    let output = rebuild_dex_with_references(
        dex,
        &string_plan,
        &new_type_values,
        new_proto,
        shorty_idx,
        void_type_idx,
        string_type_idx,
        existing_method_idx
            .map(|_| None)
            .unwrap_or_else(|| Some((system_type_idx, proto_idx, load_name_idx))),
    )?;
    Ok((output, library_string_idx, new_method_idx))
}

/// Ensure that the supplied values have entries in the DEX string pool.
///
/// Missing values are merged into the canonical UTF-16-sorted string pool.
/// Every old string index is remapped in ID tables, code, and encoded data.
/// Callers can therefore safely add a value anywhere in the sorted pool.
pub fn ensure_dex_strings(dex: &DexFile, values: &[String]) -> Result<Vec<u8>, DexEncodeError> {
    if dex.raw_data().is_empty() {
        return Err(DexEncodeError::MissingRawData);
    }
    let mut new_strings = Vec::new();
    let old_pool = read_string_pool_units(dex)?;
    for value in values {
        let units = value.encode_utf16().collect::<Vec<_>>();
        if !old_pool.iter().any(|current| current == &units)
            && !new_strings
                .iter()
                .any(|current: &String| current.encode_utf16().eq(units.iter().copied()))
        {
            new_strings.push(value.clone());
        }
    }
    if new_strings.is_empty() {
        return Ok(dex.raw_data().to_vec());
    }
    let plan = build_string_pool_plan(dex, &new_strings, &[])?;
    rebuild_dex_with_references(dex, &plan, &[], false, 0, 0, 0, None)
}

/// Replace one string-id's value and remap the complete string pool.  Since
/// DEX string IDs are sorted by UTF-16 value, a replacement may move the
/// string to a different index; all references are repaired accordingly.
pub fn replace_dex_string(
    dex: &DexFile,
    string_index: u32,
    replacement: &str,
) -> Result<Vec<u8>, DexEncodeError> {
    if string_index >= dex.header.string_ids_size {
        return Err(DexEncodeError::InvalidStringIndex(string_index));
    }
    let pool = read_string_pool_units(dex)?;
    let replacement_units = replacement.encode_utf16().collect::<Vec<_>>();
    if pool[string_index as usize] == replacement_units {
        return Ok(dex.raw_data().to_vec());
    }
    let plan = build_string_pool_plan(dex, &[], &[(string_index, replacement.to_string())])?;
    rebuild_dex_with_references(dex, &plan, &[], false, 0, 0, 0, None)
}

fn read_string_pool_units(dex: &DexFile) -> Result<Vec<Vec<u16>>, DexEncodeError> {
    let raw = dex.raw_data();
    let mut pool = Vec::with_capacity(dex.header.string_ids_size as usize);
    for index in 0..dex.header.string_ids_size as usize {
        let string_id = (dex.header.string_ids_off as usize)
            .checked_add(
                index
                    .checked_mul(4)
                    .ok_or(DexEncodeError::InvalidCodeItem)?,
            )
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        let string_data = read_u32_at(raw, string_id)? as usize;
        let mut cursor = string_data;
        let utf16_size = read_uleb_at(raw, &mut cursor)? as usize;
        let start = cursor;
        while cursor < raw.len() && raw[cursor] != 0 {
            cursor += 1;
        }
        if cursor >= raw.len() {
            return Err(DexEncodeError::InvalidCodeItem);
        }
        let units = decode_mutf8(&raw[start..cursor])?;
        if units.len() != utf16_size {
            return Err(DexEncodeError::InvalidCodeItem);
        }
        pool.push(units);
    }
    Ok(pool)
}

fn decode_mutf8(bytes: &[u8]) -> Result<Vec<u16>, DexEncodeError> {
    let mut units = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let first = bytes[cursor];
        let (unit, width) = match first {
            0x01..=0x7f => (first as u16, 1),
            0xc0..=0xdf => {
                if cursor + 1 >= bytes.len() || bytes[cursor + 1] & 0xc0 != 0x80 {
                    return Err(DexEncodeError::InvalidCodeItem);
                }
                (
                    (((first & 0x1f) as u16) << 6) | (bytes[cursor + 1] & 0x3f) as u16,
                    2,
                )
            }
            0xe0..=0xef => {
                if cursor + 2 >= bytes.len()
                    || bytes[cursor + 1] & 0xc0 != 0x80
                    || bytes[cursor + 2] & 0xc0 != 0x80
                {
                    return Err(DexEncodeError::InvalidCodeItem);
                }
                (
                    (((first & 0x0f) as u16) << 12)
                        | (((bytes[cursor + 1] & 0x3f) as u16) << 6)
                        | (bytes[cursor + 2] & 0x3f) as u16,
                    3,
                )
            }
            _ => return Err(DexEncodeError::InvalidCodeItem),
        };
        units.push(unit);
        cursor += width;
    }
    Ok(units)
}

#[derive(Debug, Clone)]
struct StringPoolPlan {
    /// The final string-id order, represented as Rust strings so that newly
    /// created string_data_items can be encoded without going through the
    /// parser's lossy StringEntry representation.
    values: Vec<String>,
    /// Mapping from every old string index to its new index.
    old_to_new: Vec<u32>,
    /// For each final string id, the old string-data item that can be reused.
    /// A `None` entry is a replacement or a genuinely new string.
    old_sources: Vec<Option<u32>>,
}

impl StringPoolPlan {
    fn index_of(&self, value: &str) -> Option<u32> {
        self.values
            .iter()
            .position(|current| current == value)
            .map(|index| index as u32)
    }

    fn remap(&self, old_index: u32) -> Result<u32, DexEncodeError> {
        self.old_to_new
            .get(old_index as usize)
            .copied()
            .ok_or(DexEncodeError::InvalidStringIndex(old_index))
    }
}

fn build_string_pool_plan(
    dex: &DexFile,
    additions: &[String],
    replacements: &[(u32, String)],
) -> Result<StringPoolPlan, DexEncodeError> {
    let old_units = read_string_pool_units(dex)?;
    let mut replacement_by_old = HashMap::with_capacity(replacements.len());
    for (old_index, value) in replacements {
        if *old_index >= old_units.len() as u32 {
            return Err(DexEncodeError::InvalidStringIndex(*old_index));
        }
        replacement_by_old.insert(*old_index, value.clone());
    }

    #[derive(Debug)]
    struct Candidate {
        units: Vec<u16>,
        value: String,
        old_index: Option<u32>,
        old_source: Option<u32>,
    }

    let mut candidates = Vec::with_capacity(old_units.len() + additions.len());
    for (old_index, units) in old_units.iter().enumerate() {
        if let Some(value) = replacement_by_old.get(&(old_index as u32)) {
            candidates.push(Candidate {
                units: value.encode_utf16().collect(),
                value: value.clone(),
                old_index: Some(old_index as u32),
                old_source: None,
            });
        } else {
            let value = String::from_utf16(units).map_err(|_| DexEncodeError::InvalidCodeItem)?;
            candidates.push(Candidate {
                units: units.clone(),
                value,
                old_index: Some(old_index as u32),
                old_source: Some(old_index as u32),
            });
        }
    }
    // If a replacement collides with another existing string, retain the old
    // value as an otherwise-unreferenced string ID. DEX string IDs are a
    // sorted set, so dropping the old value would shrink the ID table and
    // force signed relocations through every section before data_off.
    for (old_index, units) in old_units.iter().enumerate() {
        let Some(replacement) = replacement_by_old.get(&(old_index as u32)) else {
            continue;
        };
        let replacement_units = replacement.encode_utf16().collect::<Vec<_>>();
        if replacement_units != *units
            && old_units
                .iter()
                .enumerate()
                .any(|(other, other_units)| other != old_index && other_units == &replacement_units)
        {
            candidates.push(Candidate {
                units: units.clone(),
                value: String::from_utf16(units).map_err(|_| DexEncodeError::InvalidCodeItem)?,
                old_index: None,
                old_source: Some(old_index as u32),
            });
        }
    }
    for value in additions {
        candidates.push(Candidate {
            units: value.encode_utf16().collect(),
            value: value.clone(),
            old_index: None,
            old_source: None,
        });
    }
    candidates.sort_by(|left, right| left.units.cmp(&right.units));

    let mut values = Vec::new();
    let mut value_units = Vec::<Vec<u16>>::new();
    let mut old_sources = Vec::new();
    let mut old_to_new = vec![0u32; old_units.len()];
    for candidate in candidates {
        let final_index = if let Some(last_units) = value_units.last() {
            if *last_units == candidate.units {
                (values.len() - 1) as u32
            } else {
                values.push(candidate.value.clone());
                value_units.push(candidate.units.clone());
                old_sources.push(candidate.old_source);
                (values.len() - 1) as u32
            }
        } else {
            values.push(candidate.value.clone());
            value_units.push(candidate.units.clone());
            old_sources.push(candidate.old_source);
            0
        };
        if let Some(old_index) = candidate.old_index {
            old_to_new[old_index as usize] = final_index;
            // Prefer an unchanged old data item when a replacement happens to
            // produce a value already present elsewhere in the pool.
            if old_sources[final_index as usize].is_none() && candidate.old_source.is_some() {
                old_sources[final_index as usize] = candidate.old_source;
            }
        }
    }

    Ok(StringPoolPlan {
        values,
        old_to_new,
        old_sources,
    })
}

fn append_dex_string_data(output: &mut Vec<u8>, value: &str) {
    append_uleb(output, value.encode_utf16().count() as u32);
    for unit in value.encode_utf16() {
        match unit {
            0x0000 => output.extend_from_slice(&[0xc0, 0x80]),
            0x0001..=0x007f => output.push(unit as u8),
            0x0080..=0x07ff => {
                output.push(0xc0 | (unit >> 6) as u8);
                output.push(0x80 | (unit & 0x3f) as u8);
            }
            _ => {
                output.push(0xe0 | (unit >> 12) as u8);
                output.push(0x80 | ((unit >> 6) & 0x3f) as u8);
                output.push(0x80 | (unit & 0x3f) as u8);
            }
        }
    }
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
    string_plan: &StringPoolPlan,
    new_types: &[u32],
    new_proto: bool,
    shorty_idx: u32,
    return_type_idx: u32,
    parameter_type_idx: u32,
    new_method: Option<(u32, u32, u32)>,
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
    output.resize(
        output
            .len()
            .checked_add(string_plan.values.len() * 4)
            .ok_or(DexEncodeError::InvalidCodeItem)?,
        0,
    );

    let type_ids_off = output.len() as u32;
    append_raw_table(
        &mut output,
        raw,
        dex.header.type_ids_off as usize,
        dex.header.type_ids_size,
        4,
    )?;
    patch_type_ids(
        &mut output,
        type_ids_off as usize,
        dex.header.type_ids_size,
        string_plan,
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
    patch_proto_shorty_ids(
        &mut output,
        proto_ids_off as usize,
        dex.header.proto_ids_size,
        string_plan,
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
        patch_field_ids(
            &mut output,
            offset as usize,
            dex.header.fields_ids_size,
            string_plan,
        )?;
        offset
    };

    let method_ids_off = if dex.header.method_ids_size == 0 && new_method.is_none() {
        0
    } else {
        if let Some((class_idx, proto_idx, _)) = new_method {
            if class_idx > u16::MAX as u32 || proto_idx > u16::MAX as u32 {
                return Err(DexEncodeError::InvalidCodeItem);
            }
        }
        let offset = output.len() as u32;
        append_raw_table(
            &mut output,
            raw,
            dex.header.method_ids_off as usize,
            dex.header.method_ids_size,
            8,
        )?;
        patch_method_ids(
            &mut output,
            offset as usize,
            dex.header.method_ids_size,
            string_plan,
        )?;
        if let Some((class_idx, proto_idx, name_idx)) = new_method {
            output.extend_from_slice(&(class_idx as u16).to_le_bytes());
            output.extend_from_slice(&(proto_idx as u16).to_le_bytes());
            output.extend_from_slice(&name_idx.to_le_bytes());
        }
        offset
    };

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

    let string_data_start = map_entries
        .iter()
        .find(|entry| entry.kind == 0x2002)
        .map(|entry| entry.offset as usize)
        .unwrap_or(old_map_off);
    if string_data_start < old_data_off || string_data_start > old_map_off {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    let string_data_end = map_entries
        .iter()
        .filter_map(|entry| {
            let offset = entry.offset as usize;
            (offset > string_data_start && offset <= old_map_off).then_some(offset)
        })
        .min()
        .unwrap_or(old_map_off);
    // New/replaced strings are inserted at the end of the existing
    // string_data section. Keeping them inside that section is required by
    // the DEX verifier; appending them immediately before the map list leaves
    // the old map range describing the wrong bytes.
    let mut inserted_string_data = Vec::new();
    let mut inserted_string_offsets = vec![None; string_plan.values.len()];
    for (index, (value, source)) in string_plan
        .values
        .iter()
        .zip(&string_plan.old_sources)
        .enumerate()
    {
        if source.is_none() {
            inserted_string_offsets[index] = Some(inserted_string_data.len() as u32);
            append_dex_string_data(&mut inserted_string_data, value);
        }
    }
    // Keep the total insertion a multiple of four. Some later sections are
    // byte-aligned while others are four-byte aligned; preserving the old
    // alignment of every later section requires shifting them by a multiple
    // of four rather than aligning only the immediately following section.
    let padding = (4 - (inserted_string_data.len() % 4)) % 4;
    inserted_string_data.resize(
        inserted_string_data
            .len()
            .checked_add(padding)
            .ok_or(DexEncodeError::InvalidCodeItem)?,
        0,
    );
    let string_data_insert_delta = inserted_string_data.len() as u32;
    let relocation = OffsetRelocation {
        first_insert: dex.header.data_off,
        first_delta: shift,
        second_insert: string_data_end as u32,
        second_delta: string_data_insert_delta,
    };

    output.extend_from_slice(&raw[old_data_off..string_data_end]);
    let inserted_string_data_start = output.len() as u32;
    output.extend_from_slice(&inserted_string_data);
    output.extend_from_slice(&raw[string_data_end..old_map_off]);
    let old_data_copy_end = output.len();
    patch_proto_ids_relocated(
        &mut output,
        proto_ids_off as usize,
        dex.header.proto_ids_size,
        relocation,
    )?;
    patch_class_defs_relocated(
        &mut output,
        class_defs_off as usize,
        dex.header.class_defs_size,
        relocation,
    )?;
    patch_data_offsets_relocated_at(
        &mut output[data_off as usize..old_data_copy_end],
        data_off,
        &map_entries,
        dex.header.data_off,
        relocation,
        Some(string_plan),
    )?;

    let mut final_string_offsets = Vec::with_capacity(string_plan.values.len());
    for (index, source) in string_plan.old_sources.iter().enumerate() {
        let offset = if let Some(old_index) = source {
            let old_position = old_string_off
                .checked_add(*old_index as usize * 4)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
            relocation.apply(read_u32_at(raw, old_position)?)?
        } else {
            inserted_string_data_start
                .checked_add(inserted_string_offsets[index].ok_or(DexEncodeError::InvalidCodeItem)?)
                .ok_or(DexEncodeError::InvalidCodeItem)?
        };
        final_string_offsets.push(offset);
    }
    for (index, offset) in final_string_offsets.iter().enumerate() {
        write_u32_at(&mut output, string_ids_off as usize + index * 4, *offset)?;
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
            0x0001 => (string_plan.values.len() as u32, string_ids_off),
            0x0002 => (
                dex.header.type_ids_size + new_types.len() as u32,
                type_ids_off,
            ),
            0x0003 => (
                dex.header.proto_ids_size + u32::from(new_proto),
                proto_ids_off,
            ),
            0x0004 => (dex.header.fields_ids_size, field_ids_off),
            0x0005 => (
                dex.header.method_ids_size + u32::from(new_method.is_some()),
                method_ids_off,
            ),
            0x0006 => (dex.header.class_defs_size, class_defs_off),
            // The header is not in the relocated data section. Keep its map
            // entry at offset zero while the data entries move forward.
            0x0000 => (entry.count, entry.offset),
            0x1001 => (
                entry.count + u32::from(new_proto),
                relocation.apply(entry.offset)?,
            ),
            0x2002 => (
                entry.count
                    + string_plan
                        .old_sources
                        .iter()
                        .filter(|source| source.is_none())
                        .count() as u32,
                relocation.apply(entry.offset)?,
            ),
            _ => (entry.count, relocation.apply(entry.offset)?),
        };
        new_map.push(MapEntry {
            kind: entry.kind,
            count,
            offset,
        });
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
    let inserted_string_count = string_plan
        .old_sources
        .iter()
        .filter(|source| source.is_none())
        .count() as u32;
    if inserted_string_count != 0 && !new_map.iter().any(|entry| entry.kind == 0x2002) {
        new_map.push(MapEntry {
            kind: 0x2002,
            count: inserted_string_count,
            offset: inserted_string_data_start,
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
    write_u32_at(&mut output, 56, string_plan.values.len() as u32)?;
    write_u32_at(&mut output, 60, string_ids_off)?;
    write_u32_at(
        &mut output,
        64,
        dex.header.type_ids_size + new_types.len() as u32,
    )?;
    write_u32_at(&mut output, 68, type_ids_off)?;
    write_u32_at(
        &mut output,
        72,
        dex.header.proto_ids_size + u32::from(new_proto),
    )?;
    write_u32_at(&mut output, 76, proto_ids_off)?;
    write_u32_at(&mut output, 80, dex.header.fields_ids_size)?;
    write_u32_at(&mut output, 84, field_ids_off)?;
    write_u32_at(
        &mut output,
        88,
        dex.header.method_ids_size + u32::from(new_method.is_some()),
    )?;
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
    let end = offset
        .checked_add(size)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
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

fn patch_type_ids(
    output: &mut [u8],
    offset: usize,
    count: u32,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 4;
        let old = read_u32_at(output, position)?;
        write_u32_at(output, position, strings.remap(old)?)?;
    }
    Ok(())
}

fn patch_proto_shorty_ids(
    output: &mut [u8],
    offset: usize,
    count: u32,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 12;
        let old = read_u32_at(output, position)?;
        write_u32_at(output, position, strings.remap(old)?)?;
    }
    Ok(())
}

fn patch_field_ids(
    output: &mut [u8],
    offset: usize,
    count: u32,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 8 + 4;
        let old = read_u32_at(output, position)?;
        write_u32_at(output, position, strings.remap(old)?)?;
    }
    Ok(())
}

fn patch_method_ids(
    output: &mut [u8],
    offset: usize,
    count: u32,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    for index in 0..count as usize {
        let position = offset + index * 8 + 4;
        let old = read_u32_at(output, position)?;
        write_u32_at(output, position, strings.remap(old)?)?;
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

fn patch_code_item_string_indices(
    data: &mut [u8],
    offset: usize,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    let insns_size = read_u32_at(data, offset + 12)? as usize;
    let insns_offset = offset
        .checked_add(16)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let mut cursor = 0usize;
    while cursor < insns_size {
        let unit_offset = insns_offset
            .checked_add(cursor * 2)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        let word = read_u16_at(data, unit_offset)?;
        let opcode = (word & 0xff) as u8;
        let width = dex_instruction_width(data, insns_offset, cursor, insns_size)?;
        match opcode {
            0x1a => {
                let old = read_u16_at(data, unit_offset + 2)? as u32;
                let new = strings.remap(old)?;
                if new > u16::MAX as u32 {
                    return Err(DexEncodeError::StringIndexWidthChanged { old, new });
                }
                write_u16_at(data, unit_offset + 2, new as u16)?;
            }
            0x1b => {
                let old = read_u16_at(data, unit_offset + 2)? as u32
                    | (read_u16_at(data, unit_offset + 4)? as u32) << 16;
                let new = strings.remap(old)?;
                write_u16_at(data, unit_offset + 2, new as u16)?;
                write_u16_at(data, unit_offset + 4, (new >> 16) as u16)?;
            }
            _ => {}
        }
        cursor = cursor
            .checked_add(width)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
    }
    Ok(())
}

fn dex_instruction_width(
    data: &[u8],
    insns_offset: usize,
    cursor: usize,
    insns_size: usize,
) -> Result<usize, DexEncodeError> {
    let word_offset = insns_offset
        .checked_add(cursor * 2)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let word = read_u16_at(data, word_offset)?;
    let opcode = (word & 0xff) as u8;
    let width = if opcode == 0 {
        match word >> 8 {
            0x01 => 4usize
                .checked_add(read_u16_at(data, word_offset + 2)? as usize * 2)
                .ok_or(DexEncodeError::InvalidCodeItem)?,
            0x02 => 2usize
                .checked_add(read_u16_at(data, word_offset + 2)? as usize * 4)
                .ok_or(DexEncodeError::InvalidCodeItem)?,
            0x03 => {
                let element_width = read_u16_at(data, word_offset + 2)? as usize;
                let count = read_u32_at(data, word_offset + 4)? as usize;
                4usize
                    .checked_add(
                        element_width
                            .checked_mul(count)
                            .ok_or(DexEncodeError::InvalidCodeItem)?
                            .div_ceil(2),
                    )
                    .ok_or(DexEncodeError::InvalidCodeItem)?
            }
            _ => 1,
        }
    } else {
        match opcode {
            0x01
            | 0x04
            | 0x07
            | 0x0a..=0x12
            | 0x1d..=0x1e
            | 0x21
            | 0x27..=0x28
            | 0x73
            | 0x79..=0x8f
            | 0xb0..=0xcf
            | 0xe3..=0xf9 => 1,
            0x02
            | 0x05
            | 0x08
            | 0x13
            | 0x15..=0x16
            | 0x19
            | 0x1a
            | 0x1c
            | 0x1f..=0x20
            | 0x22..=0x23
            | 0x29
            | 0x2d..=0x3d
            | 0x44..=0x6d
            | 0x90..=0xaf
            | 0xd0..=0xe2
            | 0xfe..=0xff => 2,
            0x03
            | 0x06
            | 0x09
            | 0x14
            | 0x17
            | 0x1b
            | 0x24..=0x26
            | 0x2a..=0x2c
            | 0x6e..=0x72
            | 0x74..=0x78
            | 0xfc..=0xfd => 3,
            0xfa..=0xfb => 4,
            0x18 => 5,
            _ => 1,
        }
    };
    if width == 0 || cursor.checked_add(width).is_none() || cursor + width > insns_size {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    Ok(width)
}

fn patch_fixed_string_index(
    data: &mut [u8],
    offset: usize,
    width: usize,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    if width == 0 || width > 4 || offset.checked_add(width).is_none() || offset + width > data.len()
    {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    let mut old = 0u32;
    for index in 0..width {
        old |= (data[offset + index] as u32) << (index * 8);
    }
    let new = strings.remap(old)?;
    if width < 4 && new >= (1u32 << (width * 8)) {
        return Err(DexEncodeError::StringIndexWidthChanged { old, new });
    }
    for index in 0..width {
        data[offset + index] = (new >> (index * 8)) as u8;
    }
    Ok(())
}

fn patch_string_uleb(
    data: &mut [u8],
    offset: usize,
    width: usize,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    let mut cursor = offset;
    let old = read_uleb_at(data, &mut cursor)?;
    let new = strings.remap(old)?;
    if uleb_width(new) != width {
        return Err(DexEncodeError::StringIndexWidthChanged { old, new });
    }
    write_fixed_uleb(data, offset, new, width)
}

fn patch_string_uleb_p1(
    data: &mut [u8],
    offset: usize,
    width: usize,
    strings: &StringPoolPlan,
) -> Result<(), DexEncodeError> {
    let mut cursor = offset;
    let encoded = read_uleb_at(data, &mut cursor)?;
    if encoded == 0 {
        return Ok(());
    }
    let old = encoded - 1;
    let new = strings
        .remap(old)?
        .checked_add(1)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    if uleb_width(new) != width {
        return Err(DexEncodeError::StringIndexWidthChanged { old, new: new - 1 });
    }
    write_fixed_uleb(data, offset, new, width)
}

fn patch_encoded_value(
    data: &mut [u8],
    offset: usize,
    strings: &StringPoolPlan,
) -> Result<usize, DexEncodeError> {
    let header = *data.get(offset).ok_or(DexEncodeError::InvalidCodeItem)?;
    let value_arg = (header >> 5) as usize;
    let value_type = header & 0x1f;
    let mut cursor = offset + 1;
    match value_type {
        0x17 => {
            patch_fixed_string_index(data, cursor, value_arg + 1, strings)?;
            cursor += value_arg + 1;
        }
        0x1c => {
            let count = read_uleb_at(data, &mut cursor)?;
            for _ in 0..count {
                cursor += patch_encoded_value(data, cursor, strings)?;
            }
        }
        0x1d => {
            let (_, type_width) = read_uleb_at_with_width(data, &mut cursor)?;
            let _ = type_width;
            let size = read_uleb_at(data, &mut cursor)?;
            for _ in 0..size {
                let name_offset = cursor;
                let (_, name_width) = read_uleb_at_with_width(data, &mut cursor)?;
                patch_string_uleb(data, name_offset, name_width, strings)?;
                cursor += patch_encoded_value(data, cursor, strings)?;
            }
        }
        0x1e | 0x1f => {}
        _ => {
            cursor = cursor
                .checked_add(value_arg + 1)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
        }
    }
    if cursor > data.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    Ok(cursor - offset)
}

fn patch_encoded_array_item(
    data: &mut [u8],
    offset: usize,
    strings: &StringPoolPlan,
) -> Result<usize, DexEncodeError> {
    let mut cursor = offset;
    let count = read_uleb_at(data, &mut cursor)?;
    for _ in 0..count {
        cursor += patch_encoded_value(data, cursor, strings)?;
    }
    Ok(cursor - offset)
}

fn patch_annotation_item(
    data: &mut [u8],
    offset: usize,
    strings: &StringPoolPlan,
) -> Result<usize, DexEncodeError> {
    let mut cursor = offset + 1; // visibility
    read_uleb_at(data, &mut cursor)?; // type_idx
    let count = read_uleb_at(data, &mut cursor)?;
    for _ in 0..count {
        let name_offset = cursor;
        let (_, name_width) = read_uleb_at_with_width(data, &mut cursor)?;
        patch_string_uleb(data, name_offset, name_width, strings)?;
        cursor += patch_encoded_value(data, cursor, strings)?;
    }
    Ok(cursor - offset)
}

fn patch_debug_info_item(
    data: &mut [u8],
    offset: usize,
    strings: &StringPoolPlan,
) -> Result<usize, DexEncodeError> {
    let mut cursor = offset;
    read_uleb_at(data, &mut cursor)?; // line_start
    let parameter_count = read_uleb_at(data, &mut cursor)?;
    for _ in 0..parameter_count {
        let name_offset = cursor;
        let (_, width) = read_uleb_at_with_width(data, &mut cursor)?;
        patch_string_uleb_p1(data, name_offset, width, strings)?;
    }
    loop {
        let opcode = *data.get(cursor).ok_or(DexEncodeError::InvalidCodeItem)?;
        cursor += 1;
        match opcode {
            0x00 => break,
            0x01 => {
                read_uleb_at(data, &mut cursor)?;
            }
            0x02 => {
                read_sleb_at(data, &mut cursor)?;
            }
            0x03 => {
                read_uleb_at(data, &mut cursor)?;
                for _ in 0..2 {
                    let string_offset = cursor;
                    let (_, width) = read_uleb_at_with_width(data, &mut cursor)?;
                    patch_string_uleb_p1(data, string_offset, width, strings)?;
                }
            }
            0x04 => {
                read_uleb_at(data, &mut cursor)?;
                for _ in 0..3 {
                    let string_offset = cursor;
                    let (_, width) = read_uleb_at_with_width(data, &mut cursor)?;
                    patch_string_uleb_p1(data, string_offset, width, strings)?;
                }
            }
            0x05 | 0x06 => {
                read_uleb_at(data, &mut cursor)?;
            }
            0x09 => {
                let string_offset = cursor;
                let (_, width) = read_uleb_at_with_width(data, &mut cursor)?;
                patch_string_uleb_p1(data, string_offset, width, strings)?;
            }
            _ => {}
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
    patch_data_offsets_relocated_at(data, old_data_off, entries, old_data_off, relocation, None)
}

fn patch_data_offsets_relocated_at(
    data: &mut [u8],
    data_start: u32,
    entries: &[MapEntry],
    old_data_off: u32,
    relocation: OffsetRelocation,
    strings: Option<&StringPoolPlan>,
) -> Result<(), DexEncodeError> {
    for entry in entries {
        if entry.offset < old_data_off || entry.kind == 0x1000 {
            continue;
        }
        let relocated_offset = relocation.apply(entry.offset)?;
        let base = relocated_offset
            .checked_sub(data_start)
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
                    if let Some(strings) = strings {
                        patch_code_item_string_indices(data, cursor, strings)?;
                    }
                    cursor += code_item_size(data, cursor)?;
                    if cursor % 4 != 0 {
                        cursor += 4 - cursor % 4;
                    }
                }
            }
            0x2003 => {
                if let Some(strings) = strings {
                    let mut cursor = base;
                    for _ in 0..entry.count {
                        cursor += patch_debug_info_item(data, cursor, strings)?;
                    }
                }
            }
            0x2004 => {
                if let Some(strings) = strings {
                    let mut cursor = base;
                    for _ in 0..entry.count {
                        cursor += patch_annotation_item(data, cursor, strings)?;
                    }
                }
            }
            0x2005 => {
                if let Some(strings) = strings {
                    let mut cursor = base;
                    for _ in 0..entry.count {
                        cursor += patch_encoded_array_item(data, cursor, strings)?;
                    }
                }
            }
            0x2006 => {
                let mut cursor = base;
                for _ in 0..entry.count {
                    cursor += patch_annotations_directory_relocated(data, cursor, relocation)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
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

fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), DexEncodeError> {
    if offset + 2 > bytes.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), DexEncodeError> {
    if offset + 4 > bytes.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[derive(Debug, Clone)]
struct OriginalInstruction {
    offset: u32,
    raw: Vec<u16>,
    instruction: Instruction,
}

#[derive(Debug, Clone)]
struct EditAtom {
    id: usize,
    instruction: EditableInstruction,
    original: Option<OriginalInstruction>,
}

#[derive(Debug, Default)]
struct AnchoredEdits {
    before: Vec<EditableInstruction>,
    after: Vec<EditableInstruction>,
    replacement: Option<Vec<EditableInstruction>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct AtomState {
    conditional_expanded: bool,
    goto_width: u8,
}

#[derive(Debug, Clone)]
struct Segment {
    offset: u32,
    before: Vec<EditAtom>,
    main: Vec<EditAtom>,
    after: Vec<EditAtom>,
}

#[derive(Debug, Clone)]
struct PlacedAtom {
    atom: EditAtom,
    start: u32,
}

#[derive(Debug)]
struct Layout {
    atoms: Vec<PlacedAtom>,
    targets: BTreeMap<(u32, TargetPosition), u32>,
    payload_offsets: HashMap<usize, u32>,
    size: u32,
}

#[derive(Debug, Clone)]
struct TryRegion {
    start: u32,
    end: u32,
    handler: usize,
}

#[derive(Debug, Clone)]
struct CatchHandler {
    typed: Vec<(u32, u32)>,
    catch_all: Option<u32>,
}

#[derive(Debug, Clone)]
struct MethodTryData {
    regions: Vec<TryRegion>,
    handlers: Vec<CatchHandler>,
}

fn parse_try_data(
    raw: &[u8],
    code: &coeus_models::models::CodeItem,
) -> Result<Option<MethodTryData>, DexEncodeError> {
    if code.tries_size == 0 {
        return Ok(None);
    }
    let insns_start = (code.code_off as usize)
        .checked_add(16)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let insns_end = insns_start
        .checked_add(code.insns_size as usize * 2)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let tries_start = insns_end
        .checked_add(3)
        .map(|offset| offset & !3)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    let tries_bytes = code.tries_size as usize * 8;
    let handlers_start = tries_start
        .checked_add(tries_bytes)
        .ok_or(DexEncodeError::InvalidCodeItem)?;
    if handlers_start > raw.len() {
        return Err(DexEncodeError::InvalidCodeItem);
    }

    let mut regions = Vec::with_capacity(code.tries_size as usize);
    for index in 0..code.tries_size as usize {
        let offset = tries_start
            .checked_add(index * 8)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        let start = read_u32_at(raw, offset)?;
        let count = read_u16_at(raw, offset + 4)? as u32;
        let handler_offset = read_u16_at(raw, offset + 6)? as u32;
        let end = start
            .checked_add(count)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        regions.push(TryRegion {
            start,
            end,
            handler: handler_offset as usize,
        });
    }

    let mut cursor = handlers_start;
    let handler_count = read_uleb_at(raw, &mut cursor)? as usize;
    let mut handlers = Vec::with_capacity(handler_count);
    let mut handler_offsets = HashMap::with_capacity(handler_count);
    for index in 0..handler_count {
        let offset = cursor
            .checked_sub(handlers_start)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        handler_offsets.insert(offset, index);
        let (size, _) = read_sleb_at(raw, &mut cursor)?;
        if size == i32::MIN {
            return Err(DexEncodeError::InvalidCodeItem);
        }
        let typed_count = size.unsigned_abs() as usize;
        let mut typed = Vec::with_capacity(typed_count);
        for _ in 0..typed_count {
            let type_index = read_uleb_at(raw, &mut cursor)?;
            let address = read_uleb_at(raw, &mut cursor)?;
            typed.push((type_index, address));
        }
        let catch_all = if size <= 0 {
            Some(read_uleb_at(raw, &mut cursor)?)
        } else {
            None
        };
        handlers.push(CatchHandler { typed, catch_all });
    }
    for region in &mut regions {
        region.handler = *handler_offsets
            .get(&region.handler)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
    }
    Ok(Some(MethodTryData { regions, handlers }))
}

fn map_try_start(layout: &Layout, offset: u32) -> Result<u32, DexEncodeError> {
    layout
        .targets
        .get(&(offset, TargetPosition::Before))
        .copied()
        .ok_or(DexEncodeError::InvalidCodeItem)
}

fn map_try_end(
    layout: &Layout,
    segments: &[Segment],
    offset: u32,
    original_instruction_end: u32,
) -> Result<u32, DexEncodeError> {
    if let Some(mapped) = layout.targets.get(&(offset, TargetPosition::Before)) {
        return Ok(*mapped);
    }
    if offset == original_instruction_end {
        if let Some(last) = segments.last() {
            return layout
                .targets
                .get(&(last.offset, TargetPosition::After))
                .copied()
                .ok_or(DexEncodeError::InvalidCodeItem);
        }
    }
    Err(DexEncodeError::InvalidCodeItem)
}

fn map_try_handler(layout: &Layout, offset: u32) -> Result<u32, DexEncodeError> {
    layout
        .targets
        .get(&(offset, TargetPosition::Instruction))
        .copied()
        .ok_or(DexEncodeError::InvalidCodeItem)
}

fn append_sleb(output: &mut Vec<u8>, mut value: i32) {
    loop {
        let byte = (value as u8) & 0x7f;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        output.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}

fn encode_try_data_mapped<FS, FE, FH>(
    data: &MethodTryData,
    map_start: FS,
    map_end: FE,
    map_handler: FH,
) -> Result<Vec<u8>, DexEncodeError>
where
    FS: Fn(u32) -> Result<u32, DexEncodeError>,
    FE: Fn(u32) -> Result<u32, DexEncodeError>,
    FH: Fn(u32) -> Result<u32, DexEncodeError>,
{
    let mut encoded_handlers = Vec::new();
    let mut handler_offsets = Vec::with_capacity(data.handlers.len());
    for handler in &data.handlers {
        let offset = encoded_handlers.len();
        if offset > u16::MAX as usize {
            return Err(DexEncodeError::InvalidCodeItem);
        }
        handler_offsets.push(offset as u32);
        let size = if handler.catch_all.is_some() {
            -(handler.typed.len() as i32)
        } else {
            handler.typed.len() as i32
        };
        append_sleb(&mut encoded_handlers, size);
        for &(type_index, address) in &handler.typed {
            append_uleb(&mut encoded_handlers, type_index);
            append_uleb(&mut encoded_handlers, map_handler(address)?);
        }
        if let Some(address) = handler.catch_all {
            append_uleb(&mut encoded_handlers, map_handler(address)?);
        }
    }

    let mut handler_list = Vec::new();
    append_uleb(&mut handler_list, data.handlers.len() as u32);
    let handler_data_start = handler_list.len();
    handler_list.extend_from_slice(&encoded_handlers);
    let handler_offsets_base = handler_data_start as u32;

    let mut output = Vec::with_capacity(data.regions.len() * 8 + handler_list.len());
    for region in &data.regions {
        let start = map_start(region.start)?;
        let end = map_end(region.end)?;
        let count = end
            .checked_sub(start)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        let count = u16::try_from(count).map_err(|_| DexEncodeError::InvalidCodeItem)?;
        let handler_offset = handler_offsets
            .get(region.handler)
            .copied()
            .ok_or(DexEncodeError::InvalidCodeItem)?
            .checked_add(handler_offsets_base)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        let handler_offset =
            u16::try_from(handler_offset).map_err(|_| DexEncodeError::InvalidCodeItem)?;
        output.extend_from_slice(&start.to_le_bytes());
        output.extend_from_slice(&count.to_le_bytes());
        output.extend_from_slice(&handler_offset.to_le_bytes());
    }
    output.extend_from_slice(&handler_list);
    Ok(output)
}

fn is_payload(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::ArrayData(..)
            | Instruction::PackedSwitchData(..)
            | Instruction::SparseSwitchData(..)
            | Instruction::SwitchData(..)
    )
}

fn add_relative_offset(source: u32, relative: i32) -> Result<u32, DexEncodeError> {
    let target = source as i64 + relative as i64;
    if target < 0 || target > u32::MAX as i64 {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    Ok(target as u32)
}

fn original_editable_instruction(
    instruction: &Instruction,
    offset: u32,
    payloads: &HashMap<u32, Instruction>,
) -> Result<EditableInstruction, DexEncodeError> {
    let instruction_target = |relative: i32| {
        Ok(CodeTarget {
            offset: add_relative_offset(offset, relative)?,
            position: TargetPosition::Instruction,
        })
    };

    match instruction {
        Instruction::Test(_, _, _, relative) => Ok(EditableInstruction::Branch {
            instruction: instruction.clone(),
            target: instruction_target(*relative as i32)?,
        }),
        Instruction::TestZero(_, _, relative) => Ok(EditableInstruction::Branch {
            instruction: instruction.clone(),
            target: instruction_target(*relative as i32)?,
        }),
        Instruction::Goto8(relative) => Ok(EditableInstruction::Branch {
            instruction: instruction.clone(),
            target: instruction_target(*relative as i32)?,
        }),
        Instruction::Goto16(relative) => Ok(EditableInstruction::Branch {
            instruction: instruction.clone(),
            target: instruction_target(*relative as i32)?,
        }),
        Instruction::Goto32(relative) => Ok(EditableInstruction::Branch {
            instruction: instruction.clone(),
            target: instruction_target(*relative)?,
        }),
        Instruction::PackedSwitch(register, payload_relative)
        | Instruction::SparseSwitch(register, payload_relative) => {
            let payload_offset = add_relative_offset(offset, *payload_relative)?;
            let payload = payloads
                .get(&payload_offset)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
            let switch = match payload {
                Instruction::PackedSwitchData(switch) | Instruction::SparseSwitchData(switch) => {
                    switch
                }
                _ => return Err(DexEncodeError::InvalidCodeItem),
            };
            let cases = switch
                .targets
                .iter()
                .map(|(&key, &relative)| {
                    Ok((
                        key,
                        CodeTarget {
                            offset: add_relative_offset(offset, relative)?,
                            position: TargetPosition::Instruction,
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, DexEncodeError>>()?;
            Ok(EditableInstruction::Switch {
                register: *register,
                cases,
                default: None,
                form: if matches!(instruction, Instruction::PackedSwitch(..)) {
                    SwitchForm::Packed
                } else {
                    SwitchForm::Sparse
                },
            })
        }
        Instruction::FillArrayData(register, payload_relative) => {
            let payload_offset = add_relative_offset(offset, *payload_relative as i32)?;
            let payload = payloads
                .get(&payload_offset)
                .ok_or(DexEncodeError::InvalidCodeItem)?;
            let (width, data) = match payload {
                Instruction::ArrayData(width, data) => (*width, data.clone()),
                _ => return Err(DexEncodeError::InvalidCodeItem),
            };
            Ok(EditableInstruction::FillArray {
                register: *register,
                width,
                data,
            })
        }
        Instruction::Switch(..) | Instruction::SwitchData(..) => {
            Err(DexEncodeError::UnsupportedEditInstruction)
        }
        _ => Ok(EditableInstruction::Concrete(instruction.clone())),
    }
}

/// Convert a decoded instruction into the symbolic form used by the method
/// rewriter. This is public for language bindings that already own a decoded
/// instruction object.
pub fn editable_instruction_from_decoded(
    dex: &DexFile,
    method_idx: u32,
    offset: u32,
    instruction: &Instruction,
) -> Result<EditableInstruction, DexEncodeError> {
    let payloads = dex
        .classes
        .iter()
        .flat_map(|class| class.codes.iter())
        .flat_map(|method| {
            (method.method_idx == method_idx)
                .then(|| method.code.as_ref())
                .flatten()
        })
        .flat_map(|code| code.insns.iter())
        .filter(|(_, _, instruction)| is_payload(instruction))
        .map(|(_, offset, instruction)| (offset.0, instruction.clone()))
        .collect::<HashMap<_, _>>();
    original_editable_instruction(instruction, offset, &payloads)
}

fn instruction_units(atom: &EditAtom, state: AtomState) -> Result<usize, DexEncodeError> {
    match &atom.instruction {
        EditableInstruction::Concrete(instruction) => {
            if let Some(original) = &atom.original {
                Ok(original.raw.len())
            } else {
                instruction
                    .to_code_units()
                    .map(|units| units.len())
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)
            }
        }
        EditableInstruction::Branch { instruction, .. } => {
            if is_conditional(instruction) && state.conditional_expanded {
                Ok(5)
            } else if is_goto(instruction) {
                Ok(if state.goto_width == 0 {
                    goto_nominal_width(instruction) as usize
                } else {
                    state.goto_width as usize
                })
            } else {
                instruction
                    .to_code_units()
                    .map(|units| units.len())
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)
            }
        }
        EditableInstruction::Switch { default, .. } => {
            Ok(3 + if default.is_some() { 3 } else { 0 })
        }
        EditableInstruction::FillArray { .. } => Ok(3),
    }
}

fn is_conditional(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::Test(..) | Instruction::TestZero(..)
    )
}

fn is_goto(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::Goto8(..) | Instruction::Goto16(..) | Instruction::Goto32(..)
    )
}

fn goto_nominal_width(instruction: &Instruction) -> u8 {
    match instruction {
        Instruction::Goto8(..) => 1,
        Instruction::Goto16(..) => 2,
        Instruction::Goto32(..) => 3,
        _ => 0,
    }
}

fn switch_payload_units(form: SwitchForm, entries: usize) -> usize {
    match form {
        SwitchForm::Packed => 4 + entries * 2,
        SwitchForm::Sparse => 2 + entries * 4,
        SwitchForm::Auto => 2 + entries * 4,
    }
}

fn switch_is_packed(cases: &BTreeMap<i32, CodeTarget>) -> bool {
    let Some((&first, _)) = cases.first_key_value() else {
        return true;
    };
    cases
        .keys()
        .enumerate()
        .all(|(index, key)| *key == first.saturating_add(index as i32))
}

fn effective_switch_form(
    form: SwitchForm,
    cases: &BTreeMap<i32, CodeTarget>,
) -> Result<SwitchForm, DexEncodeError> {
    match form {
        SwitchForm::Auto => Ok(if switch_is_packed(cases) {
            SwitchForm::Packed
        } else {
            SwitchForm::Sparse
        }),
        SwitchForm::Packed if switch_is_packed(cases) => Ok(SwitchForm::Packed),
        SwitchForm::Packed => Err(DexEncodeError::UnsupportedEditInstruction),
        SwitchForm::Sparse => Ok(SwitchForm::Sparse),
    }
}

fn resolve_target(
    target: CodeTarget,
    targets: &BTreeMap<(u32, TargetPosition), u32>,
) -> Result<u32, DexEncodeError> {
    targets
        .get(&(target.offset, target.position))
        .copied()
        .ok_or(DexEncodeError::BranchTargetNotFound(target.offset))
}

fn layout_method(segments: &[Segment], states: &[AtomState]) -> Result<Layout, DexEncodeError> {
    let mut atoms = Vec::new();
    let mut targets = BTreeMap::new();
    let mut pc = 0u32;

    let place = |atom: &EditAtom,
                 atoms: &mut Vec<PlacedAtom>,
                 pc: &mut u32|
     -> Result<(), DexEncodeError> {
        let size = instruction_units(atom, states[atom.id])? as u32;
        atoms.push(PlacedAtom {
            atom: atom.clone(),
            start: *pc,
        });
        *pc = pc
            .checked_add(size)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        Ok(())
    };

    for segment in segments {
        targets.insert((segment.offset, TargetPosition::Before), pc);
        for atom in &segment.before {
            place(atom, &mut atoms, &mut pc)?;
        }
        targets.insert((segment.offset, TargetPosition::Instruction), pc);
        for atom in &segment.main {
            place(atom, &mut atoms, &mut pc)?;
        }
        for atom in &segment.after {
            place(atom, &mut atoms, &mut pc)?;
        }
        targets.insert((segment.offset, TargetPosition::After), pc);
    }

    let normal_end = pc;
    let mut payload_offsets = HashMap::new();
    for placed in &atoms {
        let payload_size = match &placed.atom.instruction {
            EditableInstruction::Switch { cases, form, .. } => {
                let form = effective_switch_form(*form, cases)?;
                Some(switch_payload_units(form, cases.len()))
            }
            EditableInstruction::FillArray { width, data, .. } => Some(
                Instruction::ArrayData(*width, data.clone())
                    .to_code_units()
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?
                    .len(),
            ),
            _ => None,
        };
        let Some(payload_size) = payload_size else {
            continue;
        };
        if pc % 2 != 0 {
            pc = pc.checked_add(1).ok_or(DexEncodeError::InvalidCodeItem)?;
        }
        payload_offsets.insert(placed.atom.id, pc);
        pc = pc
            .checked_add(payload_size as u32)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
    }

    if normal_end > i32::MAX as u32 || pc > i32::MAX as u32 {
        return Err(DexEncodeError::InvalidCodeItem);
    }
    Ok(Layout {
        atoms,
        targets,
        payload_offsets,
        size: pc,
    })
}

fn fits_i8(value: i64) -> bool {
    (i8::MIN as i64..=i8::MAX as i64).contains(&value)
}

fn fits_i16(value: i64) -> bool {
    (i16::MIN as i64..=i16::MAX as i64).contains(&value)
}

fn fits_i32(value: i64) -> bool {
    (i32::MIN as i64..=i32::MAX as i64).contains(&value)
}

fn invert_test(function: TestFunction) -> TestFunction {
    match function {
        TestFunction::Equal => TestFunction::NotEqual,
        TestFunction::NotEqual => TestFunction::Equal,
        TestFunction::LessThan => TestFunction::GreaterEqual,
        TestFunction::GreaterEqual => TestFunction::LessThan,
        TestFunction::GreaterThan => TestFunction::LessEqual,
        TestFunction::LessEqual => TestFunction::GreaterThan,
    }
}

fn encode_branch(
    instruction: &Instruction,
    target: CodeTarget,
    start: u32,
    state: AtomState,
    layout: &Layout,
) -> Result<Vec<u16>, DexEncodeError> {
    let target = resolve_target(target, &layout.targets)? as i64;
    let start = start as i64;
    match instruction {
        Instruction::Test(function, a, b, _) => {
            if state.conditional_expanded {
                let condition = Instruction::Test(invert_test(*function), *a, *b, 5);
                let goto_start = start + 2;
                let goto_offset = target - goto_start;
                if !fits_i32(goto_offset) {
                    return Err(DexEncodeError::BranchOutOfRange);
                }
                let mut units = condition
                    .to_code_units()
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?;
                units.extend(
                    Instruction::Goto32(goto_offset as i32)
                        .to_code_units()
                        .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?,
                );
                Ok(units)
            } else {
                let offset = target - start;
                if !fits_i16(offset) {
                    return Err(DexEncodeError::BranchOutOfRange);
                }
                Instruction::Test(*function, *a, *b, offset as i16)
                    .to_code_units()
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)
            }
        }
        Instruction::TestZero(function, register, _) => {
            if state.conditional_expanded {
                let condition = Instruction::TestZero(invert_test(*function), *register, 5);
                let goto_start = start + 2;
                let goto_offset = target - goto_start;
                if !fits_i32(goto_offset) {
                    return Err(DexEncodeError::BranchOutOfRange);
                }
                let mut units = condition
                    .to_code_units()
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?;
                units.extend(
                    Instruction::Goto32(goto_offset as i32)
                        .to_code_units()
                        .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?,
                );
                Ok(units)
            } else {
                let offset = target - start;
                if !fits_i16(offset) {
                    return Err(DexEncodeError::BranchOutOfRange);
                }
                Instruction::TestZero(*function, *register, offset as i16)
                    .to_code_units()
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)
            }
        }
        Instruction::Goto8(_) | Instruction::Goto16(_) | Instruction::Goto32(_) => {
            let offset = target - start;
            let width = if state.goto_width == 0 {
                goto_nominal_width(instruction)
            } else {
                state.goto_width
            };
            let instruction = match width {
                1 if fits_i8(offset) => Instruction::Goto8(offset as i8),
                2 if fits_i16(offset) => Instruction::Goto16(offset as i16),
                3 if fits_i32(offset) => Instruction::Goto32(offset as i32),
                1 if fits_i16(offset) => Instruction::Goto16(offset as i16),
                1 | 2 if fits_i32(offset) => Instruction::Goto32(offset as i32),
                _ => return Err(DexEncodeError::BranchOutOfRange),
            };
            instruction
                .to_code_units()
                .map_err(|_| DexEncodeError::UnsupportedEditInstruction)
        }
        _ => Err(DexEncodeError::UnsupportedEditInstruction),
    }
}

fn encode_switch_payload(
    form: SwitchForm,
    cases: &BTreeMap<i32, CodeTarget>,
    owner_start: u32,
    layout: &Layout,
) -> Result<Vec<u16>, DexEncodeError> {
    let form = effective_switch_form(form, cases)?;
    let mut resolved = Vec::with_capacity(cases.len());
    for (&key, &target) in cases {
        let target = resolve_target(target, &layout.targets)? as i64 - owner_start as i64;
        if !fits_i32(target) {
            return Err(DexEncodeError::BranchOutOfRange);
        }
        resolved.push((key, target as i32));
    }
    match form {
        SwitchForm::Packed => {
            let first_key = resolved.first().map(|(key, _)| *key).unwrap_or(0);
            let mut units = vec![
                u16::from_le_bytes([0x00, 0x01]),
                u16::try_from(resolved.len())
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?,
                first_key as u32 as u16,
                (first_key as u32 >> 16) as u16,
            ];
            for (_, target) in resolved {
                units.push(target as u32 as u16);
                units.push((target as u32 >> 16) as u16);
            }
            Ok(units)
        }
        SwitchForm::Sparse => {
            let mut units = vec![
                u16::from_le_bytes([0x00, 0x02]),
                u16::try_from(resolved.len())
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?,
            ];
            for (key, _) in &resolved {
                units.push(*key as u32 as u16);
                units.push((*key as u32 >> 16) as u16);
            }
            for (_, target) in resolved {
                units.push(target as u32 as u16);
                units.push((target as u32 >> 16) as u16);
            }
            Ok(units)
        }
        SwitchForm::Auto => unreachable!(),
    }
}

fn encode_atom(
    placed: &PlacedAtom,
    states: &[AtomState],
    layout: &Layout,
) -> Result<Vec<u16>, DexEncodeError> {
    match &placed.atom.instruction {
        EditableInstruction::Concrete(instruction) => {
            if let Some(original) = &placed.atom.original {
                Ok(original.raw.clone())
            } else {
                instruction
                    .to_code_units()
                    .map_err(|_| DexEncodeError::UnsupportedEditInstruction)
            }
        }
        EditableInstruction::Branch {
            instruction,
            target,
        } => encode_branch(
            instruction,
            *target,
            placed.start,
            states[placed.atom.id],
            layout,
        ),
        EditableInstruction::Switch {
            register,
            cases,
            default,
            form,
        } => {
            let payload_offset = layout
                .payload_offsets
                .get(&placed.atom.id)
                .copied()
                .ok_or(DexEncodeError::InvalidCodeItem)? as i64
                - placed.start as i64;
            if !fits_i32(payload_offset) {
                return Err(DexEncodeError::BranchOutOfRange);
            }
            let switch = match effective_switch_form(*form, cases)? {
                SwitchForm::Packed => Instruction::PackedSwitch(*register, payload_offset as i32),
                SwitchForm::Sparse => Instruction::SparseSwitch(*register, payload_offset as i32),
                SwitchForm::Auto => unreachable!(),
            };
            let mut units = switch
                .to_code_units()
                .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?;
            if let Some(default) = default {
                let default_start = placed.start as i64 + 3;
                let target = resolve_target(*default, &layout.targets)? as i64 - default_start;
                if !fits_i32(target) {
                    return Err(DexEncodeError::BranchOutOfRange);
                }
                units.extend(
                    Instruction::Goto32(target as i32)
                        .to_code_units()
                        .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?,
                );
            }
            Ok(units)
        }
        EditableInstruction::FillArray {
            register,
            width,
            data,
        } => {
            let payload_offset = layout
                .payload_offsets
                .get(&placed.atom.id)
                .copied()
                .ok_or(DexEncodeError::InvalidCodeItem)? as i64
                - placed.start as i64;
            if !fits_i32(payload_offset) {
                return Err(DexEncodeError::BranchOutOfRange);
            }
            let mut units = Instruction::FillArrayData(*register, payload_offset as u32)
                .to_code_units()
                .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?;
            // Keep the payload attached to this instruction. It is emitted by
            // the caller after all normal instructions and alignment padding.
            let _ = (width, data);
            Ok(std::mem::take(&mut units))
        }
    }
}

fn append_rewritten_code_item(
    dex: &DexFile,
    method_idx: u32,
    class_idx: u32,
    new_code: &[u8],
) -> Result<Vec<u8>, DexEncodeError> {
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
    output.extend_from_slice(new_code);
    output.resize(
        output.len() + (code_insert_delta as usize - code_padding - new_code.len()),
        0,
    );
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
    patch_u32_reference_relocated(
        &mut output[old_data_off..new_map_off as usize],
        (new_code_off - dex.header.data_off) as usize + 8,
        relocation,
    )?;
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
    output.extend_from_slice(&((new_map.len() + 1) as u32).to_le_bytes());
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

/// Rewrite a method using logical edit anchors. Branch offsets and switch
/// payloads are regenerated after all insertions and replacements are known.
pub fn rewrite_method_code(
    dex: &DexFile,
    method_idx: u32,
    edits: &[MethodEdit],
) -> Result<Vec<u8>, DexEncodeError> {
    let (class_idx, code) = dex
        .classes
        .iter()
        .flat_map(|class| {
            class
                .codes
                .iter()
                .map(move |method| (class.class_idx, method))
        })
        .find(|(_, method)| method.method_idx == method_idx)
        .ok_or(DexEncodeError::MethodNotFound(method_idx))?;
    let code = code
        .code
        .as_ref()
        .ok_or(DexEncodeError::MethodHasNoCode(method_idx))?;

    let raw = dex.raw_data();
    let try_data = parse_try_data(raw, code)?;
    let raw_start = code.code_off as usize + 16;
    let payloads = code
        .insns
        .iter()
        .filter(|(_, _, instruction)| is_payload(instruction))
        .map(|(_, offset, instruction)| (offset.0, instruction.clone()))
        .collect::<HashMap<_, _>>();
    let mut originals = Vec::new();
    for (size, offset, instruction) in &code.insns {
        if is_payload(instruction) {
            continue;
        }
        let units = (size.0 / 2) as usize;
        let start = raw_start
            .checked_add(offset.0 as usize * 2)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        let end = start
            .checked_add(units * 2)
            .ok_or(DexEncodeError::InvalidCodeItem)?;
        if end > raw.len() {
            return Err(DexEncodeError::InvalidCodeItem);
        }
        let mut raw_units = Vec::with_capacity(units);
        for bytes in raw[start..end].chunks_exact(2) {
            raw_units.push(u16::from_le_bytes([bytes[0], bytes[1]]));
        }
        originals.push(OriginalInstruction {
            offset: offset.0,
            raw: raw_units,
            instruction: instruction.clone(),
        });
    }
    let original_offsets = originals
        .iter()
        .map(|instruction| instruction.offset)
        .collect::<std::collections::BTreeSet<_>>();
    let original_instruction_end = originals
        .last()
        .map(|instruction| instruction.offset + instruction.raw.len() as u32)
        .unwrap_or(0);
    let mut anchored = BTreeMap::<u32, AnchoredEdits>::new();
    for edit in edits {
        if !original_offsets.contains(&edit.anchor) {
            return Err(DexEncodeError::InvalidEditAnchor(edit.anchor));
        }
        let entry = anchored.entry(edit.anchor).or_default();
        match edit.position {
            EditPosition::Before => entry.before.extend(edit.instructions.clone()),
            EditPosition::After => entry.after.extend(edit.instructions.clone()),
            EditPosition::Replace => {
                if entry.replacement.is_some() {
                    return Err(DexEncodeError::ConflictingEdits);
                }
                entry.replacement = Some(edit.instructions.clone());
            }
        }
    }

    let mut next_id = 0usize;
    let mut make_atoms = |instructions: Vec<EditableInstruction>,
                          original: Option<OriginalInstruction>|
     -> Vec<EditAtom> {
        instructions
            .into_iter()
            .map(|instruction| {
                let atom = EditAtom {
                    id: next_id,
                    instruction,
                    original: original.clone(),
                };
                next_id += 1;
                atom
            })
            .collect()
    };

    let mut segments = Vec::new();
    for original in originals {
        let edit = anchored.remove(&original.offset).unwrap_or_default();
        let original_instruction =
            original_editable_instruction(&original.instruction, original.offset, &payloads)?;
        let has_replacement = edit.replacement.is_some();
        let main = edit
            .replacement
            .unwrap_or_else(|| vec![original_instruction]);
        segments.push(Segment {
            offset: original.offset,
            before: make_atoms(edit.before, None),
            main: if main.len() == 1 && !has_replacement {
                make_atoms(main, Some(original))
            } else {
                make_atoms(main, None)
            },
            after: make_atoms(edit.after, None),
        });
    }
    if !anchored.is_empty() {
        return Err(DexEncodeError::InvalidEditAnchor(
            *anchored.keys().next().unwrap(),
        ));
    }
    if segments.is_empty() {
        return Err(DexEncodeError::MethodHasNoCode(method_idx));
    }

    let mut states = vec![AtomState::default(); next_id];
    for segment in &segments {
        for atom in segment
            .before
            .iter()
            .chain(segment.main.iter())
            .chain(segment.after.iter())
        {
            states[atom.id].goto_width = match &atom.instruction {
                EditableInstruction::Branch { instruction, .. } if is_goto(instruction) => {
                    goto_nominal_width(instruction)
                }
                _ => 0,
            };
        }
    }

    let mut layout = layout_method(&segments, &states)?;
    for _ in 0..next_id.saturating_add(2) {
        let mut changed = false;
        for placed in &layout.atoms {
            let state = &mut states[placed.atom.id];
            match &placed.atom.instruction {
                EditableInstruction::Branch {
                    instruction,
                    target,
                } if is_conditional(instruction) => {
                    let target = resolve_target(*target, &layout.targets)? as i64;
                    let offset = target - placed.start as i64;
                    if !state.conditional_expanded && !fits_i16(offset) {
                        state.conditional_expanded = true;
                        changed = true;
                    }
                }
                EditableInstruction::Branch {
                    instruction,
                    target,
                } if is_goto(instruction) => {
                    let target = resolve_target(*target, &layout.targets)? as i64;
                    let offset = target - placed.start as i64;
                    let current = state.goto_width;
                    let desired = match instruction {
                        Instruction::Goto8(..) if fits_i8(offset) => 1,
                        Instruction::Goto8(..) if fits_i16(offset) => 2,
                        Instruction::Goto8(..) if fits_i32(offset) => 3,
                        Instruction::Goto16(..) if fits_i16(offset) => 2,
                        Instruction::Goto16(..) if fits_i32(offset) => 3,
                        Instruction::Goto32(..) if fits_i32(offset) => 3,
                        _ => return Err(DexEncodeError::BranchOutOfRange),
                    };
                    if desired > current {
                        state.goto_width = desired;
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        if !changed {
            break;
        }
        layout = layout_method(&segments, &states)?;
    }

    let mut units = Vec::with_capacity(layout.size as usize);
    for placed in &layout.atoms {
        let encoded = encode_atom(placed, &states, &layout)?;
        units.extend(encoded);
    }
    for placed in &layout.atoms {
        let Some(payload_offset) = layout.payload_offsets.get(&placed.atom.id).copied() else {
            continue;
        };
        while units.len() < payload_offset as usize {
            units.push(0);
        }
        match &placed.atom.instruction {
            EditableInstruction::Switch { cases, form, .. } => {
                units.extend(encode_switch_payload(*form, cases, placed.start, &layout)?);
            }
            EditableInstruction::FillArray { width, data, .. } => {
                units.extend(
                    Instruction::ArrayData(*width, data.clone())
                        .to_code_units()
                        .map_err(|_| DexEncodeError::UnsupportedEditInstruction)?,
                );
            }
            _ => return Err(DexEncodeError::InvalidCodeItem),
        }
    }
    if units.len() != layout.size as usize {
        return Err(DexEncodeError::InvalidCodeItem);
    }

    let mut new_code = Vec::with_capacity(16 + units.len() * 2);
    new_code.extend_from_slice(&code.register_size.to_le_bytes());
    new_code.extend_from_slice(&code.ins_size.to_le_bytes());
    new_code.extend_from_slice(&code.outs_size.to_le_bytes());
    new_code.extend_from_slice(&code.tries_size.to_le_bytes());
    // Debug positions are code-relative. Until debug-info rewriting is added,
    // omit them from a variable-length rewrite instead of leaving stale PCs.
    new_code.extend_from_slice(&0u32.to_le_bytes());
    new_code.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for unit in &units {
        new_code.extend_from_slice(&unit.to_le_bytes());
    }
    if let Some(try_data) = &try_data {
        if units.len() % 2 != 0 {
            new_code.extend_from_slice(&0u16.to_le_bytes());
        }
        let encoded_try_data = encode_try_data_mapped(
            try_data,
            |offset| map_try_start(&layout, offset),
            |offset| map_try_end(&layout, &segments, offset, original_instruction_end),
            |offset| map_try_handler(&layout, offset),
        )?;
        new_code.extend_from_slice(&encoded_try_data);
    }
    append_rewritten_code_item(dex, method_idx, class_idx, &new_code)
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
        .flat_map(|class| {
            class
                .codes
                .iter()
                .map(move |method| (class.class_idx, method))
        })
        .find(|(_, method)| method.method_idx == method_idx)
        .ok_or(DexEncodeError::MethodNotFound(method_idx))?;
    let code = code
        .code
        .as_ref()
        .ok_or(DexEncodeError::MethodHasNoCode(method_idx))?;
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
    let try_data = parse_try_data(raw, code)?;
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
    new_code.extend_from_slice(&code.tries_size.to_le_bytes());
    new_code.extend_from_slice(&code.debug_info_off.to_le_bytes());
    new_code.extend_from_slice(&((code.insns_size as usize + prefix.len()) as u32).to_le_bytes());
    for unit in prefix {
        new_code.extend_from_slice(&unit.to_le_bytes());
    }
    new_code.extend_from_slice(&raw[original_start..original_end]);
    if let Some(try_data) = &try_data {
        let prefix_units =
            u32::try_from(prefix.len()).map_err(|_| DexEncodeError::InvalidCodeItem)?;
        if (prefix.len() + code.insns_size as usize) % 2 != 0 {
            new_code.extend_from_slice(&0u16.to_le_bytes());
        }
        let encoded_try_data = encode_try_data_mapped(
            try_data,
            |offset| {
                offset
                    .checked_add(prefix_units)
                    .ok_or(DexEncodeError::InvalidCodeItem)
            },
            |offset| {
                offset
                    .checked_add(prefix_units)
                    .ok_or(DexEncodeError::InvalidCodeItem)
            },
            |offset| {
                offset
                    .checked_add(prefix_units)
                    .ok_or(DexEncodeError::InvalidCodeItem)
            },
        )?;
        new_code.extend_from_slice(&encoded_try_data);
    }

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
    output.resize(
        output.len() + (code_insert_delta as usize - code_padding - new_code.len()),
        0,
    );
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

fn section_content_end(raw: &[u8], entries: &[MapEntry], kind: u16) -> Result<u32, DexEncodeError> {
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
        if offset + 4 > dex.raw_data().len() {
            break;
        }
        let current = u32::from_le_bytes([
            dex.raw_data()[offset],
            dex.raw_data()[offset + 1],
            dex.raw_data()[offset + 2],
            dex.raw_data()[offset + 3],
        ]);
        if current == class_idx {
            return Ok(offset);
        }
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
        dex.raw_data()[offset],
        dex.raw_data()[offset + 1],
        dex.raw_data()[offset + 2],
        dex.raw_data()[offset + 3],
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
    let mut reader = UlebReader {
        bytes: input,
        offset: 0,
    };
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
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }
}

fn write_uleb(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn align_vec(output: &mut Vec<u8>, alignment: usize) {
    while output.len() % alignment != 0 {
        output.push(0);
    }
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
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
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
        assert!(reparsed
            .find_method_index("Ljava/lang/System;", "loadLibrary", "(Ljava/lang/String;)V")
            .is_some());
        let code = reparsed
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .find(|method| method.method_idx == method_idx)
            .and_then(|method| method.code.as_ref())
            .expect("injected method code");
        assert_eq!(
            code.insns_size,
            5 + dex
                .classes
                .iter()
                .flat_map(|class| class.codes.iter())
                .find(|method| method.method_idx == method_idx)
                .and_then(|method| method.code.as_ref())
                .map(|code| code.insns_size)
                .unwrap()
        );
    }

    #[test]
    fn ensure_dex_strings_adds_pool_entries_and_reparses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
        let value = "coeus-string-edit".to_string();
        assert!(dex.find_string_index(&value).is_none());
        let edited =
            ensure_dex_strings(&dex, std::slice::from_ref(&value)).expect("string pool rebuild");
        let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("edited DEX reparses");
        assert!(reparsed.find_string_index(&value).is_some());
        assert_eq!(reparsed.methods.len(), dex.methods.len());
    }

    #[test]
    fn replace_dex_string_keeps_string_index_and_reparses() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
        let string_index = dex
            .find_string_index("LDeadBranch;")
            .expect("test DEX has a string to replace");
        let replacement = "LReplacedString;";
        let edited =
            replace_dex_string(&dex, string_index, replacement).expect("string pool replacement");
        let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("edited DEX reparses");
        assert_eq!(
            reparsed.get_string(string_index as usize),
            Some(replacement)
        );
        assert_eq!(reparsed.methods.len(), dex.methods.len());
    }

    #[test]
    fn replace_dex_string_handles_variable_length_data_items() {
        let path = std::env::var_os("COEUS_REPLACE_FIXTURE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from("/private/tmp/coeus-dex-check/orig/classes.dex")
            });
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
        let string_index = dex
            .strings
            .iter()
            .enumerate()
            .find_map(|(index, entry)| {
                entry
                    .to_str()
                    .ok()
                    .filter(|value| value.len() >= 4)
                    .map(|_| index as u32)
            })
            .expect("test DEX has a replaceable string");

        for replacement in ["\t\tB", "\t\tAcquired: a longer replacement"] {
            let edited = replace_dex_string(&dex, string_index, replacement)
                .expect("variable-length string replacement");
            let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
                .expect("edited DEX reparses");
            assert_eq!(
                reparsed.get_string(string_index as usize),
                Some(replacement)
            );
            assert_eq!(reparsed.methods.len(), dex.methods.len());
        }

        let added_value = "\u{2588}\u{2588}a";
        let added =
            ensure_dex_strings(&dex, &[added_value.to_string()]).expect("sorted string addition");
        let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&added), false)
            .expect("edited DEX with added string reparses");
        assert!(read_string_pool_units(&reparsed)
            .expect("reparsed string pool")
            .iter()
            .any(|units| units == &[0x2588, 0x2588, b'a' as u16]));
    }

    #[test]
    fn replace_dex_string_reorders_pool_and_references() {
        let path = std::env::var_os("COEUS_REPLACE_FIXTURE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from("/private/tmp/coeus-dex-check/orig/classes.dex")
            });
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
        let string_index = dex
            .strings
            .iter()
            .enumerate()
            .find_map(|(index, entry)| {
                entry
                    .to_str()
                    .ok()
                    .filter(|value| *value == "\t\tAcquired:")
                    .map(|_| index as u32)
            })
            .expect("test DEX has the string-order fixture");
        let edited = replace_dex_string(&dex, string_index, "x")
            .expect("replacement may move within the sorted pool");
        let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("reordered string pool reparses");
        let new_index = reparsed.find_string_index("x").expect("replacement string");
        assert_ne!(new_index, string_index);
    }

    #[test]
    fn replace_instruction_uses_code_unit_width() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
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
        let edited =
            replace_method_instruction(&dex, method_idx, instruction_index, &Instruction::Nop)
                .expect("replace one-unit instruction");
        parse_dex_buf("classes.dex", &ArrayView::new(&edited), false).expect("edited DEX reparses");
    }

    #[test]
    fn prepend_method_rebuilds_aligned_map_list() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
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
                (code.tries_size == 0 && code.array_data.is_empty() && code.switch_data.is_empty())
                    .then_some(method.method_idx)
            })
            .next()
            .expect("test DEX has a method without payloads");

        let edited =
            prepend_method_code(&dex, method_idx, &[0x0000]).expect("prepend one-unit instruction");
        parse_dex_buf("classes.dex", &ArrayView::new(&edited), false).expect("edited DEX reparses");

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

    #[test]
    fn rewrite_method_supports_variable_width_edits() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
        let (method_idx, anchor) = dex
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .filter_map(|method| {
                let code = method.code.as_ref()?;
                let first = code
                    .insns
                    .iter()
                    .find(|(_, _, instruction)| !is_payload(instruction))?;
                (code.tries_size == 0 && first.0 .0 / 2 == 1)
                    .then_some((method.method_idx, first.1 .0))
            })
            .next()
            .expect("test DEX has a one-unit method entry");
        let edited = rewrite_method_code(
            &dex,
            method_idx,
            &[MethodEdit {
                anchor,
                position: EditPosition::Replace,
                instructions: vec![
                    EditableInstruction::Concrete(Instruction::Nop),
                    EditableInstruction::Concrete(Instruction::Nop),
                ],
            }],
        )
        .expect("rewrite method");
        let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("edited DEX reparses");
        let original_size = dex
            .get_method_by_idx(method_idx)
            .and_then(|method| method.code.as_ref().map(|code| code.insns_size))
            .unwrap();
        let edited_size = reparsed
            .get_method_by_idx(method_idx)
            .and_then(|method| method.code.as_ref().map(|code| code.insns_size))
            .unwrap();
        assert_eq!(edited_size, original_size + 1);
    }

    #[test]
    fn rewrite_method_repairs_if_targets_after_insertion() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dead_branch/classes.dex");
        let Ok(bytes) = fs::read(path) else {
            return;
        };
        let dex =
            parse_dex_buf("classes.dex", &ArrayView::new(&bytes), false).expect("test DEX parses");
        let candidate = dex
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .filter_map(|method| {
                let code = method.code.as_ref()?;
                if code.tries_size != 0 || code.array_data.len() != 0 || code.switch_data.len() != 0
                {
                    return None;
                }
                code.insns
                    .iter()
                    .find_map(|(_, offset, instruction)| match instruction {
                        Instruction::Test(_, _, _, relative) => Some((
                            method.method_idx,
                            offset.0,
                            offset.0 as i32 + *relative as i32,
                        )),
                        Instruction::TestZero(_, _, relative) => Some((
                            method.method_idx,
                            offset.0,
                            offset.0 as i32 + *relative as i32,
                        )),
                        _ => None,
                    })
            })
            .next();
        let Some((method_idx, branch_offset, old_target)) = candidate else {
            return;
        };
        let edited = rewrite_method_code(
            &dex,
            method_idx,
            &[MethodEdit {
                anchor: branch_offset,
                position: EditPosition::Before,
                instructions: vec![EditableInstruction::Concrete(Instruction::Nop)],
            }],
        )
        .expect("rewrite branch method");
        let reparsed = parse_dex_buf("classes.dex", &ArrayView::new(&edited), false)
            .expect("edited branch DEX reparses");
        let code = reparsed
            .get_method_by_idx(method_idx)
            .and_then(|method| method.code.as_ref().map(|code| code.clone()))
            .unwrap();
        let (_, new_offset, instruction) = code
            .insns
            .iter()
            .find(|(_, offset, instruction)| {
                offset.0 == branch_offset + 1
                    && matches!(
                        instruction,
                        Instruction::Test(..) | Instruction::TestZero(..)
                    )
            })
            .unwrap();
        let new_target = match instruction {
            Instruction::Test(_, _, _, relative) => new_offset.0 as i32 + *relative as i32,
            Instruction::TestZero(_, _, relative) => new_offset.0 as i32 + *relative as i32,
            _ => unreachable!(),
        };
        assert_eq!(new_target, old_target + 1);
    }

    #[test]
    fn switch_payload_sizes_match_dex_layout() {
        let targets = BTreeMap::from([
            (
                1,
                CodeTarget {
                    offset: 8,
                    position: TargetPosition::Instruction,
                },
            ),
            (
                2,
                CodeTarget {
                    offset: 10,
                    position: TargetPosition::Instruction,
                },
            ),
            (
                3,
                CodeTarget {
                    offset: 12,
                    position: TargetPosition::Instruction,
                },
            ),
        ]);
        let layout = Layout {
            atoms: vec![],
            targets: BTreeMap::from([
                ((8, TargetPosition::Instruction), 8),
                ((10, TargetPosition::Instruction), 10),
                ((12, TargetPosition::Instruction), 12),
            ]),
            payload_offsets: HashMap::new(),
            size: 0,
        };
        let packed = encode_switch_payload(SwitchForm::Auto, &targets, 0, &layout)
            .expect("packed switch payload");
        assert_eq!(packed.len(), 10);
        assert_eq!(packed[0], u16::from_le_bytes([0x00, 0x01]));
        assert_eq!(packed[1], 3);
        assert_eq!(switch_payload_units(SwitchForm::Packed, 3), 10);
        assert_eq!(switch_payload_units(SwitchForm::Sparse, 3), 14);
    }
}
