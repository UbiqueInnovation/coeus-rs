// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! This module contains all models used during the dex parsing.
//! It also defines a `Decode` trait which exposes a `from_bytes` function.
//! The trait is implemented for various default types.

use core::ops::{Add, AddAssign};

mod android;
pub use android::*;

mod binaryobject;
pub use binaryobject::*;

mod dexfile;
pub use dexfile::*;

mod encoding;
pub use encoding::*;

mod files;
pub use files::*;

mod instruction;
pub use instruction::*;

mod multidexfile;
pub use multidexfile::*;
use petgraph::dot::Dot;

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize, Eq, PartialEq)]
/// A Method as it is present in a Dex-File. The name is added for convenience, and to save a lookup in the string table.
pub struct Method {
    /// The index in the types pool. This indicates the class this method belongs to
    pub class_idx: u16,
    /// The index in the method pool of this function (this is essentially the order of this method)
    pub method_idx: u16,
    /// The index in the proto type pool
    pub proto_idx: u16,
    /// The index in the string pool for the name of this method
    pub name_idx: u32,
    /// Convenience field, to save unnecessary lookups
    pub method_name: String,
    /// Convenience field, to save unnecessary lookups
    pub proto_name: String,
}

impl Decode for Method {
    type DecodableUnit = Method;
    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let class_idx = u16::from_bytes(byte_view);
        let proto_idx = u16::from_bytes(byte_view);
        let name_idx = u32::from_bytes(byte_view);
        Self {
            class_idx,
            method_idx: 0,
            proto_idx,
            name_idx,
            method_name: String::from(""),
            proto_name: String::from(""),
        }
    }
}

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize, PartialEq, Eq)]
/// A field as it is present in the Dex-File. The name is added for convenience, and to save a lookup in the string table.
pub struct Field {
    /// The index in the types pool. This indicates the class this field belongs to
    pub class_idx: u16,
    /// The index in the types pool to define the type of this field
    pub type_idx: u16,
    /// The index in the string pool for the name of this method
    pub name_idx: u32,
    /// Convenience field, to prevent unnecassary string lookups
    pub name: String,
}
impl Decode for Field {
    type DecodableUnit = Field;
    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let class_idx = u16::from_bytes(byte_view);
        let type_idx = u16::from_bytes(byte_view);
        let name_idx = u32::from_bytes(byte_view);
        Self {
            class_idx,
            type_idx,
            name_idx,
            name: String::from(""),
        }
    }
}

#[repr(C)]
#[allow(dead_code)]
/// A type is represented as a index into the string pool, which gives a string representation of this type.
pub struct TypeItem {
    /// Index into the string poolm describing this type
    pub descriptor_idx: u32,
}
#[allow(dead_code)]

impl TypeItem {
    pub fn descriptor<'a>(&self, strings: &'a [&str]) -> &'a str {
        strings[self.descriptor_idx as usize]
    }
}
#[allow(dead_code)]

impl Proto {
    pub fn get_full_identifier<R: Read + Seek>(
        &self,
        current_pos: u64,
        dex: &mut R,
        types: &[&str],
    ) -> String {
        if self.parameters_off == 0 {
            return format!("(){}", types[self.return_type_idx as usize]);
        }
        let mut start = self.parameters_off as usize;

        dex.seek(SeekFrom::Start(start as u64)).unwrap();
        let mut len_bytes: [u8; 4] = [0; 4];
        dex.read_exact(&mut len_bytes).unwrap();
        let length = i32::from_le_bytes(len_bytes);

        start += 4;
        let mut identifier = vec![];
        for _ in 0..length {
            let mut idx_bytes: [u8; 2] = [0; 2];
            dex.read_exact(&mut idx_bytes).unwrap();
            let idx = u16::from_le_bytes(idx_bytes);

            identifier.push(types[idx as usize]);
            start += 2;
        }
        dex.seek(SeekFrom::Start(current_pos)).unwrap();
        format!(
            "({}){}",
            identifier.join(""),
            types[self.return_type_idx as usize]
        )
    }
}
#[allow(dead_code)]
impl Method {
    pub fn get_description(
        &self,
        types: &[&str],
        strings: &[StringEntry],
        proto_types: &[Proto],
    ) -> String {
        let class_name = &types[self.class_idx as usize];
        let ret_type = types[proto_types[self.proto_idx as usize].return_type_idx as usize];
        let name = std::str::from_utf8(&strings[self.name_idx as usize].dat).unwrap();
        let short_idx = std::str::from_utf8(
            &strings[proto_types[self.proto_idx as usize].shorty_idx as usize].dat,
        )
        .unwrap();
        format!(
            "In Class {}  Return Type: {}  Name: {}(...)[{}]",
            class_name, ret_type, name, short_idx
        )
    }

    pub fn get_classname(&self, types: &[&str]) -> String {
        types[self.class_idx as usize].to_string()
    }
    pub fn get_function_name<'a>(&self, strings: &'a [StringEntry]) -> Cow<'a, str> {
        String::from_utf8_lossy(&strings[self.name_idx as usize].dat)
    }
    pub fn get_prototype(&self, strings: &[StringEntry], proto_types: &[Proto]) -> String {
        let proto = &proto_types[self.proto_idx as usize];
        std::str::from_utf8(&strings[proto.shorty_idx as usize].dat)
            .unwrap_or("INVALID_TYPE")
            .to_string()
    }
}
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

pub struct Proto {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    pub arguments: Vec<u16>,
}
impl Proto {
    pub fn to_string(&self, file: &DexFile) -> String {
        let return_type = self.get_return_type(file);
        let args = self
            .arguments
            .iter()
            .map(|&arg| file.get_type_name(arg).unwrap_or("INVALID").to_string())
            .collect::<Vec<_>>()
            .join("");
        format!("({}){}", args, return_type)
    }
    pub fn get_return_type(&self, file: &DexFile) -> String {
        file.get_type_name(self.return_type_idx as usize)
            .unwrap_or("INVALID")
            .to_string()
    }
}
impl Decode for Proto {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let shorty_idx = u32::from_bytes(byte_view);
        let return_type_idx = u32::from_bytes(byte_view);
        let parameters_off = u32::from_bytes(byte_view);
        //TODO: is there a better method?
        let current = byte_view.seek(SeekFrom::Current(0)).unwrap();
        let mut arguments = vec![];
        if parameters_off != 0 {
            byte_view
                .seek(SeekFrom::Start(parameters_off as u64))
                .unwrap();
            let size = u32::from_bytes(byte_view);
            for _ in 0..size {
                arguments.push(u16::from_bytes(byte_view));
            }
        }
        byte_view.seek(SeekFrom::Start(current)).unwrap();
        Self {
            shorty_idx,
            return_type_idx,
            parameters_off,
            arguments,
        }
    }
}
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]

pub struct StringEntry {
    pub utf16_size: u32,
    pub dat: Vec<u8>,
}

impl StringEntry {
    pub fn to_string(self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.dat)
    }
    pub fn to_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.dat)
    }
    pub fn to_str_lossy(&self) -> Cow<str> {
        // String::from_utf8_lossy(&self.dat)
        cesu8::from_java_cesu8(&self.dat).unwrap_or(String::from_utf8_lossy(&self.dat))
    }
}

impl Decode for StringEntry {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let (bytes, val) = StringEntry::read_leb128(byte_view).expect("Cannot read uleb");
        let mut buf = Vec::with_capacity(bytes);
        byte_view
            .take(val)
            .read_to_end(&mut buf)
            .expect("Could not take n bytes");
        StringEntry {
            utf16_size: val as u32,
            dat: buf,
        }
    }
}

#[derive(Debug, Clone)]
struct ClassRef(Class, String);
use std::{ops::Deref, sync::Arc};

impl Deref for ClassRef {
    type Target = Class;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[repr(C)]
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]

pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub fields_ids_size: u32,
    pub fields_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl Decode for DexHeader {
    type DecodableUnit = Self;
    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut my_self: Self = unsafe { std::mem::zeroed() };
        Self::read(&mut my_self, byte_view);
        my_self
    }
}

#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

pub struct EncodedArray {
    items: Vec<EncodedItem>,
}

impl EncodedArray {
    pub fn get_items(&self) -> &[EncodedItem] {
        &self.items
    }
    pub fn into_items(self) -> Vec<EncodedItem> {
        self.items
    }
}
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

pub struct EncodedItem {
    value_arg: u8,
    pub value_type: ValueType,
    values: Vec<u8>,
    pub inner: Option<EncodedArray>,
}

#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

pub enum ValueType {
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
    MethodType,
    MethodHandle,
    String,
    Type,
    Field,
    Method,
    Enum,
    Array,
    Annotation,
    Null,
    Boolean,
}

impl Decode for EncodedArray {
    type DecodableUnit = EncodedArray;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let (_, size) = Self::read_leb128(byte_view).expect("cannot get size of array");
        let mut items = vec![];
        for _ in 0..size {
            let item = EncodedItem::from_bytes(byte_view);
            items.push(item);
        }
        EncodedArray { items }
    }
}
use std::convert::TryFrom;
use std::convert::TryInto;
impl EncodedItem {
    pub fn get_field_id(&self) -> u32 {
        if !matches!(self.value_type, ValueType::Field) {
            return 0xff_ff_ff_ff;
        };
        let mut bytes = [0u8; 4];
        let mut handle = self.values.take(4);
        handle.read(&mut bytes).expect("Cannot read field_id");
        u32::from_le_bytes(bytes)
    }
    pub fn get_string_id(&self) -> u32 {
        if !matches!(self.value_type, ValueType::String) {
            return 0xff_ff_ff_ff;
        };
        let mut bytes = [0u8; 4];
        let mut handle = self.values.take(4);
        handle.read(&mut bytes).expect("Cannot read field_id");
        u32::from_le_bytes(bytes)
    }
    pub fn try_get_value<T: TryFrom<EncodedItem>>(&self) -> Option<T> {
        let self_clone = self.to_owned();
        self_clone.try_into().ok()
    }
    pub fn try_get_string<'a>(&self, file: &'a DexFile) -> Option<&'a str> {
        file.get_string(self.get_string_id() as usize)
    }
    pub fn to_string_with_string_indexer<F>(&self, get_string: F) -> String
    where
        F: Fn(usize) -> String,
    {
        match self.value_type {
            ValueType::Byte => format!("0x{:2x}", self.try_get_value::<u8>().unwrap()),
            ValueType::Short => format!("{}", self.try_get_value::<u16>().unwrap()),
            ValueType::Char => format!("'{}'", self.try_get_value::<char>().unwrap()),
            ValueType::Int => format!("{}", self.try_get_value::<u32>().unwrap()),
            ValueType::Long => format!("{}", self.try_get_value::<u64>().unwrap()),
            ValueType::Float => format!("{:?}", self),
            ValueType::Double => format!("{:?}", self),
            ValueType::MethodType => format!("{:?}", self),
            ValueType::MethodHandle => format!("{:?}", self),
            ValueType::String => format!("\"{}\"", get_string(self.get_string_id() as usize)),
            ValueType::Type => format!("{:?}", self),
            ValueType::Field => format!("{:?}", self),
            ValueType::Method => format!("{:?}", self),
            ValueType::Enum => format!("{:?}", self),
            ValueType::Array => format!("{:?}", self),
            ValueType::Annotation => format!("{:?}", self),
            ValueType::Null => format!("null"),
            ValueType::Boolean => format!("{}", self.try_get_value::<bool>().unwrap()),
        }
    }
    pub fn to_string(&self, file: &DexFile) -> String {
        self.to_string_with_string_indexer(|idx| {
            file.get_string(idx as usize)
                .unwrap_or("STRING_NOT_FOUND")
                .to_string()
        })
    }
}

impl Decode for EncodedItem {
    type DecodableUnit = EncodedItem;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let byte = u8::from_bytes(byte_view);
        let value_arg = (byte & 0b1110_0000) >> 5;
        let value_type = byte & 0b0001_1111;
        let value_type = match value_type {
            0x0 => ValueType::Byte,
            0x02 => ValueType::Short,
            0x03 => ValueType::Char,
            0x04 => ValueType::Int,
            0x06 => ValueType::Long,
            0x10 => ValueType::Float,
            0x11 => ValueType::Double,
            0x15 => ValueType::MethodType,
            0x16 => ValueType::MethodHandle,
            0x17 => ValueType::String,
            0x18 => ValueType::Type,
            0x19 => ValueType::Field,
            0x1a => ValueType::Method,
            0x1b => ValueType::Enum,
            0x1c => ValueType::Array,
            0x1d => ValueType::Annotation,
            0x1e => ValueType::Null,
            0x1f => ValueType::Boolean,
            _ => panic!("Wrong type {} / {:.2x}", value_arg, value_type),
        };
        if matches!(value_type, ValueType::Boolean | ValueType::Null) {
            EncodedItem {
                value_arg,
                value_type,
                values: vec![],
                inner: None,
            }
        } else if matches!(value_type, ValueType::Array) {
            let encoded_array = EncodedArray::from_bytes(byte_view);
            EncodedItem {
                value_arg,
                value_type,
                values: vec![],
                inner: Some(encoded_array),
            }
        } else if matches!(value_type, ValueType::Annotation) {
            EncodedItem {
                value_arg,
                value_type,
                values: vec![],
                inner: None,
            }
        } else {
            let mut buffer = vec![0u8; (value_arg + 1) as usize];
            byte_view
                .read_exact(&mut buffer)
                .expect("Could not write variable length");
            EncodedItem {
                value_arg,
                value_type,
                values: buffer,
                inner: None,
            }
        }
    }
}

macro_rules! impl_value_type {
    ($rust_type:ty, $value_type:path, |$the_ident:ident|$conv:block ) => {
        // Implement Into for convenience
        impl TryInto<Vec<$rust_type>> for EncodedArray {
            type Error = Box<dyn std::error::Error>;
            fn try_into(self) -> Result<Vec<$rust_type>, Self::Error> {
                self.items
                    .into_iter()
                    .map(|item| (item).try_into())
                    .collect()
            }
        }
        impl TryInto<Vec<$rust_type>> for &EncodedArray {
            type Error = Box<dyn std::error::Error>;
            fn try_into(self) -> Result<Vec<$rust_type>, Self::Error> {
                self.items
                    .iter()
                    .map(|item| (item).clone().try_into())
                    .collect()
            }
        }
        impl TryFrom<EncodedItem> for $rust_type {
            type Error = Box<dyn std::error::Error>;

            fn try_from($the_ident: EncodedItem) -> Result<Self, Self::Error> {
                if matches!($the_ident.value_type, $value_type) {
                    Ok($conv)
                } else {
                    Err("Not the correct type".into())
                }
            }
        }
    };
}

// TODO: We need to figure out if the read does what we actually want. The documentation suggests to sign extend the values,
// which we are currently completly ignoring.

impl_value_type!(EncodedArray, ValueType::Array, |e| { e.inner.unwrap() });

impl_value_type!(bool, ValueType::Boolean, |e| { e.value_arg == 1 });

impl_value_type!(u8, ValueType::Byte, |e| { e.values[0] });

impl_value_type!(char, ValueType::Char, |e| { e.values[0] as char });

impl_value_type!(u16, ValueType::Short, |e| {
    let mut bytes = [0u8; 2];
    let mut handle = e.values.take(2);
    handle.read(&mut bytes).expect("Cannot Read");
    u16::from_le_bytes(bytes)
});

impl_value_type!(u32, ValueType::Int, |e| {
    let mut bytes = [0u8; 4];
    let mut handle = e.values.take(4);
    handle.read(&mut bytes).expect("Cannot read");
    u32::from_le_bytes(bytes)
});

impl_value_type!(u64, ValueType::Long, |e| {
    let mut bytes = [0u8; 8];
    let mut handle = e.values.take(8);
    handle.read(&mut bytes).expect("Cannot read");
    u64::from_le_bytes(bytes)
});

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct MethodData {
    pub name: String,
    pub method: Arc<Method>,
    pub method_idx: u32,
    pub access_flags: AccessFlags,
    pub code: Option<CodeItem>,
    #[serde(skip_serializing, skip_deserializing)]
    pub call_graph: Option<Graph<(u32, Instruction), i32>>,
}
impl PartialEq for MethodData {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.method == other.method
            && self.method_idx == other.method_idx
            && self.access_flags == other.access_flags
            && self.code == other.code
    }
}

impl MethodData {
    pub fn get_instruction_graph(&self, file: &Arc<DexFile>) -> String {
        let Some(cg) = self.call_graph.as_ref() else {
            return String::new();
        };
        let mut cg = cg.clone();
        let mut addr_label = HashMap::new();
        for n in cg.node_weights_mut() {
            let m =
                n.1.disassembly_from_opcode(n.0 as i32, &mut addr_label, file.clone());
            n.1 = Instruction::ArbitraryData(m);
        }
        format!("{:?}", Dot::new(&cg))
    }
    pub fn get_disassembly(&self, file: &Arc<DexFile>) -> String {
        let mut lines = vec![];
        if let Some(proto) = file.protos.get(self.method.proto_idx as usize) {
            let return_type = file
                .get_type_name(proto.return_type_idx as usize)
                // .and_then(|t| t.split("/").last())
                // .and_then(|t| Some(t.replace(";", "")))
                .unwrap_or("INVALID")
                .to_string();
            let args = proto
                .arguments
                .iter()
                .map(|&arg| {
                    file.get_type_name(arg)
                        // .and_then(|t| t.split("/").last())
                        // .and_then(|t| Some(t.replace(";", "")))
                        .unwrap_or("INVALID")
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join("");
            lines.push(format!(
                ".method {} {}({}){}",
                self.access_flags.get_string_representation(),
                self.name,
                args,
                return_type
            ));
            if let Some(method_details) = &self.code {
                lines.push(format!(".registers {}", method_details.register_size));
                let mut code_lines = HashMap::new();
                let mut labels = HashMap::new();
                for instruction in &method_details.insns {
                    code_lines.insert(
                        instruction.1,
                        instruction.2.disassembly_from_opcode(
                            instruction.1 .0 as i32,
                            &mut labels,
                            file.clone(),
                        ),
                    );
                }
                for label in labels {
                    let line = code_lines
                        .entry(label.0.into())
                        .or_insert_with(|| "".to_string());
                    *line = format!(":{} #{:#x}\n{} ", label.1, label.0, line,);
                }
                let mut lines_of_code: Vec<_> = code_lines.into_iter().collect();
                lines_of_code.sort_by(|(addr1, _), (addr2, _)| addr1.partial_cmp(addr2).unwrap());
                lines.extend(
                    lines_of_code
                        .into_iter()
                        .map(|(addr, line)| format!("{} #{:#x}", line, u32::from(addr))),
                );
            }
            lines.push(format!(".end method"));
        }
        lines.join("\n")
    }
}

use bitflags::*;

bitflags! {
#[derive(::serde::Serialize, ::serde::Deserialize, PartialEq, Clone, Debug, Copy)]
   pub struct AccessFlags: u64 {
        const PUBLIC = 0x1;
        const PRIVATE = 0x2;
        const PROTECTED = 0x4;
        const STATIC = 0x8;
        const FINAL = 0x10;
        const SYNCRHONIZED = 0x20;
        const VOLATILE = 0x40;
        const BRIDGE_OR_VOLATILE = 0x40;
        const TRANSIENT_OR_VARARGS = 0x80;
        const NATIVE = 0x100;
        const INTERFACE = 0x200;
        const ABSTRACT = 0x400;
        const STRICT = 0x800;
        const SYNTHETIC = 0x1000;
        const ANNOTATION = 0x2000;
        const ENUM = 0x4000;
        const CONSTRUCTOR = 0x10000;
        const DECLARED_SYNCHRONIZED= 0x20000;

    }
}

impl std::fmt::Display for AccessFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.get_string_representation())
    }
}

impl AccessFlags {
    pub fn get_string_representation(&self) -> String {
        let mut flags = vec![];
        if self.contains(AccessFlags::PUBLIC) {
            flags.push("public");
        } else if self.contains(AccessFlags::PRIVATE) {
            flags.push("private");
        } else if self.contains(AccessFlags::PROTECTED) {
            flags.push("protected");
        }

        if self.contains(AccessFlags::STATIC) {
            flags.push("static");
        } else if self.contains(AccessFlags::FINAL) {
            flags.push("final");
        } else if self.contains(AccessFlags::SYNCRHONIZED) {
            flags.push("synchronized");
        }

        if self.contains(AccessFlags::NATIVE) {
            flags.push("native");
        }
        if self.contains(AccessFlags::INTERFACE) {
            flags.push("interface");
        }
        if self.contains(AccessFlags::ABSTRACT) {
            flags.push("abstract");
        }
        if self.contains(AccessFlags::STRICT) {
            flags.push("strict");
        }
        if self.contains(AccessFlags::ANNOTATION) {
            flags.push("annotation");
        }
        if self.contains(AccessFlags::ENUM) {
            flags.push("enum");
        }
        if self.contains(AccessFlags::CONSTRUCTOR) {
            flags.push("constructor");
        }

        flags.join(" ")
    }
}

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize, PartialEq)]
pub enum AnnotationVisibility {
    VisibilityBuild,
    VisibilityRuntime,
    VisibilitySystem,
    Unknown,
}

impl std::fmt::Display for AnnotationVisibility {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.get_string_representation())
    }
}

impl AnnotationVisibility {
    pub fn get_string_representation(&self) -> String {
        match self {
            AnnotationVisibility::VisibilityBuild => String::from("Build"),
            AnnotationVisibility::VisibilityRuntime => String::from("Runtime"),
            AnnotationVisibility::VisibilitySystem => String::from("System"),
            AnnotationVisibility::Unknown => String::from("Error"),
        }
    }
}

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct AnnotationElementsData {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct Annotation {
    pub visibility: AnnotationVisibility,
    pub type_idx: u64,
    pub class_name: String,
    pub elements: Vec<AnnotationElementsData>,
}

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct AnnotationMethod {
    pub method_idx: u32,
    pub visibility: AnnotationVisibility,
    pub type_idx: u64,
    pub class_name: String,
    pub elements: Vec<AnnotationElementsData>,
}
#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct AnnotationField {
    pub field_idx: u32,
    pub visibility: AnnotationVisibility,
    pub type_idx: u64,
    pub class_name: String,
    pub elements: Vec<AnnotationElementsData>,
}

#[derive(Clone, Debug, ::serde::Serialize, ::serde::Deserialize)]
pub struct Class {
    pub dex_identifier: String,
    pub class_idx: u32,
    pub class_name: String,
    pub access_flags: AccessFlags,
    pub super_class: u32,
    pub interfaces: Vec<u16>,
    pub annotations_off: u32,
    pub annotations: Vec<Annotation>,
    pub method_annotations: Vec<AnnotationMethod>,
    pub field_annotations: Vec<AnnotationField>,
    #[serde(skip_serializing)]
    pub class_data: Option<ClassData>,
    // #[serde(skip_serializing)]
    pub codes: Vec<Arc<MethodData>>,
    #[serde(skip_serializing)]
    pub static_fields: Vec<EncodedItem>,
}
impl PartialEq for Class {
    fn eq(&self, other: &Self) -> bool {
        self.dex_identifier == other.dex_identifier && self.class_idx == other.class_idx
    }
}

impl Default for Class {
    fn default() -> Self {
        Self::new("".to_string(), 0, "INVALID".to_string())
    }
}

impl Class {
    pub fn new(dex_identifier: String, class_idx: u32, class_name: String) -> Class {
        Class {
            dex_identifier,
            class_idx,
            class_name,
            access_flags: AccessFlags::PUBLIC,
            super_class: 1,
            interfaces: vec![],
            annotations_off: 0,
            annotations: vec![],
            method_annotations: vec![],
            field_annotations: vec![],
            class_data: None,
            codes: vec![],
            static_fields: vec![],
        }
    }
    pub fn get_package_name(&self) -> String {
        let friendly_name = self.get_human_friendly_name();
        let splits = friendly_name.split('.').collect::<Vec<_>>();
        splits
            .last()
            .map(|a| a.to_string())
            .unwrap_or(friendly_name)
    }
    pub fn get_human_friendly_name(&self) -> String {
        self.class_name
            .replace("L", "")
            .replace(";", "")
            .replace("/", ".")
    }

    pub fn get_data_for_static_field(&self, field_idx: u32) -> Option<&EncodedItem> {
        if let Some(cd) = &self.class_data {
            for (data, field) in self.static_fields.iter().zip(&cd.static_fields) {
                if field.field_idx == field_idx {
                    return Some(data);
                }
            }
        }
        None
    }
    pub fn get_superclass(&self, dex_file: Arc<DexFile>) -> Option<Arc<Self>> {
        let super_class_id = self.super_class;
        let c = dex_file.get_class_by_type(super_class_id)?;
        Some(c)
    }
    pub fn get_disassembly(&self, md: &MultiDexFile) -> String {
        let file = md
            .dex_file_from_identifier(&self.dex_identifier)
            .expect("Multi Dex File needs to match this class");
        let class_name = self.class_name.clone();
        let (file, class) = if !self.codes.is_empty() && self.class_data.is_some() {
            (file, Arc::new(self.clone()))
        } else if let Some((file, class)) = md
            .classes()
            .iter()
            .find(|(_, class)| class.class_name == class_name)
        {
            (file.clone(), class.clone())
        } else {
            return "NO CLASS DEF FOUND".to_string();
        };
        let mut lines = vec![];
        lines.push(format!(
            ".class {} {}",
            class.access_flags.get_string_representation(),
            class_name
        ));
        lines.push(format!(
            ".super {}",
            file.get_type_name(class.super_class as usize)
                .unwrap_or("INVALID")
        ));
        for &interface in &self.interfaces {
            lines.push(format!(
                ".implements {}",
                file.get_type_name(interface).unwrap_or("INVALID")
            ));
        }

        if let Some(class_data) = &class.class_data {
            for field in &class_data.instance_fields {
                if let Some(the_field) = file.fields.get(field.field_idx as usize) {
                    lines.push(format!(
                        ".field {} {}:{}",
                        field.access_flags.get_string_representation(),
                        the_field.name,
                        file.get_type_name(the_field.type_idx).unwrap_or("")
                    ));
                }
            }
            for (index, field) in class_data.static_fields.iter().enumerate() {
                if let Some(the_field) = file.fields.get(field.field_idx as usize) {
                    // let value_string =
                    lines.push(format!(
                        ".field {} {}:{} {}",
                        field.access_flags.get_string_representation(),
                        the_field.name,
                        file.get_type_name(the_field.type_idx).unwrap_or(""),
                        if let Some(item) = self.static_fields.get(index) {
                            String::from("= ") + item.to_string(&file).as_str()
                        } else {
                            String::new()
                        }
                    ))
                }
            }
        }

        for code in &class.codes {
            let method_code = code.get_disassembly(&file);
            lines.push(method_code);
        }

        lines.join("\n")
    }
}

#[repr(C)]
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]
pub struct AnnotationElement {
    pub name_idx: u64,
    pub value: EncodedItem,
}

impl Decode for AnnotationElement {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let (_, n_idx) = Self::read_leb128(byte_view).unwrap();
        let val = EncodedItem::from_bytes(byte_view);

        Self {
            name_idx: n_idx,
            value: val,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
pub struct EncodedAnnotation {
    pub type_idx: u64,
    pub size: u64,
    pub elements: Vec<AnnotationElement>,
}

impl Decode for EncodedAnnotation {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let (_, type_idx) = Self::read_leb128(byte_view).unwrap();
        let (_, size) = Self::read_leb128(byte_view).unwrap();

        let mut elements: Vec<AnnotationElement> = vec![];
        for _ in 0..size {
            let annotation_element: AnnotationElement = AnnotationElement::from_bytes(byte_view);
            elements.push(annotation_element);
        }

        Self {
            type_idx,
            size,
            elements,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct AnnotationItem {
    pub visibility: AnnotationVisibility,
    pub annotation: EncodedAnnotation,
}

impl Decode for AnnotationItem {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let vis: AnnotationVisibility = match u8::from_bytes(byte_view) {
            0x00 => AnnotationVisibility::VisibilityBuild,
            0x01 => AnnotationVisibility::VisibilityRuntime,
            0x02 => AnnotationVisibility::VisibilitySystem,
            _ => AnnotationVisibility::Unknown,
        };

        let enc_annotation: EncodedAnnotation = EncodedAnnotation::from_bytes(byte_view);

        Self {
            visibility: vis,
            annotation: enc_annotation,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct AnnotationOffItem {
    pub annotation_off: u32,
}

impl Decode for AnnotationOffItem {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let off = u32::from_bytes(byte_view);

        Self {
            annotation_off: off,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct AnnotationSetItem {
    pub size: u32,
    pub entries: Vec<AnnotationOffItem>,
}

impl Decode for AnnotationSetItem {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let size = u32::from_bytes(byte_view);

        let mut entries: Vec<AnnotationOffItem> = vec![];

        for _ in 0..size {
            let annotation_off_item: AnnotationOffItem = AnnotationOffItem::from_bytes(byte_view);
            entries.push(annotation_off_item);
        }

        Self { size, entries }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FieldAnnotation {
    pub field_idx: u32,
    pub annotations_off: u32,
}

impl Decode for FieldAnnotation {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let field_idx = u32::from_bytes(byte_view);
        let annotations_off = u32::from_bytes(byte_view);
        Self {
            field_idx,
            annotations_off,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MethodAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

impl Decode for MethodAnnotation {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let method_idx = u32::from_bytes(byte_view);
        let annotations_off = u32::from_bytes(byte_view);
        Self {
            method_idx,
            annotations_off,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ParameterAnnotation {
    pub method_idx: u32,
    pub annotations_off: u32,
}

impl Decode for ParameterAnnotation {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let method_idx = u32::from_bytes(byte_view);
        let annotations_off = u32::from_bytes(byte_view);
        Self {
            method_idx,
            annotations_off,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct AnnotationsDirectoryItem {
    pub class_annotations_off: u32,
    pub fields_size: u32,
    pub annotated_methods_size: u32,
    pub annotated_parameters_size: u32,
    pub field_annotations: Vec<FieldAnnotation>,
    pub method_annotations: Vec<MethodAnnotation>,
    pub parameter_annotations: Vec<ParameterAnnotation>,
}

impl Decode for AnnotationsDirectoryItem {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let class_annotations_off: u32 = u32::from_bytes(byte_view);
        let fields_size: u32 = u32::from_bytes(byte_view);
        let annotated_methods_size: u32 = u32::from_bytes(byte_view);
        let annotated_parameters_size: u32 = u32::from_bytes(byte_view);

        let mut field_annotations: Vec<FieldAnnotation> = vec![];
        let mut method_annotations: Vec<MethodAnnotation> = vec![];
        let mut parameter_annotations: Vec<ParameterAnnotation> = vec![];

        for _ in 0..fields_size {
            let field_annotation: FieldAnnotation = FieldAnnotation::from_bytes(byte_view);
            field_annotations.push(field_annotation);
        }

        for _ in 0..annotated_methods_size {
            let method_annotation: MethodAnnotation = MethodAnnotation::from_bytes(byte_view);
            method_annotations.push(method_annotation);
        }

        for _ in 0..annotated_parameters_size {
            let parameter_annotation: ParameterAnnotation =
                ParameterAnnotation::from_bytes(byte_view);
            parameter_annotations.push(parameter_annotation);
        }

        Self {
            class_annotations_off,
            fields_size,
            annotated_methods_size,
            annotated_parameters_size,
            field_annotations,
            method_annotations,
            parameter_annotations,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ClassDefItem {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

impl Decode for ClassDefItem {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut my_self: Self = unsafe { std::mem::zeroed() };
        Self::read(&mut my_self, byte_view);
        my_self
    }
}
#[repr(C)]
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

pub struct ClassData {
    pub static_fields_size: u64,
    pub instance_fields_size: u64,
    pub direct_methods_size: u64,
    pub virtual_methods_size: u64,

    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

impl Decode for ClassData {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let (_, static_fields_size) = ClassData::read_leb128(byte_view).unwrap();
        let (_, instance_fields_size) = ClassData::read_leb128(byte_view).unwrap();
        let (_, direct_methods_size) = ClassData::read_leb128(byte_view).unwrap();
        let (_, virtual_methods_size) = ClassData::read_leb128(byte_view).unwrap();

        let mut static_fields = vec![];
        let mut instance_fields = vec![];
        let mut direct_methods = vec![];
        let mut virtual_methods = vec![];
        let mut last_index = 0;

        for i in 0..static_fields_size {
            let mut field = EncodedField::from_bytes(byte_view);
            if i == 0 {
                last_index = field.field_idx;
            } else {
                last_index += field.field_idx;
                field.field_idx = last_index;
            }
            static_fields.push(field);
        }
        last_index = 0;
        for i in 0..instance_fields_size {
            let mut field = EncodedField::from_bytes(byte_view);
            if i == 0 {
                last_index = field.field_idx;
            } else {
                last_index += field.field_idx;
                field.field_idx = last_index;
            }
            instance_fields.push(field);
        }
        last_index = 0;
        for i in 0..direct_methods_size {
            let mut field = EncodedMethod::from_bytes(byte_view);
            if i == 0 {
                last_index = field.method_idx;
            } else {
                last_index += field.method_idx;
                field.method_idx = last_index;
            }
            direct_methods.push(field);
        }
        last_index = 0;
        for i in 0..virtual_methods_size {
            let mut field = EncodedMethod::from_bytes(byte_view);
            if i == 0 {
                last_index = field.method_idx;
            } else {
                last_index += field.method_idx;
                field.method_idx = last_index;
            }
            virtual_methods.push(field);
        }

        ClassData {
            static_fields_size,
            instance_fields_size,
            direct_methods_size,
            virtual_methods_size,
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: AccessFlags,
}
impl Decode for EncodedField {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let (_, diff) = Self::read_leb128(byte_view).unwrap();
        let (_, flags) = Self::read_leb128(byte_view).unwrap();
        Self {
            field_idx: diff as u32,
            access_flags: AccessFlags::from_bits(flags).expect("access flags wrong"),
        }
    }
}
#[repr(C)]
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: AccessFlags,
    pub code_off: u64,
}

impl Decode for EncodedMethod {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let (_, diff) = Self::read_leb128(byte_view).unwrap();
        let (_, flags) = Self::read_leb128(byte_view).unwrap();
        let (_, code_off) = Self::read_leb128(byte_view).unwrap();
        Self {
            method_idx: diff as u32,
            access_flags: AccessFlags::from_bits(flags).expect("access flags wrong"),
            code_off,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    ::serde::Serialize,
    ::serde::Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct InstructionSize(pub u32);
#[derive(
    Debug,
    Clone,
    Copy,
    ::serde::Serialize,
    ::serde::Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct InstructionOffset(pub u32);

impl Add<InstructionSize> for InstructionOffset {
    type Output = InstructionOffset;

    fn add(self, rhs: InstructionSize) -> Self::Output {
        self + rhs.0
    }
}
impl AddAssign<InstructionSize> for InstructionOffset {
    fn add_assign(&mut self, rhs: InstructionSize) {
        *self = *self + rhs;
    }
}

impl Add<u32> for InstructionOffset {
    type Output = InstructionOffset;

    fn add(self, rhs: u32) -> Self::Output {
        (self.0 + rhs).into()
    }
}
impl AddAssign<u32> for InstructionOffset {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0 + rhs;
    }
}

impl Add<i32> for InstructionOffset {
    type Output = InstructionOffset;

    fn add(self, rhs: i32) -> Self::Output {
        (self.0 as i32 + rhs).into()
    }
}
impl AddAssign<i32> for InstructionOffset {
    fn add_assign(&mut self, rhs: i32) {
        self.0 = (self.0 as i32 + rhs) as u32;
    }
}

impl Add<u32> for InstructionSize {
    type Output = InstructionSize;

    fn add(self, rhs: u32) -> Self::Output {
        (self.0 + rhs).into()
    }
}
impl AddAssign<u32> for InstructionSize {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0 + rhs;
    }
}

impl Add<i32> for InstructionSize {
    type Output = InstructionSize;

    fn add(self, rhs: i32) -> Self::Output {
        (self.0 as i32 + rhs).into()
    }
}
impl AddAssign<i32> for InstructionSize {
    fn add_assign(&mut self, rhs: i32) {
        self.0 = (self.0 as i32 + rhs) as u32;
    }
}

impl From<InstructionOffset> for u32 {
    fn from(inner: InstructionOffset) -> Self {
        inner.0
    }
}

impl From<InstructionSize> for u32 {
    fn from(inner: InstructionSize) -> Self {
        inner.0
    }
}

impl From<InstructionOffset> for i32 {
    fn from(inner: InstructionOffset) -> Self {
        inner.0 as i32
    }
}
impl From<i32> for InstructionSize {
    fn from(v: i32) -> Self {
        InstructionSize(v as u32)
    }
}
impl From<i32> for InstructionOffset {
    fn from(v: i32) -> Self {
        InstructionOffset(v as u32)
    }
}
impl From<u32> for InstructionSize {
    fn from(v: u32) -> Self {
        InstructionSize(v)
    }
}
impl From<u32> for InstructionOffset {
    fn from(v: u32) -> Self {
        InstructionOffset(v)
    }
}
impl From<InstructionSize> for i32 {
    fn from(inner: InstructionSize) -> Self {
        inner.0 as i32
    }
}

impl From<InstructionOffset> for usize {
    fn from(inner: InstructionOffset) -> Self {
        inner.0 as usize
    }
}

impl From<InstructionSize> for usize {
    fn from(inner: InstructionSize) -> Self {
        inner.0 as usize
    }
}

#[repr(C)]
#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, PartialEq)]

//we ignore try handlers for know
pub struct CodeItem {
    /// Absolute offset of this code_item in the containing DEX file.
    pub code_off: u32,
    pub register_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    #[serde(skip_serializing, skip_deserializing)]
    pub insns: Vec<(InstructionSize, InstructionOffset, Instruction)>,
    #[serde(skip_serializing, skip_deserializing)]
    pub array_data: Vec<(InstructionSize, InstructionOffset, Instruction)>,
    #[serde(skip_serializing, skip_deserializing)]
    pub switch_data: Vec<(InstructionSize, InstructionOffset, Instruction)>,
}
#[derive(Clone, Debug, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
pub struct Switch {
    id: u32,
    pub targets: HashMap<i32, i32>,
}
use std::hash::Hash;
#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Switch {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Decode for CodeItem {
    type DecodableUnit = Self;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let register_size = u16::from_bytes(byte_view);
        let ins_size = u16::from_bytes(byte_view);
        let outs_size = u16::from_bytes(byte_view);
        let tries_size = u16::from_bytes(byte_view);
        let debug_info_off = u32::from_bytes(byte_view);
        let insns_size = u32::from_bytes(byte_view);
        let mut insns: Vec<(InstructionSize, InstructionOffset, Instruction)> = vec![];
        let mut a_data: Vec<(InstructionSize, InstructionOffset, Instruction)> = vec![];
        let mut switch_data: Vec<(InstructionSize, InstructionOffset, Instruction)> = vec![];
        //instructions are always short + stuff
        let mut i = 0;
        while i < insns_size {
            let op = u16::from_bytes(byte_view);
            let (op_size, is_pseudo, element_size) = Instruction::get_op_len(op, byte_view);

            //for now we only handlle fillel
            if is_pseudo {
                if op.to_be_bytes()[0] == 0x01 {
                    //packed switch
                    //we don't know how to handle that
                    let number_of_entries = (op_size / 4) as i32;
                    let first_key = i32::from_bytes(byte_view);
                    let mut targets = HashMap::new();
                    for i in 0..number_of_entries {
                        targets.insert(first_key + i, i32::from_bytes(byte_view));
                    }
                    let id: u32 = rand::random();
                    let switch = Switch { id, targets };
                    insns.push((
                        op_size.into(),
                        i.into(),
                        Instruction::PackedSwitchData(switch.clone()),
                    ));
                    switch_data.push((
                        op_size.into(),
                        i.into(),
                        Instruction::PackedSwitchData(switch.clone()),
                    ));
                } else if op.to_be_bytes()[0] == 0x02 {
                    //sparse switch
                    let number_of_entries = (op_size / 4) as i32;
                    let mut keys = vec![];
                    let mut values = vec![];
                    let mut targets = HashMap::new();
                    for _ in 0..number_of_entries {
                        keys.push(i32::from_bytes(byte_view));
                    }
                    for _ in 0..number_of_entries {
                        values.push(i32::from_bytes(byte_view));
                    }
                    for (key, value) in keys.into_iter().zip(values) {
                        targets.insert(key, value);
                    }
                    let id: u32 = rand::random();
                    let switch = Switch { id, targets };
                    insns.push((
                        op_size.into(),
                        i.into(),
                        Instruction::SparseSwitchData(switch.clone()),
                    ));
                    switch_data.push((
                        op_size.into(),
                        i.into(),
                        Instruction::SparseSwitchData(switch.clone()),
                    ));
                } else {
                    // log::debug!("found array with {} elements of size {}", op_size, element_size);
                    let mut array_data = vec![];
                    for _ in 0..op_size {
                        array_data.push(u8::from_bytes(byte_view))
                    }

                    insns.push((
                        op_size.into(),
                        i.into(),
                        Instruction::ArrayData(element_size as u16, array_data.clone()),
                    ));
                    a_data.push((
                        op_size.into(),
                        i.into(),
                        Instruction::ArrayData(element_size as u16, array_data),
                    ));
                }

                i += (1 + op_size) / 2 + 4;
                if (op_size * element_size) % 2 != 0 {
                    u8::from_bytes(byte_view);
                }
                continue;
            }

            //no pseudo instruction
            let bytes = op_size / 2 - 1;
            let mut data = vec![];
            for _ in 0..bytes {
                data.push(u16::from_bytes(byte_view));
            }
            let opccode = Instruction::get_opcode(op, data.as_ref());

            insns.push((op_size.into(), i.into(), opccode));
            i += 1 + bytes as u32;
        }
        CodeItem {
            code_off: 0,
            register_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns_size,
            insns,
            array_data: a_data,
            switch_data,
        }
    }
}
use std::{
    borrow::Cow,
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
    str::Utf8Error,
    string::FromUtf8Error,
};

use petgraph::Graph;

#[derive(Debug, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
#[doc(hidden)]
pub enum TestFunction {
    Equal,
    NotEqual,
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,
}

impl From<u8> for TestFunction {
    fn from(val: u8) -> Self {
        match val {
            0 => TestFunction::Equal,
            1 => TestFunction::NotEqual,
            2 => TestFunction::LessThan,
            3 => TestFunction::GreaterEqual,
            4 => TestFunction::GreaterThan,
            5 => TestFunction::LessEqual,
            _ => TestFunction::Equal,
        }
    }
}

#[allow(dead_code)]
pub struct Match {
    pub value: String,
    pub origin: StringType,
    pub desc: String,
    pub class: String,
    pub function_name: String,
    pub argc: usize,
}

#[allow(dead_code)]
pub enum StringType {
    Method,
    Type,
    UTF8String,
    ProtoType,
}

impl ToString for StringType {
    fn to_string(&self) -> String {
        match self {
            StringType::Method => String::from("Method"),
            StringType::Type => String::from("Type"),
            StringType::UTF8String => String::from("UTF8String"),
            StringType::ProtoType => String::from("ProtoType"),
        }
    }
}
