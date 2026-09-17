// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    io::{Cursor, Read, Write},
};

use anyhow::bail;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use tokio::runtime::Runtime;

use crate::{jdwp::JdwpClient, FromBytes, ToBytes};

#[derive(Debug, Clone)]
pub struct JdwpCommandPacket {
    pub length: u32,
    pub id: u32,
    pub flags: u8,
    pub command_set: u8,
    pub command: u8,
    pub data: Vec<u8>,
}
impl FromBytes for JdwpCommandPacket {
    type ResultObject = JdwpCommandPacket;
    type ErrorObject = anyhow::Error;
    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, Self::ErrorObject>
    where
        R: Read,
    {
        let length = buf.read_u32::<BigEndian>()?;
        let id = buf.read_u32::<BigEndian>()?;
        let flags = buf.read_u8()?;
        let command_set = buf.read_u8()?;
        let command = buf.read_u8()?;
        if length < 11 {
            bail!("Invalid JDWP command packet length: {length}");
        }
        let mut data = vec![0u8; (length - 11) as usize];
        buf.read_exact(&mut data)?;

        Ok(Self {
            length,
            id,
            flags,
            command_set,
            command,
            data,
        })
    }
}
impl ToBytes for JdwpCommandPacket {
    type ErrorObject = anyhow::Error;
    fn bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut data = vec![];
        data.write_u32::<BigEndian>(self.length)?;
        data.write_u32::<BigEndian>(self.id)?;
        data.write_u8(self.flags)?;
        data.write_u8(self.command_set)?;
        data.write_u8(self.command)?;
        data.write_all(&self.data)?;
        Ok(data)
    }
}

#[derive(Debug, Clone)]
pub struct JdwpReplyPacket {
    length: u32,
    id: u32,
    flags: u8,
    error_code: u16,
    data: Vec<u8>,
}
impl FromBytes for JdwpReplyPacket {
    type ResultObject = JdwpReplyPacket;
    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, anyhow::Error>
    where
        R: Read,
    {
        let length = buf.read_u32::<BigEndian>()?;
        let id = buf.read_u32::<BigEndian>()?;
        let flags = buf.read_u8()?;
        let error_code = buf.read_u16::<BigEndian>()?;
        if length < 11 {
            bail!("Invalid JDWP reply packet length: {length}");
        }
        let mut data = vec![0u8; (length - 11) as usize];
        buf.read_exact(&mut data)?;

        Ok(Self {
            length,
            id,
            flags,
            error_code,
            data,
        })
    }
}
impl ToBytes for JdwpReplyPacket {
    type ErrorObject = anyhow::Error;
    fn bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut data = vec![];
        data.write_u32::<BigEndian>(self.length)?;
        data.write_u32::<BigEndian>(self.id)?;
        data.write_u8(self.flags)?;
        data.write_u16::<BigEndian>(self.error_code)?;
        data.write_all(&self.data)?;
        Ok(data)
    }
}

impl JdwpReplyPacket {
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
    pub fn get_data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
    pub fn get_flags(&self) -> u8 {
        self.flags
    }
    pub fn is_error(&self) -> bool {
        self.error_code > 0
    }
    pub fn get_error(&self) -> u16 {
        self.error_code
    }
}

#[derive(Debug, Clone)]
pub struct Method {
    pub method_id: u64,
    pub name: String,
    pub signature: String,
    pub mod_bits: u32,
    pub variable_table: VariableTable,
}
impl Method {
    pub fn get_name(&self) -> &str {
        &self.name
    }
    pub fn get_signature(&self) -> &str {
        &self.signature
    }
}

#[derive(Debug, Clone)]
pub struct Class {
    pub ty: ClassType,
    pub ref_type: u64,
    pub status: u32,
    pub methods: HashMap<String, Method>,
}

impl Class {
    pub fn get_id(&self) -> u64 {
        self.ref_type
    }
    pub fn set_breakpoint(&self, name: &str, code_index: u64) -> anyhow::Result<JdwpCommandPacket> {
        let Some(m) = self.methods.get(name) else {
            bail!("Method not found");
        };

        let location = Location {
            ty: self.ty,
            class_id: self.ref_type,
            method_id: m.method_id,
            code_index,
        };
        JdwpCommandPacket::set_breakpoint(rand::random(), &location)
    }
    pub fn get_method(&self, method_id: u64) -> anyhow::Result<&Method> {
        let Some(m) = self
            .methods
            .iter()
            .find(|(_, m)| m.method_id == method_id)
            .map(|(_, m)| m)
        else {
            bail!("Method not found");
        };
        Ok(m)
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub field_id: u64,
    pub name: String,
    pub signature: String,
    pub flags: u32,
    pub value: Option<SlotValue>,
}

impl FromBytes for Field {
    type ResultObject = Field;

    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, Self::ErrorObject>
    where
        R: Read,
    {
        let field_id = buf.read_u64::<BigEndian>()?;
        let name = String::from_bytes(buf)?;
        let signature = String::from_bytes(buf)?;
        let flags = buf.read_u32::<BigEndian>()?;
        Ok(Field {
            field_id,
            name,
            signature,
            flags,
            value: None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum ClassType {
    Class = 1,
    Interface = 2,
    Array = 3,
}

impl TryFrom<u8> for ClassType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> anyhow::Result<ClassType> {
        match value {
            1 => Ok(Self::Class),
            2 => Ok(Self::Interface),
            3 => Ok(Self::Array),
            _ => bail!("wrong type"),
        }
    }
}

#[repr(C)]
pub enum VmType {
    Array = 91,
    Byte = 66,
    Char = 67,
    Object = 76,
    Float = 70,
    Double = 68,
    Int = 73,
    Long = 74,
    Short = 83,
    Void = 86,
    Boolean = 90,
    String = 115,
    Thread = 116,
    ThreadGroup = 103,
    ClassLoader = 108,
    ClassObject = 99,
}
impl TryFrom<u8> for VmType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> anyhow::Result<VmType> {
        match value {
            91 => Ok(Self::Array),
            66 => Ok(Self::Byte),
            67 => Ok(Self::Char),
            76 => Ok(Self::Object),
            70 => Ok(Self::Float),
            68 => Ok(Self::Double),
            73 => Ok(Self::Int),
            74 => Ok(Self::Long),
            83 => Ok(Self::Short),
            86 => Ok(Self::Void),
            90 => Ok(Self::Boolean),
            115 => Ok(Self::String),
            116 => Ok(Self::Thread),
            103 => Ok(Self::ThreadGroup),
            108 => Ok(Self::ClassLoader),
            99 => Ok(Self::ClassObject),
            _ => bail!("Unknown type"),
        }
    }
}
impl TryFrom<&str> for VmType {
    type Error = anyhow::Error;
    fn try_from(value: &str) -> anyhow::Result<VmType> {
        match value
            .chars()
            .next()
            .ok_or_else(|| anyhow::Error::msg("Too few characters"))?
        {
            '[' => Ok(Self::Array),
            'B' => Ok(Self::Byte),
            'C' => Ok(Self::Char),

            'F' => Ok(Self::Float),
            'D' => Ok(Self::Double),
            'I' => Ok(Self::Int),
            'J' => Ok(Self::Long),
            'S' => Ok(Self::Short),
            'V' => Ok(Self::Void),
            'Z' => Ok(Self::Boolean),
            'L' => Ok(Self::Object),
            _ => bail!("Unknown type"),
        }
    }
}

const TYPES: [char; 11] = ['[', 'Z', 'B', 'F', 'D', 'I', 'J', 'S', 'V', 'C', 'L'];

#[repr(C)]
pub enum JdwpEventType {
    SingleStep = 1,
    Breakpoint,
    FramePop,
    Exception,
    UserDefined,
    ThreadStart,
    ThreadDeath,
    ClassPrepare,
    ClassUnload,
    ClassLoad,
    FieldAccess = 20,
    FieldModification,
    ExceptionCatch = 30,
    MethodEntry = 40,
    MethodExit,
    MethodExitWithReturnValue,
    MonitorContendedEnter,
    MonitorContendendEntered,
    MonitorWait,
    MonitorWaited,
    VmStart = 90,
    VmDeath = 99,
}

#[derive(Debug, Clone)]
pub enum JdwpPacket {
    CommandPacket(JdwpCommandPacket),
    ReplyPacket(JdwpReplyPacket),
}

impl ToBytes for JdwpPacket {
    type ErrorObject = anyhow::Error;
    fn bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            JdwpPacket::CommandPacket(pkg) => pkg.bytes(),
            JdwpPacket::ReplyPacket(pkg) => pkg.bytes(),
        }
    }
}

#[derive(Debug)]
pub struct StackFrame {
    pub thread_id: u64,
    pub frame_id: u64,
    pub location: Location,
}

impl StackFrame {
    pub fn get_location(&self) -> Location {
        self.location
    }
    pub fn set_value(
        &self,
        client: &mut JdwpClient,
        runtime: &Runtime,
        slot_idx: u32,
        value: &SlotValue,
    ) -> anyhow::Result<()> {
        runtime.block_on(async {
            let cmd =
                JdwpCommandPacket::set_values(20, self.thread_id, self.frame_id, slot_idx, value)?;
            client.send_cmd(JdwpPacket::CommandPacket(cmd))?;
            let _ = client.wait_for_reply().await?;
            Ok(())
        })
    }
    pub fn get_values(
        &self,
        m: &coeus_models::models::CodeItem,
        client: &mut JdwpClient,
        runtime: &Runtime,
    ) -> anyhow::Result<Vec<SlotValue>> {
        runtime.block_on(async {
            let mut slots_in_scope = vec![Slot {
                code_index: 0,
                name: String::new(),
                signature: String::from("L"),
                length: 0,
                slot_idx: 0,
            }];
            let mut slot_values = vec![];
            for i in 0..m.register_size {
                let mut error_code = 1;
                let mut types_iterator = TYPES.iter();
                while error_code != 0 && error_code != 35 {
                    let Some(ty) = types_iterator.next() else {
                        break;
                    };

                    slots_in_scope[0] = Slot {
                        code_index: 0,
                        name: String::new(),
                        signature: ty.to_string(),
                        length: 0,
                        slot_idx: i as u32,
                    };
                    let cmd = JdwpCommandPacket::get_values(
                        rand::random(),
                        self.thread_id,
                        self.frame_id,
                        &slots_in_scope,
                    )?;
                    client.send_cmd(JdwpPacket::CommandPacket(cmd))?;
                    let reply = client.wait_for_reply().await?;
                    error_code = reply.get_error();
                    if error_code == 34 {
                        continue;
                    }
                    log::debug!("Values: {:?}", reply);
                    let mut reader = Cursor::new(reply.data);
                    let number_of_values = reader.read_u32::<BigEndian>()?;
                    if number_of_values != 1 {
                        break;
                    }

                    let Ok(val) = SlotValue::from_bytes(&mut reader) else {
                        break;
                    };
                    slot_values.push(val);
                }
            }

            Ok(slot_values)
        })
    }
}
impl FromBytes for StackFrame {
    type ResultObject = Self;
    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, anyhow::Error>
    where
        R: Read,
    {
        let frame_id = buf.read_u64::<BigEndian>()?;
        let location = Location::from_bytes(buf)?;
        Ok(Self {
            thread_id: 0,
            frame_id,
            location,
        })
    }
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct Composite {
    suspend_policy: u8,
    pub events: Vec<Event>,
}
#[derive(Debug)]
pub enum Event {
    SingleStep(SimpleEventData),
    Breakpoint(SimpleEventData),
    VmStart(u64),
    VmDeath,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SimpleEventData {
    request_id: u32,
    thread_id: u64,
    location: Location,
}
impl SimpleEventData {
    pub fn get_thread(&self) -> Thread {
        Thread {
            thread_id: self.thread_id,
        }
    }
    pub fn get_method<'class_lifetime>(
        &self,
        class: &'class_lifetime Class,
    ) -> anyhow::Result<&'class_lifetime Method> {
        class.get_method(self.location.method_id)
    }
    pub fn get_class_id(&self) -> u64 {
        self.location.class_id
    }
}

impl FromBytes for SimpleEventData {
    type ResultObject = Self;
    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, anyhow::Error>
    where
        R: Read,
    {
        let request_id: u32 = buf.read_u32::<BigEndian>()?;
        let thread_id: u64 = buf.read_u64::<BigEndian>()?;
        let location: Location = Location::from_bytes(buf)?;
        Ok(Self {
            request_id,
            thread_id,
            location,
        })
    }
}

impl TryFrom<JdwpCommandPacket> for Composite {
    type Error = anyhow::Error;
    fn try_from(value: JdwpCommandPacket) -> anyhow::Result<Composite> {
        let mut reader = Cursor::new(value.data);
        let suspend_policy: u8 = reader.read_u8()?;
        let number_of_events: u32 = reader.read_u32::<BigEndian>()?;
        let mut events = vec![];
        for _ in 0..number_of_events {
            let event_kind = reader.read_u8()?;
            match event_kind {
                1 => {
                    let bp: SimpleEventData = SimpleEventData::from_bytes(&mut reader)?;
                    events.push(Event::SingleStep(bp));
                }
                2 => {
                    let bp: SimpleEventData = SimpleEventData::from_bytes(&mut reader)?;
                    events.push(Event::Breakpoint(bp));
                }
                90 => {
                    let _request_id = reader.read_u32::<BigEndian>()?;
                    let thread_id = reader.read_u64::<BigEndian>()?;
                    events.push(Event::VmStart(thread_id));
                }
                99 => {
                    let _request_id = reader.read_u32::<BigEndian>()?;
                    events.push(Event::VmDeath);
                }
                _ => bail!("Unsupported JDWP event kind: {event_kind}"),
            }
        }
        Ok(Self {
            suspend_policy,
            events,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VariableTable {
    pub arg_count: u32,
    pub slots: Vec<Slot>,
}
impl VariableTable {
    pub fn get_slots_in_scope(&self, code_index: u64) -> Vec<Slot> {
        self.slots
            .iter()
            .filter(|slot| {
                slot.code_index <= code_index && code_index < slot.code_index + slot.length as u64
            })
            .cloned()
            .collect::<Vec<_>>()
    }
}

impl TryFrom<JdwpReplyPacket> for VariableTable {
    type Error = anyhow::Error;
    fn try_from(value: JdwpReplyPacket) -> anyhow::Result<VariableTable> {
        log::debug!("{:?}", value);
        let mut reader = Cursor::new(value.data);

        let arg_count: u32 = reader.read_u32::<BigEndian>()?;
        let number_of_slots: u32 = reader.read_u32::<BigEndian>()?;
        let mut slots = vec![];
        for _ in 0..number_of_slots {
            let slot = Slot::from_bytes(&mut reader)?;
            slots.push(slot);
        }
        Ok(VariableTable { arg_count, slots })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Location {
    ty: ClassType,
    pub class_id: u64,
    pub method_id: u64,
    pub code_index: u64,
}
impl FromBytes for Location {
    type ResultObject = Self;
    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(reader: &mut R) -> Result<Self::ResultObject, anyhow::Error>
    where
        R: Read,
    {
        let ty: u8 = reader.read_u8()?;
        let class_id = reader.read_u64::<BigEndian>()?;
        let method_id = reader.read_u64::<BigEndian>()?;
        let code_index = reader.read_u64::<BigEndian>()?;
        Ok(Self {
            ty: ty.try_into()?,
            class_id,
            method_id,
            code_index,
        })
    }
}
impl ToBytes for Location {
    type ErrorObject = anyhow::Error;
    fn bytes(&self) -> Result<Vec<u8>, Self::ErrorObject> {
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u8(self.ty as u8)?;
        buffer.write_u64::<BigEndian>(self.class_id)?;
        buffer.write_u64::<BigEndian>(self.method_id)?;
        buffer.write_u64::<BigEndian>(self.code_index)?;
        Ok(buffer)
    }
}

pub struct Thread {
    thread_id: u64,
}
impl Thread {
    pub fn get_top_frame(
        &self,
        client: &mut JdwpClient,
        runtime: &Runtime,
    ) -> anyhow::Result<StackFrame> {
        runtime.block_on(async {
            let cmd = JdwpCommandPacket::get_stack_frames(rand::random(), self.thread_id, 0, 1)?;
            client.send_cmd(JdwpPacket::CommandPacket(cmd))?;
            let reply = client.wait_for_reply().await?;
            let mut reader = Cursor::new(reply.data);
            let number_of_frames = reader.read_u32::<BigEndian>()?;
            if number_of_frames != 1 {
                bail!("Got more frames than expected");
            }
            let mut frame = StackFrame::from_bytes(&mut reader)?;
            frame.thread_id = self.thread_id;
            Ok(frame)
        })
    }
}
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Slot {
    code_index: u64,
    name: String,
    pub signature: String,
    length: u32,
    pub slot_idx: u32,
}
impl Slot {
    pub fn get_signature(&self) -> &str {
        &self.signature
    }
}

impl FromBytes for String {
    type ResultObject = Self;
    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, anyhow::Error>
    where
        R: Read,
    {
        let string_length = buf.read_u32::<BigEndian>()?;
        let mut string_buffer = vec![0u8; string_length as usize];
        buf.read_exact(&mut string_buffer)?;
        let string = std::str::from_utf8(&string_buffer)?.to_string();
        Ok(string)
    }
}

impl FromBytes for Slot {
    type ResultObject = Self;
    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, anyhow::Error>
    where
        R: Read,
    {
        let code_index = buf.read_u64::<BigEndian>()?;
        let name = String::from_bytes(buf)?;
        let signature = String::from_bytes(buf)?;
        let length = buf.read_u32::<BigEndian>()?;
        let slot_idx = buf.read_u32::<BigEndian>()?;
        Ok(Self {
            code_index,
            name,
            signature,
            length,
            slot_idx,
        })
    }
}
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SlotValue {
    ty: u8,
    pub value: Value,
}
impl ToBytes for SlotValue {
    type ErrorObject = anyhow::Error;

    fn bytes(&self) -> Result<Vec<u8>, Self::ErrorObject> {
        let mut data = vec![];
        match self.value {
            Value::Object(o) => {
                data.write_u8(VmType::Object as u8)?;
                data.write_u64::<BigEndian>(o)?;
            }
            Value::Byte(b) => {
                data.write_u8(VmType::Byte as u8)?;
                data.write_i8(b)?;
            }
            Value::Short(s) => {
                data.write_u8(VmType::Short as u8)?;
                data.write_i16::<BigEndian>(s)?;
            }
            Value::Int(i) => {
                data.write_u8(VmType::Int as u8)?;
                data.write_i32::<BigEndian>(i)?;
            }
            Value::Long(l) => {
                data.write_u8(VmType::Long as u8)?;
                data.write_i64::<BigEndian>(l)?;
            }
            Value::String(s) => {
                data.write_u8(VmType::String as u8)?;
                data.write_u64::<BigEndian>(s)?;
            }
            Value::Array(a) => {
                data.write_u8(VmType::Array as u8)?;
                data.write_u64::<BigEndian>(a)?;
            }
            Value::Float(f) => {
                data.write_u8(VmType::Float as u8)?;
                data.write_f32::<BigEndian>(f)?;
            }
            Value::Double(d) => {
                data.write_u8(VmType::Double as u8)?;
                data.write_f64::<BigEndian>(d)?;
            }
            Value::Boolean(b) => {
                data.write_u8(VmType::Boolean as u8)?;
                data.write_u8(b)?;
            }
            Value::Char(c) => {
                data.write_u8(VmType::Char as u8)?;
                data.write_i8(c as i8)?;
            }
            Value::Void => {
                data.write_u8(VmType::Void as u8)?;
            }
            Value::Reference(reference) => {
                data.write_u8(self.ty)?;
                data.write_u64::<BigEndian>(reference)?;
            }
        }
        Ok(data)
    }
}
impl FromBytes for SlotValue {
    type ResultObject = Self;
    type ErrorObject = anyhow::Error;

    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, anyhow::Error>
    where
        R: Read,
    {
        let ty = buf.read_u8()?;
        Ok(match VmType::try_from(ty)? {
            VmType::Array => SlotValue {
                ty,
                value: Value::Array(buf.read_u64::<BigEndian>()?),
            },
            VmType::Byte => SlotValue {
                ty,
                value: Value::Byte(buf.read_i8()?),
            },
            VmType::Char => SlotValue {
                ty,
                value: Value::Char(buf.read_u8()? as char),
            },
            VmType::Object => SlotValue {
                ty,
                value: Value::Object(buf.read_u64::<BigEndian>()?),
            },
            VmType::Float => SlotValue {
                ty,
                value: Value::Float(buf.read_f32::<BigEndian>()?),
            },
            VmType::Double => SlotValue {
                ty,
                value: Value::Double(buf.read_f64::<BigEndian>()?),
            },
            VmType::Int => SlotValue {
                ty,
                value: Value::Int(buf.read_i32::<BigEndian>()?),
            },
            VmType::Long => SlotValue {
                ty,
                value: Value::Long(buf.read_i64::<BigEndian>()?),
            },
            VmType::Short => SlotValue {
                ty,
                value: Value::Short(buf.read_i16::<BigEndian>()?),
            },
            VmType::Void => SlotValue {
                ty,
                value: Value::Void,
            },
            VmType::Boolean => SlotValue {
                ty,
                value: Value::Boolean(buf.read_u8()?),
            },
            VmType::String => SlotValue {
                ty,
                value: Value::String(buf.read_u64::<BigEndian>()?),
            },
            VmType::Thread => SlotValue {
                ty,
                value: Value::Reference(buf.read_u64::<BigEndian>()?),
            },
            VmType::ThreadGroup => SlotValue {
                ty,
                value: Value::Reference(buf.read_u64::<BigEndian>()?),
            },
            VmType::ClassLoader => SlotValue {
                ty,
                value: Value::Reference(buf.read_u64::<BigEndian>()?),
            },
            VmType::ClassObject => SlotValue {
                ty,
                value: Value::Reference(buf.read_u64::<BigEndian>()?),
            },
        })
    }
}
impl From<Value> for SlotValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Object(_) => SlotValue {
                ty: VmType::Object as u8,
                value: value,
            },
            Value::Byte(_) => SlotValue {
                ty: VmType::Byte as u8,
                value: value,
            },
            Value::Short(_) => SlotValue {
                ty: VmType::Short as u8,
                value: value,
            },
            Value::Int(_) => SlotValue {
                ty: VmType::Int as u8,
                value: value,
            },
            Value::Long(_) => SlotValue {
                ty: VmType::Long as u8,
                value: value,
            },
            Value::String(_) => SlotValue {
                ty: VmType::String as u8,
                value: value,
            },
            Value::Array(_) => SlotValue {
                ty: VmType::Array as u8,
                value: value,
            },
            Value::Float(_) => SlotValue {
                ty: VmType::Float as u8,
                value: value,
            },
            Value::Double(_) => SlotValue {
                ty: VmType::Double as u8,
                value: value,
            },
            Value::Boolean(_) => SlotValue {
                ty: VmType::Boolean as u8,
                value: value,
            },
            Value::Char(_) => SlotValue {
                ty: VmType::Char as u8,
                value: value,
            },
            Value::Void => SlotValue {
                ty: VmType::Void as u8,
                value: value,
            },
            Value::Reference(_) => SlotValue {
                ty: VmType::ClassObject as u8,
                value: value,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum Value {
    Object(u64),
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    String(u64),
    Array(u64),
    Float(f32),
    Double(f64),
    Boolean(u8),
    Char(char),
    Void,
    Reference(u64),
}
#[derive(Debug, Clone)]
pub enum ArrayValues {
    ByteArray(Vec<u8>),
    ShortArray(Vec<u16>),
    IntArray(Vec<i32>),
    LongArray(Vec<i64>),
    FloatArray(Vec<f32>),
    DoubleArray(Vec<f64>),
    BooleanArray(Vec<bool>),
}
#[derive(Debug, Clone)]
pub struct ClassInstance {
    pub object_id: u64,
    pub reference_type: u64,
    pub signature: String,
    pub fields: Vec<Field>,
}
