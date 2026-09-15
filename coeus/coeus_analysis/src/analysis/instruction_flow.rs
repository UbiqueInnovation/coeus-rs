// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    fmt::Display,
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Div, Mul, Rem, Shl, Shr, Sub},
    sync::{Arc, Mutex},
};

use coeus_models::models::{
    Class, CodeItem, DexFile, Field, Instruction, InstructionOffset, InstructionSize, Method,
};
use coeus_parse::coeus_emulation::vm::{
    runtime::StringClass, ClassInstance, Register, VMException, VM,
};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use regex::Regex;

/// Rust does implicit "casting" of the opperation to SAR or SHR depending on the
/// type of the opperand. Since java does not know unsigned integers we introduce our
/// custom trait
pub trait UShr<T = Self> {
    type Output;
    fn ushr(self, rhs: T) -> Self::Output;
}

#[derive(Clone, Debug)]
pub struct InstructionFlow {
    branches: Vec<Branch>,
    method: Arc<HashMap<InstructionOffset, (InstructionSize, Instruction)>>,
    dex: Arc<DexFile>,
    register_size: u16,
    already_branched: Vec<(u64, InstructionOffset)>,
    conservative: bool,
}

impl InstructionFlow {
    pub fn get_method_arc(
        &self,
    ) -> Arc<HashMap<InstructionOffset, (InstructionSize, Instruction)>> {
        self.method.clone()
    }
}

#[derive(Clone, Debug)]
pub struct Branch {
    pub parent_id: Option<u64>,
    pub id: u64,
    pub pc: InstructionOffset,
    pub state: State,
    pub previous_pc: InstructionOffset,
    pub finished: bool,
}
impl Default for Branch {
    fn default() -> Self {
        Self {
            parent_id: None,
            id: rand::random(),
            pc: InstructionOffset(0),
            previous_pc: InstructionOffset(0),
            state: Default::default(),
            finished: false,
        }
    }
}
impl PartialEq for Branch {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
#[derive(Clone, Debug)]
pub struct State {
    pub id: u64,
    pub registers: Vec<Value>,
    pub last_instruction: Option<LastInstruction>,
    pub tainted: bool,
    pub loop_count: HashMap<InstructionOffset, u32>,
}
impl Default for State {
    fn default() -> Self {
        let id: u64 = rand::random();
        Self {
            id,
            registers: Default::default(),
            last_instruction: Default::default(),
            tainted: false,
            loop_count: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub enum InstructionType {
    FunctionCall,
    ReadStaticField,
    StoreStaticField,
    BinaryOperation,
}

#[derive(Clone)]
pub enum LastInstruction {
    FunctionCall {
        name: String,
        signature: String,
        class_name: String,
        class: Arc<Class>,
        method: Arc<Method>,
        args: Vec<Value>,
        result: Option<Value>,
    },
    ReadStaticField {
        file: Arc<DexFile>,
        class_name: String,
        class: Arc<Class>,
        field: Arc<Field>,
        name: String,
    },
    StoreStaticField {
        file: Arc<DexFile>,
        class_name: String,
        class: Arc<Class>,
        field: Arc<Field>,
        name: String,
        arg: Value,
    },
    BinaryOperation {
        left: Value,
        right: Value,
        operation: fn(&Value, &Value) -> Value,
    },
}

impl Display for LastInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let LastInstruction::FunctionCall {
            name,
            signature: _,
            class_name,
            class: _,
            method: _,
            args,
            result,
        } = self
        {
            f.write_str(&format!(
                "{}->{}({}) : {}",
                class_name,
                name,
                args.iter()
                    .map(|a| format!("{}", a))
                    .collect::<Vec<_>>()
                    .join(","),
                result
                    .as_ref()
                    .and_then(|a| Some(format!("{}", a)))
                    .unwrap_or("Void".to_string())
            ))
        } else {
            f.write_str(&format!("{:?}", self))
        }
    }
}

impl LastInstruction {
    pub fn execute(&mut self, vm: &mut VM) -> Result<Value, VMException> {
        match self {
            LastInstruction::FunctionCall {
                name: _name,
                signature: _signature,
                class_name,
                class,
                method,
                args,
                result,
            } => {
                let evaluated_args = args
                    .into_iter()
                    .filter_map(|a| a.try_get_value(vm).ok())
                    .filter(|a| !matches!(a, Value::Unknown { .. } | Value::Empty))
                    .collect::<Vec<_>>();
                if evaluated_args.len() != args.len() {
                    return Err(VMException::LinkerError);
                }
                let mut vm_args = vec![];
                for arg in evaluated_args {
                    let arg = match arg {
                        Value::String(n) => {
                            let string_class = StringClass::new(n);
                            vm.new_instance(
                                StringClass::class_name().to_string(),
                                coeus_parse::coeus_emulation::vm::Value::Object(string_class),
                            )
                            .unwrap_or(Register::Null)
                        }
                        Value::Boolean(b) => Register::Literal(if b { 1 } else { 0 }),
                        Value::Number(n) => Register::Literal(n as i32),
                        Value::Char(n) => Register::Literal(n as i32),
                        Value::Byte(n) => Register::Literal(n as i32),
                        Value::Bytes(bytes) => vm
                            .new_instance(
                                "[B".to_string(),
                                coeus_parse::coeus_emulation::vm::Value::Array(bytes),
                            )
                            .unwrap_or(Register::Null),
                        Value::Variable(_f) => {
                            unreachable!("We evaluated before")
                        }
                        Value::Unknown { ty } | Value::Object { ty } => vm
                            .new_instance(
                                ty,
                                coeus_parse::coeus_emulation::vm::Value::Object(
                                    ClassInstance::new(class.clone()),
                                ),
                            )
                            .unwrap_or(Register::Null),

                        Value::Invalid => Register::Null,
                        Value::Empty => Register::Empty,
                    };
                    vm_args.push(arg);
                }
                if let Ok((file, function)) = vm.lookup_method(class_name, &method) {
                    let function = function.clone();
                    if let Some(code) = &function.code {
                        vm.start(
                            method.method_idx as u32,
                            &file.get_identifier(),
                            code,
                            vm_args,
                        )?;
                    } else {
                        vm.invoke_runtime(file.clone(), method.method_idx as u32, vm_args)?;
                    };
                } else {
                    vm.invoke_runtime_with_method(class_name, method.clone(), vm_args)?;
                }

                let r = vm
                    .get_return_object()
                    .map(|a| match a {
                        coeus_parse::coeus_emulation::vm::Value::Array(a) => Value::Bytes(a),
                        coeus_parse::coeus_emulation::vm::Value::Object(o) => {
                            if &o.class.class_name == StringClass::class_name() {
                                Value::String(format!("{}", o))
                            } else {
                                Value::Object {
                                    ty: o.class.class_name.to_string(),
                                }
                            }
                        }
                        coeus_parse::coeus_emulation::vm::Value::Int(i) => {
                            if let Some(Value::Object { ty }) = result {
                                if ty == "Z" {
                                    Value::Boolean(i == 1)
                                } else {
                                    Value::Number(i as i128)
                                }
                            } else {
                                Value::Number(i as i128)
                            }
                        }
                        coeus_parse::coeus_emulation::vm::Value::Short(s) => {
                            Value::Number(s as i128)
                        }
                        coeus_parse::coeus_emulation::vm::Value::Byte(b) => Value::Byte(b as u8),
                    })
                    .unwrap_or(Value::Invalid);
                *result = Some(r.clone());
                Ok(r)
            }
            LastInstruction::BinaryOperation {
                left,
                right,
                operation,
            } => {
                let left = left.try_get_value(vm)?;
                let right = right.try_get_value(vm)?;
                let result = operation(&left, &right);
                Ok(result)
            }
            _ => Err(VMException::LinkerError),
        }
    }
}

impl std::fmt::Debug for LastInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FunctionCall {
                name,
                signature,
                method: _method,
                class_name: _class_name,
                class: _class,
                args,
                result,
            } => f
                .debug_struct("FunctionCall")
                .field("name", name)
                .field("signature", signature)
                .field("args", args)
                .field("result", result)
                .finish(),
            Self::ReadStaticField { name, .. } => {
                f.debug_struct("ReadField").field("name", name).finish()
            }
            Self::StoreStaticField { name, arg, .. } => f
                .debug_struct("StoreField")
                .field("name", name)
                .field("arg", arg)
                .finish(),
            Self::BinaryOperation {
                left,
                right,
                operation: _operation,
            } => f
                .debug_struct("BinaryOperation")
                .field("left", left)
                .field("right", right)
                .finish(),
        }
    }
}
#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Number(i128),
    Boolean(bool),
    Char(char),
    Byte(u8),
    Bytes(Vec<u8>),
    Variable(Box<LastInstruction>),
    Unknown { ty: String },
    Object { ty: String },
    Invalid,
    Empty,
}
impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::String(s) => f.write_str(&format!("\"{}\"", s)),
            Value::Number(n) => f.write_str(&n.to_string()),
            Value::Boolean(b) => f.write_str(&b.to_string()),
            Value::Char(c) => f.write_str(&format!("'{}'", c)),
            Value::Byte(b) => f.write_str(&format!("{:02x}", b)),
            Value::Bytes(b) => f.write_str(&format!(
                "[{}]",
                b.iter()
                    .map(|a| format!("{:02x}", a))
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            Value::Variable(v) => f.write_str(&v.to_string()),
            Value::Unknown { ty } => f.write_str(&format!("Unknown{{ ty={} }}", ty)),
            Value::Object { ty } => f.write_str(&format!("Object{{ ty={} }}", ty)),
            Value::Invalid => f.write_str("INVALID"),
            Value::Empty => f.write_str("EMPTY"),
        }
    }
}

impl Value {
    pub fn try_get_number(&self) -> Option<i128> {
        match self {
            Self::Number(number) => Some(*number),
            Self::Byte(b) => Some(*b as i128),
            Self::Char(c) => Some(*c as i128),
            Self::Boolean(b) => Some(if *b { 1 } else { 0 }),
            _ => None,
        }
    }
    pub fn try_get_value(&mut self, vm: &mut VM) -> Result<Value, VMException> {
        if let Value::Variable(instruction) = self {
            instruction.execute(vm)
        } else {
            Ok(self.clone())
        }
    }
    pub fn is_constant(&self) -> bool {
        !matches!(
            self,
            Value::Variable(..)
                | Value::Unknown { .. }
                | Value::Object { .. }
                | Value::Invalid
                | Value::Empty
        )
    }
}

impl<'a> BitXor for &'a Value {
    type Output = Value;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left ^ right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs ^ rhs)
    }
}
impl<'a> BitXor<i128> for &'a Value {
    type Output = Value;

    fn bitxor(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left ^ right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs ^ rhs)
    }
}
impl<'a> BitAnd for &'a Value {
    type Output = Value;

    fn bitand(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left & right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left & right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs & rhs)
    }
}
impl<'a> BitAnd<i128> for &'a Value {
    type Output = Value;

    fn bitand(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left & right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs & rhs)
    }
}
impl<'a> BitOr for &'a Value {
    type Output = Value;

    fn bitor(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left | right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left | right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs | rhs)
    }
}
impl<'a> BitOr<i128> for &'a Value {
    type Output = Value;

    fn bitor(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left | right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs | rhs)
    }
}
impl<'a> Rem for &'a Value {
    type Output = Value;

    fn rem(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left % right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left % right,
            }));
        } else {
            return Value::Invalid;
        };
        if rhs == 0 {
            return Value::Invalid;
        }
        Value::Number(lhs % rhs)
    }
}
impl<'a> Rem<i128> for &'a Value {
    type Output = Value;

    fn rem(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left % right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs % rhs)
    }
}
impl<'a> Add for &'a Value {
    type Output = Value;
    fn add(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left + right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left + right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs + rhs)
    }
}
impl<'a> Add<i128> for &'a Value {
    type Output = Value;

    fn add(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left + right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs + rhs)
    }
}
impl<'a> Sub for &'a Value {
    type Output = Value;

    fn sub(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left - right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left - right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs - rhs)
    }
}
impl<'a> Sub<i128> for &'a Value {
    type Output = Value;

    fn sub(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left - right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs - rhs)
    }
}
impl<'a> Mul for &'a Value {
    type Output = Value;

    fn mul(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left * right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left * right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs * rhs)
    }
}
impl<'a> Mul<i128> for &'a Value {
    type Output = Value;

    fn mul(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left * right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs * rhs)
    }
}
impl<'a> Div for &'a Value {
    type Output = Value;

    fn div(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left / right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left / right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs * rhs)
    }
}
impl<'a> Div<i128> for &'a Value {
    type Output = Value;

    fn div(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left * right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs / rhs)
    }
}
impl<'a> Shl for &'a Value {
    type Output = Value;

    fn shl(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left << right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left << right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs << rhs)
    }
}
impl<'a> Shl<i128> for &'a Value {
    type Output = Value;

    fn shl(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left << right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs << rhs)
    }
}
impl<'a> Shr for &'a Value {
    type Output = Value;

    fn shr(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left >> right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left >> right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs >> rhs)
    }
}
impl<'a> Shr<i128> for &'a Value {
    type Output = Value;

    fn shr(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left >> right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs >> rhs)
    }
}

impl<'a> UShr for &'a Value {
    type Output = Value;

    fn ushr(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left.ushr(right),
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left.ushr(right),
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(((lhs as u128) >> rhs) as i128)
    }
}

impl<'a> UShr<i128> for &'a Value {
    type Output = Value;

    fn ushr(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs as i128),
                operation: |left, right| left.ushr(right),
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(((lhs as u128) >> rhs) as i128)
    }
}

const MAX_ITERATIONS: usize = 1_000;
impl InstructionFlow {
    pub fn get_instruction(
        &self,
        offset: &InstructionOffset,
    ) -> Option<(InstructionSize, Instruction)> {
        self.method.get(offset).map(|a| a.clone())
    }
    pub fn reset(&mut self, start: u32) {
        self.branches.clear();
        self.already_branched.clear();
        self.new_branch(InstructionOffset(start), None);
    }
    pub fn new(method: CodeItem, dex: Arc<DexFile>, conservative: bool) -> Self {
        let register_size = method.register_size;
        let method: HashMap<_, _> = method
            .insns
            .into_iter()
            .map(|(size, offset, instruction)| (offset, (size, instruction)))
            .collect();

        Self {
            branches: vec![],
            method: Arc::new(method),
            dex,
            register_size,
            already_branched: vec![],
            conservative,
        }
    }

    pub fn get_all_branch_decisions(&mut self) -> Vec<Branch> {
        if self.branches.is_empty() {
            self.new_branch(InstructionOffset(0), None);
        }
        let mut branches = vec![];
        let mut iterations = 0;
        loop {
            self.next_instruction(self.method.clone());
            for b in &self.branches {
                let instruction = if let Some(instruction) = self.method.get(&b.pc) {
                    instruction
                } else {
                    log::debug!("NO INSTRUCTION FOUND AT {:?}", b.pc);
                    continue;
                };

                branches
                    .iter_mut()
                    .filter(|branch: &&mut Branch| branch.id == b.id)
                    .for_each(|branch| branch.state.tainted = b.state.tainted);

                if matches!(
                    instruction.1,
                    Instruction::Test(..) | Instruction::TestZero(..)
                ) {
                    branches.push(b.clone());
                }
            }
            if self.is_done() || iterations > MAX_ITERATIONS {
                branches.reverse();
                // only show the last of the loop branches
                branches.sort_by_key(|b| b.id);
                branches.dedup_by(|left, right| {
                    left.id == right.id && left.previous_pc == right.previous_pc
                });
                break;
            }
            iterations += 1;
        }
        branches
    }
    pub fn find_all_instruction_with_op<F: Fn(&str) -> bool>(
        &mut self,
        instruction: InstructionType,
        op: F,
    ) -> Vec<Branch> {
        let mut branches = vec![];
        let mut iterations = 0;
        self.new_branch(InstructionOffset(0), None);
        loop {
            self.next_instruction(self.method.clone());
            for state in self.get_all_states() {
                match (state.last_instruction.as_ref(), &instruction) {
                    (
                        Some(LastInstruction::FunctionCall { signature: sig, .. }),
                        InstructionType::FunctionCall,
                    )
                    | (
                        Some(LastInstruction::ReadStaticField { name: sig, .. }),
                        InstructionType::ReadStaticField,
                    )
                    | (
                        Some(LastInstruction::StoreStaticField { name: sig, .. }),
                        InstructionType::StoreStaticField,
                    ) if op(sig) => {
                        if let Some(b) = self.branches.iter().find(|a| a.state.id == state.id) {
                            branches.push(b.clone());
                        }
                    }
                    _ => {}
                }
            }
            if self.is_done() {
                return branches;
            }
            if self.branches.len() > 300 && iterations > 150 {
                return branches;
            }
            if iterations > MAX_ITERATIONS {
                return branches;
            }

            iterations += 1;
        }
    }

    pub fn find_all_calls(&mut self, signature: &str) -> Vec<Branch> {
        self.find_all_instruction_with_op(InstructionType::FunctionCall, |s| s == signature)
    }
    pub fn find_all_calls_regex(&mut self, regex: &Regex) -> Vec<Branch> {
        self.find_all_instruction_with_op(InstructionType::FunctionCall, |s| regex.is_match(s))
    }
    pub fn find_all_calls_with_op<F: Fn(&str) -> bool>(&mut self, op: F) -> Vec<Branch> {
        self.find_all_instruction_with_op(InstructionType::FunctionCall, op)
    }

    pub fn find_all_static_reads(&mut self, name: &str) -> Vec<Branch> {
        self.find_all_instruction_with_op(InstructionType::ReadStaticField, |s| s == name)
    }
    pub fn find_all_static_reads_regex(&mut self, regex: &Regex) -> Vec<Branch> {
        self.find_all_instruction_with_op(InstructionType::ReadStaticField, |s| regex.is_match(s))
    }

    pub fn find_all_static_writes(&mut self, name: &str) -> Vec<Branch> {
        self.find_all_instruction_with_op(InstructionType::StoreStaticField, |s| s == name)
    }
    pub fn find_all_static_writes_regex(&mut self, regex: &Regex) -> Vec<Branch> {
        self.find_all_instruction_with_op(InstructionType::StoreStaticField, |s| regex.is_match(s))
    }
    pub fn next_instruction(
        &mut self,
        method: Arc<HashMap<InstructionOffset, (InstructionSize, Instruction)>>,
    ) {
        let branches_to_add: Arc<Mutex<Vec<(InstructionOffset, Branch)>>> =
            Arc::new(Mutex::new(vec![]));
        let clone_branches_to_add = branches_to_add.clone();
        let branches_to_taint: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(vec![]));
        let clone_branches_to_taint = branches_to_taint.clone();
        let already_branched = Arc::new(Mutex::new(self.already_branched.clone()));
        let clone_already_branched = already_branched.clone();
        let conservative = self.conservative.clone();
        let dex = self.dex.clone();
        self.branches
            .par_iter_mut()
            .filter(|b| !b.finished)
            .for_each(move |b| {
                if b.pc != InstructionOffset(0) && b.previous_pc == b.pc {
                    b.finished = true;
                    // log::debug!("WE DID NOT STEP {:?}", self.method.get(&b.pc));
                    return;
                }
                b.previous_pc = b.pc;
                let instruction = if let Some(instruction) = method.get(&b.pc) {
                    instruction
                } else {
                    // branches_to_remove.push(b.id);
                    b.finished = true;
                    log::debug!("NO INSTRUCTION FOUND AT {:?}", b.pc);
                    return;
                };

                match instruction.1 {
                    Instruction::ArbitraryData(_) => {}
                    // Flow Control
                    Instruction::Goto8(offset) => {
                        b.pc += offset as i32;
                        return;
                    }
                    Instruction::Goto16(offset) => {
                        b.pc += offset as i32;
                        return;
                    }
                    Instruction::Goto32(offset) => {
                        b.pc += offset as i32;
                        return;
                    }
                    // we can ignore check casts and just do nothing
                    Instruction::CheckCast(..) => {}

                    Instruction::Test(test, left, right, offset) => {
                        if already_branched
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|(id, offset)| offset == &b.pc && id == &b.id)
                        {
                            branches_to_taint.lock().unwrap().push(b.id);
                            for b in already_branched.lock().unwrap().iter()
                            // .filter(|(_, offset)| offset == &b.pc)
                            {
                                branches_to_taint.lock().unwrap().push(b.0);
                            }
                            b.pc += instruction.0 .0 / 2;
                            log::debug!(
                                "We have already branched, continue normal flow without jump"
                            );
                            return;
                        }
                        b.state.loop_count.entry(b.pc).or_insert(0).add_assign(1);
                        already_branched.lock().unwrap().push((b.id, b.pc));
                        if let (Some(left), Some(right)) = (
                            b.state.registers[u8::from(left) as usize].try_get_number(),
                            b.state.registers[u8::from(right) as usize].try_get_number(),
                        ) {
                            log::warn!("DEAD BRANCH: {:?}", instruction);
                            let jump_to_offset = match test {
                                coeus_models::models::TestFunction::Equal => left == right,
                                coeus_models::models::TestFunction::NotEqual => left != right,
                                coeus_models::models::TestFunction::LessThan => left < right,
                                coeus_models::models::TestFunction::LessEqual => left <= right,
                                coeus_models::models::TestFunction::GreaterThan => left > right,
                                coeus_models::models::TestFunction::GreaterEqual => left >= right,
                            };
                            if jump_to_offset {
                                b.pc += offset as i32;
                                return;
                            }
                        } else {
                            if conservative
                                || matches!(
                                    b.state.registers[u8::from(left) as usize],
                                    Value::Empty
                                )
                                || matches!(
                                    b.state.registers[u8::from(right) as usize],
                                    Value::Empty
                                )
                            {
                                b.state.tainted = true;
                            }
                            let mut new_branch = b.clone();
                            new_branch.parent_id = Some(b.id);
                            new_branch.pc += offset as i32;
                            new_branch.state.loop_count = HashMap::new();
                            branches_to_add.lock().unwrap().push((b.pc, new_branch));
                        }
                    }
                    Instruction::TestZero(test, left, offset) => {
                        if already_branched
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|(id, offset)| offset == &b.pc && &b.id == id)
                        {
                            branches_to_taint.lock().unwrap().push(b.id);
                            for b in already_branched.lock().unwrap().iter()
                            // .filter(|(_, offset)| offset == &b.pc)
                            {
                                branches_to_taint.lock().unwrap().push(b.0);
                            }
                            b.pc += instruction.0 .0 / 2;
                            log::debug!(
                                "We have already branched, continue normal flow without jump"
                            );
                            return;
                        }
                        b.state.loop_count.entry(b.pc).or_insert(0).add_assign(1);
                        already_branched.lock().unwrap().push((b.id, b.pc));
                        if let Some(left) =
                            b.state.registers[u8::from(left) as usize].try_get_number()
                        {
                            log::warn!("DEAD BRANCH");
                            let jump_to_offset = match test {
                                coeus_models::models::TestFunction::Equal => left == 0,
                                coeus_models::models::TestFunction::NotEqual => left != 0,
                                coeus_models::models::TestFunction::LessThan => left < 0,
                                coeus_models::models::TestFunction::LessEqual => left <= 0,
                                coeus_models::models::TestFunction::GreaterThan => left > 0,
                                coeus_models::models::TestFunction::GreaterEqual => left >= 0,
                            };
                            if jump_to_offset {
                                b.pc += offset as i32;
                                return;
                            }
                        } else {
                            if conservative
                                || matches!(
                                    b.state.registers[u8::from(left) as usize],
                                    Value::Empty
                                )
                            {
                                b.state.tainted = true;
                            }
                            let mut new_branch = b.clone();
                            new_branch.pc += offset as i32;
                            new_branch.parent_id = Some(b.id);
                            new_branch.state.loop_count = HashMap::new();
                            branches_to_add.lock().unwrap().push((b.pc, new_branch));
                        }
                    }
                    Instruction::PackedSwitch(_, table_offset) | Instruction::SparseSwitch(_, table_offset) => {
                        if let Some((_, Instruction::PackedSwitchData(switch))) =
                            method.get(&(b.pc + table_offset))
                        {
                            for (_, offset) in &switch.targets {
                                if already_branched
                                    .lock()
                                    .unwrap()
                                    .iter()
                                    .any(|(_, offset)| offset == &b.pc)
                                {
                                    continue;
                                }
                                let mut new_branch = b.clone();
                                new_branch.parent_id = Some(b.id);
                                new_branch.pc += *offset as i32;
                                branches_to_add.lock().unwrap().push((b.pc, new_branch));
                            }
                        }
                        if let Some((_, Instruction::SparseSwitchData(switch))) =
                            method.get(&(b.pc + table_offset))
                        {
                            for (_, offset) in &switch.targets {
                                if already_branched
                                    .lock()
                                    .unwrap()
                                    .iter()
                                    .any(|(_, offset)| offset == &b.pc)
                                {
                                    continue;
                                }
                                let mut new_branch = b.clone();
                                new_branch.parent_id = Some(b.id);
                                new_branch.pc += *offset as i32;
                                branches_to_add.lock().unwrap().push((b.pc, new_branch));
                            }
                        }
                        // branches_to_remove.push(b.id);
                        b.finished = true;
                        return;
                    }

                    //basic arithmetic
                    Instruction::XorInt(left, right) | Instruction::XorLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            ^ &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::XorIntDst(dst, left, right)
                    | Instruction::XorLongDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            ^ &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::XorIntDstLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] ^ (lit as i128)
                    }
                    Instruction::XorIntDstLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] ^ (lit as i128)
                    }
                    Instruction::RemIntDst(dst, left, right)
                    | Instruction::RemLongDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            % &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::RemInt(left, right) | Instruction::RemLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            % &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::RemIntLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] % (lit as i128)
                    }
                    Instruction::RemIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] % (lit as i128)
                    }

                    Instruction::AddInt(left, right) | Instruction::AddLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            + &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::AddIntDst(dst, left, right)
                    | Instruction::AddLongDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            + &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::AddIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] + (lit as i128)
                    }
                    Instruction::AddIntLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] + (lit as i128)
                    }

                    Instruction::SubInt(left, right) | Instruction::SubLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            - &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::SubIntDst(dst, left, right)
                    | Instruction::SubLongDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            - &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::SubIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] - (lit as i128)
                    }
                    Instruction::SubIntLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] - (lit as i128)
                    }

                    Instruction::MulInt(left, right) | Instruction::MulLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            * &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::MulIntDst(dst, left, right)
                    | Instruction::MulLongDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            * &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::MulIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] * (lit as i128)
                    }
                    Instruction::MulIntLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] * (lit as i128)
                    }

                    Instruction::DivInt(left, right) | Instruction::DivLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            / &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::DivIntDst(dst, left, right)
                    | Instruction::DivLongDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            / &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::DivIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] / (lit as i128)
                    }
                    Instruction::DivIntLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] / (lit as i128)
                    }

                    Instruction::AndInt(left, right) | Instruction::AndLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            & &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::AndLongDst(dst, left, right)
                    | Instruction::AndIntDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            & &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::AndIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] & (lit as i128)
                    }
                    Instruction::AndIntLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] & (lit as i128)
                    }

                    Instruction::OrInt(left, right) | Instruction::OrLong(left, right) => {
                        b.state.registers[u8::from(left) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            | &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::OrIntDst(dst, left, right)
                    | Instruction::OrLongDst(dst, left, right) => {
                        b.state.registers[u8::from(dst) as usize] = &b.state.registers
                            [u8::from(left) as usize]
                            | &b.state.registers[u8::from(right) as usize]
                    }
                    Instruction::OrIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] | (lit as i128)
                    }
                    Instruction::OrIntLit16(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] | (lit as i128)
                    }

                    // invocations
                    Instruction::Invoke(_) => {}
                    Instruction::InvokeType(_) => {}

                    Instruction::InvokeInterface(_, method, ref regs) => {
                        let m = &dex.methods[method as usize];
                        let proto = &dex.protos[m.proto_idx as usize];

                        let sig = proto.to_string(&dex);
                        let return_type = proto.get_return_type(&dex);
                        let class_name = dex.get_type_name(m.class_idx).unwrap_or_default();
                        let class = dex
                            .get_class_by_type_name_idx(m.class_idx)
                            .unwrap_or(Arc::new(Class {
                                class_name: class_name.to_string(),
                                class_idx: m.class_idx as u32,
                                ..Default::default()
                            }))
                            .clone();
                        let impls = dex.get_implementations_for(&class);
                        let mut args = regs
                            .iter()
                            .map(|a| b.state.registers[*a as usize].clone())
                            .collect::<Vec<_>>();
                        if impls.len() == 1 {
                            let (_f, new_class) = &impls[0];
                            args[0] = Value::Object {
                                ty: new_class.class_name.clone(),
                            };
                            for v in &new_class.codes {
                                if v.method.method_name == m.method_name {
                                    let function_call = LastInstruction::FunctionCall {
                                        name: v.method.method_name.clone(),
                                        method: v.method.clone(),
                                        class_name: new_class.class_name.to_string(),
                                        class: new_class.clone(),
                                        signature: format!(
                                            "{}->{}{}",
                                            new_class.class_name, m.method_name, sig
                                        ),
                                        args: args.clone(),
                                        result: if return_type == "V" {
                                            None
                                        } else {
                                            Some(Value::Object {
                                                ty: return_type.clone(),
                                            })
                                        },
                                    };
                                    b.state.last_instruction = Some(function_call);
                                }
                            }
                            if b.state.last_instruction.is_none() {
                                let function_call = LastInstruction::FunctionCall {
                                    name: m.method_name.clone(),
                                    method: m.clone(),
                                    class_name: class_name.to_string(),
                                    class,
                                    signature: format!("{}->{}{}", class_name, m.method_name, sig),
                                    args,
                                    result: if return_type == "V" {
                                        None
                                    } else {
                                        Some(Value::Object { ty: return_type })
                                    },
                                };
                                b.state.last_instruction = Some(function_call);
                            }
                        } else {
                            let function_call = LastInstruction::FunctionCall {
                                name: m.method_name.clone(),
                                method: m.clone(),
                                class_name: class_name.to_string(),
                                class,
                                signature: format!("{}->{}{}", class_name, m.method_name, sig),
                                args,
                                result: if return_type == "V" {
                                    None
                                } else {
                                    Some(Value::Object { ty: return_type })
                                },
                            };
                            b.state.last_instruction = Some(function_call);
                        }
                    }

                    Instruction::InvokeVirtual(_, method, ref regs)
                    | Instruction::InvokeSuper(_, method, ref regs)
                    | Instruction::InvokeDirect(_, method, ref regs)
                    | Instruction::InvokeStatic(_, method, ref regs) => {
                        let m = &dex.methods[method as usize];
                        let proto = &dex.protos[m.proto_idx as usize];

                        let sig = proto.to_string(&dex);
                        let return_type = proto.get_return_type(&dex);
                        let class_name = dex.get_type_name(m.class_idx).unwrap_or_default();
                        let class = dex
                            .get_class_by_type_name_idx(m.class_idx)
                            .unwrap_or(Arc::new(Class {
                                class_name: class_name.to_string(),
                                class_idx: m.class_idx as u32,
                                ..Default::default()
                            }))
                            .clone();
                        let args = regs
                            .iter()
                            .map(|a| b.state.registers[*a as usize].clone())
                            .collect::<Vec<_>>();
                        let function_call = LastInstruction::FunctionCall {
                            name: m.method_name.clone(),
                            method: m.clone(),
                            class_name: class_name.to_string(),
                            class,
                            signature: format!("{}->{}{}", class_name, m.method_name, sig),
                            args,
                            result: if return_type == "V" {
                                None
                            } else {
                                Some(Value::Object { ty: return_type })
                            },
                        };
                        b.state.last_instruction = Some(function_call);
                    }

                    Instruction::InvokeVirtualRange(_, method, _)
                    | Instruction::InvokeSuperRange(_, method, _)
                    | Instruction::InvokeDirectRange(_, method, _)
                    | Instruction::InvokeStaticRange(_, method, _)
                    | Instruction::InvokeInterfaceRange(_, method, _) => {
                        let m = &dex.methods[method as usize];
                        let proto = &dex.protos[m.proto_idx as usize];
                        let sig = proto.to_string(&dex);
                        let return_type = proto.get_return_type(&dex);
                        let class_name = dex.get_type_name(m.class_idx).unwrap_or_default();
                        let class = dex
                            .get_class_by_type_name_idx(m.class_idx)
                            .unwrap_or(Arc::new(Class {
                                class_name: class_name.to_string(),
                                class_idx: m.class_idx as u32,
                                ..Default::default()
                            }))
                            .clone();
                        let args = vec![];
                        let function_call = LastInstruction::FunctionCall {
                            name: m.method_name.clone(),
                            method: m.clone(),
                            class_name: class_name.to_string(),
                            class,
                            signature: format!("{}->{}{}", class_name, m.method_name, sig),
                            args,
                            result: if return_type == "V" {
                                None
                            } else {
                                Some(Value::Object { ty: return_type })
                            },
                        };
                        b.state.last_instruction = Some(function_call);
                    }

                    // const
                    Instruction::ConstLit4(reg, val) => {
                        b.state.registers[u8::from(reg) as usize] =
                            Value::Number(i8::from(val) as i128)
                    }
                    Instruction::ConstLit16(reg, val) => {
                        b.state.registers[reg as usize] = Value::Number(val as i128)
                    }
                    Instruction::ConstLit32(reg, val) => {
                        b.state.registers[reg as usize] = Value::Number(val as i128)
                    }
                    Instruction::ConstHigh16(reg, val) => {
                        b.state.registers[reg as usize] =
                            Value::Number((i32::from(val as i16) << 16) as i128)
                    }
                    Instruction::ConstWide(reg, val) => {
                        b.state.registers[reg as usize] = Value::Number(val as i128)
                    }

                    Instruction::ConstString(reg, str_idx) => {
                        b.state.registers[reg as usize] = dex
                            .get_string(str_idx)
                            .map(|a| Value::String(a.to_string()))
                            .unwrap_or(Value::Unknown {
                                ty: String::from("Ljava/lang/String;"),
                            });
                    }
                    Instruction::ConstStringJumbo(reg, str_idx) => {
                        b.state.registers[reg as usize] = dex
                            .get_string(str_idx as usize)
                            .map(|a| Value::String(a.to_string()))
                            .unwrap_or(Value::Unknown {
                                ty: String::from("Ljava/lang/String;"),
                            })
                    }
                    Instruction::ConstClass(reg, c) => {
                        let class_name = dex
                            .get_class_name(c)
                            .map(|a| Value::Unknown { ty: a.to_string() })
                            .unwrap_or(Value::Unknown {
                                ty: String::from("TYPE NOT FOUND"),
                            });
                        b.state.registers[reg as usize] = class_name;
                    }
                    Instruction::Const => {}

                    // casts
                    Instruction::IntToByte(dst, src) => {
                        if let Value::Number(numb) = b.state.registers[u8::from(src) as usize] {
                            b.state.registers[u8::from(dst) as usize] = Value::Byte(numb as u8);
                        }
                    }
                    Instruction::IntToChar(dst, src) => {
                        if let Value::Number(numb) = b.state.registers[u8::from(src) as usize] {
                            b.state.registers[u8::from(dst) as usize] =
                                Value::Char(numb as u8 as char);
                        }
                    }

                    // new instances and arrays
                    Instruction::ArrayLength(dst, array) => {
                        if let Value::Bytes(ref v) = b.state.registers[u8::from(array) as usize] {
                            b.state.registers[u8::from(dst) as usize] =
                                Value::Number(v.len() as i128);
                        } else {
                            b.state.registers[u8::from(dst) as usize] = Value::Invalid;
                        }
                    }
                    Instruction::NewInstance(reg, ty) => {
                        if let Some(type_name) = dex.get_type_name(ty) {
                            b.state.registers[reg as usize] = Value::Object {
                                ty: type_name.to_string(),
                            };
                        } else {
                            b.state.registers[reg as usize] = Value::Unknown {
                                ty: format!("UNKNOWN"),
                            };
                        }
                    }
                    Instruction::NewInstanceType(_) => {}
                    Instruction::NewArray(_, _, _) => {}
                    Instruction::FilledNewArray(_, _, _) => {}
                    Instruction::FilledNewArrayRange(_, _, _) => {}
                    Instruction::FillArrayData(_, _) => {}
                    Instruction::ArrayGetByte(dst, arr_reg, index_reg) => {
                        if let (Value::Bytes(a), Value::Number(index)) = (
                            &b.state.registers[arr_reg as usize],
                            &b.state.registers[index_reg as usize],
                        ) {
                            b.state.registers[dst as usize] = Value::Byte(a[*index as usize]);
                        } else {
                            b.state.registers[dst as usize] = Value::Empty;
                        }
                    }
                    Instruction::ArrayPutByte(src, arr_reg, index_reg) => {
                        let index = if let Value::Number(n) = b.state.registers[index_reg as usize]
                        {
                            Some(n)
                        } else {
                            None
                        };
                        let byte = if let Value::Byte(b) = b.state.registers[src as usize] {
                            Some(b)
                        } else {
                            None
                        };
                        if let (Value::Bytes(a), Some(index)) =
                            (&mut b.state.registers[arr_reg as usize], index)
                        {
                            if let Some(b) = byte {
                                a[index as usize] = b;
                            }
                        }
                    }
                    Instruction::ArrayGetChar(dst, arr_reg, index_reg) => {
                        if let (Value::Bytes(a), Value::Number(index)) = (
                            &b.state.registers[arr_reg as usize],
                            &b.state.registers[index_reg as usize],
                        ) {
                            b.state.registers[dst as usize] =
                                Value::Char(a[*index as usize] as char);
                        } else {
                            b.state.registers[dst as usize] = Value::Empty;
                        }
                    }
                    Instruction::ArrayPutChar(src, arr_reg, index_reg) => {
                        let index = if let Value::Number(n) = b.state.registers[index_reg as usize]
                        {
                            Some(n)
                        } else {
                            None
                        };
                        let byte = if let Value::Char(b) = b.state.registers[src as usize] {
                            Some(b)
                        } else {
                            None
                        };
                        if let (Value::Bytes(a), Some(index)) =
                            (&mut b.state.registers[arr_reg as usize], index)
                        {
                            if let Some(b) = byte {
                                a[index as usize] = b as u8;
                            }
                        }
                    }

                    // FieldAccess
                    Instruction::StaticGet(dst, field)
                    | Instruction::StaticGetObject(dst, field)
                    | Instruction::StaticGetBoolean(dst, field)
                    | Instruction::StaticGetByte(dst, field)
                    | Instruction::StaticGetChar(dst, field)
                    | Instruction::StaticGetShort(dst, field) => {
                        let dst: u8 = (dst).into();
                        b.state.registers[dst as usize] = Value::Empty;
                        if let Some(field) = dex.fields.get(field as usize) {
                            let class_name = dex
                                .get_type_name(field.class_idx)
                                .unwrap_or_default()
                                .to_string();
                            let class = dex
                                .get_class_by_type(field.class_idx)
                                .unwrap_or(Arc::new(Class {
                                    class_name: class_name.to_string(),
                                    class_idx: field.class_idx as u32,
                                    ..Default::default()
                                }))
                                .clone();
                            b.state.last_instruction = Some(LastInstruction::ReadStaticField {
                                file: dex.clone(),
                                class,
                                class_name,
                                field: field.clone(),
                                name: field.name.to_string(),
                            });
                        }
                    }
                    Instruction::StaticGetWide(dst, field) => {
                        let dst: u8 = (dst).into();
                        b.state.registers[dst as usize] = Value::Empty;
                        b.state.registers[dst as usize + 1] = Value::Empty;
                        if let Some(field) = dex.fields.get(field as usize) {
                            let class_name = dex
                                .get_type_name(field.class_idx)
                                .unwrap_or_default()
                                .to_string();
                            let class = dex
                                .get_class_by_type_name_idx(field.class_idx)
                                .unwrap_or(Arc::new(Class {
                                    class_name: class_name.to_string(),
                                    class_idx: field.class_idx as u32,
                                    ..Default::default()
                                }))
                                .clone();
                            b.state.last_instruction = Some(LastInstruction::ReadStaticField {
                                file: dex.clone(),
                                class,
                                class_name,
                                field: field.clone(),
                                name: field.name.to_string(),
                            });
                        }
                    }
                    Instruction::StaticPut(_, _) => {}
                    Instruction::StaticPutWide(_, _) => {}
                    Instruction::StaticPutObject(_, _) => {}
                    Instruction::StaticPutBoolean(_, _) => {}
                    Instruction::StaticPutByte(_, _) => {}
                    Instruction::StaticPutChar(_, _) => {}
                    Instruction::StaticPutShort(_, _) => {}

                    Instruction::InstanceGet(dst, _, _)
                    | Instruction::InstanceGetObject(dst, _, _)
                    | Instruction::InstanceGetShort(dst, _, _)
                    | Instruction::InstanceGetBoolean(dst, _, _)
                    | Instruction::InstanceGetByte(dst, _, _)
                    | Instruction::InstanceGetChar(dst, _, _) => {
                        let dst: u8 = (dst).into();
                        b.state.registers[dst as usize] = Value::Empty;
                    }
                    Instruction::InstanceGetWide(dst, ..) => {
                        let dst: u8 = (dst).into();
                        b.state.registers[dst as usize] = Value::Empty;
                        b.state.registers[dst as usize + 1] = Value::Empty;
                    }

                    Instruction::InstancePut(_, _, _) => {}
                    Instruction::InstancePutWide(_, _, _) => {}
                    Instruction::InstancePutObject(_, _, _) => {}
                    Instruction::InstancePutBoolean(_, _, _) => {}
                    Instruction::InstancePutByte(_, _, _) => {}
                    Instruction::InstancePutChar(_, _, _) => {}
                    Instruction::InstancePutShort(_, _, _) => {}

                    // moves
                    Instruction::Move(dst, src) | Instruction::MoveObject(dst, src) => {
                        let dst: u8 = (dst).into();
                        let src: u8 = (src).into();
                        b.state.registers[dst as usize] = b.state.registers[src as usize].clone();
                    }
                    Instruction::Move16(dst, src) | Instruction::MoveObject16(dst, src) => {
                        b.state.registers[dst as usize] = b.state.registers[src as usize].clone();
                    }

                    Instruction::MoveResult(reg)
                    | Instruction::MoveResultWide(reg)
                    | Instruction::MoveResultObject(reg) => {
                        if let Some(function_call) = &b.state.last_instruction {
                            b.state.registers[reg as usize] =
                                Value::Variable(Box::new(function_call.clone()));
                        }
                    }

                    Instruction::MoveFrom16(dst, ..)
                    | Instruction::MoveWideFrom16(dst, ..)
                    | Instruction::MoveObjectFrom16(dst, ..) => {
                        let dst: usize = dst.into();
                        b.state.registers[dst] = Value::Empty;
                    }
                    Instruction::MoveWide(dst, ..) => {
                        let dst: u32 = dst.into();
                        b.state.registers[dst as usize] = Value::Empty;
                    }
                    Instruction::MoveWide16(dst, ..) => {
                        let dst: usize = dst.into();
                        b.state.registers[dst] = Value::Empty;
                    }

                    // branch finished
                    // we also use this for unhandled instructions
                    Instruction::ReturnVoid | Instruction::Return(..) | Instruction::Throw(..) => {
                        // branches_to_remove.push(b.id);
                        b.finished = true;
                        return;
                    }

                    // We don't need those
                    Instruction::NotImpl(_, _) => {
                        branches_to_taint.lock().unwrap().push(b.id);
                        for reg in &mut b.state.registers {
                            *reg = Value::Empty;
                        }
                    }
                    Instruction::ArrayData(_, _) => {}
                    Instruction::PackedSwitchData(_) | Instruction::SparseSwitchData(_) => {}

                    Instruction::ShrIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            &b.state.registers[u8::from(left) as usize] >> (lit as i128)
                    }
                    Instruction::UShrIntLit8(dst, left, lit) => {
                        b.state.registers[u8::from(dst) as usize] =
                            b.state.registers[u8::from(left) as usize].ushr(lit as i128)
                    }

                    Instruction::Nop => {}
                    _ => {}
                }
                // reset last_function if this is not a function call
                // and we are not in an move-result-object
                if !is_function_call(&instruction.1)
                    && !is_move_result(&instruction.1)
                    && matches!(
                        b.state.last_instruction,
                        Some(LastInstruction::FunctionCall { .. })
                    )
                {
                    b.state.last_instruction = None;
                }
                b.pc += instruction.0 .0 / 2;
            });
        // for remove_id in &branches_to_remove {
        //     if let Some(b) = self.branches.iter_mut().find(|b| b.id == remove_id) {
        //         b.finished = true;
        //     }
        // }
        // self.branches
        //     .retain(|a| !branches_to_remove.iter().any(|id| &a.id == id));
        self.already_branched = Arc::try_unwrap(clone_already_branched)
            .unwrap()
            .into_inner()
            .unwrap();
        let branches_to_taint = Arc::try_unwrap(clone_branches_to_taint)
            .unwrap()
            .into_inner()
            .unwrap();
        for b_to_taint in branches_to_taint.iter() {
            taint_recursively(*b_to_taint, &mut self.branches);
            // self.branches
            //     .iter_mut()
            //     .filter(|b| {
            //         b.id == b_to_taint
            //             || (b.parent_id.is_some() && b.parent_id.unwrap() == b_to_taint)
            //     })
            //     .for_each(|b| b.state.tainted = true);
        }
        let branches_to_add = Arc::try_unwrap(clone_branches_to_add)
            .unwrap()
            .into_inner()
            .unwrap();
        if self.branches.len() < 1000 {
            for (offset, b) in branches_to_add {
                let id = self.fork(b);
                self.already_branched.push((id, offset));
            }
        }
    }
    fn new_branch(&mut self, pc: InstructionOffset, parent_id: Option<u64>) {
        if self.branches.len() > 10 {
            println!("Føk, we have too many branches");
            return;
        }
        self.branches.push(Branch {
            parent_id,
            id: rand::random(),
            pc,
            previous_pc: pc,
            state: State {
                id: rand::random(),
                registers: vec![Value::Empty; self.register_size as usize],
                last_instruction: None,
                tainted: false,
                loop_count: HashMap::new(),
            },
            finished: false,
        });
    }
    fn fork(&mut self, mut branch: Branch) -> u64 {
        let id: u64 = rand::random();
        branch.id = id;
        branch.state.id = rand::random();
        self.branches.push(branch);
        id
    }
    pub fn is_done(&self) -> bool {
        self.branches.is_empty()
    }
    pub fn get_all_states(&self) -> Vec<&State> {
        self.branches.iter().map(|b| &b.state).collect()
    }
    pub fn get_all_branches(&self) -> &Vec<Branch> {
        &self.branches
    }
}

fn taint_recursively(id: u64, branches: &mut [Branch]) {
    let mut parents = Vec::with_capacity(branches.len());
    for b in branches.iter_mut() {
        if b.id == id {
            b.state.tainted = true;
            continue;
        }
        if let Some(parent_id) = b.parent_id {
            if parent_id == id {
                parents.push(b.id);
            }
        }
    }
    for parent in parents {
        taint_recursively(parent, branches);
    }
}

fn is_move_result(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::MoveResult(..)
            | Instruction::MoveResultObject(..)
            | Instruction::MoveResultWide(..)
    )
}
fn is_function_call(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::Invoke(..)
            | Instruction::InvokeDirect(..)
            | Instruction::InvokeDirectRange(..)
            | Instruction::InvokeInterface(..)
            | Instruction::InvokeInterfaceRange(..)
            | Instruction::InvokeStatic(..)
            | Instruction::InvokeStaticRange(..)
            | Instruction::InvokeSuper(..)
            | Instruction::InvokeSuperRange(..)
            | Instruction::InvokeVirtual(..)
            | Instruction::InvokeVirtualRange(..)
    )
}
