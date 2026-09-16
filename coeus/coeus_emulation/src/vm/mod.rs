// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use petgraph::graph::NodeIndex;
use rand::prelude::StdRng;
use rand::Rng;
#[cfg(not(target_arch = "wasm32"))]
use rayon::iter::ParallelIterator;

use coeus_macros::iterator;

use self::runtime::{invoke_runtime, invoke_runtime_with_method, StringClass};

use coeus_models::models::{
    BinaryObject, Class, CodeItem, DexFile, Instruction, InstructionOffset, InstructionSize,
    Method, MethodData, ValueType,
};

pub mod dynamic_runtime;
pub mod runtime;

use runtime::VM_BUILTINS;

const MAX_SIZE: usize = 100_000;

#[derive(Clone)]
pub struct VMState {
    pub pc: InstructionOffset,
    pub last_instruction_size: InstructionSize,
    pub current_instruction_size: InstructionSize,
    pub current_stackframe: Vec<Register>,
    pub return_reg: Register,
    num_params: usize,
    num_registers: usize,
    current_instructions: HashMap<InstructionOffset, (InstructionSize, Instruction)>,
    pub current_dex_file: Arc<DexFile>,
    pub current_method_index: u32,
    pub vm_state: ExecutionState,
    last_break_point_reg: u32,
}

impl std::fmt::Debug for VMState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VMState")
            .field("PC", &self.pc)
            .field("CurrentStackframe", &self.current_stackframe)
            .field("ReturnRegister", &self.return_reg)
            .field("CurrentState", &self.vm_state)
            .field("CurrentMethodIndex", &self.current_method_index)
            .field("CurrentDexFile", &self.current_dex_file.identifier)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExecutionState {
    Stopped,
    Paused,
    Running,
    RunningStaticInitializer,
    StaticInitializer,
    Error,
    Finished,
}

#[derive(Clone, Debug)]
pub enum InformationNode<'a> {
    Source(Value),
    Field(u32),
    Method(u32),
    String(u32),
    ArrayData(&'a [u8]),
}
#[derive(Clone, Debug)]
pub enum Value {
    Array(Vec<u8>),
    Object(ClassInstance),
    Int(i32),
    Short(i16),
    Byte(i8),
}
impl Value {
    pub fn as_string(&self) -> Option<String> {
        if let Value::Object(cl) = self {
            if cl.class.class_name == runtime::StringClass::class_name() {
                return Some(format!("{}", cl));
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
pub enum InternalObject {
    String(String),
    Class(Arc<Class>),
    Vec(Vec<u8>),
    I32(i32),
    U32(u32),
    I64(i64),
}

#[derive(Clone, Debug)]
pub struct ClassInstance {
    pub internal_state: HashMap<String, InternalObject>,
    pub instances: HashMap<String, u32>,
    pub class: Arc<Class>,
}

impl std::fmt::Display for ClassInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.class.class_name == "Ljava/lang/String;" {
            match self.internal_state.get("tmp_string") {
                Some(InternalObject::String(string)) => f.write_fmt(format_args!("{}", string)),
                _ => {
                    log::debug!("New string instance... {:?}", self.class);
                    f.write_fmt(format_args!("NEW INSTANCE"))
                }
            }
        } else {
            f.debug_struct("ClassInstance")
                .field("class", &self.class)
                .field("instances", &self.instances)
                .finish()
        }
    }
}

impl ClassInstance {
    pub fn new(class: Arc<Class>) -> Self {
        ClassInstance {
            internal_state: HashMap::new(),
            instances: HashMap::new(),
            class,
        }
    }
    pub fn from_class_name(
        class_name: &str,
        internal_state: HashMap<String, InternalObject>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(class) = VM_BUILTINS.get(class_name) {
            Ok(ClassInstance {
                instances: HashMap::new(),
                internal_state,
                class: class.clone(),
            })
        } else {
            Err("No Builtin found".into())
        }
    }
    pub fn with_internal_state(
        class: Arc<Class>,
        internal_state: HashMap<String, InternalObject>,
    ) -> Self {
        ClassInstance {
            internal_state,
            instances: HashMap::new(),
            class: class,
        }
    }
}
/// Represents a virtual Dex Machine
#[derive(Clone)]
pub struct VM {
    pub current_state: VMState,
    stack_frames: Vec<VMState>,
    heap: HashMap<u32, Value>,
    instances: HashMap<String, (NodeIndex, u32)>,
    dex_file: Arc<DexFile>,
    runtime: Vec<Arc<DexFile>>,
    resources: Arc<HashMap<String, Arc<BinaryObject>>>,
    builtins: Arc<HashMap<String, Arc<Class>>>,
    cached_methods: HashMap<String, (Arc<DexFile>, Arc<MethodData>)>,
    rng: Arc<Mutex<RefCell<StdRng>>>,
    break_points: Vec<Breakpoint>,
    stop_on_array_use: bool,
    stop_on_string_use: bool,
    stop_on_array_return: bool,
    stop_on_string_return: bool,
    skip_next_breakpoint: bool,
}

#[derive(Debug)]
pub enum VMException {
    RegisterNotFound(usize),
    StackFrameMissing,
    NoInstructionAtAddress(u32, usize),
    ClassNotFound(u16),
    OutOfMemory,
    InstanceNotFound(u32),
    IndexOutOfBounds,
    WrongNumberOfArguments,
    InvalidRegisterType,
    StackOverflow,
    MethodNotFound(String),
    InvalidMemoryAddress(u32),
    LinkerError,
    StaticDataNotFound(u32),
    Breakpoint(InstructionOffset, u32, BreakpointContext),
    ExceptionThrown,
}
#[derive(Debug, Copy, Clone)]
pub enum BreakpointContext {
    ResultObjectRegister(u16),
    ArrayReg(u16, u16),
    StringReg(u16, u16),
    FieldSet(u16, u16),
    None,
}
#[derive(Debug, Clone)]
pub enum Breakpoint {
    ArrayUse,
    StringUse,
    StringReturn,
    ArrayReturn,
    RegisterAccess(u8),
    PrototypeResult(u16),
    FunctionResult(u16),
    Instruction(u32),
    FieldSet(u16),
    FieldGet(u16),
    FunctionEntry,
    FunctionExit,
}
use rand::SeedableRng;
/// Implementation for Virtual Machine
/// provides functions to emulate a function
// TODO: we need a way to set breakpoints for certain events e.g. when an array is used
impl VM {
    pub fn get_heap(&self) -> HashMap<u32, Value> {
        self.heap.clone()
    }
    pub fn get_heap_ref(&self) -> &HashMap<u32, Value> {
        &self.heap
    }
    pub fn get_heap_mut(&mut self) -> &mut HashMap<u32, Value> {
        &mut self.heap
    }
    pub fn get_instances(&self) -> HashMap<String, (NodeIndex, u32)> {
        self.instances.clone()
    }
    pub fn new(
        dex_file: Arc<DexFile>,
        runtime: Vec<Arc<DexFile>>,
        resources: Arc<HashMap<String, Arc<BinaryObject>>>,
    ) -> VM {
        let rng = rand::rngs::StdRng::seed_from_u64(0xff_ff_ff_ff);

        VM {
            current_state: VMState {
                pc: 0.into(),
                last_instruction_size: 0.into(),
                current_instruction_size: 0.into(),
                current_stackframe: vec![],
                return_reg: Register::Empty,
                num_params: 0,
                num_registers: 0,
                current_instructions: HashMap::new(),
                current_dex_file: dex_file.clone(),
                current_method_index: 0,
                vm_state: ExecutionState::Stopped,

                last_break_point_reg: 0,
            },
            cached_methods: HashMap::new(),
            stack_frames: vec![],
            heap: HashMap::new(),
            instances: HashMap::new(),
            dex_file,
            runtime,
            resources,
            builtins: VM_BUILTINS.clone(),
            rng: Arc::new(Mutex::new(RefCell::new(rng))),
            break_points: vec![],
            stop_on_array_use: false,
            stop_on_array_return: false,
            stop_on_string_return: false,
            stop_on_string_use: false,
            skip_next_breakpoint: false,
        }
    }

    pub fn set_breakpoint(&mut self, break_point: Breakpoint) {
        match break_point {
            Breakpoint::ArrayUse => {
                self.stop_on_array_use = true;
            }
            Breakpoint::StringUse => self.stop_on_string_use = true,
            Breakpoint::StringReturn => self.stop_on_string_return = true,
            Breakpoint::ArrayReturn => self.stop_on_array_return = true,
            _ => {}
        }
        self.break_points.push(break_point);
    }
    pub fn clear_breakpoints(&mut self) {
        self.stop_on_array_use = false;
        self.stop_on_string_use = false;
        self.stop_on_string_return = false;
        self.stop_on_array_return = false;
        self.break_points.clear();
    }
    pub fn get_breakpoints_clone(&self) -> Vec<Breakpoint> {
        self.break_points.clone()
    }
    pub fn continue_execution(
        &mut self,
        start_address: InstructionOffset,
    ) -> Result<(), VMException> {
        self.skip_next_breakpoint = true;
        self.execute(start_address)
    }
    pub fn skip_over(&mut self) -> Result<(), VMException> {
        self.current_state.pc += self.current_state.current_instruction_size;
        self.execute(self.current_state.pc)
    }
    pub fn reset(&mut self) {
        self.current_state.pc = 0.into();
        self.current_state.current_stackframe = vec![];
        self.current_state.return_reg = Register::Empty;
        self.current_state.num_params = 0;
        self.current_state.num_registers = 0;
        self.current_state.current_instructions = HashMap::new();
        self.current_state.current_dex_file = self.dex_file.clone();
        self.current_state.vm_state = ExecutionState::Stopped;
        self.current_state.current_method_index = 0;

        self.stack_frames.clear();
        self.heap.clear();
        self.instances.clear();
        self.skip_next_breakpoint = false;
    }
    pub fn new_instance(&mut self, ty: String, value: Value) -> Result<Register, VMException> {
        if let Some(heap_address) = self.malloc() {
            self.heap.insert(heap_address, value);
            Ok(Register::Reference(ty, heap_address))
        } else {
            Err(VMException::OutOfMemory)
        }
    }
    pub fn get_registers(&self) -> Vec<Register> {
        self.current_state.current_stackframe.clone()
    }
    pub fn get_current_state(&self) -> &VMState {
        &self.current_state
    }
    pub fn get_stack_frames(&self) -> &[VMState] {
        &self.stack_frames
    }
    pub fn get_instance(&self, reg: Register) -> Value {
        match reg {
            Register::Literal(l) => Value::Int(l),
            Register::Reference(_, address) => self.heap[&address].clone(),
            Register::Null => Value::Int(0),
            _ => Value::Int(0),
        }
    }
    pub fn start(
        &mut self,
        method_idx: u32,
        dex_file: &str,
        code_item: &CodeItem,
        arguments: Vec<Register>,
    ) -> Result<(), VMException> {
        self.current_state.pc = 0.into();
        self.current_state.return_reg = Register::Empty;
        self.current_state.current_stackframe = vec![];
        self.current_state.num_params = code_item.ins_size as usize;
        self.current_state.num_registers = code_item.register_size as usize;
        self.current_state.current_method_index = method_idx;
        self.stack_frames.clear();
        self.current_state.current_dex_file = if self.dex_file.identifier == dex_file {
            self.dex_file.clone()
        } else {
            self.runtime
                .iter()
                .find(|df| df.identifier == dex_file)
                .ok_or(VMException::LinkerError)?
                .clone()
        };

        if arguments.len() != self.current_state.num_params {
            return Err(VMException::WrongNumberOfArguments);
        }

        let start_params = self.current_state.num_registers - self.current_state.num_params;

        let mut registers = Vec::with_capacity(self.current_state.num_registers);
        for _ in 0..start_params {
            registers.push(Register::Empty);
        }
        for arg in arguments {
            registers.push(arg);
        }
        self.current_state.current_stackframe = registers;

        let code_hash = code_item
            .insns
            .clone()
            .into_iter()
            .map(|ele| (ele.1, (ele.0, ele.2)))
            .collect();
        self.current_state.current_instructions = code_hash;

        match self.execute(InstructionOffset(0)) {
            Ok(_) => {
                log::debug!("Function reached return statement");
                Ok(())
            }
            Err(exception) => Err(exception),
        }
    }

    /// Returned MethodData is guaranteed to have an implementation
    pub fn lookup_method(
        &self,
        class_name: &str,
        method: &Method,
    ) -> Result<(Arc<DexFile>, Arc<MethodData>), VMException> {
        if let Some(method_data) = self
            .dex_file
            .get_method_by_name_and_prototype(
                class_name,
                method.method_name.as_str(),
                &method.proto_name,
            )
            .map(|d| (self.dex_file.clone(), d))
        {
            return Ok(method_data);
        }
        if let Some(method_data) = iterator!(self.runtime)
            .filter_map(|dex| {
                dex.get_method_by_name_and_prototype(
                    class_name,
                    method.method_name.as_str(),
                    &method.proto_name,
                )
                .map(|d| (dex.clone(), d))
            })
            .collect::<Vec<(Arc<DexFile>, Arc<MethodData>)>>()
            .first()
        {
            return Ok(method_data.clone());
        }

        let Some(class) = self.dex_file.get_class_by_name(&class_name) else {
            return Err(VMException::LinkerError);
        };

        let mut super_class = class.get_superclass(self.dex_file.clone());
        while let Some(c) = super_class.as_ref() {
            if let Some(method_data) = iterator!(self.runtime)
                .filter_map(|dex| {
                    dex.get_method_by_name_and_prototype(
                        &c.class_name,
                        method.method_name.as_str(),
                        &method.proto_name,
                    )
                    .map(|d| (dex.clone(), d))
                })
                .collect::<Vec<(Arc<DexFile>, Arc<MethodData>)>>()
                .first()
            {
                return Ok(method_data.clone());
            }
            super_class = c.get_superclass(self.dex_file.clone());
        }
        Err(VMException::LinkerError)
    }

    fn get_method<'a>(
        &'a mut self,
        dex_file: &'a Arc<DexFile>,
        method_idx: u32,
    ) -> Result<(Arc<DexFile>, Arc<MethodData>), VMException> {
        if let Some(method_data) = dex_file.get_method_by_idx(method_idx) {
            // self.method_link_table.insert(method_idx, *method_data);
            return Ok((dex_file.clone(), method_data));
        }
        let method = dex_file
            .methods
            .get(method_idx as usize)
            .ok_or_else(|| VMException::MethodNotFound(format!("Method Index: {}", method_idx)))?;

        let proto_type = dex_file
            .protos
            .get(method.proto_idx as usize)
            .ok_or_else(|| {
                VMException::MethodNotFound(format!(
                    "Method Index: {}, Proto Index: {}",
                    method_idx, method.proto_idx
                ))
            })?
            .to_string(dex_file);

        let class_name = dex_file
            .get_type_name(method.class_idx)
            .ok_or(VMException::ClassNotFound(method.class_idx))?;

        let method_cache_key = format!("{}->{}{}", class_name, method.method_name, proto_type);
        if let Some(md) = self.cached_methods.get(&method_cache_key) {
            return Ok((md.0.clone(), md.1.clone()));
        }

        if let Some(method_data) = iterator!(self.runtime)
            .filter_map(|dex| {
                dex.get_method_by_name_and_prototype(
                    class_name,
                    method.method_name.as_str(),
                    &proto_type,
                )
                .map(|d| (dex.clone(), d))
            })
            .collect::<Vec<(Arc<DexFile>, Arc<MethodData>)>>()
            .first()
        {
            self.cached_methods.insert(
                method_cache_key,
                (method_data.0.clone(), method_data.1.clone()),
            );
            return Ok(method_data.clone());
        }

        let Some((dex, class)) = iterator!(self.runtime)
            .find_map_first(|d| d.get_class_by_name(class_name).map(|c| (d, c)))
        else {
            return Err(VMException::LinkerError);
        };
        // try super class
        let mut super_class = class.get_superclass(dex.clone());

        while let Some(c) = super_class.as_ref() {
            if let Some(method_data) = iterator!(self.runtime)
                .filter_map(|dex| {
                    dex.get_method_by_name_and_prototype(
                        &c.class_name,
                        method.method_name.as_str(),
                        &proto_type,
                    )
                    .map(|d| (dex.clone(), d))
                })
                .collect::<Vec<(Arc<DexFile>, Arc<MethodData>)>>()
                .first()
            {
                self.cached_methods.insert(
                    method_cache_key,
                    (method_data.0.clone(), method_data.1.clone()),
                );
                return Ok(method_data.clone());
            }
            super_class = c.get_superclass(dex_file.clone());
        }
        Err(VMException::LinkerError)
    }
    fn get_class(&self, dex_file: Arc<DexFile>, type_idx: u32) -> Result<Arc<Class>, VMException> {
        // if let Some(method) = self.class_link_table.get(&type_idx) {
        //     return Ok(method);
        // }
        //first search current dexfile
        if let Some(class) = dex_file.get_class_by_type(type_idx) {
            // self.class_link_table.insert(type_idx, class);
            return Ok(class);
        }

        let class_name = dex_file
            .get_type_name(type_idx as usize)
            .ok_or(VMException::ClassNotFound(type_idx as u16))?;

        if let Some(class) = iterator!(self.runtime)
            .filter_map(|dex| dex.get_class_by_name(class_name))
            .collect::<Vec<Arc<Class>>>()
            .first()
        {
            return Ok(class.clone());
        }
        if let Some(class) = iterator!(self.builtins)
            .filter_map(|(_, class)| {
                if class.class_name == class_name {
                    Some(class.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<Arc<Class>>>()
            .first()
        {
            return Ok(class.clone());
        }

        Err(VMException::ClassNotFound(type_idx as u16))
    }

    fn binary_op<T>(
        &mut self,
        dst: T,
        a: T,
        b: T,
        op: fn(i32, i32) -> Result<i32, VMException>,
    ) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
    {
        let mut new_register = Register::Empty;
        if let Register::Literal(a) = *self
            .current_state
            .current_stackframe
            .get(a.into())
            .ok_or_else(|| VMException::RegisterNotFound(a.into()))?
        {
            if let Register::Literal(b) = *self
                .current_state
                .current_stackframe
                .get(b.into())
                .ok_or_else(|| VMException::RegisterNotFound(b.into()))?
            {
                new_register = Register::Literal(op(a, b)?);
            }
        }
        self.update_register(dst.into(), new_register)
    }
    fn binary_op_lit<T, U>(
        &mut self,
        dst: T,
        a: T,
        lit: U,
        op: fn(i32, i32) -> i32,
    ) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
        U: Into<i32> + Copy,
    {
        let mut new_register = Register::Empty;
        if let Register::Literal(a) = *self
            .current_state
            .current_stackframe
            .get(a.into())
            .ok_or_else(|| VMException::RegisterNotFound(a.into()))?
        {
            new_register = Register::Literal(op(a, lit.into()));
        }
        self.update_register(dst.into(), new_register)
    }
    fn reg_literal(&self, reg: usize) -> Option<i32> {
        match self.current_state.current_stackframe.get(reg) {
            Some(Register::Literal(v)) => Some(*v),
            _ => None,
        }
    }
    fn reg_wide(&self, reg: usize) -> Option<i64> {
        match self.current_state.current_stackframe.get(reg) {
            Some(Register::LiteralWide(v)) => Some(*v),
            _ => None,
        }
    }
    fn reg_float(&self, reg: usize) -> Option<f32> {
        self.reg_literal(reg).map(|v| f32::from_bits(v as u32))
    }
    fn reg_double(&self, reg: usize) -> Option<f64> {
        self.reg_wide(reg).map(|v| f64::from_bits(v as u64))
    }
    fn long_binop<T>(
        &mut self,
        dst: T,
        a: T,
        b: T,
        op: fn(i64, i64) -> i64,
    ) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
    {
        let new_register = match (self.reg_wide(a.into()), self.reg_wide(b.into())) {
            (Some(a), Some(b)) => Register::LiteralWide(op(a, b)),
            _ => Register::Empty,
        };
        self.update_register(dst.into(), new_register)
    }
    fn float_binop<T>(
        &mut self,
        dst: T,
        a: T,
        b: T,
        op: fn(f32, f32) -> f32,
    ) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
    {
        let new_register = match (self.reg_float(a.into()), self.reg_float(b.into())) {
            (Some(a), Some(b)) => Register::Literal(op(a, b).to_bits() as i32),
            _ => Register::Empty,
        };
        self.update_register(dst.into(), new_register)
    }
    fn double_binop<T>(
        &mut self,
        dst: T,
        a: T,
        b: T,
        op: fn(f64, f64) -> f64,
    ) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
    {
        let new_register = match (self.reg_double(a.into()), self.reg_double(b.into())) {
            (Some(a), Some(b)) => Register::LiteralWide(op(a, b).to_bits() as i64),
            _ => Register::Empty,
        };
        self.update_register(dst.into(), new_register)
    }
    fn float_cmp<T>(
        &mut self,
        dst: T,
        a: T,
        b: T,
        nan_result: std::cmp::Ordering,
    ) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
    {
        let new_register = match (self.reg_float(a.into()), self.reg_float(b.into())) {
            (Some(a), Some(b)) => {
                Register::Literal(match a.partial_cmp(&b).unwrap_or(nan_result) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                })
            }
            _ => Register::Empty,
        };
        self.update_register(dst.into(), new_register)
    }
    fn double_cmp<T>(
        &mut self,
        dst: T,
        a: T,
        b: T,
        nan_result: std::cmp::Ordering,
    ) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
    {
        let new_register = match (self.reg_double(a.into()), self.reg_double(b.into())) {
            (Some(a), Some(b)) => {
                Register::Literal(match a.partial_cmp(&b).unwrap_or(nan_result) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                })
            }
            _ => Register::Empty,
        };
        self.update_register(dst.into(), new_register)
    }

    fn execute(&mut self, start_address: InstructionOffset) -> Result<(), VMException> {
        let mut dex_file = self.current_state.current_dex_file.clone();
        let mut code_item = self.current_state.current_instructions.clone();
        let mut current_instruction =
            code_item
                .get(&start_address)
                .ok_or(VMException::NoInstructionAtAddress(
                    self.current_state.current_method_index,
                    start_address.into(),
                ))?;
        let mut method_idx = self.current_state.current_method_index;

        let mut steps = 0;

        self.current_state.vm_state = ExecutionState::Running;
        self.current_state.last_instruction_size = 0.into();

        //  self.current_state.current_method_index = method_idx;
        loop {
            steps += 1;
            if steps > 10000 {
                return Err(VMException::StackOverflow);
            }
            log::debug!("{:?}", self.current_state.current_stackframe);
            log::debug!("Executing: {:?} ", current_instruction.1);
            log::debug!("PC: {}", u32::from(self.current_state.pc));
            self.current_state.current_instruction_size =
                InstructionSize(current_instruction.0 .0 / 2);
            match &current_instruction.1 {
                Instruction::ArbitraryData(_) => {}
                Instruction::PackedSwitch(reg, table_offset)
                | Instruction::SparseSwitch(reg, table_offset) => {
                    let reg_data = if let Some(Register::Literal(reg)) =
                        self.current_state.current_stackframe.get(*reg as usize)
                    {
                        reg
                    } else {
                        return Err(VMException::RegisterNotFound((*reg) as usize));
                    };
                    if let Some((_, Instruction::PackedSwitchData(switch))) =
                        code_item.get(&(self.current_state.pc + *table_offset))
                    {
                        if let Some(offset) = switch.targets.get(reg_data) {
                            self.current_state.pc += *offset as i32;
                            current_instruction = code_item.get(&self.current_state.pc).ok_or(
                                VMException::NoInstructionAtAddress(
                                    self.current_state.current_method_index,
                                    self.current_state.pc.into(),
                                ),
                            )?;
                            continue;
                        }
                    }
                    if let Some((_, Instruction::SparseSwitchData(switch))) =
                        code_item.get(&(self.current_state.pc + *table_offset))
                    {
                        if let Some(offset) = switch.targets.get(reg_data) {
                            self.current_state.pc += *offset as i32;
                            current_instruction = code_item.get(&self.current_state.pc).ok_or(
                                VMException::NoInstructionAtAddress(
                                    self.current_state.current_method_index,
                                    self.current_state.pc.into(),
                                ),
                            )?;
                            continue;
                        }
                    }
                }
                // for now we just ignore checkcasts
                Instruction::CheckCast(..) => {}
                Instruction::PackedSwitchData(_) | Instruction::SparseSwitchData(_) => {}
                Instruction::Throw(_) => {
                    return Err(VMException::ExceptionThrown);
                }
                Instruction::Nop => {}
                &Instruction::Move(dst, src) => {
                    let src_reg: u8 = src.into();
                    let dst_reg: u8 = dst.into();
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src_reg as usize)
                        .ok_or(VMException::RegisterNotFound(src_reg as usize))?
                        .to_owned();

                    self.update_register(dst_reg as usize, src)?;
                }
                &Instruction::MoveFrom16(dst_reg, src_reg) => {
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src_reg as usize)
                        .ok_or(VMException::RegisterNotFound(src_reg as usize))?
                        .to_owned();
                    self.update_register(dst_reg as usize, src)?;
                }
                &Instruction::Move16(dst_reg, src_reg) => {
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src_reg as usize)
                        .ok_or(VMException::RegisterNotFound(src_reg as usize))?
                        .to_owned();
                    self.update_register(dst_reg as usize, src)?;
                }
                &Instruction::MoveWide(dst, src) => {
                    let src_reg: u8 = src.into();
                    let dst_reg: u8 = dst.into();
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src_reg as usize)
                        .ok_or(VMException::RegisterNotFound(src_reg as usize))?
                        .to_owned();
                    self.update_register(dst_reg as usize, src)?;
                }
                &Instruction::MoveWideFrom16(dst, src) => {
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src as usize)
                        .ok_or(VMException::RegisterNotFound(src as usize))?
                        .to_owned();
                    self.update_register(dst as usize, src)?;
                }
                &Instruction::MoveWide16(dst, src) => {
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src as usize)
                        .ok_or(VMException::RegisterNotFound(src as usize))?
                        .to_owned();
                    self.update_register(dst as usize, src)?;
                }

                &Instruction::MoveObject(dst_reg, src_reg) => {
                    let src_reg: u8 = src_reg.into();
                    let dst_reg: u8 = dst_reg.into();
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src_reg as usize)
                        .ok_or(VMException::RegisterNotFound(src_reg as usize))?
                        .to_owned();
                    self.update_register(dst_reg as usize, src)?;
                }
                &Instruction::MoveObjectFrom16(dst_reg, src_reg) => {
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src_reg as usize)
                        .ok_or(VMException::RegisterNotFound(src_reg as usize))?
                        .to_owned();
                    self.update_register(dst_reg as usize, src)?;
                }
                &Instruction::MoveObject16(dst_reg, src_reg) => {
                    let src = self
                        .current_state
                        .current_stackframe
                        .get(src_reg as usize)
                        .ok_or(VMException::RegisterNotFound(src_reg as usize))?
                        .to_owned();
                    self.update_register(dst_reg as usize, src)?;
                }
                &Instruction::MoveException(dst) => {
                    self.update_register(dst as usize, self.current_state.return_reg.clone())?;
                    self.current_state.return_reg = Register::Empty;
                }
                Instruction::MonitorEnter(_) | Instruction::MonitorExit(_) => {}
                &Instruction::XorInt(dst_a, b) => {
                    let dst: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst, dst, b, |a, b| Ok(a ^ b))?;
                }
                &Instruction::XorLong(dst, b) => {
                    let dst: u8 = dst.into();
                    let b: u8 = b.into();
                    self.long_binop(dst, dst, b, |a, b| a ^ b)?;
                }
                &Instruction::XorIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a ^ b))?;
                }
                &Instruction::XorIntDstLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| a ^ b)?;
                }
                &Instruction::XorLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a ^ b)?;
                }

                &Instruction::XorIntDstLit16(dst, a, lit) => {
                    let dst: u8 = dst.into();
                    let a: u8 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| a ^ b)?;
                }
                &Instruction::RemIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| {
                        if b == 0 {
                            return Err(VMException::InvalidRegisterType);
                        }
                        Ok(a % b)
                    })?;
                }
                &Instruction::RemLongDst(dst, a, b) => {
                    if self.reg_wide(b as usize) == Some(0) {
                        return Err(VMException::InvalidRegisterType);
                    }
                    self.long_binop(dst, a, b, |a, b| a % b)?;
                }
                &Instruction::RemInt(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();

                    self.binary_op(dst_a, dst_a, b, |a, b| {
                        if b == 0 {
                            return Err(VMException::InvalidRegisterType);
                        }
                        Ok(a % b)
                    })?;
                }
                &Instruction::RemLong(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    if self.reg_wide(b as usize) == Some(0) {
                        return Err(VMException::InvalidRegisterType);
                    }
                    self.long_binop(dst_a, dst_a, b, |a, b| a % b)?;
                }
                &Instruction::RemIntLit16(dst, a, lit) => {
                    let dst: u8 = dst.into();
                    let a: u8 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| {
                        (a as i16).wrapping_rem(b as i16) as i32
                    })?;
                }
                &Instruction::RemIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| (a as i8).wrapping_rem(b as i8) as i32)?;
                }
                &Instruction::AddInt(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst_a, dst_a, b, |a, b| Ok(a.wrapping_add(b)))?;
                }
                &Instruction::AddIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a.wrapping_add(b)))?;
                }
                &Instruction::AddIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| (a as i8).wrapping_add(b as i8) as i32)?;
                }
                &Instruction::ShrIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| {
                        (a as i8).wrapping_shr(b as u32) as i32
                    })?;
                }
                &Instruction::UShrIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| {
                        (a as u32).wrapping_shr(b as u32) as i32
                    })?;
                }
                &Instruction::ShlIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| a.wrapping_shl(b as u32))?;
                }
                &Instruction::ShlInt(dst_a, b) => {
                    let dst: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst, dst, b, |a, b| Ok(a.wrapping_shl(b as u32)))?;
                }
                &Instruction::ShrInt(dst_a, b) => {
                    let dst: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst, dst, b, |a, b| Ok(a.wrapping_shr(b as u32)))?;
                }
                &Instruction::UShrInt(dst_a, b) => {
                    let dst: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst, dst, b, |a, b| {
                        Ok((a as u32).wrapping_shr(b as u32) as i32)
                    })?;
                }
                &Instruction::ShlIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a.wrapping_shl(b as u32)))?;
                }
                &Instruction::ShrIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a.wrapping_shr(b as u32)))?;
                }
                &Instruction::UShrIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| {
                        Ok((a as u32).wrapping_shr(b as u32) as i32)
                    })?;
                }
                &Instruction::ShlLong(dst_a, b) => {
                    let dst: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst, dst, b, |a, b| a.wrapping_shl(b as u32))?;
                }
                &Instruction::ShrLong(dst_a, b) => {
                    let dst: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst, dst, b, |a, b| a.wrapping_shr(b as u32))?;
                }
                &Instruction::UShrLong(dst_a, b) => {
                    let dst: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst, dst, b, |a, b| a.wrapping_shr(b as u32))?;
                }
                &Instruction::ShlLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a.wrapping_shl(b as u32))?;
                }
                &Instruction::ShrLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a.wrapping_shr(b as u32))?;
                }
                &Instruction::UShrLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a.wrapping_shr(b as u32))?;
                }
                &Instruction::AddIntLit16(dst, a, lit) => {
                    let dst: u16 = dst.into();
                    let a: u16 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| {
                        (a as i16).wrapping_add(b as i16) as i32
                    })?;
                }
                &Instruction::AddLong(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst_a, dst_a, b, |a, b| a.wrapping_add(b))?;
                }
                &Instruction::AddLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a.wrapping_add(b))?;
                }

                &Instruction::MulInt(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst_a, dst_a, b, |a, b| Ok(a.wrapping_mul(b)))?;
                }
                &Instruction::MulIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a.wrapping_mul(b)))?;
                }
                &Instruction::MulIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| (a as i8).wrapping_mul(b as i8) as i32)?;
                }
                &Instruction::MulIntLit16(dst, a, lit) => {
                    let dst: u16 = dst.into();
                    let a: u16 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| {
                        (a as i16).wrapping_mul(b as i16) as i32
                    })?;
                }
                &Instruction::MulLong(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst_a, dst_a, b, |a, b| a.wrapping_mul(b))?;
                }
                &Instruction::MulLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a.wrapping_mul(b))?;
                }
                &Instruction::DivInt(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst_a, dst_a, b, |a, b| Ok(a.wrapping_div(b)))?;
                }
                &Instruction::DivIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a.wrapping_div(b)))?;
                }
                &Instruction::DivIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| (a as i8).wrapping_div(b as i8) as i32)?;
                }
                &Instruction::DivIntLit16(dst, a, lit) => {
                    let dst: u16 = dst.into();
                    let a: u16 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| {
                        (a as i16).wrapping_div(b as i16) as i32
                    })?;
                }
                &Instruction::DivLong(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    if self.reg_wide(b as usize) == Some(0) {
                        return Err(VMException::InvalidRegisterType);
                    }
                    self.long_binop(dst_a, dst_a, b, |a, b| a.wrapping_div(b))?;
                }
                &Instruction::DivLongDst(dst, a, b) => {
                    if self.reg_wide(b as usize) == Some(0) {
                        return Err(VMException::InvalidRegisterType);
                    }
                    self.long_binop(dst, a, b, |a, b| a.wrapping_div(b))?;
                }

                &Instruction::SubInt(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst_a, dst_a, b, |a, b| Ok(a.wrapping_sub(b)))?;
                }
                &Instruction::SubIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a.wrapping_sub(b)))?;
                }
                &Instruction::SubIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| (a as i8).wrapping_sub(b as i8) as i32)?;
                }
                &Instruction::SubIntLit16(dst, a, lit) => {
                    let dst: u16 = dst.into();
                    let a: u16 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| {
                        (a as i16).wrapping_sub(b as i16) as i32
                    })?;
                }
                &Instruction::SubLong(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst_a, dst_a, b, |a, b| a.wrapping_sub(b))?;
                }
                &Instruction::SubLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a.wrapping_sub(b))?;
                }

                &Instruction::AndInt(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst_a, dst_a, b, |a, b| Ok(a & b))?;
                }
                &Instruction::AndIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a & b))?;
                }
                &Instruction::AndIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| a & b)?;
                }
                &Instruction::AndIntLit16(dst, a, lit) => {
                    let dst: u16 = dst.into();
                    let a: u16 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| a & b)?;
                }
                &Instruction::AndLong(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst_a, dst_a, b, |a, b| a & b)?;
                }
                &Instruction::AndLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a & b)?;
                }

                &Instruction::OrInt(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.binary_op(dst_a, dst_a, b, |a, b| Ok(a | b))?;
                }
                &Instruction::OrIntDst(dst, a, b) => {
                    self.binary_op(dst, a, b, |a, b| Ok(a | b))?;
                }
                &Instruction::OrIntLit8(dst, a, lit) => {
                    self.binary_op_lit(dst, a, lit, |a, b| a | b)?;
                }
                &Instruction::OrIntLit16(dst, a, lit) => {
                    let dst: u16 = dst.into();
                    let a: u16 = a.into();
                    self.binary_op_lit(dst, a, lit, |a, b| a | b)?;
                }
                &Instruction::OrLong(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.long_binop(dst_a, dst_a, b, |a, b| a | b)?;
                }
                &Instruction::OrLongDst(dst, a, b) => {
                    self.long_binop(dst, a, b, |a, b| a | b)?;
                }

                &Instruction::Test(test, a, b, offset) => {
                    let a: u8 = a.into();
                    let b: u8 = b.into();
                    if let (Some(a), Some(b)) = (
                        self.current_state.current_stackframe.get(a as usize),
                        self.current_state.current_stackframe.get(b as usize),
                    ) {
                        if matches!(a, Register::Empty) | matches!(b, Register::Empty) {
                            return Err(VMException::RegisterNotFound(0));
                        }
                        match test {
                            coeus_models::models::TestFunction::Equal => {
                                if *a == *b {
                                    self.current_state.pc += offset as u32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::NotEqual => {
                                if *a != *b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::LessThan => {
                                if *a < *b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::LessEqual => {
                                if *a <= *b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::GreaterThan => {
                                if *a > *b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::GreaterEqual => {
                                if *a >= *b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                        }
                        current_instruction = code_item.get(&self.current_state.pc).ok_or(
                            VMException::NoInstructionAtAddress(
                                self.current_state.current_method_index,
                                self.current_state.pc.into(),
                            ),
                        )?;
                        continue;
                    } else {
                        return Err(VMException::RegisterNotFound(0));
                    }
                }
                &Instruction::TestZero(test, a, offset) => {
                    let a: u8 = a.into();
                    let b = Register::Literal(0);
                    if let Some(a) = self.current_state.current_stackframe.get(a as usize) {
                        match test {
                            coeus_models::models::TestFunction::Equal => {
                                if *a == b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::NotEqual => {
                                if *a != b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::LessThan => {
                                if *a < b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::LessEqual => {
                                if *a <= b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::GreaterThan => {
                                if *a > b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                            coeus_models::models::TestFunction::GreaterEqual => {
                                if *a >= b {
                                    self.current_state.pc += offset as i32;
                                } else {
                                    self.current_state.pc += (current_instruction.0 .0) / 2;
                                }
                            }
                        }
                        current_instruction = code_item.get(&self.current_state.pc).ok_or(
                            VMException::NoInstructionAtAddress(
                                self.current_state.current_method_index,
                                self.current_state.pc.into(),
                            ),
                        )?;
                        continue;
                    } else {
                        return Err(VMException::RegisterNotFound(a as usize));
                    }
                }
                &Instruction::Goto8(offset) => {
                    self.current_state.pc += offset as i32;
                    current_instruction = code_item.get(&self.current_state.pc).ok_or(
                        VMException::NoInstructionAtAddress(
                            self.current_state.current_method_index,
                            self.current_state.pc.into(),
                        ),
                    )?;
                    continue;
                }
                &Instruction::Goto16(offset) => {
                    self.current_state.pc += offset as i32;
                    current_instruction = code_item.get(&self.current_state.pc).ok_or(
                        VMException::NoInstructionAtAddress(
                            self.current_state.current_method_index,
                            self.current_state.pc.into(),
                        ),
                    )?;
                    continue;
                }
                &Instruction::Goto32(offset) => {
                    self.current_state.pc += offset as i32;
                    current_instruction = code_item.get(&self.current_state.pc).ok_or(
                        VMException::NoInstructionAtAddress(
                            self.current_state.current_method_index,
                            self.current_state.pc.into(),
                        ),
                    )?;
                    continue;
                }
                &Instruction::ArrayGetByte(dst, array_reference, index)
                | &Instruction::ArrayGetChar(dst, array_reference, index) => {
                    if let Some(Register::Reference(_, array_reference)) = self
                        .current_state
                        .current_stackframe
                        .get(array_reference as usize)
                    {
                        if let Some(Value::Array(data)) = &self.heap.get(array_reference) {
                            if let Some(&Register::Literal(index)) =
                                self.current_state.current_stackframe.get(index as usize)
                            {
                                if let Some(byte) = data.get(index as usize) {
                                    let new_register = Register::Literal(*byte as i32);
                                    self.update_register(dst as usize, new_register)?;
                                } else {
                                    log::debug!("{:?}", current_instruction);
                                    log::debug!("{:?}", self.current_state.current_stackframe);
                                    return Err(VMException::IndexOutOfBounds);
                                }
                            }
                        } else {
                            log::debug!("{:?}", current_instruction);
                            log::debug!("{:?}", self.current_state.current_stackframe);
                            return Err(VMException::InstanceNotFound(*array_reference));
                        }
                    }
                }
                &Instruction::ArrayPutByte(src, array_reference, index)
                | &Instruction::ArrayPutChar(src, array_reference, index) => {
                    if let Some(Register::Reference(_, array_reference)) = self
                        .current_state
                        .current_stackframe
                        .get(array_reference as usize)
                    {
                        if let Some(Register::Literal(index)) =
                            self.current_state.current_stackframe.get(index as usize)
                        {
                            if let Some(Value::Array(data)) =
                                &mut self.heap.get_mut(array_reference)
                            {
                                if let Some(byte) = data.get_mut(*index as usize) {
                                    if let Some(&Register::Literal(val)) =
                                        self.current_state.current_stackframe.get(src as usize)
                                    {
                                        *byte = val as u8;
                                    }
                                } else {
                                    log::debug!("{:?}", current_instruction);
                                    log::debug!("{:?}", self.current_state.current_stackframe);
                                    return Err(VMException::IndexOutOfBounds);
                                }
                            } else {
                                log::debug!("{:?}", current_instruction);
                                log::debug!("{:?}", self.current_state.current_stackframe);
                                return Err(VMException::InstanceNotFound(*array_reference));
                            }
                        }
                    } else {
                        log::debug!("{:?}", current_instruction);
                        log::debug!("{:?}", self.current_state.current_stackframe);
                        return Err(VMException::RegisterNotFound(array_reference as usize));
                    }
                }
                Instruction::Invoke(_) => {
                    return Err(VMException::LinkerError);
                }
                Instruction::InvokeType(a) => {
                    log::debug!("Invoke {}", a);
                    return Err(VMException::LinkerError);
                }
                &Instruction::MoveResult(dst) => {
                    self.update_register(dst as usize, self.current_state.return_reg.clone())?;
                    self.current_state.return_reg = Register::Empty;
                }
                &Instruction::MoveResultWide(dst) => {
                    self.update_register(dst as usize, self.current_state.return_reg.clone())?;
                    self.current_state.return_reg = Register::Empty;
                }
                &Instruction::MoveResultObject(dst) => {
                    self.update_register(dst as usize, self.current_state.return_reg.clone())?;
                    self.current_state.return_reg = Register::Empty;
                }
                Instruction::ReturnVoid => {
                    if let Some(state) = self.stack_frames.pop() {
                        self.current_state = state;
                        current_instruction = self
                            .current_state
                            .current_instructions
                            .get(&self.current_state.pc)
                            .ok_or_else(|| {
                                log::error!(
                                    "RETURN POINTER ({}) NOT REFERENCING A INSTRUCTION! FATAL!",
                                    u32::from(self.current_state.pc)
                                );
                                log::error!(
                                    "Possible addresses: {:?}",
                                    self.current_state.current_instructions.keys()
                                );
                                log::error!("{:#?}", self.current_state);
                                log::error!("{:#?}", self.stack_frames);
                                VMException::NoInstructionAtAddress(
                                    self.current_state.current_method_index,
                                    self.current_state.pc.into(),
                                )
                            })?;
                        code_item = self.current_state.current_instructions.clone();
                        dex_file = self.current_state.current_dex_file.clone();
                    } else {
                        self.current_state.vm_state = ExecutionState::Finished;
                        return Ok(());
                    }
                }
                &Instruction::Return(reg) => {
                    let register = self.current_state.current_stackframe.get(reg as usize);
                    if !self.skip_next_breakpoint {
                        if (self.stop_on_array_return || self.stop_on_string_return)
                            && matches!(register, Some(Register::Reference(ty,..)) if ty == "[B" || ty == "[C" || ty == "Ljava/lang/String;" )
                        {
                            return Err(VMException::Breakpoint(
                                self.current_state.pc,
                                self.current_state.current_method_index,
                                BreakpointContext::ResultObjectRegister(reg as u16),
                            ));
                        }
                    } else {
                        self.skip_next_breakpoint = false
                    }
                    if let Some(register) = register {
                        self.current_state.return_reg = (*register).clone();
                    }

                    if let Some(mut state) = self.stack_frames.pop() {
                        state.return_reg = self.current_state.return_reg.clone();
                        self.current_state = state;

                        current_instruction = if let Some(i) = self
                            .current_state
                            .current_instructions
                            .get(&self.current_state.pc)
                        {
                            i
                        } else {
                            return Err(VMException::NoInstructionAtAddress(
                                self.current_state.current_method_index,
                                self.current_state.pc.0 as usize,
                            ));
                        };
                        code_item = self.current_state.current_instructions.clone();
                        dex_file = self.current_state.current_dex_file.clone();
                    } else {
                        self.current_state.vm_state = ExecutionState::Finished;
                        return Ok(());
                    }
                }
                Instruction::Const => {
                    return Err(VMException::LinkerError);
                }
                &Instruction::ConstLit4(dst, lit) => {
                    let lit: i8 = lit.into();
                    let dst: u8 = dst.into();
                    let new_register = Register::Literal(lit.into());
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstLit16(dst, lit) => {
                    let new_register = Register::Literal(lit.into());
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstLit32(dst, lit) => {
                    let new_register = Register::Literal(lit);
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstHigh16(dst, lit) => {
                    let new_register = Register::Literal(i32::from(lit) << 16);
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstWide(dst, lit) => {
                    let new_register = Register::LiteralWide(lit);
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstWideLit16(dst, lit) => {
                    let new_register = Register::LiteralWide(lit.into());
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstWideLit32(dst, lit) => {
                    let new_register = Register::LiteralWide(lit.into());
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstWideHigh16(dst, lit) => {
                    let new_register = Register::LiteralWide((i64::from(lit) << 48));
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstString(dst, reference) => {
                    let const_str = self
                        .current_state
                        .current_dex_file
                        .get_string(reference)
                        .ok_or(VMException::StaticDataNotFound(reference as u32))?
                        .to_string();

                    let new_register = self.new_instance(
                        StringClass::class_name().to_string(),
                        Value::Object(StringClass::new(const_str.to_string())),
                    )?;
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstStringJumbo(dst, reference) => {
                    let const_str = self
                        .current_state
                        .current_dex_file
                        .get_string(reference as usize)
                        .ok_or(VMException::StaticDataNotFound(reference))?
                        .to_string();

                    let new_register = self.new_instance(
                        StringClass::class_name().to_string(),
                        Value::Object(StringClass::new(const_str.to_string())),
                    )?;
                    self.update_register(dst, new_register)?;
                }
                &Instruction::ConstClass(dst, type_idx) => {
                    let class = self.get_class(dex_file.clone(), (type_idx) as u32)?;
                    if let Some(heap_address) = self.malloc() {
                        self.heap.insert(
                            heap_address,
                            Value::Object(ClassInstance::new(class.clone())),
                        );
                        let new_register =
                            Register::Reference(class.class_name.clone(), heap_address);
                        self.update_register(dst, new_register)?;
                    } else {
                        return Err(VMException::OutOfMemory);
                    }
                }
                &Instruction::IntToByte(dst, src) | &Instruction::IntToChar(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(&Register::Literal(val)) =
                        self.current_state.current_stackframe.get(src as usize)
                    {
                        let new_val: i8 = val as i8;
                        let new_register = Register::Literal(new_val as i32);
                        self.update_register(dst as usize, new_register)?;
                    }
                }
                &Instruction::IntToShort(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_literal(src as usize) {
                        self.update_register(dst as usize, Register::Literal(val as i16 as i32))?;
                    }
                }
                &Instruction::IntToLong(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_literal(src as usize) {
                        self.update_register(dst as usize, Register::LiteralWide(val as i64))?;
                    }
                }
                &Instruction::IntToFloat(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_literal(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::Literal((val as f32).to_bits() as i32),
                        )?;
                    }
                }
                &Instruction::IntToDouble(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_literal(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::LiteralWide((val as f64).to_bits() as i64),
                        )?;
                    }
                }
                &Instruction::LongToInt(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_wide(src as usize) {
                        self.update_register(dst as usize, Register::Literal(val as i32))?;
                    }
                }
                &Instruction::LongToFloat(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_wide(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::Literal((val as f32).to_bits() as i32),
                        )?;
                    }
                }
                &Instruction::LongToDouble(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_wide(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::LiteralWide((val as f64).to_bits() as i64),
                        )?;
                    }
                }
                &Instruction::FloatToInt(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_float(src as usize) {
                        self.update_register(dst as usize, Register::Literal(val as i32))?;
                    }
                }
                &Instruction::FloatToLong(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_float(src as usize) {
                        self.update_register(dst as usize, Register::LiteralWide(val as i64))?;
                    }
                }
                &Instruction::FloatToDouble(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_float(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::LiteralWide((val as f64).to_bits() as i64),
                        )?;
                    }
                }
                &Instruction::DoubleToInt(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_double(src as usize) {
                        self.update_register(dst as usize, Register::Literal(val as i32))?;
                    }
                }
                &Instruction::DoubleToLong(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_double(src as usize) {
                        self.update_register(dst as usize, Register::LiteralWide(val as i64))?;
                    }
                }
                &Instruction::DoubleToFloat(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_double(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::Literal((val as f32).to_bits() as i32),
                        )?;
                    }
                }
                &Instruction::NegInt(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_literal(src as usize) {
                        self.update_register(dst as usize, Register::Literal(val.wrapping_neg()))?;
                    }
                }
                &Instruction::NotInt(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_literal(src as usize) {
                        self.update_register(dst as usize, Register::Literal(!val))?;
                    }
                }
                &Instruction::NegLong(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_wide(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::LiteralWide(val.wrapping_neg()),
                        )?;
                    }
                }
                &Instruction::NegFloat(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_literal(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::Literal(val ^ 0x8000_0000u32 as i32),
                        )?;
                    }
                }
                &Instruction::NegDouble(dst, src) => {
                    let dst: u8 = dst.into();
                    let src: u8 = src.into();
                    if let Some(val) = self.reg_wide(src as usize) {
                        self.update_register(
                            dst as usize,
                            Register::LiteralWide(val ^ 0x8000_0000_0000_0000u64 as i64),
                        )?;
                    }
                }
                &Instruction::ArrayLength(dst, array_ref_reg) => {
                    let dst: u8 = dst.into();
                    let array_ref_reg: u8 = array_ref_reg.into();
                    if let Some(Register::Reference(_, array_reference)) = self
                        .current_state
                        .current_stackframe
                        .get(array_ref_reg as usize)
                    {
                        if let Some(Value::Array(array)) = self.heap.get(array_reference) {
                            let new_register = Register::Literal(array.len() as i32);
                            self.update_register(dst as usize, new_register)?;
                        }
                    } else {
                        return Err(VMException::InvalidRegisterType);
                    }
                }
                Instruction::NewInstance(dst, type_idx) => {
                    let class = self.get_class(dex_file.clone(), (*type_idx) as u32)?;

                    if let Some(heap_address) = self.malloc() {
                        self.heap
                            .insert(heap_address, Value::Object(ClassInstance::new(class)));
                        let new_register =
                            if let Some(type_name) = dex_file.get_type_name((*type_idx) as usize) {
                                Register::Reference(type_name.to_owned(), heap_address)
                            } else {
                                return Err(VMException::OutOfMemory);
                            };
                        let dst = self
                            .current_state
                            .current_stackframe
                            .get_mut((*dst) as usize)
                            .ok_or(VMException::RegisterNotFound((*dst) as usize))?;
                        *dst = new_register;
                    } else {
                        return Err(VMException::OutOfMemory);
                    }
                }
                Instruction::NewInstanceType(_) => {
                    return Err(VMException::LinkerError);
                }
                &Instruction::NewArray(dst, size, ty) => {
                    let size: u8 = size.into();
                    let dst: u8 = dst.into();
                    if let Some(Register::Literal(size)) =
                        self.current_state.current_stackframe.get(size as usize)
                    {
                        if (*size as usize) > MAX_SIZE {
                            log::warn!("{} is too large to allocate, abbort execution", *size);
                            return Err(VMException::StackOverflow);
                        }
                        let arr = vec![0; *size as usize];
                        if let Some(heap_address) = self.malloc() {
                            self.heap.insert(heap_address, Value::Array(arr));
                            let type_name = if let Some(type_name) =
                                self.current_state.current_dex_file.get_type_name(ty)
                            {
                                type_name.to_string()
                            } else {
                                "[B".to_string()
                            };
                            let new_register = Register::Reference(type_name, heap_address as u32);
                            let dst = self
                                .current_state
                                .current_stackframe
                                .get_mut(dst as usize)
                                .ok_or(VMException::RegisterNotFound(dst as usize))?;
                            *dst = new_register;
                        }
                    }
                }
                Instruction::FilledNewArray(_, _, data) => {
                    if let Some(heap_address) = self.malloc() {
                        self.heap.insert(heap_address, Value::Array(data.clone()));
                        self.current_state.return_reg =
                            Register::Reference("[B".to_string(), heap_address);
                    } else {
                        return Err(VMException::OutOfMemory);
                    }
                }
                Instruction::FilledNewArrayRange(first, _type_idx, count) => {
                    let count = *count as usize;
                    let mut data = Vec::with_capacity(count);
                    for i in 0..count {
                        let val = self.reg_literal(*first as usize + i).unwrap_or(0);
                        data.extend_from_slice(&val.to_le_bytes());
                    }
                    if let Some(heap_address) = self.malloc() {
                        self.heap.insert(heap_address, Value::Array(data));
                        self.current_state.return_reg =
                            Register::Reference("[B".to_string(), heap_address);
                    } else {
                        return Err(VMException::OutOfMemory);
                    }
                }
                &Instruction::FillArrayData(reference, data) => {
                    if let Some(Register::Reference(_, reference)) = self
                        .current_state
                        .current_stackframe
                        .get(reference as usize)
                    {
                        let val = self
                            .heap
                            .get_mut(reference)
                            .ok_or(VMException::InstanceNotFound(*reference))?;
                        if let Instruction::ArrayData(_, data) = &code_item
                            .get(&(self.current_state.pc + data as i32))
                            .ok_or(VMException::InstanceNotFound(data as u32))?
                            .1
                        {
                            *val = Value::Array(data.clone());
                        }
                    }
                }
                //TODO: implement ranged opcodes
                Instruction::InvokeSuperRange(..)
                | Instruction::InvokeVirtualRange(..)
                | Instruction::InvokeDirectRange(..) => {
                    return Err(VMException::LinkerError);
                }
                Instruction::InvokeStaticRange(..) => {
                    return Err(VMException::LinkerError);
                }
                Instruction::InvokeInterfaceRange(..) => {
                    return Err(VMException::LinkerError);
                }

                Instruction::InvokeSuper(_, _, _) => {}
                Instruction::InvokeVirtual(_, method_ref, argument_registers)
                | Instruction::InvokeDirect(_, method_ref, argument_registers) => {
                    if self.stack_frames.len() > 50 {
                        return Err(VMException::StackOverflow);
                    }

                    let mut arguments = vec![];

                    for (regs, &arg) in argument_registers.iter().enumerate() {
                        let reg = self
                            .current_state
                            .current_stackframe
                            .get(arg as usize)
                            .ok_or(VMException::RegisterNotFound(arg as usize))?
                            .clone();
                        if (self.stop_on_array_use || self.stop_on_string_use)
                        // just make sure we don't include breakpoints in non direct execution (e.g clinit from staticget)
                        && matches!(self.current_state.vm_state, ExecutionState::Running)
                        {
                            if regs as u32 >= self.current_state.last_break_point_reg {
                                if !self.skip_next_breakpoint {
                                    if let Register::Reference(_, ref reference) = reg {
                                        match self.heap.get(reference) {
                                            Some(Value::Array(_)) if self.stop_on_array_use => {
                                                self.current_state.vm_state =
                                                    ExecutionState::Paused;
                                                self.current_state.last_break_point_reg =
                                                    regs as u32;
                                                return Err(VMException::Breakpoint(
                                                    self.current_state.pc,
                                                    self.current_state.current_method_index,
                                                    BreakpointContext::ArrayReg(
                                                        arg as u16,
                                                        *method_ref,
                                                    ),
                                                ));
                                            }
                                            Some(Value::Object(class_instance))
                                                if class_instance.class.class_name
                                                    == StringClass::class_name() =>
                                            {
                                                self.current_state.vm_state =
                                                    ExecutionState::Paused;
                                                self.current_state.last_break_point_reg =
                                                    regs as u32;
                                                return Err(VMException::Breakpoint(
                                                    self.current_state.pc,
                                                    self.current_state.current_method_index,
                                                    BreakpointContext::StringReg(
                                                        arg as u16,
                                                        *method_ref,
                                                    ),
                                                ));
                                            }
                                            _ => {}
                                        }
                                    }
                                } else {
                                    log::debug!("Skip breakpoint");
                                    self.skip_next_breakpoint = false
                                }
                            }
                        }

                        arguments.push(reg);
                    }
                    self.current_state.last_break_point_reg = 0;

                    //save current execution state
                    self.stack_frames.push(self.current_state.clone());

                    self.current_state.current_method_index = *method_ref as u32;
                    method_idx = self.current_state.current_method_index;

                    if let Ok((file, the_code)) = self.get_method(&dex_file, (*method_ref) as u32) {
                        let the_code = the_code
                            .code
                            .as_ref()
                            .ok_or_else(|| VMException::MethodNotFound(the_code.name.clone()))?
                            .to_owned();
                        let the_code_hash = the_code
                            .insns
                            .clone()
                            .into_iter()
                            .map(|ele| (ele.1, (ele.0, ele.2)))
                            .collect();

                        //build stackframe

                        self.current_state.current_dex_file = file;

                        self.current_state.pc = 0.into();
                        self.current_state.return_reg = Register::Empty;
                        //self.current_state.current_stackframe = vec![];
                        self.current_state.num_params = the_code.ins_size as usize;
                        self.current_state.num_registers = the_code.register_size as usize;

                        let start_params =
                            self.current_state.num_registers - self.current_state.num_params;

                        let mut registers = Vec::with_capacity(self.current_state.num_registers);
                        for _ in 0..start_params {
                            registers.push(Register::Empty);
                        }
                        for i in 0..self.current_state.num_params {
                            if let Some(arg) = arguments.get(i) {
                                registers.push((*arg).clone());
                            } else {
                                registers.push(Register::Empty);
                            }
                        }
                        self.current_state.current_stackframe = registers;

                        //push new instructions
                        self.current_state.current_instructions = the_code_hash;

                        //self.execute((*method_ref) as u32, 0)?;
                        dex_file = self.current_state.current_dex_file.clone();
                        code_item = self.current_state.current_instructions.clone();
                        current_instruction = code_item.get(&self.current_state.pc).ok_or(
                            VMException::NoInstructionAtAddress(
                                self.current_state.current_method_index,
                                self.current_state.pc.into(),
                            ),
                        )?;

                        continue;
                    } else {
                        self.invoke_runtime(dex_file.clone(), method_idx as u32, arguments)?;
                        if let Some(stack_frame) = self.stack_frames.pop() {
                            method_idx = stack_frame.current_method_index;
                            self.current_state.current_method_index = method_idx;
                        }
                    }
                }
                Instruction::InvokeStatic(arg_count, method_ref, argument_registers) => {
                    if self.stack_frames.len() > 50 {
                        return Err(VMException::StackOverflow);
                    }

                    let mut arguments = vec![];
                    for (regs, &arg) in argument_registers.iter().enumerate() {
                        let reg = self
                            .current_state
                            .current_stackframe
                            .get(arg as usize)
                            .ok_or(VMException::RegisterNotFound(arg as usize))?
                            .clone();
                        if (self.stop_on_array_use || self.stop_on_string_use)
                            && matches!(self.current_state.vm_state, ExecutionState::Running)
                        //     .break_points
                        //     .iter()
                        //     .find(|a| matches!(a, Breakpoint::ArrayUse | Breakpoint::StringUse))
                        {
                            if regs as u32 >= self.current_state.last_break_point_reg {
                                if !self.skip_next_breakpoint {
                                    if let Register::Reference(_, ref reference) = reg {
                                        match self.heap.get(reference) {
                                            Some(Value::Array(_)) if self.stop_on_array_use => {
                                                self.current_state.vm_state =
                                                    ExecutionState::Paused;
                                                self.current_state.last_break_point_reg =
                                                    regs as u32;
                                                return Err(VMException::Breakpoint(
                                                    self.current_state.pc,
                                                    method_idx,
                                                    BreakpointContext::ArrayReg(
                                                        arg as u16,
                                                        *method_ref,
                                                    ),
                                                ));
                                            }
                                            Some(Value::Object(class_instance))
                                                if self.stop_on_string_use
                                                    && class_instance.class.class_name
                                                        == StringClass::class_name() =>
                                            {
                                                self.current_state.vm_state =
                                                    ExecutionState::Paused;
                                                self.current_state.last_break_point_reg =
                                                    regs as u32;
                                                return Err(VMException::Breakpoint(
                                                    self.current_state.pc,
                                                    method_idx,
                                                    BreakpointContext::StringReg(
                                                        arg as u16,
                                                        *method_ref,
                                                    ),
                                                ));
                                            }
                                            _ => {}
                                        }
                                    }
                                } else {
                                    log::debug!("Skip breakpoint");
                                    self.skip_next_breakpoint = false
                                }
                            }
                        }

                        arguments.push(reg);
                    }
                    self.current_state.last_break_point_reg = 0;
                    //save current execution state
                    self.stack_frames.push(self.current_state.clone());

                    self.current_state.current_method_index = *method_ref as u32;
                    method_idx = self.current_state.current_method_index;

                    if let Ok((file, the_code)) = self.get_method(&dex_file, *method_ref as u32) {
                        let method_name = &the_code.name;
                        let access_flags = &the_code.access_flags;

                        let the_code = the_code
                            .code
                            .as_ref()
                            .ok_or_else(|| VMException::MethodNotFound(the_code.name.clone()))?
                            .to_owned();
                        let the_code_hash = the_code
                            .insns
                            .clone()
                            .into_iter()
                            .map(|ele| (ele.1, (ele.0, ele.2)))
                            .collect();

                        if the_code.ins_size != u16::from(*arg_count) {
                            log::debug!(
                                "Expected: {} [{}] got {} [{} {}]",
                                the_code.ins_size,
                                the_code.register_size,
                                arg_count,
                                access_flags,
                                method_name
                            );
                            return Err(VMException::WrongNumberOfArguments);
                        }

                        self.current_state.current_dex_file = file;

                        self.current_state.pc = 0.into();
                        self.current_state.return_reg = Register::Empty;
                        //self.current_state.current_stackframe = vec![];
                        self.current_state.num_params = the_code.ins_size as usize;
                        self.current_state.num_registers = the_code.register_size as usize;

                        let start_params =
                            self.current_state.num_registers - self.current_state.num_params;

                        let mut registers = Vec::with_capacity(self.current_state.num_registers);
                        for _ in 0..start_params {
                            registers.push(Register::Empty);
                        }
                        for argument in arguments {
                            registers.push(argument);
                        }

                        self.current_state.current_stackframe = registers;

                        log::debug!(
                            "Running: {:?}",
                            self.get_method(&dex_file, method_idx)
                                .and_then(|a| Ok(a.1.name.clone()))
                        );
                        //push new instructions
                        self.current_state.current_instructions = the_code_hash;

                        //self.execute((*method_ref) as u32,  0)?;
                        dex_file = self.current_state.current_dex_file.clone();
                        code_item = self.current_state.current_instructions.clone();
                        current_instruction = code_item.get(&self.current_state.pc).ok_or(
                            VMException::NoInstructionAtAddress(
                                self.current_state.current_method_index,
                                self.current_state.pc.into(),
                            ),
                        )?;
                        continue;
                    } else {
                        let result =
                            self.invoke_runtime(dex_file.clone(), *method_ref as u32, arguments);
                        //we ignore it for now
                        match result {
                            Ok(_) => {
                                log::debug!("successfull execution of builtin");
                            }
                            Err(err) => {
                                log::warn!("Builtin failed with {:#?}. skipping", err);
                            }
                        }
                        if let Some(stack_frame) = self.stack_frames.pop() {
                            method_idx = stack_frame.current_method_index;
                            self.current_state.current_method_index = method_idx;
                        }
                    }
                }
                Instruction::InvokeInterface(_, _, _) => {
                    return Err(VMException::LinkerError);
                }

                Instruction::NotImpl(_, _) => {
                    return Err(VMException::LinkerError);
                }
                Instruction::ArrayData(_, _) => {}

                &Instruction::StaticGet(dst, field_idx) => {
                    let field = if let Some(field) = dex_file.fields.get(field_idx as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_type_name(field.class_idx as usize) {
                            c.to_string()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);
                    let Some((_, addr)) = self.instances.get(&field_name) else {
                        return Err(VMException::LinkerError);
                    };
                    let Some(Value::Int(o)) = self.heap.get(addr) else {
                        return Err(VMException::LinkerError);
                    };
                    let new_register = Register::Literal(*o);
                    self.update_register(dst, new_register)?;
                }
                &Instruction::StaticGetWide(dst, field_idx) => {
                    let field = if let Some(field) = dex_file.fields.get(field_idx as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_type_name(field.class_idx as usize) {
                            c.to_string()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);
                    if let Some((_, addr)) = self.instances.get(&field_name) {
                        if let Some(Value::Int(o)) = self.heap.get(addr) {
                            self.update_register(dst, Register::LiteralWide(*o as i64))?;
                        }
                    }
                }
                &Instruction::StaticGetObject(dst, field_idx) => {
                    let field = if let Some(field) = dex_file.fields.get(field_idx as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_type_name(field.class_idx as usize) {
                            c.to_string()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);
                    if !self.instances.contains_key(&field_name)
                        && !matches!(
                            self.current_state.vm_state,
                            ExecutionState::RunningStaticInitializer
                        )
                    {
                        if let Some(field) = dex_file.fields.get(field_idx as usize) {
                            if let Some(class) = iterator!(self.dex_file.classes)
                                .find_any(|c| c.class_idx == field.class_idx as u32)
                            {
                                if let Some(data) =
                                    class.get_data_for_static_field(field_idx as u32)
                                {
                                    //data.
                                    match &data.value_type {
                                        ValueType::String => {
                                            let str = data.get_string_id();
                                            if let Some(str) =
                                                self.dex_file.get_string(str as usize)
                                            {
                                                let str = str.to_string();
                                                let instance = runtime::StringClass::new(str);
                                                if let Ok(Register::Reference(_, memory_address)) =
                                                    self.new_instance(
                                                        StringClass::class_name().to_string(),
                                                        Value::Object(instance),
                                                    )
                                                {
                                                    self.instances.insert(
                                                        field_name.clone(),
                                                        (NodeIndex::new(0), memory_address),
                                                    );
                                                };
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            if let Some(class) = iterator!(self.dex_file.classes)
                                .find_any(|c| c.class_idx == field.class_idx as u32)
                            {
                                if let Some(static_init) =
                                    iterator!(class.codes).find_any(|m| m.name == "<clinit>")
                                {
                                    // set pc one back so we can come bakc here

                                    // if self.current_state.pc - self.current_state.last_instruction_size
                                    //     >= 0
                                    // {
                                    //     self.current_state.pc -=
                                    //         self.current_state.last_instruction_size;
                                    // }
                                    self.current_state.vm_state =
                                        ExecutionState::RunningStaticInitializer;
                                    self.stack_frames.push(self.current_state.clone());

                                    self.current_state.pc = 0.into();
                                    self.current_state.num_params = 0;
                                    self.current_state.vm_state = ExecutionState::StaticInitializer;
                                    self.current_state.num_registers =
                                        if let Some(c) = static_init.code.as_ref() {
                                            c.register_size as usize
                                        } else {
                                            return Err(VMException::LinkerError);
                                        };

                                    let mut registers =
                                        Vec::with_capacity(self.current_state.num_registers);
                                    for _ in 0..self.current_state.num_registers {
                                        registers.push(Register::Empty);
                                    }
                                    self.current_state.current_stackframe = registers;
                                    //TODO: refactor to use shared codeitem
                                    // but here we know thart code item must exist, as we would early return else
                                    let the_code_hash = static_init
                                        .code
                                        .as_ref()
                                        .unwrap()
                                        .insns
                                        .clone()
                                        .into_iter()
                                        .map(|ele| (ele.1, (ele.0, ele.2)))
                                        .collect();

                                    self.current_state.last_instruction_size = 0.into();
                                    log::debug!("Field not found, run static initializer");
                                    {
                                        self.current_state.current_method_index =
                                            static_init.method.method_idx as u32;
                                        method_idx = self.current_state.current_method_index;
                                        //push new instructions
                                        self.current_state.current_instructions = the_code_hash;

                                        dex_file = self.current_state.current_dex_file.clone();
                                        code_item = self.current_state.current_instructions.clone();
                                        current_instruction = code_item
                                            .get(&self.current_state.pc)
                                            .ok_or(VMException::NoInstructionAtAddress(
                                                self.current_state.current_method_index,
                                                self.current_state.pc.into(),
                                            ))?;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    if !self.instances.contains_key(&field_name) {
                        //so we ran our static class initializer, but still no reference.
                        // Let's check if it is a Context or Application and return a pseudo reference
                        if let Some(field) = dex_file.fields.get(field_idx as usize) {
                            if let Some(type_name) = dex_file.get_type_name(field.type_idx as usize)
                            {
                                if type_name == "Landroid/content/Context;"
                                    || type_name == "Landroid/app/Application;"
                                    || type_name == "Ljava/nio/charset/Charset;"
                                {
                                    let instance =
                                        ClassInstance::new(VM_BUILTINS[type_name].clone());
                                    if let Ok(Register::Reference(_, memory_address)) = self
                                        .new_instance(
                                            type_name.to_string(),
                                            Value::Object(instance),
                                        )
                                    {
                                        self.instances.insert(
                                            field_name.clone(),
                                            (NodeIndex::new(0), memory_address),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    if matches!(
                        self.current_state.vm_state,
                        ExecutionState::RunningStaticInitializer
                    ) {
                        self.current_state.vm_state = ExecutionState::Running;
                    }

                    if let Some((_, val)) = self.instances.get(&field_name) {
                        match self.heap.get(val) {
                            Some(Value::Object(class)) => {
                                let new_register =
                                    Register::Reference(class.class.class_name.to_string(), *val);
                                self.update_register(dst, new_register)?;
                            }
                            Some(Value::Array(_)) => {
                                let new_register = Register::Reference("[B".to_string(), *val);
                                self.update_register(dst, new_register)?;
                            }
                            _ => {
                                return Err(VMException::InvalidMemoryAddress(*val));
                            }
                        }
                    } else {
                        return Err(VMException::StaticDataNotFound(field_idx as u32));
                    }
                }
                Instruction::StaticGetBoolean(_, _) => {}
                Instruction::StaticGetByte(_, _) => {}
                Instruction::StaticGetChar(_, _) => {}
                Instruction::StaticGetShort(_, _) => {}
                &Instruction::StaticPut(src, field_idx) => {
                    let field = if let Some(field) = dex_file.fields.get(field_idx as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);
                    if let Some(&Register::Literal(lit)) =
                        self.current_state.current_stackframe.get(src as usize)
                    {
                        let reg = self.new_instance("".to_string(), Value::Int(lit))?;
                        let entry = self
                            .instances
                            .entry(field_name)
                            .or_insert((NodeIndex::new(0), 0));
                        let Register::Reference(_, addr) = reg else {
                            return Err(VMException::LinkerError);
                        };
                        entry.1 = addr;
                    }
                }
                Instruction::StaticPutWide(_, _) => {}
                &Instruction::StaticPutObject(src, field_idx) => {
                    let field = if let Some(field) = dex_file.fields.get(field_idx as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);

                    if let Some(&Register::Reference(_, address)) =
                        self.current_state.current_stackframe.get(src as usize)
                    {
                        let _class_resource = if let Some(cr) = self.heap.get(&address) {
                            cr
                        } else {
                            return Err(VMException::InvalidMemoryAddress(address));
                        };
                        if !self.skip_next_breakpoint {
                            if iterator!(self.break_points).any(
                                |bp| matches!(bp, Breakpoint::FieldSet(idx) if *idx == field_idx),
                            ) {
                                match _class_resource {
                                    Value::Array(_) => {
                                        return Err(VMException::Breakpoint(
                                            self.current_state.pc,
                                            self.current_state.current_method_index,
                                            BreakpointContext::FieldSet(src as u16, field_idx),
                                        ))
                                    }
                                    Value::Object(val)
                                        if val.class.class_name == StringClass::class_name() =>
                                    {
                                        return Err(VMException::Breakpoint(
                                            self.current_state.pc,
                                            self.current_state.current_method_index,
                                            BreakpointContext::FieldSet(src as u16, field_idx),
                                        ))
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            self.skip_next_breakpoint = false;
                        }
                        match self.instances.get_mut(&field_name) {
                            Some((_, val)) => {
                                *val = address;
                            }
                            None => {
                                log::debug!("Insert instances");
                                self.instances
                                    .insert(field_name, (NodeIndex::new(0), address));
                            }
                        }
                    } else {
                        return Err(VMException::RegisterNotFound(src as usize));
                    }
                }
                Instruction::StaticPutBoolean(_, _) => {}
                Instruction::StaticPutByte(_, _) => {}
                Instruction::StaticPutChar(_, _) => {}
                Instruction::StaticPutShort(_, _) => {}
                Instruction::InstanceGet(dst, obj, field_id) => {
                    let dst: u8 = (*dst).into();
                    let obj: u8 = (*obj).into();
                    let field_id = *field_id;

                    let field = if let Some(field) = dex_file.fields.get(field_id as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);

                    if let Some(Register::Reference(_, instance)) =
                        self.current_state.current_stackframe.get(obj as usize)
                    {
                        if let Some(Value::Object(class_instance)) = self.heap.get(instance) {
                            if let Some(field_instance) = class_instance.instances.get(&field_name)
                            {
                                let val = self
                                    .heap
                                    .get(field_instance)
                                    .ok_or(VMException::StaticDataNotFound(field_id as u32))?
                                    .clone();
                                if let Value::Int(val) = val {
                                    self.update_register(dst, Register::Literal(val))?;
                                } else {
                                    return Err(VMException::InvalidRegisterType);
                                }
                            } else {
                                log::debug!(
                                    "{:?} was not found",
                                    dex_file.get_string(
                                        dex_file.fields[field_id as usize].name_idx as usize
                                    )
                                );
                                self.update_register(dst, Register::Literal(0))?;
                                return Err(VMException::InvalidRegisterType);
                            }
                        }
                    } else {
                        return Err(VMException::InvalidRegisterType);
                    }
                }
                Instruction::InstanceGetWide(_, _, _) => {}
                &Instruction::InstanceGetObject(dst, instance, field_id) => {
                    let dst: u8 = dst.into();
                    let instance: u8 = instance.into();

                    let field = if let Some(field) = dex_file.fields.get(field_id as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);

                    if let Some(Register::Reference(_, instance)) =
                        self.current_state.current_stackframe.get(instance as usize)
                    {
                        if let Some(Value::Object(class_instance)) = self.heap.get(instance) {
                            if let Some(field_instance) = class_instance.instances.get(&field_name)
                            {
                                let new_register = Register::Reference(
                                    class_instance.class.class_name.to_string(),
                                    *field_instance,
                                );
                                self.update_register(dst, new_register)?;
                            } else {
                                return Err(VMException::InvalidRegisterType);
                            }
                        } else {
                            return Err(VMException::InvalidRegisterType);
                        }
                    } else {
                        return Err(VMException::InvalidRegisterType);
                    }
                }
                Instruction::InstanceGetBoolean(dst, instance, field_id)
                | Instruction::InstanceGetByte(dst, instance, field_id)
                | Instruction::InstanceGetChar(dst, instance, field_id)
                | Instruction::InstanceGetShort(dst, instance, field_id) => {
                    let dst: u8 = (*dst).into();
                    let instance: u8 = (*instance).into();
                    let field_id = *field_id;
                    let field = if let Some(field) = dex_file.fields.get(field_id as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);
                    if let Some(Register::Reference(_, instance)) =
                        self.current_state.current_stackframe.get(instance as usize)
                    {
                        if let Some(Value::Object(class_instance)) = self.heap.get(instance) {
                            if let Some(field_instance) = class_instance.instances.get(&field_name)
                            {
                                if let Some(Value::Int(o)) = self.heap.get(field_instance) {
                                    self.update_register(dst as usize, Register::Literal(*o))?;
                                }
                            }
                        }
                    }
                }
                &Instruction::InstancePut(src, instance, field_id) => {
                    let src: u8 = src.into();
                    let instance: u8 = instance.into();

                    let field = if let Some(field) = dex_file.fields.get(field_id as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);

                    if let (Some(Register::Literal(src)), Some(Register::Reference(_, instance))) = (
                        self.current_state.current_stackframe.get(src as usize),
                        self.current_state.current_stackframe.get(instance as usize),
                    ) {
                        if let Some(Value::Object(class_instance)) = self.heap.get(instance) {
                            let class_instance = class_instance.clone();
                            if let Some(field_instance) = class_instance.instances.get(&field_name)
                            {
                                let field_instance = *field_instance;
                                self.heap
                                    .entry(field_instance)
                                    .and_modify(|e| *e = Value::Int(*src));
                            } else {
                                let address;
                                {
                                    address = self.malloc();
                                    if let Some(address) = address {
                                        self.heap.entry(address).or_insert(Value::Int(*src));
                                    }
                                }
                                if let Some(Value::Object(class_instance)) =
                                    self.heap.get_mut(instance)
                                {
                                    if let Some(address) = address {
                                        class_instance.instances.insert(field_name, address);
                                    }
                                }
                            }
                        }
                    }
                }
                Instruction::InstancePutWide(_, _, _) => {}
                &Instruction::InstancePutObject(src, instance, field_id) => {
                    let src: u8 = src.into();
                    let instance: u8 = instance.into();

                    let field = if let Some(field) = dex_file.fields.get(field_id as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);

                    if let (
                        Some(Register::Reference(_, src)),
                        Some(Register::Reference(_, instance)),
                    ) = (
                        self.current_state.current_stackframe.get(src as usize),
                        self.current_state.current_stackframe.get(instance as usize),
                    ) {
                        if let Some(Value::Object(class_instance)) = self.heap.get_mut(instance) {
                            let field_instance =
                                class_instance.instances.entry(field_name).or_insert(0);
                            *field_instance = *src;
                        }
                    }
                }
                Instruction::InstancePutBoolean(src, instance, field_id)
                | Instruction::InstancePutByte(src, instance, field_id)
                | Instruction::InstancePutChar(src, instance, field_id)
                | Instruction::InstancePutShort(src, instance, field_id) => {
                    let src: u8 = (*src).into();
                    let instance: u8 = (*instance).into();
                    let field_id = *field_id;
                    let field = if let Some(field) = dex_file.fields.get(field_id as usize) {
                        field
                    } else {
                        return Err(VMException::ClassNotFound(0));
                    };
                    let class_name =
                        if let Some(c) = dex_file.get_class_by_type(field.class_idx as u32) {
                            c.class_name.clone()
                        } else {
                            return Err(VMException::ClassNotFound(field.class_idx as u16));
                        };
                    let field_name = format!("{}->{}", class_name, field.name);
                    if let Some(Register::Literal(src_val)) =
                        self.current_state.current_stackframe.get(src as usize)
                    {
                        if let Some(Register::Reference(_, instance)) =
                            self.current_state.current_stackframe.get(instance as usize)
                        {
                            if let Some(Value::Object(class_instance)) = self.heap.get(instance) {
                                let class_instance = class_instance.clone();
                                if let Some(field_instance) =
                                    class_instance.instances.get(&field_name)
                                {
                                    if let Some(address) = self.malloc() {
                                        self.heap.entry(address).or_insert(Value::Int(*src_val));
                                        if let Some(Value::Object(class_instance)) =
                                            self.heap.get_mut(instance)
                                        {
                                            class_instance.instances.insert(field_name, address);
                                        }
                                    }
                                } else {
                                    let address;
                                    {
                                        address = self.malloc();
                                        if let Some(address) = address {
                                            self.heap
                                                .entry(address)
                                                .or_insert(Value::Int(*src_val));
                                        }
                                    }
                                    if let Some(Value::Object(class_instance)) =
                                        self.heap.get_mut(instance)
                                    {
                                        if let Some(address) = address {
                                            class_instance.instances.insert(field_name, address);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                &Instruction::CmplFloat(dst, a, b) => {
                    self.float_cmp(dst, a, b, std::cmp::Ordering::Less)?;
                }
                &Instruction::CmpgFloat(dst, a, b) => {
                    self.float_cmp(dst, a, b, std::cmp::Ordering::Greater)?;
                }
                &Instruction::CmplDouble(dst, a, b) => {
                    self.double_cmp(dst, a, b, std::cmp::Ordering::Less)?;
                }
                &Instruction::CmpgDouble(dst, a, b) => {
                    self.double_cmp(dst, a, b, std::cmp::Ordering::Greater)?;
                }
                &Instruction::CmpLong(dst, a, b) => {
                    let new_register = match (self.reg_wide(a as usize), self.reg_wide(b as usize))
                    {
                        (Some(a), Some(b)) => Register::Literal(match a.partial_cmp(&b) {
                            Some(std::cmp::Ordering::Less) => -1,
                            Some(std::cmp::Ordering::Equal) => 0,
                            Some(std::cmp::Ordering::Greater) => 1,
                            None => 0,
                        }),
                        _ => Register::Empty,
                    };
                    self.update_register(dst, new_register)?;
                }
                &Instruction::AddFloat(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.float_binop(dst_a, dst_a, b, |a, b| a + b)?;
                }
                &Instruction::AddFloatDst(dst, a, b) => {
                    self.float_binop(dst, a, b, |a, b| a + b)?;
                }
                &Instruction::SubFloat(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.float_binop(dst_a, dst_a, b, |a, b| a - b)?;
                }
                &Instruction::SubFloatDst(dst, a, b) => {
                    self.float_binop(dst, a, b, |a, b| a - b)?;
                }
                &Instruction::MulFloat(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.float_binop(dst_a, dst_a, b, |a, b| a * b)?;
                }
                &Instruction::MulFloatDst(dst, a, b) => {
                    self.float_binop(dst, a, b, |a, b| a * b)?;
                }
                &Instruction::DivFloat(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.float_binop(dst_a, dst_a, b, |a, b| a / b)?;
                }
                &Instruction::DivFloatDst(dst, a, b) => {
                    self.float_binop(dst, a, b, |a, b| a / b)?;
                }
                &Instruction::RemFloat(dst_a, b) => {
                    let dst_a: u8 = dst_a.into();
                    let b: u8 = b.into();
                    self.float_binop(dst_a, dst_a, b, |a, b| a % b)?;
                }
                &Instruction::RemFloatDst(dst, a, b) => {
                    self.float_binop(dst, a, b, |a, b| a % b)?;
                }
                Instruction::AddDouble(dst_a, b) => {
                    let dst_a: u8 = (*dst_a).into();
                    let b: u8 = (*b).into();
                    self.double_binop(dst_a, dst_a, b, |a, b| a + b)?;
                }
                &Instruction::AddDoubleDst(dst, a, b) => {
                    self.double_binop(dst, a, b, |a, b| a + b)?;
                }
                Instruction::SubDouble(dst_a, b) => {
                    let dst_a: u8 = (*dst_a).into();
                    let b: u8 = (*b).into();
                    self.double_binop(dst_a, dst_a, b, |a, b| a - b)?;
                }
                &Instruction::SubDoubleDst(dst, a, b) => {
                    self.double_binop(dst, a, b, |a, b| a - b)?;
                }
                Instruction::MulDouble(dst_a, b) => {
                    let dst_a: u8 = (*dst_a).into();
                    let b: u8 = (*b).into();
                    self.double_binop(dst_a, dst_a, b, |a, b| a * b)?;
                }
                &Instruction::MulDoubleDst(dst, a, b) => {
                    self.double_binop(dst, a, b, |a, b| a * b)?;
                }
                Instruction::DivDouble(dst_a, b) => {
                    let dst_a: u8 = (*dst_a).into();
                    let b: u8 = (*b).into();
                    self.double_binop(dst_a, dst_a, b, |a, b| a / b)?;
                }
                &Instruction::DivDoubleDst(dst, a, b) => {
                    self.double_binop(dst, a, b, |a, b| a / b)?;
                }
                Instruction::RemDouble(dst_a, b) => {
                    let dst_a: u8 = (*dst_a).into();
                    let b: u8 = (*b).into();
                    self.double_binop(dst_a, dst_a, b, |a, b| a % b)?;
                }
                &Instruction::RemDoubleDst(dst, a, b) => {
                    self.double_binop(dst, a, b, |a, b| a % b)?;
                }
                &Instruction::ArrayGetWide(dst, array_reference, index) => {
                    if let (Some(Register::Reference(_, array_reference)), Some(index)) = (
                        self.current_state
                            .current_stackframe
                            .get(array_reference as usize),
                        self.reg_literal(index as usize),
                    ) {
                        if let Some(Value::Array(data)) = self.heap.get(array_reference) {
                            let start = (index as usize)
                                .checked_mul(8)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            let window = data
                                .get(start..start + 8)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            let mut bytes = [0u8; 8];
                            bytes.copy_from_slice(window);
                            let new_register = Register::LiteralWide(i64::from_le_bytes(bytes));
                            self.update_register(dst, new_register)?;
                        }
                    }
                }
                &Instruction::ArrayGetBoolean(dst, array_reference, index) => {
                    if let (Some(Register::Reference(_, array_reference)), Some(index)) = (
                        self.current_state
                            .current_stackframe
                            .get(array_reference as usize),
                        self.reg_literal(index as usize),
                    ) {
                        if let Some(Value::Array(data)) = self.heap.get(array_reference) {
                            if let Some(&val) = data.get(index as usize) {
                                let new_register = Register::Literal(i32::from(val != 0));
                                self.update_register(dst, new_register)?;
                            }
                        }
                    }
                }
                &Instruction::ArrayGetShort(dst, array_reference, index) => {
                    if let (Some(Register::Reference(_, array_reference)), Some(index)) = (
                        self.current_state
                            .current_stackframe
                            .get(array_reference as usize),
                        self.reg_literal(index as usize),
                    ) {
                        if let Some(Value::Array(data)) = self.heap.get(array_reference) {
                            let start = (index as usize)
                                .checked_mul(2)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            let window = data
                                .get(start..start + 2)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            let bytes = [window[0], window[1]];
                            let new_register = Register::Literal(i16::from_le_bytes(bytes) as i32);
                            self.update_register(dst, new_register)?;
                        }
                    }
                }
                &Instruction::ArrayGetObject(dst, array_reference, index) => {
                    if let (Some(Register::Reference(_, array_reference)), Some(index)) = (
                        self.current_state
                            .current_stackframe
                            .get(array_reference as usize),
                        self.reg_literal(index as usize),
                    ) {
                        if let Some(Value::Array(data)) = self.heap.get(array_reference) {
                            let start = (index as usize)
                                .checked_mul(4)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            let window = data
                                .get(start..start + 4)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            let bytes = [window[0], window[1], window[2], window[3]];
                            let addr = u32::from_le_bytes(bytes);
                            let new_register = match self.heap.get(&addr) {
                                Some(Value::Object(class_instance)) => Register::Reference(
                                    class_instance.class.class_name.clone(),
                                    addr,
                                ),
                                _ => Register::Empty,
                            };
                            self.update_register(dst, new_register)?;
                        }
                    }
                }
                &Instruction::ArrayPutWide(src, array_reference, index) => {
                    if let (Some(Register::Reference(_, array_reference)), Some(index)) = (
                        self.current_state
                            .current_stackframe
                            .get(array_reference as usize),
                        self.reg_literal(index as usize),
                    ) {
                        let data = self.reg_wide(src as usize);
                        if let (Some(Value::Array(data)), Some(val)) =
                            (self.heap.get_mut(array_reference), data)
                        {
                            let start = (index as usize)
                                .checked_mul(8)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            if start + 8 > data.len() {
                                return Err(VMException::IndexOutOfBounds);
                            }
                            data[start..start + 8].copy_from_slice(&val.to_le_bytes());
                        }
                    }
                }
                &Instruction::ArrayPutBoolean(src, array_reference, index) => {
                    if let (Some(Register::Reference(_, array_reference)), Some(index)) = (
                        self.current_state
                            .current_stackframe
                            .get(array_reference as usize),
                        self.reg_literal(index as usize),
                    ) {
                        let d = self.reg_literal(src as usize);
                        if let Some(Value::Array(data)) = self.heap.get_mut(array_reference) {
                            if let Some(byte) = data.get_mut(index as usize) {
                                if let Some(val) = d {
                                    *byte = (val != 0) as u8;
                                }
                            } else {
                                return Err(VMException::IndexOutOfBounds);
                            }
                        }
                    }
                }
                &Instruction::ArrayPutShort(src, array_reference, index) => {
                    if let (Some(Register::Reference(_, array_reference)), Some(index)) = (
                        self.current_state
                            .current_stackframe
                            .get(array_reference as usize),
                        self.reg_literal(index as usize),
                    ) {
                        let d = self.reg_literal(src as usize);
                        if let (Some(Value::Array(data)), Some(val)) =
                            (self.heap.get_mut(array_reference), d)
                        {
                            let start = (index as usize)
                                .checked_mul(2)
                                .ok_or(VMException::IndexOutOfBounds)?;
                            if start + 2 > data.len() {
                                return Err(VMException::IndexOutOfBounds);
                            }
                            data[start..start + 2].copy_from_slice(&(val as i16).to_le_bytes());
                        }
                    }
                }
                Instruction::InstanceOf(dst, object, type_idx) => {
                    // let mut result = Register::Literal(0);
                    // if let Some(Register::Reference(_, instance)) =
                    //     self.current_state.current_stackframe.get((*object).into() as usize)
                    // {
                    //     if let Some(Value::Object(class_instance)) = self.heap.get(instance) {
                    //         if let Some(type_name) =
                    //             dex_file.get_type_name((*type_idx) as usize)
                    //         {
                    //             if class_instance.class.class_name == *type_name {
                    //                 result = Register::Literal(1);
                    //             }
                    //         }
                    //     }
                    // }
                    // self.update_register((*dst).into() as usize, result)?;
                }
                Instruction::Switch(_) | Instruction::SwitchData(_) => {}
                Instruction::ConstMethodHandle(..)
                | Instruction::ConstMethodType(..)
                | Instruction::ConstDynamic(..)
                | Instruction::InvokeCustom(..) => {}
                _ => return Err(VMException::LinkerError),
            }
            if matches!(self.current_state.vm_state, ExecutionState::Finished) {
                return Ok(());
            }
            if !matches!(
                self.current_state.vm_state,
                ExecutionState::RunningStaticInitializer
            ) {
                self.current_state.last_instruction_size =
                    InstructionSize((current_instruction.0 .0) / 2);
                self.current_state.pc += self.current_state.last_instruction_size;
            }
            current_instruction = code_item.get(&self.current_state.pc).ok_or(
                VMException::NoInstructionAtAddress(
                    self.current_state.current_method_index,
                    self.current_state.pc.into(),
                ),
            )?;
        }
    }

    pub fn invoke_runtime(
        &mut self,
        dex_file: Arc<DexFile>,
        method_idx: u32,
        arguments: Vec<Register>,
    ) -> Result<(), VMException> {
        if self
            .invoke_dynamic_runtime(dex_file.clone(), method_idx, &arguments)
            .is_ok()
        {
            return Ok(());
        }
        invoke_runtime(self, dex_file, method_idx, arguments)?;
        Ok(())
    }
    pub fn invoke_runtime_with_method(
        &mut self,
        class_name: &str,
        method: Arc<Method>,
        arguments: Vec<Register>,
    ) -> Result<(), VMException> {
        if self
            .invoke_dynamic_runtime_with_method(class_name, method.clone(), &arguments)
            .is_ok()
        {
            return Ok(());
        }
        invoke_runtime_with_method(self, class_name, method, arguments)?;
        Ok(())
    }

    fn update_register<T>(&mut self, dst: T, new_register: Register) -> Result<(), VMException>
    where
        T: Into<usize> + Copy,
    {
        let dst = self
            .current_state
            .current_stackframe
            .get_mut(dst.into())
            .ok_or_else(|| VMException::RegisterNotFound(dst.into()))?;
        *dst = new_register;
        Ok(())
    }

    fn malloc(&self) -> Option<u32> {
        let mut tries = 0;
        if let Ok(rng) = self.rng.lock() {
            loop {
                let heap_address = rng.borrow_mut().gen::<u32>();
                if !self.heap.contains_key(&heap_address) {
                    log::debug!("allocated memory at {}", heap_address);
                    return Some(heap_address);
                }
                tries += 1;
                if tries > 10 {
                    return None;
                }
            }
        } else {
            None
        }
    }

    pub fn get_return_object(&self) -> Option<Value> {
        match self.current_state.return_reg {
            Register::Literal(l) => Some(Value::Int(l)),
            Register::Reference(_, reference) => {
                if let Some(instance) = self.heap.get(&reference) {
                    Some(instance.to_owned())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Register {
    Literal(i32),
    LiteralWide(i64),
    Paired(u32),
    Reference(String, u32),
    Empty,
    Null,
}

impl Ord for Register {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let left = self.get_int();
        let right = other.get_int();
        left.cmp(&right)
    }
}
impl Eq for Register {}
impl PartialOrd for Register {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let left = self.get_int();
        let right = other.get_int();
        left.partial_cmp(&right)
    }
}
impl PartialEq for Register {
    fn eq(&self, other: &Self) -> bool {
        let left = self.get_int();
        let right = other.get_int();
        left.eq(&right)
    }
}

impl Register {
    pub fn get_int(&self) -> i64 {
        match self {
            &Register::Literal(a) => a as i64,
            &Register::Reference(_, a) => a as i64,
            Register::Empty => 0,
            Register::Null => 0,
            _ => 0,
        }
    }
}
