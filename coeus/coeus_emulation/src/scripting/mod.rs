#![cfg(feature = "rhai")]
// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::sync::Arc;

use coeus_models::models::{DexFile, InstructionOffset, Method, MethodData, MultiDexFile};
use rhai::{module_resolvers::StaticModuleResolver, plugin::*, Array};

use crate::vm::{
    runtime::StringClass, BreakpointContext, ClassInstance, ExecutionState, Register, VMException,
    Value, VM,
};

#[export_module]
pub mod dex_emulation {
    use std::sync::Arc;

    use crate::vm::VM;
    use coeus_models::models::{Files, MultiDexFile};
    use rhai::ImmutableString;

    #[rhai_fn(name = "new_vm")]
    pub fn new_vm(files: &mut Files, md: MultiDexFile) -> VM {
        VM::new(
            md.primary.clone(),
            md.secondary.clone(),
            Arc::new(files.binaries.clone()),
        )
    }
    #[rhai_fn(name = "get_function")]
    pub fn get_function(
        apk: &mut MultiDexFile,
        class: ImmutableString,
        name: ImmutableString,
        shorty: ImmutableString,
    ) -> Method {
        apk.classes()
            .iter()
            .filter_map(|(f, c)| {
                if c.class_name == class.as_str() {
                    for m in &c.codes {
                        if m.name == name {
                            let method = f.methods[m.method_idx as usize].clone();
                            let proto = f.protos[method.proto_idx as usize].clone();
                            if let Some(proto_shorty) = f.get_string(proto.shorty_idx as usize) {
                                if proto_shorty == shorty.as_str() {
                                    return Some((*method).clone());
                                }
                            }
                        }
                    }
                }
                None
            })
            .collect::<Vec<Method>>()
            .first()
            .unwrap()
            .to_owned()
    }
}

#[export_module]
pub mod global {
    #[rhai_fn(name = "push", name = "+=")]
    pub fn push_register(list: &mut Array, item: Register) {
        list.push(Dynamic::from(item));
    }
    #[rhai_fn(name = "insert")]
    pub fn insert_register(list: &mut Array, position: i64, item: Register) {
        if position <= 0 {
            list.insert(0, Dynamic::from(item));
        } else if (position as usize) >= list.len() - 1 {
            list.push(Dynamic::from(item));
        } else {
            list.insert(position as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "pad")]
    pub fn pad_register(list: &mut Array, len: i64, item: Register) {
        if len as usize > list.len() {
            list.resize(len as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "==")]
    pub fn equals_register(item1: &mut Register, item: Register) -> bool {
        item1 == &item
    }
}

#[derive(Clone)]
pub struct EmulatedFunction {
    vm: VM,
    apk: MultiDexFile,
    method: MethodData,
    init_file: String,
    last_state: Option<(InstructionOffset, u32, BreakpointContext)>,
}

impl EmulatedFunction {
    fn new(vm: VM, dex_file: MultiDexFile, method: Method) -> Self {
        if let Some((file, method_data)) = dex_file
            .classes()
            .iter()
            .filter_map(|(f, c)| {
                if let Some(code_data) = c.codes.iter().find(|c| *c.method == method) {
                    return Some((f, code_data));
                }
                None
            })
            .collect::<Vec<(&Arc<DexFile>, &MethodData)>>()
            .first()
        {
            return EmulatedFunction {
                vm,
                apk: dex_file,
                init_file: file.identifier.clone(),
                method: (*method_data).to_owned(),
                last_state: None,
            };
        }
        panic!("Could not generate instance");
    }
    fn run(&mut self, args: Array) -> bool {
        match self.vm.start(
            self.method.method_idx,
            &self.init_file,
            self.method.code.as_ref().unwrap(),
            args.into_iter().map(|c| c.cast::<Register>()).collect(),
        ) {
            Ok(_) => true,
            Err(VMException::Breakpoint(pc, name, context)) => {
                self.last_state = Some((pc, name, context));
                false
            }
            Err(_) => true,
        }
    }
    fn continue_run(&mut self) -> bool {
        let last_state = if let Some(last_state) = self.last_state {
            last_state
        } else {
            return false;
        };

        match self.vm.continue_execution(last_state.0) {
            Ok(_) => true,
            Err(VMException::Breakpoint(pc, name, context)) => {
                self.last_state = Some((pc, name, context));
                false
            }
            Err(_) => true,
        }
    }

    fn new_class_argument(
        &mut self,
        class_name: ImmutableString,
        constructor_shorty: ImmutableString,
        constructor_args: Array,
    ) -> Dynamic {
        let classes = self.apk.classes();
        let class = classes
            .iter()
            .find(|(_, c)| c.class_name == class_name.as_str())
            .unwrap();
        let instance = self.vm.new_class_instance(class_name.as_str()).unwrap();
        let init_method = class
            .1
            .codes
            .iter()
            .find(|m| {
                let proto = class.0.protos[m.method.proto_idx as usize].clone();
                let shorty = class.0.get_string(proto.shorty_idx as usize).unwrap_or("");
                m.name == "<init>" && constructor_shorty == shorty
            })
            .unwrap();
        let mut args = constructor_args
            .into_iter()
            .map(|a| a.cast::<Register>())
            .collect::<Vec<Register>>();
        args.insert(0, instance.clone());
        let _ = self.vm.start(
            init_method.method_idx,
            &class.0.identifier,
            init_method.code.as_ref().unwrap(),
            args,
        );
        Dynamic::from(instance)
    }
    fn get_result_value(&mut self) -> Value {
        self.vm.get_return_object().unwrap()
    }
    fn get_result(&mut self) -> String {
        if let Some(result) = self.vm.get_return_object() {
            match result {
                Value::Object(obj) => format!("{}", obj),
                Value::Array(arr) => format!("Returned Array: {:?}", &arr[..]),
                Value::Int(i) => format!("{}", i),
                _ => format!("{:?}", result),
            }
        } else {
            String::from("")
        }
    }
    fn get_current_frame(&mut self) -> Vec<Register> {
        self.vm.get_registers()
    }

    fn is_breakpoint(&mut self) -> bool {
        matches!(
            self.vm.get_current_state().vm_state,
            ExecutionState::Stopped | ExecutionState::Paused
        )
    }
    fn is_error(&mut self) -> bool {
        matches!(self.vm.get_current_state().vm_state, ExecutionState::Error)
    }
    fn is_finished(&mut self) -> bool {
        matches!(
            self.vm.get_current_state().vm_state,
            ExecutionState::Finished
        )
    }

    fn new_string_argument(&mut self, string: ImmutableString) -> Dynamic {
        let string = StringClass::new(string.to_string());
        if let Ok(instance) = self
            .vm
            .new_instance(StringClass::class_name().to_string(), Value::Object(string))
        {
            return Dynamic::from(instance);
        }
        panic!("SHOULD NOT HAPPEN");
    }
    fn new_value_argument(&mut self, value: Value) -> Dynamic {
        Dynamic::from(
            match &value {
                Value::Array(_) => self.vm.new_instance("[B".to_string(), value),
                Value::Object(v) => self.vm.new_instance(v.class.class_name.clone(), value),
                Value::Int(_) => self.vm.new_instance("I".to_string(), value),
                Value::Short(_) => self.vm.new_instance("S".to_string(), value),
                Value::Byte(_) => self.vm.new_instance("B".to_string(), value),
            }
            .unwrap(),
        )
    }
    fn new_array_argument(&mut self, arr: Array) -> Dynamic {
        if let Ok(instance) = self.vm.new_instance(
            "[B".to_string(),
            Value::Array(arr.into_iter().map(|c| c.cast::<i64>() as u8).collect()),
        ) {
            return Dynamic::from(instance);
        }
        panic!("SHOULD NOT HAPPEN");
    }
    fn new_i32_argument(&mut self, int: i64) -> Dynamic {
        Dynamic::from(Register::Literal(int as i32))
    }
    fn new_i64_argument(&mut self, int: i64) -> Dynamic {
        Dynamic::from(Register::LiteralWide(int))
    }
}

pub fn register_vm_module(engine: &mut Engine, resolver: &mut StaticModuleResolver) {
    engine
        .register_type::<EmulatedFunction>()
        .register_fn("new_emulated_function", EmulatedFunction::new)
        .register_fn("run", EmulatedFunction::run)
        .register_fn("continue", EmulatedFunction::continue_run)
        .register_fn("get_result", EmulatedFunction::get_result)
        .register_fn("new_argument", EmulatedFunction::new_class_argument)
        .register_fn("new_argument", EmulatedFunction::new_string_argument)
        .register_fn("new_argument", EmulatedFunction::new_array_argument)
        .register_fn("new_argument", EmulatedFunction::new_i32_argument)
        .register_fn("new_argument", EmulatedFunction::new_value_argument)
        .register_fn("new_i64_argument", EmulatedFunction::new_i64_argument)
        .register_fn("get_current_frame", EmulatedFunction::get_current_frame)
        .register_fn("is_breakpoint", EmulatedFunction::is_breakpoint)
        .register_fn("is_error", EmulatedFunction::is_error)
        .register_fn("get_result_value", EmulatedFunction::get_result_value)
        .register_fn("is_finished", EmulatedFunction::is_finished);
    let global_module = exported_module!(global);
    engine.register_global_module(global_module.into());
    let vm_module = exported_module!(dex_emulation);
    resolver.insert("coeus_emulation", vm_module);
}
