// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use coeus::coeus_emulation::vm::{
    dynamic_runtime::Invokable, runtime::StringClass, ClassInstance, InternalObject, Register,
    Value, VM,
};
use pyo3::{exceptions::PyRuntimeError, prelude::*};

use crate::parse::AnalyzeObject;

#[pyclass]
#[derive(Clone)]
pub struct DexVm {
    pub(crate) vm: Arc<Mutex<VM>>,
}

#[pyclass]
#[derive(Clone)]
pub struct VmResult {
    pub(crate) data: Value,
    pub(crate) vm: DexVm,
}

// method(arg1, arg2, arg3) =>

#[pyclass(unsendable)]
#[derive(Clone)]
pub struct UnsafeContext {
    vm_ptr: *mut VM,
    args: Vec<Register>,
}

#[pyclass]
#[derive(Clone)]
pub struct UnsafeRegister {
    register: Register,
}

#[pymethods]
impl UnsafeRegister {
    #[new]
    pub fn new(py: Python, any: Py<PyAny>, unsafe_context: &mut UnsafeContext) -> PyResult<Self> {
        if let Ok(s) = any.extract::<String>(py) {
            return Ok(unsafe_context.new_string(s.as_str()));
        }
        if let Ok(b) = any.extract::<bool>(py) {
            return Ok(UnsafeRegister {
                register: Register::Literal(if b { 1 } else { 0 }),
            });
        }
        if let Ok(int) = any.extract::<i32>(py) {
            return Ok(UnsafeRegister {
                register: Register::Literal(int),
            });
        }
        if let Ok(b) = any.extract::<Vec<u8>>(py) {
            return Ok(unsafe_context.new_array(b));
        }
        Err(PyRuntimeError::new_err("Unknown type"))
    }
}

#[pymethods]
impl UnsafeContext {
    fn new_string(&mut self, s: &str) -> UnsafeRegister {
        let ctx = unsafe { &mut *self.vm_ptr };

        let register = ctx
            .new_instance(
                StringClass::class_name().to_string(),
                Value::Object(StringClass::new(s.to_string())),
            )
            .expect("Could not create string");
        UnsafeRegister { register }
    }
    fn new_array(&mut self, array: Vec<u8>) -> UnsafeRegister {
        let ctx = unsafe { &mut *self.vm_ptr };

        let register = ctx
            .new_instance("[B".to_string(), Value::Array(array))
            .expect("Could not create string");
        UnsafeRegister { register }
    }
    fn get_string_from_heap(&self, addr: UnsafeRegister) -> PyResult<String> {
        let ctx = unsafe { &mut *self.vm_ptr };
        let the_heap = ctx.get_heap_ref();
        let Register::Reference(_name, addr) = addr.register else {
            return Err(PyRuntimeError::new_err("Wrong register type"));
        };
        let Some(Value::Object(obj)) = the_heap.get(&addr) else {
            return Err(PyRuntimeError::new_err("Object not found"));
        };
        let Some(InternalObject::String(string)) = obj.internal_state.get("tmp_string") else {
            return Err(PyRuntimeError::new_err("Object not a string"));
        };
        Ok(string.to_string())
    }
    fn get_array_from_heap(&self, addr: UnsafeRegister) -> PyResult<Vec<u8>> {
        let ctx = unsafe { &mut *self.vm_ptr };
        let the_heap = ctx.get_heap_ref();
        let Register::Reference(_name, addr) = addr.register else {
            return Err(PyRuntimeError::new_err("Wrong register type"));
        };
        let Some(Value::Array(a)) = the_heap.get(&addr) else {
            return Err(PyRuntimeError::new_err("Object not found"));
        };

        Ok(a.clone())
    }
    pub fn set_result(&self, register: UnsafeRegister) {
        let ctx = unsafe { &mut *self.vm_ptr };
        ctx.current_state.return_reg = register.register;
    }
    pub fn get_value(&self, py: Python, register: UnsafeRegister) -> PyResult<Py<PyAny>> {
        match &register.register {
            Register::Literal(lit) => Ok(lit.into_py(py)),
            Register::LiteralWide(lit) => Ok(lit.into_py(py)),
            Register::Reference(name, _) if name == "Ljava/lang/String;" => {
                Ok(self.get_string_from_heap(register)?.into_py(py))
            }
            Register::Reference(name, _) if name == "[B" => {
                Ok(self.get_array_from_heap(register)?.into_py(py))
            }
            Register::Reference(name, _) if name == "[C" => {
                Ok(self.get_array_from_heap(register)?.into_py(py))
            }
            _ => Ok(register.into_py(py)),
        }
    }
    pub fn get_arguments(&self) -> PyResult<Vec<UnsafeRegister>> {
        Ok(self
            .args
            .iter()
            .map(|r| UnsafeRegister {
                register: r.clone(),
            })
            .collect())
    }
}

#[pyclass(frozen)]
#[derive(Clone)]
pub struct DynamicPythonClass {
    class_name: String,
    py_class: Py<PyAny>,
}
#[pymethods]
impl DynamicPythonClass {
    #[new]
    pub fn new(class_name: &str, py_class: Py<PyAny>) -> Self {
        DynamicPythonClass {
            class_name: class_name.to_string(),
            py_class,
        }
    }
}

impl Invokable for DynamicPythonClass {
    fn call<'py>(
        &self,
        fn_name: &str,
        vm: &mut VM,
        args: &[Register],
    ) -> Result<(), coeus::coeus_emulation::vm::VMException> {
        Python::with_gil(|py| {
            let args = args.to_vec();
            let unsafe_context = UnsafeContext { vm_ptr: vm, args };
            let Ok(unsafe_context) = unsafe_context.into_pyobject(py) else {
                return;
            };

            let py_model = self.py_class.as_any();
            py_model
                .call_method(py, fn_name, (unsafe_context,), None)
                .unwrap();
        });
        Ok(())
    }
}

#[pymethods]
impl VmResult {
    pub fn get_value<'py>(&'py self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Ok(match &self.data {
            coeus::coeus_emulation::vm::Value::Array(l) => l.into_pyobject(py)?.into_any(),
            coeus::coeus_emulation::vm::Value::Object(l) => DexClassObject {
                class: l.clone(),
                vm: self.vm.to_owned(),
            }
            .into_pyobject(py)?
            .into_any(),
            coeus::coeus_emulation::vm::Value::Int(i) => i.into_pyobject(py)?.into_any(),
            coeus::coeus_emulation::vm::Value::Short(s) => s.into_pyobject(py)?.into_any(),
            coeus::coeus_emulation::vm::Value::Byte(b) => b.into_pyobject(py)?.into_any(),
        })
    }
}

#[pyclass]
#[derive(Clone)]
pub struct DexClassObject {
    pub(crate) class: ClassInstance,
    pub(crate) vm: DexVm,
}

#[pymethods]
impl DexClassObject {
    pub fn get_instances(&self) -> PyResult<Vec<String>> {
        let vm = if let Ok(vm) = self.vm.vm.lock() {
            vm
        } else {
            return Err(PyRuntimeError::new_err("Could not acquire lock"));
        };
        let mut instances = vec![];
        for (field, ptr) in &self.class.instances {
            let instance = vm.get_instance(Register::Reference("".to_string(), *ptr));
            instances.push(format!("{} = {:?}", field, instance));
        }
        Ok(instances)
    }
    pub fn __str__(&self) -> PyResult<String> {
        Ok(format!("Instance of {}", self.class.class.class_name))
    }
    pub fn __getitem__(&self, name: &str) -> PyResult<String> {
        if let Some(field_value) = self
            .class
            .instances
            .iter()
            .find(|(field_name, _)| field_name.ends_with(name))
            .map(|(_, a)| a)
        {
            let vm = if let Ok(vm) = self.vm.vm.lock() {
                vm
            } else {
                return Err(PyRuntimeError::new_err("Could not acquire lock"));
            };
            let instance = vm.get_instance(Register::Reference("".to_string(), *field_value));

            if let Value::Object(cl) = &instance {
                return Ok(format!("{}", cl));
            } else {
                return Ok(format!("{:?}", instance));
            }
        } else {
            Err(PyRuntimeError::new_err(format!(
                "{} not found on {}",
                name, self.class.class.class_name
            )))
        }
    }
}

#[pymethods]
impl DexVm {
    #[new]
    pub fn new(ao: &AnalyzeObject) -> Self {
        let primary = ao.files.multi_dex[0].primary.clone();
        let primary_identifier = primary.identifier.clone();
        let runtime = ao
            .files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(multi_dex.primary.clone()).chain(multi_dex.secondary.clone())
            })
            .filter(|dex| dex.identifier != primary_identifier)
            .collect();
        let vm = VM::new(primary, runtime, Arc::new(HashMap::new()));
        Self {
            vm: Arc::new(Mutex::new(vm)),
        }
    }

    pub fn register_class(&mut self, clazz: DynamicPythonClass) {
        VM::register_class(&clazz.class_name.to_string(), Box::new(clazz))
            .expect("Could not register");
    }

    pub fn get_current_state(&self) -> String {
        format!("{:?}", self.vm.lock().unwrap().get_current_state())
    }
    pub fn get_heap(&self) -> String {
        format!("Heap: {:?}", self.vm.lock().unwrap().get_heap())
    }
    pub fn get_instances(&self) -> String {
        format!("Heap: {:?}", self.vm.lock().unwrap().get_instances())
    }
    pub fn get_static_field(&self, fqdn: &str) -> PyResult<VmResult> {
        let vm = if let Ok(vm) = self.vm.lock() {
            vm
        } else {
            return Err(PyRuntimeError::new_err("Could not acquire lock"));
        };
        let instances = vm.get_instances();
        let heap = vm.get_heap();
        if let Some((_, address)) = instances.get(fqdn) {
            if let Some(obj) = heap.get(address) {
                return Ok(VmResult {
                    data: obj.to_owned(),
                    vm: self.clone(),
                });
            }
        }
        Err(PyRuntimeError::new_err("Could not get static field"))
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<DexVm>()?;
    m.add_class::<DynamicPythonClass>()?;
    m.add_class::<UnsafeContext>()?;
    m.add_class::<UnsafeRegister>()?;
    Ok(())
}
