use std::convert::TryFrom;

// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
use coeus::coeus_debug::{
    jdwp::JdwpClient,
    models::{ClassInstance, Composite, Event, SlotValue, StackFrame},
    Runtime,
};
use pyo3::{
    exceptions::PyRuntimeError,
    pyclass, pyfunction, pymethods,
    types::{PyAnyMethods, PyBool, PyFloat, PyInt, PyModule, PyModuleMethods, PyString},
    wrap_pyfunction, Bound, IntoPy, Py, PyAny, PyResult, Python, ToPyObject,
};
use std::{collections::HashSet, path::Path, time::Duration};

use crate::{analysis::Method, parse::AnalyzeObject};

#[pyclass]
#[derive(Clone)]
pub struct DebuggableApp {
    #[pyo3(get)]
    pub pid: u32,
    #[pyo3(get)]
    pub process_name: String,
    #[pyo3(get)]
    pub package_name: Option<String>,
}

#[pymethods]
impl DebuggableApp {
    pub fn __str__(&self) -> String {
        match &self.package_name {
            Some(package) if package == &self.process_name => {
                format!("{} (pid {})", package, self.pid)
            }
            Some(package) => format!("{} [{}] (pid {})", package, self.process_name, self.pid),
            None => format!("{} (pid {})", self.process_name, self.pid),
        }
    }
}

#[pyfunction]
#[pyo3(signature = (serial=None, adb_path=None))]
pub fn list_debuggable_apps(
    py: Python<'_>,
    serial: Option<&str>,
    adb_path: Option<&str>,
) -> PyResult<Vec<DebuggableApp>> {
    let serial = serial.map(str::to_owned);
    let adb_path = adb_path.map(str::to_owned);
    let result = py.allow_threads(|| {
        coeus::coeus_parse::signing::list_debuggable_apps(
            serial.as_deref(),
            adb_path.as_deref().map(Path::new),
        )
    });
    result
        .map(|apps| {
            apps.into_iter()
                .map(|app| DebuggableApp {
                    pid: app.pid,
                    process_name: app.process_name,
                    package_name: app.package_name,
                })
                .collect()
        })
        .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
#[pyo3(signature = (pid, local_port, serial=None, adb_path=None))]
pub fn forward_jdwp(
    py: Python<'_>,
    pid: u32,
    local_port: u16,
    serial: Option<&str>,
    adb_path: Option<&str>,
) -> PyResult<()> {
    let serial = serial.map(str::to_owned);
    let adb_path = adb_path.map(str::to_owned);
    py.allow_threads(|| {
        coeus::coeus_parse::signing::forward_jdwp(
            pid,
            local_port,
            serial.as_deref(),
            adb_path.as_deref().map(Path::new),
        )
    })
    .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
#[pyo3(signature = (local_port, serial=None, adb_path=None))]
pub fn remove_jdwp_forward(
    local_port: u16,
    serial: Option<&str>,
    adb_path: Option<&str>,
) -> PyResult<()> {
    coeus::coeus_parse::signing::remove_jdwp_forward(local_port, serial, adb_path.map(Path::new))
        .map_err(PyRuntimeError::new_err)
}

#[pyclass]
#[derive(Clone)]
#[allow(dead_code)]
pub struct VmBreakpoint {
    request_id: u32,
    class_name: String,
    class: coeus::coeus_debug::models::Class,
    name_and_sig: String,
    code_index: u64,
}

#[pymethods]
impl VmBreakpoint {
    pub fn location(&self) -> String {
        format!(
            "{}->{}@{}",
            self.class_name, self.name_and_sig, self.code_index
        )
    }
}

#[pyclass]
#[derive(Clone)]
pub struct VmInstance {
    inner: ClassInstance,
}

#[pymethods]
impl VmInstance {
    pub fn to_string(&self, py: Python, debugger: &mut Debugger) -> PyResult<String> {
        let mut output = self.inner.signature.to_string();
        output.push('\n');
        for f in &self.inner.fields {
            let value = if let Some(v) = &f.value {
                let stack_val = StackValue { slot: v.clone() };
                let s = stack_val.get_value(debugger, py)?;
                if let Ok(val) = s.extract::<VmInstance>(py) {
                    format!("[{}@{}]", val.inner.signature, val.inner.object_id)
                } else {
                    format!("{s} [{v:?}]")
                }
            } else {
                "null".to_string()
            };
            output.push_str(&format!("\t{} : {} = {:?}\n", f.name, f.signature, value));
        }
        Ok(output)
    }
}

#[pyclass]
/// A debugger struct, holding the jdwp_client for communication with the Debugger
/// and the runtime
pub struct Debugger {
    pub(crate) jdwp_client: JdwpClient,
    pub(crate) rt: Runtime,
    pub(crate) last_step_id: Option<u32>,
    pub(crate) break_points: Vec<VmBreakpoint>,
}

#[pyclass]
pub struct DebuggerStackFrame {
    stack_frame: StackFrame,
}
#[pyclass]
pub struct StackValue {
    slot: SlotValue,
}
#[pymethods]
impl StackValue {
    pub fn __str__(&self) -> String {
        format!("{:?}", self.slot)
    }
    #[new]
    pub fn new(
        py: Python,
        debugger: &mut Debugger,
        value: Py<PyAny>,
        old_value: Option<&StackValue>,
    ) -> PyResult<StackValue> {
        let bound_val = value.bind(py);
        let val = bound_val.as_ref();
        match val {
            v if v.is_none() => {
                let null_value = match old_value.map(|old| &old.slot.value) {
                    Some(coeus::coeus_debug::models::Value::Array(_)) => {
                        coeus::coeus_debug::models::Value::Array(0)
                    }
                    Some(coeus::coeus_debug::models::Value::String(_)) => {
                        coeus::coeus_debug::models::Value::String(0)
                    }
                    _ => coeus::coeus_debug::models::Value::Object(0),
                };
                Ok(StackValue {
                    slot: null_value.into(),
                })
            }
            v if v.is_instance_of::<PyBool>() => {
                let value: bool = val.extract()?;
                let stack_value = coeus::coeus_debug::models::Value::Boolean(value as u8);
                Ok(StackValue {
                    slot: stack_value.into(),
                })
            }
            v if v.is_instance_of::<PyInt>() => {
                let stack_value = if let Some(old_value) = old_value {
                    match old_value.slot.value {
                        coeus::coeus_debug::models::Value::Int(_) => {
                            let value: i32 = val.extract()?;
                            coeus::coeus_debug::models::Value::Int(value)
                        }
                        coeus::coeus_debug::models::Value::Byte(_) => {
                            let value: i8 = val.extract()?;
                            coeus::coeus_debug::models::Value::Byte(value)
                        }
                        coeus::coeus_debug::models::Value::Char(_) => {
                            let value: char = val.extract()?;
                            coeus::coeus_debug::models::Value::Char(value)
                        }
                        coeus::coeus_debug::models::Value::Long(_) => {
                            let value: i64 = val.extract()?;
                            coeus::coeus_debug::models::Value::Long(value)
                        }
                        _ => {
                            return Err(PyRuntimeError::new_err(
                                "Old register was not an integer type",
                            ))
                        }
                    }
                } else {
                    let value: i32 = val.extract()?;
                    coeus::coeus_debug::models::Value::Int(value)
                };

                Ok(StackValue {
                    slot: stack_value.into(),
                })
            }
            v if v.is_instance_of::<PyFloat>() => {
                let stack_value = if let Some(old_value) = old_value {
                    match old_value.slot.value {
                        coeus::coeus_debug::models::Value::Float(_) => {
                            let value: f32 = val.extract()?;
                            coeus::coeus_debug::models::Value::Float(value)
                        }
                        coeus::coeus_debug::models::Value::Double(_) => {
                            let value: f64 = val.extract()?;
                            coeus::coeus_debug::models::Value::Double(value)
                        }
                        _ => {
                            return Err(PyRuntimeError::new_err(
                                "Old register was not an integer type",
                            ))
                        }
                    }
                } else {
                    let value: f32 = val.extract()?;
                    coeus::coeus_debug::models::Value::Float(value)
                };
                Ok(StackValue {
                    slot: stack_value.into(),
                })
            }
            v if v.is_instance_of::<PyString>() => {
                let value: String = val.extract()?;
                let slot = debugger.new_string(value.as_str())?;

                Ok(slot)
            }
            _ => Err(PyRuntimeError::new_err("Unknown type")),
        }
    }
    pub fn get_value(&self, debugger: &mut Debugger, py: Python) -> PyResult<Py<PyAny>> {
        match self.slot.value {
            coeus::coeus_debug::models::Value::Object(o) => {
                if o == 0 {
                    return Ok(None::<String>.to_object(py));
                }
                let s = match debugger.jdwp_client.get_object(&debugger.rt, o) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(PyRuntimeError::new_err(format!(
                            "Could not get object_reference: {e}",
                        )))
                    }
                };
                Ok(VmInstance { inner: s }.into_py(py))
            }
            coeus::coeus_debug::models::Value::Byte(b) => Ok(b.to_object(py)),
            coeus::coeus_debug::models::Value::Short(s) => Ok(s.to_object(py)),
            coeus::coeus_debug::models::Value::Int(i) => Ok(i.to_object(py)),
            coeus::coeus_debug::models::Value::Long(l) => Ok(l.to_object(py)),
            coeus::coeus_debug::models::Value::String(s) => {
                if s == 0 {
                    return Ok(None::<String>.to_object(py));
                }
                let Ok(s) = debugger.jdwp_client.get_string(&debugger.rt, s) else {
                    return Err(PyRuntimeError::new_err("Could not get string"));
                };
                Ok(s.to_object(py))
            }
            coeus::coeus_debug::models::Value::Array(a) => {
                if a == 0 {
                    return Ok(None::<String>.to_object(py));
                }
                let Ok(values) = debugger.jdwp_client.get_array(&debugger.rt, a) else {
                    return Err(PyRuntimeError::new_err("Could not get array"));
                };
                Ok(format!("{:?}", values).to_object(py))
            }
            coeus::coeus_debug::models::Value::Float(f) => Ok(f.to_object(py)),
            coeus::coeus_debug::models::Value::Double(d) => Ok(d.to_object(py)),
            coeus::coeus_debug::models::Value::Boolean(b) => Ok((b == 1).to_object(py)),
            coeus::coeus_debug::models::Value::Char(c) => Ok(c.to_object(py)),
            coeus::coeus_debug::models::Value::Void => Ok(None::<String>.to_object(py)),
            coeus::coeus_debug::models::Value::Reference(_) => Ok(None::<String>.to_object(py)),
        }
    }
}

fn debug_string_registers(method: &Method, code_index: u64) -> HashSet<u16> {
    let Some(code) = method
        .method_data
        .as_ref()
        .and_then(|data| data.code.as_ref())
    else {
        return HashSet::new();
    };

    let mut string_registers = HashSet::new();
    let mut pending_invoke_returns_string = None;
    for (_, offset, instruction) in &code.insns {
        if u32::from(*offset) as u64 > code_index {
            break;
        }

        match instruction {
            instruction if invoke_method_index(instruction).is_some() => {
                pending_invoke_returns_string = invoke_method_index(instruction)
                    .and_then(|method_idx| method.file.methods.get(method_idx as usize))
                    .and_then(|target| method.file.protos.get(target.proto_idx as usize))
                    .and_then(|proto| method.file.get_type_name(proto.return_type_idx as usize))
                    .map(|return_type| return_type == "Ljava/lang/String;");
            }
            coeus::coeus_models::models::Instruction::MoveResultObject(register) => {
                if pending_invoke_returns_string == Some(true) {
                    string_registers.insert(*register as u16);
                } else {
                    string_registers.remove(&(*register as u16));
                }
                pending_invoke_returns_string = None;
            }
            coeus::coeus_models::models::Instruction::MoveResult(register)
            | coeus::coeus_models::models::Instruction::MoveResultWide(register) => {
                string_registers.remove(&(*register as u16));
                pending_invoke_returns_string = None;
            }
            coeus::coeus_models::models::Instruction::ConstString(register, _)
            | coeus::coeus_models::models::Instruction::ConstStringJumbo(register, _) => {
                string_registers.insert(*register as u16);
                pending_invoke_returns_string = None;
            }
            coeus::coeus_models::models::Instruction::MoveObject(destination, source) => {
                copy_debug_string_type(
                    &mut string_registers,
                    u16::from(*destination),
                    u16::from(*source),
                );
                pending_invoke_returns_string = None;
            }
            coeus::coeus_models::models::Instruction::MoveObjectFrom16(destination, source) => {
                copy_debug_string_type(&mut string_registers, u16::from(*destination), *source);
                pending_invoke_returns_string = None;
            }
            coeus::coeus_models::models::Instruction::MoveObject16(destination, source) => {
                copy_debug_string_type(&mut string_registers, *destination, *source);
                pending_invoke_returns_string = None;
            }
            coeus::coeus_models::models::Instruction::CheckCast(register, type_idx) => {
                if method.file.get_type_name(*type_idx) == Some("Ljava/lang/String;") {
                    string_registers.insert(*register as u16);
                } else {
                    string_registers.remove(&(*register as u16));
                }
                pending_invoke_returns_string = None;
            }
            coeus::coeus_models::models::Instruction::NewInstance(register, _) => {
                string_registers.remove(&(*register as u16));
                pending_invoke_returns_string = None;
            }
            _ => pending_invoke_returns_string = None,
        }
    }

    string_registers
}

fn copy_debug_string_type(string_registers: &mut HashSet<u16>, destination: u16, source: u16) {
    if string_registers.contains(&source) {
        string_registers.insert(destination);
    } else {
        string_registers.remove(&destination);
    }
}

fn invoke_method_index(instruction: &coeus::coeus_models::models::Instruction) -> Option<u16> {
    use coeus::coeus_models::models::Instruction;

    match instruction {
        Instruction::InvokeVirtual(_, method_idx, _)
        | Instruction::InvokeSuper(_, method_idx, _)
        | Instruction::InvokeDirect(_, method_idx, _)
        | Instruction::InvokeStatic(_, method_idx, _)
        | Instruction::InvokeInterface(_, method_idx, _)
        | Instruction::InvokeVirtualRange(_, method_idx, _)
        | Instruction::InvokeSuperRange(_, method_idx, _)
        | Instruction::InvokeDirectRange(_, method_idx, _)
        | Instruction::InvokeStaticRange(_, method_idx, _)
        | Instruction::InvokeInterfaceRange(_, method_idx, _) => Some(*method_idx),
        _ => None,
    }
}

#[pymethods]
impl DebuggerStackFrame {
    pub fn get_values_for(&self, debugger: &mut Debugger, m: &Method) -> PyResult<Vec<StackValue>> {
        let Some(code_item) = m.method_data.as_ref().and_then(|md| md.code.as_ref()) else {
            return Err(PyRuntimeError::new_err("We need code data"));
        };
        let Ok(values) =
            self.stack_frame
                .get_values(code_item, &mut debugger.jdwp_client, &debugger.rt)
        else {
            return Err(PyRuntimeError::new_err("Failed to get values"));
        };
        let string_registers = debug_string_registers(m, self.get_code_index());
        Ok(values
            .into_iter()
            .enumerate()
            .map(|(slot, mut value)| {
                if string_registers.contains(&(slot as u16))
                    && matches!(value.value, coeus::coeus_debug::models::Value::Object(_))
                {
                    let object_id = match value.value {
                        coeus::coeus_debug::models::Value::Object(object_id) => object_id,
                        _ => unreachable!("the value was checked to be an object"),
                    };
                    value = coeus::coeus_debug::models::Value::String(object_id).into();
                }
                StackValue { slot: value }
            })
            .collect())
    }
    pub fn set_value(
        &self,
        debugger: &mut Debugger,
        slot_idx: u32,
        slot_value: &StackValue,
    ) -> PyResult<()> {
        self.stack_frame
            .set_value(
                &mut debugger.jdwp_client,
                &debugger.rt,
                slot_idx,
                &slot_value.slot,
            )
            .map_err(|e| PyRuntimeError::new_err(format!("Set value failed{e}",)))
    }
    pub fn get_code(&self, debugger: &mut Debugger, ao: &AnalyzeObject) -> PyResult<String> {
        let class_name = self.get_class_name(debugger)?.replace('$', r"\$");
        let method_name = self.get_method_name(debugger)?;
        let method_signature = self.get_method_signature(debugger)?;
        let code_index = self.get_code_index();
        let location_class = ao.find_classes(&class_name)?;
        if location_class.is_empty() {
            return Err(PyRuntimeError::new_err("No class found"));
        }
        let location_class = location_class[0].as_class()?;
        let location_method = location_class
            .get_method_by_proto_type(&method_name, &method_signature)
            .or_else(|_| location_class.get_method(&method_name))?;
        let code = location_method.code().replace(
            &format!("#{code_index:#x}"),
            &format!("#{code_index:#x} <==========="),
        );
        Ok(code)
    }
    pub fn get_code_index(&self) -> u64 {
        self.stack_frame.get_location().code_index
    }
    pub fn get_class_name(&self, debugger: &mut Debugger) -> PyResult<String> {
        debugger
            .jdwp_client
            .get_class_name(&debugger.rt, self.stack_frame.location.class_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Could not get signature: {e}")))
    }
    pub fn get_method_name(&self, debugger: &mut Debugger) -> PyResult<String> {
        let signature = debugger
            .jdwp_client
            .get_class_name(&debugger.rt, self.stack_frame.location.class_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Could not get signature: {e}")))?;
        let classes = debugger
            .jdwp_client
            .get_class(&debugger.rt, &signature)
            .map_err(|e| PyRuntimeError::new_err(format!("Could not get class: {e}")))?;
        if classes.is_empty() {
            return Err(PyRuntimeError::new_err("No class found"));
        }
        let class = &classes[0];
        let method = class
            .get_method(self.stack_frame.location.method_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Could not find method on class {e}")))?;
        Ok(method.name.clone())
    }
    pub fn get_method_signature(&self, debugger: &mut Debugger) -> PyResult<String> {
        let signature = debugger
            .jdwp_client
            .get_class_name(&debugger.rt, self.stack_frame.location.class_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Could not get signature: {e}")))?;
        let classes = debugger
            .jdwp_client
            .get_class(&debugger.rt, &signature)
            .map_err(|e| PyRuntimeError::new_err(format!("Could not get class: {e}")))?;
        if classes.is_empty() {
            return Err(PyRuntimeError::new_err("No class found"));
        }
        let method = classes[0]
            .get_method(self.stack_frame.location.method_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Could not find method on class {e}")))?;
        Ok(method.signature.clone())
    }
    pub fn step(&self, debugger: &mut Debugger) -> PyResult<()> {
        let result = debugger
            .jdwp_client
            .step(&debugger.rt, self.stack_frame.thread_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Single Step failed: {}", e)))?;
        debugger.last_step_id = Some(result);
        Ok(())
    }
}

impl Debugger {
    fn wait_for_package_inner(
        &mut self,
        py: Python<'_>,
        timeout: Option<Duration>,
        return_on_non_breakpoint: bool,
    ) -> PyResult<Option<DebuggerStackFrame>> {
        // The GUI calls this from a worker thread. Release Python's GIL while
        // JDWP is waiting on the socket so the command loop stays responsive.
        loop {
            let cmd = if let Some(timeout) = timeout {
                match py
                    .allow_threads(|| self.jdwp_client.wait_for_event_timeout(&self.rt, timeout))
                {
                    Ok(Some(cmd)) => cmd,
                    Ok(None) => return Ok(None),
                    Err(error) => {
                        return Err(PyRuntimeError::new_err(format!(
                            "JDWP event wait failed: {error}"
                        )))
                    }
                }
            } else {
                let Some(cmd) =
                    py.allow_threads(|| self.jdwp_client.wait_for_event_blocking(&self.rt))
                else {
                    return Err(PyRuntimeError::new_err(
                        "JDWP connection closed while waiting for a debugger event",
                    ));
                };
                cmd
            };
            let Ok(composite) = Composite::try_from(cmd) else {
                // VM_START, VM_DEATH, and other non-breakpoint events may be
                // queued by ART. The polling API returns after one such event
                // so the GUI can service queued breakpoint commands instead of
                // spinning here forever under an event flood.
                if return_on_non_breakpoint {
                    return Ok(None);
                }
                continue;
            };
            let Some((bp, is_single_step)) =
                composite.events.iter().find_map(|event| match event {
                    Event::Breakpoint(bp) => Some((bp, false)),
                    Event::SingleStep(bp) => Some((bp, true)),
                    Event::VmStart(_) | Event::VmDeath => None,
                })
            else {
                if composite
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::VmStart(_)))
                {
                    // VM_START is automatically generated and its suspend
                    // policy is target-dependent. Resume defensively so an
                    // initial suspended VM can reach the requested breakpoint.
                    self.jdwp_client.resume(&self.rt, 1).map_err(|error| {
                        PyRuntimeError::new_err(format!("Could not resume VM start: {error}"))
                    })?;
                }
                if return_on_non_breakpoint {
                    return Ok(None);
                }
                continue;
            };
            if is_single_step {
                if let Some(event_id) = self.last_step_id.take() {
                    let _ = self.jdwp_client.clear_step(&self.rt, event_id);
                }
            }
            let thread = bp.get_thread();
            let stack_frame = thread
                .get_top_frame(&mut self.jdwp_client, &self.rt)
                .map_err(|error| {
                    PyRuntimeError::new_err(format!("Could not get Stackframe: {error}"))
                })?;

            return Ok(Some(DebuggerStackFrame { stack_frame }));
        }
    }
}

#[pymethods]
impl Debugger {
    #[new]
    pub fn new(py: Python<'_>, host: &str, port: u16) -> PyResult<Debugger> {
        let host = host.to_owned();
        match py.allow_threads(|| coeus::coeus_debug::create_debugger(&host, port)) {
            Ok((jdwp_client, rt)) => Ok(Debugger {
                jdwp_client,
                rt,
                last_step_id: None,
                break_points: vec![],
            }),
            Err(e) => Err(PyRuntimeError::new_err(format!("{}", e))),
        }
    }
    pub fn new_string(&mut self, string: &str) -> PyResult<StackValue> {
        let string_reference = self
            .jdwp_client
            .create_string(&self.rt, string)
            .map_err(|e| PyRuntimeError::new_err(format!("Create String failed: {}", e)))?;
        let slot_value: SlotValue =
            coeus::coeus_debug::models::Value::String(string_reference).into();
        Ok(StackValue { slot: slot_value })
    }

    pub fn close(&mut self) {
        self.jdwp_client.close();
    }

    pub fn set_breakpoint(&mut self, method: &Method, code_index: u64) -> PyResult<()> {
        let class = method.get_class();
        let class_name = class.name();
        let class = match self.jdwp_client.get_class(&self.rt, class_name) {
            Ok(c) => c,
            Err(e) => {
                return Err(PyRuntimeError::new_err(format!(
                    "Class command failed: {e}",
                )))
            }
        };
        if class.is_empty() {
            return Err(PyRuntimeError::new_err("Class not yet loaded"));
        }

        let first = &class[0];
        let name_and_sig = method.signature().replace(&format!("{class_name}->"), "");
        let cmd = match first.set_breakpoint(&name_and_sig, code_index) {
            Ok(cmd) => cmd,
            Err(e) => {
                return Err(PyRuntimeError::new_err(format!(
                    "Could not get breakpoint command {e}",
                )))
            }
        };
        let Ok(id) = self.jdwp_client.set_breakpoint(&self.rt, cmd) else {
            return Err(PyRuntimeError::new_err("Could not set breakpoint"));
        };
        self.break_points.push(VmBreakpoint {
            request_id: id,
            class_name: class_name.to_string(),
            class: class[0].clone(),
            name_and_sig,
            code_index,
        });
        Ok(())
    }
    pub fn clear_breakpoint(&mut self, method: &Method, code_index: u64) -> PyResult<()> {
        let class_name = method.get_class().name().to_string();
        let name_and_sig = method.signature().replace(&format!("{class_name}->"), "");
        let Some(request_id) = self
            .break_points
            .iter()
            .find(|breakpoint| {
                breakpoint.class_name == class_name
                    && breakpoint.name_and_sig == name_and_sig
                    && breakpoint.code_index == code_index
            })
            .map(|breakpoint| breakpoint.request_id)
        else {
            return Err(PyRuntimeError::new_err("Breakpoint not found"));
        };
        self.jdwp_client
            .clear_breakpoint(&self.rt, request_id)
            .map_err(|error| {
                PyRuntimeError::new_err(format!("Could not clear breakpoint: {error}"))
            })?;
        self.break_points.retain(|breakpoint| {
            !(breakpoint.request_id == request_id
                && breakpoint.class_name == class_name
                && breakpoint.name_and_sig == name_and_sig
                && breakpoint.code_index == code_index)
        });
        Ok(())
    }
    pub fn resume(&mut self) -> PyResult<()> {
        self.jdwp_client
            .resume(&self.rt, 1)
            .map_err(|e| PyRuntimeError::new_err(format!("{}", e)))
    }
    pub fn wait_for_package(&mut self, py: Python) -> PyResult<DebuggerStackFrame> {
        self.wait_for_package_inner(py, None, false)?
            .ok_or_else(|| {
                PyRuntimeError::new_err("JDWP connection closed while waiting for a debugger event")
            })
    }
    pub fn poll_for_package(
        &mut self,
        py: Python,
        timeout_millis: u64,
    ) -> PyResult<Option<DebuggerStackFrame>> {
        self.wait_for_package_inner(py, Some(Duration::from_millis(timeout_millis.max(1))), true)
    }
    pub fn get_code_indices(&self, method: &Method) -> PyResult<Vec<u32>> {
        let Some(code_item) = method.method_data.as_ref().and_then(|m| m.code.as_ref()) else {
            return Err(PyRuntimeError::new_err("We need code data"));
        };
        Ok(coeus::coeus_debug::get_code_indizes_from_code(code_item))
    }
    pub fn get_breakpoints(&self) -> Vec<VmBreakpoint> {
        self.break_points.clone()
    }
}
pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<DebuggableApp>()?;
    m.add_class::<Debugger>()?;
    m.add_class::<DebuggerStackFrame>()?;
    m.add_class::<StackValue>()?;
    m.add_class::<VmBreakpoint>()?;
    m.add_class::<VmInstance>()?;
    m.add_function(wrap_pyfunction!(list_debuggable_apps, m)?)?;
    m.add_function(wrap_pyfunction!(forward_jdwp, m)?)?;
    m.add_function(wrap_pyfunction!(remove_jdwp_forward, m)?)?;
    Ok(())
}
