use std::convert::TryFrom;

// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
use coeus::coeus_debug::{
    jdwp::JdwpClient,
    models::{ClassInstance, Composite, Event, JdwpPacket, SlotValue, StackFrame},
    Runtime,
};
use pyo3::{
    exceptions::PyRuntimeError,
    pyclass, pyfunction, pymethods,
    types::{PyAnyMethods, PyBool, PyFloat, PyInt, PyLong, PyModule, PyModuleMethods, PyString},
    wrap_pyfunction, Bound, IntoPy, Py, PyAny, PyResult, Python, ToPyObject,
};
use std::path::Path;

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
    serial: Option<&str>,
    adb_path: Option<&str>,
) -> PyResult<Vec<DebuggableApp>> {
    coeus::coeus_parse::signing::list_debuggable_apps(serial, adb_path.map(Path::new))
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
    pid: u32,
    local_port: u16,
    serial: Option<&str>,
    adb_path: Option<&str>,
) -> PyResult<()> {
    coeus::coeus_parse::signing::forward_jdwp(pid, local_port, serial, adb_path.map(Path::new))
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
                let Ok(s) = debugger.jdwp_client.get_string(&debugger.rt, s) else {
                    return Err(PyRuntimeError::new_err("Could not get string"));
                };
                Ok(s.to_object(py))
            }
            coeus::coeus_debug::models::Value::Array(a) => {
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
        Ok(values.into_iter().map(|slot| StackValue { slot }).collect())
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
        let code_index = self.get_code_index();
        let location_class = ao.find_classes(&class_name)?;
        if location_class.is_empty() {
            return Err(PyRuntimeError::new_err("No class found"));
        }
        let location_class = &location_class[0];
        let location_method = location_class.as_class()?.get_method(&method_name)?;
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
    pub fn step(&self, debugger: &mut Debugger) -> PyResult<()> {
        let result = debugger
            .jdwp_client
            .step(&debugger.rt, self.stack_frame.thread_id)
            .map_err(|e| PyRuntimeError::new_err(format!("Single Step failed: {}", e)))?;
        debugger.last_step_id = Some(result);
        Ok(())
    }
}

#[pymethods]
impl Debugger {
    #[new]
    pub fn new(host: &str, port: u16) -> PyResult<Debugger> {
        match coeus::coeus_debug::create_debugger(host, port) {
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
    pub fn resume(&mut self) -> PyResult<()> {
        self.jdwp_client
            .resume(&self.rt, 1)
            .map_err(|e| PyRuntimeError::new_err(format!("{}", e)))
    }
    pub fn wait_for_package(&mut self, py: Python) -> PyResult<DebuggerStackFrame> {
        // The GUI calls this from a worker thread. Release Python's GIL while
        // JDWP is waiting on the socket so the command loop stays responsive.
        let reply = py.allow_threads(|| self.jdwp_client.wait_for_package_blocking(&self.rt));
        let Some(reply) = reply else {
            return Err(PyRuntimeError::new_err("Nothing"));
        };
        let JdwpPacket::CommandPacket(cmd) = reply else {
            return Err(PyRuntimeError::new_err("Nothing"));
        };
        let Ok(composite) = Composite::try_from(cmd) else {
            return Err(PyRuntimeError::new_err("Not composite event"));
        };
        let (Event::Breakpoint(bp) | Event::SingleStep(bp)) = &composite.events[0];
        if let Event::SingleStep(_) = &composite.events[0] {
            if let Some(event_id) = self.last_step_id.take() {
                let _ = self.jdwp_client.clear_step(&self.rt, event_id);
            }
        }
        let thread = bp.get_thread();
        let Ok(stack_frame) = thread.get_top_frame(&mut self.jdwp_client, &self.rt) else {
            return Err(PyRuntimeError::new_err("Could not get Stackframe"));
        };

        Ok(DebuggerStackFrame { stack_frame })
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
