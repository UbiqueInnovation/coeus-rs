// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use base64::{engine::general_purpose, Engine as _};
use std::sync::Arc;

use coeus_emulation::vm::{runtime::StringClass, Register, VMException, Value, VM};
use coeus_models::models::{DexFile, EncodedItem, Field, Method};

/// A type representing statically found data (by just inspecting the instructions)
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub struct StaticRegister {
    pub register: u8,
    pub out_arg_number: u8,
    pub argument_number: u8,
    pub is_argument: bool,
    pub is_array: bool,
    pub split_data: Vec<StaticRegisterData>,
    pub ty: Option<String>,
    pub data: Option<StaticRegisterData>,
    pub transformation: Option<FunctionTransformation>,
    pub inner_data: Vec<u8>,
    pub last_branch: Option<(bool, Option<FunctionTransformation>)>,
}

impl std::fmt::Display for StaticRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(transformation) = &self.transformation {
            write!(f, "{}", transformation)?;
        } else if let Some(data) = &self.data {
            write!(
                f,
                "{}{} [{}]",
                data,
                if self.is_argument {
                    format!("[arg{}]", self.argument_number)
                } else {
                    "".to_string()
                },
                if let Some((what, Some(trans))) = &self.last_branch {
                    format!("if {} is {}", trans, what)
                } else {
                    "".to_string()
                }
            )?;
        } else if self.is_array {
            write!(
                f,
                "base64decode({})",
                general_purpose::STANDARD.encode(&self.inner_data)
            )?;
        } else {
            write!(f, "[{:?}]", self.ty)?;
        }

        Ok(())
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub enum StaticRegisterData {
    Field {
        class_name: String,
        field: Arc<Field>,
        init_data: Option<EncodedItem>,
    },
    Array {
        base64: String,
    },
    String {
        content: String,
    },
    Literal(i64),
    Object,
}
impl std::fmt::Display for StaticRegisterData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StaticRegisterData::Array { base64 } => {
                write!(f, "base64decode({})", base64)?;
            }
            StaticRegisterData::Field {
                class_name,
                field,
                init_data,
            } => {
                write!(
                    f,
                    "{}->{}  (init_data: {:?})",
                    class_name.split("/").last().unwrap(),
                    field.name,
                    init_data
                )?;
            }
            StaticRegisterData::String { content } => {
                write!(f, "String: \"{}\"", content)?;
            }
            StaticRegisterData::Literal(lit) => {
                write!(f, "{}", lit)?;
            }
            StaticRegisterData::Object => {
                write!(f, "@object")?;
            }
        };
        Ok(())
    }
}

/// A representation of the usage and hence transformation of registers. Helps keeping track of the usage of anchors like const-string or arguments
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub struct FunctionTransformation {
    pub dex_file: Arc<DexFile>,
    pub class_name: String,
    pub method: Arc<Method>,
    pub input_register: Vec<StaticRegister>,
    pub return_type: String,
    pub depends_on_argument: bool,
}

impl std::fmt::Display for FunctionTransformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}->{}(", self.class_name, self.method.method_name)?;
        write!(
            f,
            "{}",
            self.input_register
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )?;
        write!(f, ")")?;
        Ok(())
    }
}

impl FunctionTransformation {
    /// Evaluate the transformation. For now only evaluate if all arguments have data and were not transformed (e.g. constants).
    pub fn run_transformation(&self, vm: &mut VM) -> Result<StaticRegisterData, VMException> {
        let (file, method_data) = vm.lookup_method(&self.class_name, &self.method)?;
        let method_data = method_data.clone();
        let code_item = method_data
            .code
            .as_ref()
            .ok_or(VMException::MethodNotFound(self.method.method_name.clone()))?;
        let mut arguments = vec![];
        for arg in &self.input_register {
            let register = if let Some(arg) = &arg.transformation {
                arg.run_transformation(vm)?
            } else if let Some(data) = &arg.data {
                data.to_owned()
            } else {
                return Err(VMException::InvalidRegisterType);
            };
            let vm_register = match register {
                StaticRegisterData::Array { base64 } => vm.new_instance(
                    "[B".to_string(),
                    Value::Array(
                        general_purpose::STANDARD
                            .decode(&base64)
                            .map_err(|_| VMException::InvalidRegisterType)?,
                    ),
                )?,
                StaticRegisterData::String { content } => vm.new_instance(
                    StringClass::class_name().to_string(),
                    Value::Object(StringClass::new(content)),
                )?,
                StaticRegisterData::Literal(l) => Register::Literal(l as i32),
                _ => return Err(VMException::InvalidRegisterType),
            };
            arguments.push(vm_register);
        }
        vm.clear_breakpoints();

        vm.start(
            self.method.method_idx.into(),
            file.get_identifier(),
            &code_item,
            arguments,
        )?;
        let result = vm
            .get_return_object()
            .ok_or(VMException::RegisterNotFound(0))?;
        Ok(match result {
            Value::Array(a) => StaticRegisterData::Array {
                base64: general_purpose::STANDARD.encode(&a),
            },
            Value::Object(s) => {
                if s.class.class_name == StringClass::class_name() {
                    StaticRegisterData::String {
                        content: format!("{}", s),
                    }
                } else {
                    StaticRegisterData::Object
                }
            }
            Value::Int(i) => StaticRegisterData::Literal(i as i64),
            Value::Short(s) => StaticRegisterData::Literal(s as i64),
            Value::Byte(b) => StaticRegisterData::Literal(b as i64),
        })
    }
}
