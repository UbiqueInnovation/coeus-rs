// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use coeus::coeus_analysis::analysis::dex::get_native_methods;
use coeus::coeus_analysis::analysis::{
    find_any, find_classes, find_fields, find_methods, get_methods, ALL_TYPES,
};
use coeus::coeus_models::models::{AndroidManifest, DexFile, Files};
use coeus::coeus_parse::dex::graph::information_graph::build_information_graph;
use coeus::coeus_parse::dex::graph::Supergraph;
use pyo3::exceptions::{PyIOError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;

use crate::analysis::DexString;
use crate::analysis::Method;

#[pyclass]
#[derive(Clone)]
pub struct Runtime {
    pub runtime: Vec<Arc<DexFile>>,
}
#[pyclass]
#[derive(Clone)]
pub struct Manifest {
    _file: Arc<DexFile>,
    manifest_content: String,
    manifest: AndroidManifest,
}

#[pymethods]
impl Manifest {
    pub fn get_json(&self) -> String {
        serde_json::to_string(&self.manifest).unwrap()
    }
    pub fn get_xml(&self) -> String {
        self.manifest_content.clone()
    }
}

#[pyclass]
#[derive(Clone)]
pub struct Dex {
    _file: Arc<DexFile>,
    dex_name: String,
    identifier: String,
}

#[pymethods]
impl Dex {
    pub fn get_name(&self) -> String {
        self.dex_name.clone()
    }
    pub fn get_identifier(&self) -> String {
        self.identifier.clone()
    }
}

#[pyclass]
/// Abstract object holding all resources found. Use this as the root object for further analysis.
pub struct AnalyzeObject {
    pub(crate) files: Files,
    pub(crate) supergraph: Option<Arc<Supergraph>>,
}
const NON_INTERESTING_CLASSES: [&str; 16] = [
    "Lj$/time",
    "Lj$/util/",
    "Lkotlin/",
    "Lkotlinx/",
    "Landroidx/",
    "Lcom/sun",
    "Landroid/app",
    "Landroid/widget",
    "Landroid/content",
    "Landroid/graphics",
    "Lcom/google/protobuf",
    "Lcom/google/android",
    "Lokhttp3/internal",
    "okio",
    "moshi",
    "Lorg/bouncycastle/",
];
impl AnalyzeObject {
    pub fn build_main_supergraph(
        &mut self,
        excluded_classes: &[String],
    ) -> Result<Arc<Supergraph>, String> {
        self.build_supergraph_for_multi_dex(0, excluded_classes)
    }
    pub fn build_supergraph_for_multi_dex(
        &mut self,
        index: usize,
        excluded_classes: &[String],
    ) -> Result<Arc<Supergraph>, String> {
        let c = Arc::new(self.files.binaries.clone());
        if index >= self.files.multi_dex.len() {
            return Err("Index out of bounds".to_string());
        }
        let mut new = NON_INTERESTING_CLASSES.to_vec();
        new.extend(excluded_classes.iter().map(|s| s.as_str()));
        let Ok(supergraph) = build_information_graph(&self.files.multi_dex[0], c, &new, None, None)
        else {
            return Err("Failed to build the graph".to_string());
        };
        let supergraph = Arc::new(supergraph);
        self.supergraph = Some(supergraph.clone());
        Ok(supergraph)
    }

    pub fn get_file_field(&self) -> &Files {
        &self.files
    }
}

#[pymethods]
impl AnalyzeObject {
    #[new]
    pub fn new(archive: &str, build_graph: bool, max_depth: i64) -> PyResult<Self> {
        match coeus::coeus_parse::extraction::load_file(archive, build_graph, max_depth) {
            Ok(files) => Ok(AnalyzeObject {
                files,
                supergraph: None,
            }),
            Err(e) => Err(PyIOError::new_err(format!("{e:?}"))),
        }
    }
    pub fn build_supergraph(&mut self, ignore_classes: Vec<String>) -> PyResult<()> {
        self.build_main_supergraph(&ignore_classes)
            .map_err(PyRuntimeError::new_err)?;
        Ok(())
    }

    pub fn get_runtime(&self, file: &Method) -> PyResult<Runtime> {
        let file_identifier = &file.file.identifier;
        if let Some(runtime_files) = self.files.multi_dex.iter().find(|a| {
            &a.primary.identifier == file_identifier
                || a.secondary
                    .iter()
                    .any(|sec| &sec.identifier == file_identifier)
        }) {
            Ok(Runtime {
                runtime: runtime_files.secondary.to_vec(),
            })
        } else {
            Err(PyRuntimeError::new_err("runtime not found"))
        }
    }

    pub fn get_manifests(&self) -> Vec<Manifest> {
        self.files
            .multi_dex
            .iter()
            .map(|a| Manifest {
                _file: a.primary.clone(),
                manifest_content: a.manifest_content.clone(),
                manifest: a.android_manifest.clone(),
            })
            .collect()
    }

    pub fn get_resource_string(&mut self, id: u32) -> Option<(String, HashMap<String, String>)> {
        if self.files.arsc.is_none() {
            let _ = self.files.load_arsc();
        }
        self.files.get_string_from_resource(id)
    }

    pub fn get_resource_mipmap_file_name(&mut self, id: u32) -> Option<(String, HashMap<String,String>)> {
        if self.files.arsc.is_none() {
            let _ = self.files.load_arsc();
        }
        self.files.get_mipmap_file_name_from_resource(id)       
    }

    pub fn get_file(&self, py: Python, name: &str) -> PyObject {
        let mut _file_content: String;
        let bin_object = self.files.binaries.get(name).unwrap();

        if name.ends_with(".xml") {
            let xml = match self.files.decode_resource(bin_object.data()) {
                Some(xml) => xml,
                None => {
                    println!("Could not decode file {}", name);
                    String::from("")
                }
            };
            let result = xml.as_bytes();
            PyBytes::new(py, result).into()
        } else {
            let result = bin_object.data();
            PyBytes::new(py, result).into()
        }
    }

    /// Get file contents but without decoding xml files like AndroidManifest.xml or ARSC files
    pub fn get_raw_file(&self, py: Python, name: &str) -> PyObject {
        let mut _file_content: String;
        let bin_object = self.files.binaries.get(name).unwrap();
        let result = bin_object.data();
        PyBytes::new(py, result).into()
    }

    /// Find all dynamically registered native functions
    pub fn find_dynamically_registered_functions(
        &self,
        regex: &str,
        lib_name: &str,
    ) -> Vec<crate::analysis::Evidence> {
        let reg = if let Ok(reg) = Regex::new(regex) {
            reg
        } else {
            return vec![];
        };
        let bin_object = if let Some(lib) = self.files.binaries.get(lib_name) {
            lib
        } else {
            return vec![];
        };
        coeus::coeus_analysis::analysis::native::find_dynamically_registered_function(
            &reg,
            bin_object.clone(),
        )
        .into_iter()
        .map(|evidence| crate::analysis::Evidence { evidence })
        .collect()
    }

    pub fn get_file_names(&self) -> Vec<String> {
        let mut results = vec![];
        for key in self.files.binaries.keys() {
            results.push(key.clone());
        }
        results
    }

    pub fn get_dex_names(&self) -> Vec<&String> {
        let mut results = vec![];

        for md in &self.files.multi_dex {
            results.push(&md.primary.file_name);
            let res: Vec<&String> = md.secondary.iter().map(|sec| &sec.file_name).collect();
            results.extend(res);
        }
        results
    }

    pub fn get_primary_dex(&self) -> Vec<Dex> {
        self.files
            .multi_dex
            .iter()
            .map(|a| Dex {
                _file: a.primary.clone(),
                dex_name: a.primary.get_dex_name().to_string(),
                identifier: a.primary.identifier.clone(),
            })
            .collect()
    }

    /// Find all functions in the dex file having the modifier `native`
    pub fn get_native_methods(&self) -> Vec<Method> {
        let mut methods = vec![];
        for md in &self.files.multi_dex {
            let ms = get_native_methods(md, &self.files);

            for (file, method) in ms {
                let class = if let Some(class) = file.get_class_by_type(method.class_idx) {
                    class
                } else {
                    println!("{} has no class def somethings off", method.class_idx);
                    continue;
                };
                let method_data = class
                    .codes
                    .iter()
                    .find(|a| a.method_idx == method.method_idx as u32)
                    .cloned();
                methods.push(Method {
                    method,
                    method_data,
                    file,
                    class,
                });
            }
        }
        methods
    }

    pub fn __getitem__(&self, name: &str) -> Vec<(String, Vec<u8>)> {
        let mut results = vec![];
        for key in self.files.binaries.keys() {
            if key.contains(name) {
                if key.ends_with(".xml") {
                    if let Some(xml) = self.files.decode_resource(self.files.binaries[key].data()) {
                        results.push((key.clone(), xml.as_bytes().to_vec()));
                        continue;
                    }
                }
                results.push((key.clone(), self.files.binaries[key].data().to_vec()));
            }
        }
        results
    }

    pub fn find_native_imports(
        &self,
        library: &str,
        pattern: &str,
    ) -> Vec<crate::analysis::Evidence> {
        let pattern = if let Ok(reg) = Regex::new(pattern) {
            reg
        } else {
            return vec![];
        };
        let obj = if let Some(obj) = self.files.binaries.get(library) {
            obj
        } else {
            return vec![];
        };
        let imports =
            coeus::coeus_analysis::analysis::native::find_imported_functions(&pattern, obj.clone());
        imports
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect()
    }
    pub fn find_native_exports(
        &self,
        library: &str,
        pattern: &str,
    ) -> Vec<crate::analysis::Evidence> {
        let pattern = if let Ok(reg) = Regex::new(pattern) {
            reg
        } else {
            return vec![];
        };
        let obj = if let Some(obj) = self.files.binaries.get(library) {
            obj
        } else {
            return vec![];
        };
        let exports =
            coeus::coeus_analysis::analysis::native::find_exported_functions(&pattern, obj.clone());
        exports
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect()
    }
    pub fn find_native_strings(
        &self,
        library: &str,
        pattern: &str,
    ) -> Vec<crate::analysis::Evidence> {
        let pattern = if let Ok(reg) = Regex::new(pattern) {
            reg
        } else {
            return vec![];
        };
        let obj = if let Some(obj) = self.files.binaries.get(library) {
            obj
        } else {
            return vec![];
        };
        let strings = coeus::coeus_analysis::analysis::native::find_strings(&pattern, obj.clone());
        strings
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect()
    }

    /// Find methods in the analyzed object by utilising a regular expression
    #[pyo3(text_signature = "($self, name,/)")]
    pub fn find_methods(&self, name: &str) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new(name).map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = find_methods(&regex, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }

    /// Find fields in the analyzed object by utilising a regular expression
    #[pyo3(text_signature = "($self, name,/)")]
    pub fn find_fields(&self, name: &str) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new(name).map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = find_fields(&regex, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    /// Find strings in the analyzed object by utilising a regular expression
    #[pyo3(text_signature = "($self, name,/)")]
    pub fn find_strings(&self, name: &str) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new(name).map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = coeus::coeus_analysis::analysis::find_strings(&regex, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    #[pyo3(text_signature = "($self, regex, only_symbols, /)")]
    pub fn find_strings_native(
        &self,
        regex: &str,
        only_symbols: bool,
    ) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new(regex).map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files =
            coeus::coeus_analysis::analysis::find_strings_native(&regex, &self.files, only_symbols);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    /// Find methods in the analyzed object by utilising a regular expression
    #[pyo3(text_signature = "($self, name,/)")]
    pub fn find_classes(&self, name: &str) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new(name).map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = find_classes(&regex, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    /// Get all classes
    #[pyo3(text_signature = "($self)")]
    pub fn get_classes(&self) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new("").map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = find_classes(&regex, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    /// Get all classes as a vector of coeus-python::analysis::Class
    #[pyo3(text_signature = "($self)")]
    pub fn get_classes_as_class(&self) -> PyResult<Vec<crate::analysis::Class>> {
        let regex = Regex::new("").map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = find_classes(&regex, &self.files);
        let classes: Vec<crate::analysis::Class> = files
            .into_iter()
            .map(|evidence| {
                let evi = crate::analysis::Evidence { evidence };
                evi.as_class().unwrap()
            })
            .collect();
        Ok(classes)
    }
    /// Get all methods
    #[pyo3(text_signature = "($self,/)")]
    pub fn get_methods(&self) -> PyResult<Vec<crate::analysis::Evidence>> {
        let files = get_methods(&self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    /// Get all methods as a vector of coeus-python::analysis::Method
    #[pyo3(text_signature = "($self,/)")]
    pub fn get_methods_as_method(&self) -> PyResult<Vec<crate::analysis::Method>> {
        let mthds = get_methods(&self.files);
        let methods: Vec<Method> = mthds
            .into_iter()
            .map(|evidence| {
                let evi = crate::analysis::Evidence { evidence };
                evi.as_method().unwrap()
            })
            .collect();
        Ok(methods)
    }
    /// Get all strings
    #[pyo3(text_signature = "($self,/)")]
    pub fn get_strings(&self) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new("").map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = coeus::coeus_analysis::analysis::find_strings(&regex, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    /// Get all strings as a vector of DexString
    #[pyo3(text_signature = "($self,/)")]
    pub fn get_strings_as_string(&self) -> PyResult<Vec<crate::analysis::DexString>> {
        let regex = Regex::new("").map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let strings = coeus::coeus_analysis::analysis::find_strings(&regex, &self.files);
        let strings: Vec<DexString> = strings
            .into_iter()
            .map(|evidence| {
                let evi = crate::analysis::Evidence { evidence };
                evi.as_string().unwrap()
            })
            .collect();
        Ok(strings)
    }
    /// Get all fields
    #[pyo3(text_signature = "($self,/)")]
    pub fn get_fields(&self) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new("").map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = find_fields(&regex, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
    /// Get all fields as a vector of DexField
    #[pyo3(text_signature = "($self,/)")]
    pub fn get_fields_as_field(&self) -> PyResult<Vec<crate::analysis::DexField>> {
        let regex = Regex::new("").map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let fields = find_fields(&regex, &self.files);
        let fields: Vec<crate::analysis::DexField> = fields
            .into_iter()
            .map(|evidence| {
                let evi = crate::analysis::Evidence { evidence };
                evi.as_field().unwrap()
            })
            .collect();
        Ok(fields)
    }
    #[pyo3(text_signature = "($self, name,/)")]
    pub fn find(&self, name: &str) -> PyResult<Vec<crate::analysis::Evidence>> {
        let regex = Regex::new(name).map_err(|e| PyRuntimeError::new_err(format!("{:?}", e)))?;
        let files = find_any(&regex, &ALL_TYPES, &self.files);
        Ok(files
            .into_iter()
            .map(|evidence| crate::analysis::Evidence { evidence })
            .collect())
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<AnalyzeObject>()?;
    m.add_class::<Manifest>()?;
    Ok(())
}
