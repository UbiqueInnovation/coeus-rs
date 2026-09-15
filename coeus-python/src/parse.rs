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
use coeus::coeus_parse::dex::{
    encode::{inject_load_library, prepend_method_code, replace_method_instruction_units},
    parse_dex_buf,
    ArrayView,
};
use pyo3::exceptions::{PyIOError, PyIndexError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

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
    pub(crate) history: Vec<String>,
}

impl AnalyzeObject {
    fn record_action(&mut self, action: impl Into<String>) {
        self.history.push(action.into());
    }
}

impl SplitApkSet {
    fn from_paths_internal(
        py: Python<'_>,
        paths: Vec<PathBuf>,
        build_graph: bool,
        max_depth: i64,
    ) -> PyResult<Self> {
        if paths.is_empty() {
            return Err(PyRuntimeError::new_err("APK set must contain at least one APK"));
        }
        let mut members = Vec::with_capacity(paths.len());
        let mut names = Vec::with_capacity(paths.len());
        let mut seen = HashSet::new();
        for path in paths {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    PyRuntimeError::new_err(format!("invalid APK path: {}", path.display()))
                })?
                .to_string();
            if !seen.insert(name.clone()) {
                return Err(PyRuntimeError::new_err(format!(
                    "duplicate APK member name: {name}"
                )));
            }
            let path_string = path.to_string_lossy().into_owned();
            let object = AnalyzeObject::new(&path_string, build_graph, max_depth)?;
            members.push(Py::new(py, object)?);
            names.push(name);
        }
        Ok(Self {
            members,
            names,
            history: Vec::new(),
        })
    }

    fn output_paths(&self, output_dir: &Path) -> PyResult<Vec<PathBuf>> {
        fs::create_dir_all(output_dir).map_err(|error| {
            PyIOError::new_err(format!(
                "could not create APK output directory {}: {error}",
                output_dir.display()
            ))
        })?;
        Ok(self
            .names
            .iter()
            .map(|name| output_dir.join(name))
            .collect())
    }

    fn write_members(&self, py: Python<'_>, paths: &[PathBuf]) -> PyResult<()> {
        for (member, path) in self.members.iter().zip(paths) {
            let object = member.bind(py).borrow();
            coeus::coeus_parse::apk::repack(&object.files, path).map_err(|error| {
                PyIOError::new_err(format!("could not write {}: {error}", path.display()))
            })?;
        }
        Ok(())
    }

    fn collect_history(&self, py: Python<'_>) -> Vec<String> {
        let mut history = self.history.clone();
        for (name, member) in self.names.iter().zip(&self.members) {
            let object = member.bind(py).borrow();
            history.extend(
                object
                    .history
                    .iter()
                    .map(|action| format!("{name}: {action}")),
            );
        }
        history
    }
}

fn new_staging_directory(label: &str) -> PyResult<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "coeus-{label}-{}-{timestamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).map_err(|error| {
        PyIOError::new_err(format!("could not create temporary Coeus directory: {error}"))
    })?;
    Ok(path)
}

fn path_option(value: Option<&str>) -> Option<&Path> {
    value.map(Path::new)
}

/// A collection of APKs belonging to one split-install set.
///
/// Each member remains a normal `AnalyzeObject`; the container only provides
/// lifecycle operations which need to act on all members, such as pulling,
/// signing, saving, and installing the set.
#[pyclass]
pub struct SplitApkSet {
    members: Vec<Py<AnalyzeObject>>,
    names: Vec<String>,
    history: Vec<String>,
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

    fn replace_loaded_dex(&mut self, dex_name: &str, bytes: Vec<u8>) -> PyResult<()> {
        for multi_dex_index in 0..self.files.multi_dex.len() {
            let primary_matches = {
                let dex = &self.files.multi_dex[multi_dex_index].primary;
                dex.get_dex_name() == dex_name || dex.file_name == dex_name
            };
            if primary_matches {
                let file_name = self.files.multi_dex[multi_dex_index].primary.file_name.clone();
                let archive_name = self.files.multi_dex[multi_dex_index]
                    .primary
                    .get_dex_name()
                    .to_string();
                let parsed = parse_dex_buf(&file_name, &ArrayView::new(&bytes), false)
                    .ok_or_else(|| PyRuntimeError::new_err("could not reparse edited DEX"))?;
                self.files.multi_dex[multi_dex_index].primary = Arc::new(parsed);
                self.files
                    .set_file(archive_name, bytes)
                    .map_err(PyRuntimeError::new_err)?;
                self.supergraph = None;
                return Ok(());
            }
            if let Some(index) = self.files.multi_dex[multi_dex_index]
                .secondary
                .iter()
                .position(|dex| dex.get_dex_name() == dex_name || dex.file_name == dex_name)
            {
                let file_name = self.files.multi_dex[multi_dex_index].secondary[index]
                    .file_name
                    .clone();
                let archive_name = self.files.multi_dex[multi_dex_index].secondary[index]
                    .get_dex_name()
                    .to_string();
                let parsed = parse_dex_buf(&file_name, &ArrayView::new(&bytes), false)
                    .ok_or_else(|| PyRuntimeError::new_err("could not reparse edited DEX"))?;
                self.files.multi_dex[multi_dex_index].secondary[index] = Arc::new(parsed);
                self.files
                    .set_file(archive_name, bytes)
                    .map_err(PyRuntimeError::new_err)?;
                self.supergraph = None;
                return Ok(());
            }
        }
        Err(PyRuntimeError::new_err(format!(
            "DEX not found: {dex_name}"
        )))
    }

    fn loaded_dex_for_method(
        &self,
        method: &Method,
    ) -> PyResult<(String, u32, Arc<DexFile>)> {
        let method_idx = method.method.method_idx as u32;
        let dex = self
            .files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
            })
            .find(|dex| {
                dex.identifier == method.file.identifier
                    || dex.file_name == method.file.file_name
            })
            .cloned()
            .ok_or_else(|| {
                PyRuntimeError::new_err(format!("DEX not found for method {}", method.signature()))
            })?;
        Ok((dex.get_dex_name().to_string(), method_idx, dex))
    }

    fn instruction_index(
        dex: &DexFile,
        method_idx: u32,
        instruction: &crate::analysis::DexInstruction,
    ) -> PyResult<usize> {
        let code = dex
            .classes
            .iter()
            .flat_map(|class| class.codes.iter())
            .find(|method| method.method_idx == method_idx)
            .and_then(|method| method.code.as_ref())
            .ok_or_else(|| PyRuntimeError::new_err("method has no code"))?;
        code.insns
            .iter()
            .position(|(size, offset, _)| {
                offset.0 == instruction.offset && size.0 / 2 == instruction.size
            })
            .ok_or_else(|| {
                PyRuntimeError::new_err(format!(
                    "instruction at offset {} is not part of method {}",
                    instruction.offset, method_idx
                ))
            })
    }
}

#[pymethods]
impl SplitApkSet {
    #[new]
    #[pyo3(signature = (paths, build_graph=false, max_depth=-1))]
    pub fn new(
        py: Python<'_>,
        paths: Vec<String>,
        build_graph: bool,
        max_depth: i64,
    ) -> PyResult<Self> {
        Self::from_paths_internal(
            py,
            paths.into_iter().map(PathBuf::from).collect(),
            build_graph,
            max_depth,
        )
    }

    /// Pull the base APK and all split APKs reported by `pm path`.
    #[staticmethod]
    #[pyo3(signature = (package_name, serial=None, adb_path=None, build_graph=false, max_depth=-1))]
    pub fn from_adb(
        py: Python<'_>,
        package_name: &str,
        serial: Option<&str>,
        adb_path: Option<&str>,
        build_graph: bool,
        max_depth: i64,
    ) -> PyResult<Self> {
        let staging = new_staging_directory("adb")?;
        let result = (|| {
            let paths = coeus::coeus_parse::signing::pull_installed_apks(
                package_name,
                &staging,
                serial,
                path_option(adb_path),
            )
            .map_err(PyRuntimeError::new_err)?;
            let mut set = Self::from_paths_internal(py, paths, build_graph, max_depth)?;
            set.history
                .push(format!("pulled APK set for {package_name} from adb"));
            Ok(set)
        })();
        let _ = fs::remove_dir_all(&staging);
        result
    }

    /// List installed package names, optionally filtering with a regex.
    #[staticmethod]
    #[pyo3(signature = (package_regex=None, serial=None, adb_path=None))]
    pub fn list_packages(
        package_regex: Option<&str>,
        serial: Option<&str>,
        adb_path: Option<&str>,
    ) -> PyResult<Vec<String>> {
        coeus::coeus_parse::signing::list_installed_packages(
            package_regex,
            serial,
            path_option(adb_path),
        )
        .map_err(PyRuntimeError::new_err)
    }

    /// Reload a previously saved `.coeus` state archive.
    #[staticmethod]
    #[pyo3(signature = (path, build_graph=false, max_depth=-1))]
    pub fn load_state(
        py: Python<'_>,
        path: &str,
        build_graph: bool,
        max_depth: i64,
    ) -> PyResult<Self> {
        let file = File::open(path)
            .map_err(|error| PyIOError::new_err(format!("could not open state archive: {error}")))?;
        let mut archive = ZipArchive::new(file)
            .map_err(|error| PyRuntimeError::new_err(format!("invalid .coeus archive: {error}")))?;
        let mut metadata = None;
        let mut apk_bytes = HashMap::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|error| {
                PyRuntimeError::new_err(format!("could not read state archive entry: {error}"))
            })?;
            let entry_name = entry.name().to_string();
            if entry_name == "state.json" {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).map_err(|error| {
                    PyRuntimeError::new_err(format!("could not read state metadata: {error}"))
                })?;
                metadata = Some(bytes);
            } else if let Some(name) = entry_name.strip_prefix("apks/") {
                if entry.is_dir()
                    || name.is_empty()
                    || name.contains('/')
                    || name == "."
                    || name == ".."
                {
                    return Err(PyRuntimeError::new_err(format!(
                        "invalid APK member in state archive: {entry_name}"
                    )));
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).map_err(|error| {
                    PyRuntimeError::new_err(format!(
                        "could not read APK member {entry_name}: {error}"
                    ))
                })?;
                if apk_bytes.insert(name.to_string(), bytes).is_some() {
                    return Err(PyRuntimeError::new_err(format!(
                        "duplicate APK member in state archive: {name}"
                    )));
                }
            }
        }
        let metadata = metadata.ok_or_else(|| {
            PyRuntimeError::new_err(".coeus archive does not contain state.json")
        })?;
        let metadata: serde_json::Value = serde_json::from_slice(&metadata)
            .map_err(|error| PyRuntimeError::new_err(format!("invalid state metadata: {error}")))?;
        let members = metadata
            .get("members")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| PyRuntimeError::new_err("state metadata has no members list"))?;
        let mut member_names = Vec::with_capacity(members.len());
        for member in members {
            let name = member
                .as_str()
                .filter(|name| !name.is_empty() && !name.contains('/') && *name != "." && *name != "..")
                .ok_or_else(|| PyRuntimeError::new_err("state metadata contains an invalid member name"))?;
            if !apk_bytes.contains_key(name) {
                return Err(PyRuntimeError::new_err(format!(
                    "state archive is missing APK member {name}"
                )));
            }
            member_names.push(name.to_string());
        }

        let staging = new_staging_directory("state")?;
        let result = (|| {
            let mut paths = Vec::with_capacity(member_names.len());
            for name in &member_names {
                let member_path = staging.join(name);
                fs::write(&member_path, apk_bytes.get(name).expect("validated state member"))
                    .map_err(|error| {
                        PyIOError::new_err(format!(
                            "could not materialize state member {name}: {error}"
                        ))
                    })?;
                paths.push(member_path);
            }
            let mut set = Self::from_paths_internal(py, paths, build_graph, max_depth)?;
            set.history = metadata
                .get("history")
                .and_then(serde_json::Value::as_array)
                .map(|history| {
                    history
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            Ok(set)
        })();
        let _ = fs::remove_dir_all(&staging);
        result
    }

    pub fn __len__(&self) -> usize {
        self.members.len()
    }

    pub fn __getitem__(&self, py: Python<'_>, index: isize) -> PyResult<Py<AnalyzeObject>> {
        let index = if index < 0 {
            self.members.len() as isize + index
        } else {
            index
        };
        if index < 0 || index as usize >= self.members.len() {
            return Err(PyIndexError::new_err("APK member index out of range"));
        }
        Ok(self.members[index as usize].clone_ref(py))
    }

    pub fn get_apks(&self, py: Python<'_>) -> Vec<Py<AnalyzeObject>> {
        self.members
            .iter()
            .map(|member| member.clone_ref(py))
            .collect()
    }

    pub fn get_names(&self) -> Vec<String> {
        self.names.clone()
    }

    /// Return the base APK object. `pm path` normally reports it first, but
    /// selecting by name makes the helper safe if a caller supplied paths in
    /// another order.
    pub fn get_base_apk(&self, py: Python<'_>) -> PyResult<Py<AnalyzeObject>> {
        let index = self
            .names
            .iter()
            .position(|name| name == "base.apk" || name.starts_with("base-"))
            .unwrap_or(0);
        Ok(self.members[index].clone_ref(py))
    }

    pub fn get_history(&self, py: Python<'_>) -> Vec<String> {
        self.collect_history(py)
    }

    /// Write every current member to `output_dir` using its original split name.
    pub fn write_all(&mut self, py: Python<'_>, output_dir: &str) -> PyResult<Vec<String>> {
        let paths = self.output_paths(Path::new(output_dir))?;
        self.write_members(py, &paths)?;
        self.history.push(format!("write_all to {output_dir}"));
        Ok(paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect())
    }

    /// Repack and sign every member with the same keystore and alias.
    #[pyo3(signature = (output_dir, keystore, alias, store_password, key_password=None, apksigner=None))]
    pub fn sign_all(
        &mut self,
        py: Python<'_>,
        output_dir: &str,
        keystore: &str,
        alias: &str,
        store_password: &str,
        key_password: Option<&str>,
        apksigner: Option<&str>,
    ) -> PyResult<Vec<String>> {
        let paths = self.output_paths(Path::new(output_dir))?;
        self.write_members(py, &paths)?;
        for path in &paths {
            coeus::coeus_parse::signing::sign_apk(
                path,
                path_option(apksigner),
                Path::new(keystore),
                alias,
                store_password,
                key_password,
            )
            .map_err(PyRuntimeError::new_err)?;
        }
        self.history.push(format!("sign_all to {output_dir}"));
        Ok(paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect())
    }

    /// Verify every signed member in an output directory.
    #[pyo3(signature = (output_dir, apksigner=None))]
    pub fn verify_all(
        &self,
        output_dir: &str,
        apksigner: Option<&str>,
    ) -> PyResult<Vec<String>> {
        let paths = self.output_paths(Path::new(output_dir))?;
        let mut output = Vec::with_capacity(paths.len());
        for path in paths {
            output.push(
                coeus::coeus_parse::signing::verify_apk(path, path_option(apksigner))
                    .map_err(PyRuntimeError::new_err)?,
            );
        }
        Ok(output)
    }

    /// Install all members from an output directory using `adb install-multiple`.
    #[pyo3(signature = (output_dir, serial=None, adb_path=None, replace_existing=true, allow_downgrade=false))]
    pub fn install_all(
        &mut self,
        output_dir: &str,
        serial: Option<&str>,
        adb_path: Option<&str>,
        replace_existing: bool,
        allow_downgrade: bool,
    ) -> PyResult<String> {
        let paths = self.output_paths(Path::new(output_dir))?;
        let result = coeus::coeus_parse::signing::install_apks(
            &paths,
            serial,
            path_option(adb_path),
            replace_existing,
            allow_downgrade,
        )
        .map_err(PyRuntimeError::new_err)?;
        self.history.push(format!("install_all from {output_dir}"));
        Ok(result)
    }

    /// Launch an installed package through `adb shell monkey`.
    #[pyo3(signature = (package_name, serial=None, adb_path=None))]
    pub fn launch(
        &mut self,
        package_name: &str,
        serial: Option<&str>,
        adb_path: Option<&str>,
    ) -> PyResult<String> {
        let result = coeus::coeus_parse::signing::launch_package(
            package_name,
            serial,
            path_option(adb_path),
        )
        .map_err(PyRuntimeError::new_err)?;
        self.history.push(format!("launch {package_name}"));
        Ok(result)
    }

    /// Save current member APKs and the high-level edit history in a `.coeus` archive.
    pub fn save_state(&mut self, py: Python<'_>, path: &str) -> PyResult<()> {
        let mut history = self.collect_history(py);
        history.push("save_state".to_string());
        let metadata = serde_json::json!({
            "format_version": 1,
            "members": self.names.clone(),
            "history": history,
        });
        let file = File::create(path).map_err(|error| {
            PyIOError::new_err(format!("could not create state archive {path}: {error}"))
        })?;
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("state.json", options).map_err(|error| {
            PyIOError::new_err(format!("could not write state metadata: {error}"))
        })?;
        writer
            .write_all(metadata.to_string().as_bytes())
            .map_err(|error| PyIOError::new_err(format!("could not write state metadata: {error}")))?;

        for (name, member) in self.names.iter().zip(&self.members) {
            let data = {
                let object = member.bind(py).borrow();
                coeus::coeus_parse::apk::repack_to_bytes(&object.files).map_err(|error| {
                    PyIOError::new_err(format!("could not save APK member {name}: {error}"))
                })?
            };
            writer
                .start_file(format!("apks/{name}"), options)
                .map_err(|error| {
                    PyIOError::new_err(format!("could not write APK member {name}: {error}"))
                })?;
            writer.write_all(&data).map_err(|error| {
                PyIOError::new_err(format!("could not write APK member {name}: {error}"))
            })?;
        }
        writer
            .finish()
            .map_err(|error| PyIOError::new_err(format!("could not finish state archive: {error}")))?;
        self.history.push("save_state".to_string());
        Ok(())
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
                history: Vec::new(),
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

    /// Set an Android manifest attribute in the binary XML. `value` accepts
    /// `true`/`false`, an integer, or a string.
    pub fn set_manifest_attribute(
        &mut self,
        element: &str,
        attribute: &str,
        value: &str,
    ) -> PyResult<()> {
        coeus::coeus_parse::apk::set_manifest_attribute(&mut self.files, element, attribute, value)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action(format!(
            "set_manifest_attribute {element}.{attribute}={value}"
        ));
        Ok(())
    }

    pub fn set_debuggable(&mut self, enabled: bool) -> PyResult<()> {
        self.set_manifest_attribute(
            "application",
            "debuggable",
            if enabled { "true" } else { "false" },
        )
    }

    /// Change the package name used as the Android install identity.
    /// DEX descriptors and package-qualified component names are not renamed.
    pub fn set_package_name(&mut self, package_name: &str) -> PyResult<()> {
        coeus::coeus_parse::apk::set_package_name(&mut self.files, package_name)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action(format!("set_package_name {package_name}"));
        Ok(())
    }

    pub fn get_manifest_xml(&self) -> String {
        self.files.manifest_content.clone()
    }

    /// Replace AndroidManifest.xml from namespace-aware textual XML.
    pub fn set_manifest_xml(&mut self, xml: &str) -> PyResult<()> {
        coeus::coeus_parse::apk::set_manifest_xml(&mut self.files, xml)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action("set_manifest_xml".to_string());
        Ok(())
    }

    /// Replace an Android binary-XML resource from textual XML.
    pub fn set_xml_resource(&mut self, path: &str, xml: &str) -> PyResult<()> {
        coeus::coeus_parse::apk::set_xml_resource(&mut self.files, path, xml)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action(format!("set_xml_resource {path}"));
        Ok(())
    }

    /// Add a bundled XML resource and wire it into the manifest with a typed
    /// resource reference. It permits cleartext traffic and trusts user CAs.
    pub fn allow_plaintext_and_user_certificates(&mut self) -> PyResult<()> {
        coeus::coeus_parse::apk::allow_plaintext_and_user_certificates(&mut self.files)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action("allow_plaintext_and_user_certificates".to_string());
        Ok(())
    }

    /// Add or replace a raw APK entry, including shared objects and DEX files.
    pub fn set_file(&mut self, name: &str, data: Vec<u8>) -> PyResult<()> {
        self.files
            .set_file(name.to_string(), data)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action(format!("set_file {name}"));
        Ok(())
    }

    pub fn add_file(&mut self, name: &str, data: Vec<u8>) -> PyResult<()> {
        self.files
            .add_file(name.to_string(), data)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action(format!("add_file {name}"));
        Ok(())
    }

    pub fn remove_file(&mut self, name: &str) -> PyResult<()> {
        self.files
            .remove_file(name)
            .map_err(PyRuntimeError::new_err)?;
        self.record_action(format!("remove_file {name}"));
        Ok(())
    }

    pub fn write_apk(&self, output: &str) -> PyResult<()> {
        coeus::coeus_parse::apk::repack(&self.files, output)
            .map_err(|error| PyIOError::new_err(error.to_string()))
    }

    /// Repack and sign one APK with the Android SDK's `apksigner` tool.
    #[pyo3(signature = (output, keystore, alias, store_password, key_password=None, apksigner=None))]
    pub fn sign_apk(
        &mut self,
        output: &str,
        keystore: &str,
        alias: &str,
        store_password: &str,
        key_password: Option<&str>,
        apksigner: Option<&str>,
    ) -> PyResult<()> {
        self.write_apk(output)?;
        coeus::coeus_parse::signing::sign_apk(
            output,
            path_option(apksigner),
            Path::new(keystore),
            alias,
            store_password,
            key_password,
        )
        .map_err(PyRuntimeError::new_err)?;
        self.record_action(format!("sign_apk to {output}"));
        Ok(())
    }

    /// Verify an APK using the Android SDK's `apksigner` tool.
    #[pyo3(signature = (apk, apksigner=None))]
    pub fn verify_apk(&self, apk: &str, apksigner: Option<&str>) -> PyResult<String> {
        coeus::coeus_parse::signing::verify_apk(apk, path_option(apksigner))
            .map_err(PyRuntimeError::new_err)
    }

    /// Return high-level edits made through the Python API since loading.
    pub fn get_history(&self) -> Vec<String> {
        self.history.clone()
    }

    /// Replace an instruction selected from `method.get_instructions()` with
    /// another decoded instruction object. The replacement must have the same
    /// width as the selected instruction.
    pub fn replace_instruction(
        &mut self,
        method: &Method,
        instruction: &crate::analysis::DexInstruction,
        replacement: &crate::analysis::DexInstruction,
    ) -> PyResult<()> {
        let (dex_name, method_idx, dex) = self.loaded_dex_for_method(method)?;
        let instruction_index = Self::instruction_index(&dex, method_idx, instruction)?;
        let replacement_units = replacement
            .instruction
            .to_code_units()
            .map_err(PyRuntimeError::new_err)?;
        let bytes = replace_method_instruction_units(
            &dex,
            method_idx,
            instruction_index,
            &replacement_units,
        )
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.replace_loaded_dex(&dex_name, bytes)?;
        self.record_action(format!("replace_instruction {}", method.signature()));
        Ok(())
    }

    /// Explicitly named alias for callers that prefer the longer editing API
    /// name alongside the encoded low-level `replace_method_instruction`.
    pub fn replace_method_instruction_object(
        &mut self,
        method: &Method,
        instruction: &crate::analysis::DexInstruction,
        replacement: &crate::analysis::DexInstruction,
    ) -> PyResult<()> {
        self.replace_instruction(method, instruction, replacement)
    }

    /// Prepend decoded instruction objects to a method selected by its method
    /// object. This is the object-oriented counterpart to the code-unit API.
    pub fn prepend_instructions(
        &mut self,
        method: &Method,
        instructions: Vec<crate::analysis::DexInstruction>,
    ) -> PyResult<()> {
        let (dex_name, method_idx, dex) = self.loaded_dex_for_method(method)?;
        let mut prefix = Vec::new();
        for instruction in instructions {
            prefix.extend(
                instruction
                    .instruction
                    .to_code_units()
                    .map_err(PyRuntimeError::new_err)?,
            );
        }
        let bytes = prepend_method_code(&dex, method_idx, &prefix)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.replace_loaded_dex(&dex_name, bytes)?;
        self.record_action(format!("prepend_instructions {}", method.signature()));
        Ok(())
    }

    pub fn prepend_method_instructions(
        &mut self,
        method: &Method,
        instructions: Vec<crate::analysis::DexInstruction>,
    ) -> PyResult<()> {
        self.prepend_instructions(method, instructions)
    }

    /// Insert `System.loadLibrary(library_name)` into a method object selected
    /// during analysis. This also adds the required DEX string/type/proto and
    /// method references when the target DEX does not already contain them.
    pub fn inject_load_library_for_method(
        &mut self,
        method: &Method,
        library_name: &str,
        register: u8,
    ) -> PyResult<()> {
        let (dex_name, method_idx, dex) = self.loaded_dex_for_method(method)?;
        let bytes = inject_load_library(&dex, method_idx, library_name, register)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.replace_loaded_dex(&dex_name, bytes)?;
        self.record_action(format!(
            "inject_load_library {} ({library_name})",
            method.signature()
        ));
        Ok(())
    }

    /// Select a method from a class object and inject the loader into it. If
    /// several overloads exist, pass the full prototype, e.g.
    /// `(Ljava/lang/String;)V`.
    #[pyo3(signature = (class, method_name, library_name, register, proto_type=None))]
    pub fn inject_load_library_for_class(
        &mut self,
        class: &crate::analysis::Class,
        method_name: &str,
        library_name: &str,
        register: u8,
        proto_type: Option<&str>,
    ) -> PyResult<()> {
        let method = if let Some(proto_type) = proto_type {
            class.get_method_by_proto_type(method_name, proto_type)?
        } else {
            class.get_method(method_name)?
        };
        self.inject_load_library_for_method(&method, library_name, register)
    }

    /// Replace one decoded instruction with same-width code units and reparse
    /// the affected DEX. This keeps all unmodelled DEX sections intact.
    pub fn replace_method_instruction(
        &mut self,
        dex_name: &str,
        method_idx: u32,
        instruction_index: usize,
        code_units: Vec<u16>,
    ) -> PyResult<()> {
        let dex = self
            .files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
            })
            .find(|dex| dex.get_dex_name() == dex_name || dex.file_name == dex_name)
            .cloned()
            .ok_or_else(|| PyRuntimeError::new_err(format!("DEX not found: {dex_name}")))?;
        let bytes =
            replace_method_instruction_units(&dex, method_idx, instruction_index, &code_units)
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.replace_loaded_dex(dex_name, bytes)?;
        self.record_action(format!(
            "replace_method_instruction {dex_name}:{method_idx}:{instruction_index}"
        ));
        Ok(())
    }

    pub fn prepend_method_code(
        &mut self,
        dex_name: &str,
        method_idx: u32,
        prefix_code_units: Vec<u16>,
    ) -> PyResult<()> {
        let dex = self
            .files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
            })
            .find(|dex| dex.get_dex_name() == dex_name || dex.file_name == dex_name)
            .cloned()
            .ok_or_else(|| PyRuntimeError::new_err(format!("DEX not found: {dex_name}")))?;
        let bytes = prepend_method_code(&dex, method_idx, &prefix_code_units)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.replace_loaded_dex(dex_name, bytes)?;
        self.record_action(format!("prepend_method_code {dex_name}:{method_idx}"));
        Ok(())
    }

    /// Add the required DEX references if necessary, then insert
    /// const-string/invoke-static for System.loadLibrary at method entry.
    pub fn inject_load_library(
        &mut self,
        dex_name: &str,
        method_idx: u32,
        library_name: &str,
        register: u8,
    ) -> PyResult<()> {
        let dex = self
            .files
            .multi_dex
            .iter()
            .flat_map(|multi_dex| {
                std::iter::once(&multi_dex.primary).chain(multi_dex.secondary.iter())
            })
            .find(|dex| dex.get_dex_name() == dex_name || dex.file_name == dex_name)
            .cloned()
            .ok_or_else(|| PyRuntimeError::new_err(format!("DEX not found: {dex_name}")))?;
        let bytes = inject_load_library(&dex, method_idx, library_name, register)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.replace_loaded_dex(dex_name, bytes)?;
        self.record_action(format!(
            "inject_load_library {dex_name}:{method_idx} ({library_name})"
        ));
        Ok(())
    }

    pub fn get_resource_string(&mut self, id: u32) -> Option<(String, HashMap<String, String>)> {
        if self.files.arsc.is_none() {
            let _ = self.files.load_arsc();
        }
        self.files.get_string_from_resource(id)
    }

    pub fn get_resource_mipmap_file_name(
        &mut self,
        id: u32,
    ) -> Option<(String, HashMap<String, String>)> {
        if self.files.arsc.is_none() {
            let _ = self.files.load_arsc();
        }
        self.files.get_mipmap_file_name_from_resource(id)
    }

    pub fn get_file(&self, py: Python, name: &str) -> PyObject {
        let Some(raw) = self.files.raw_file(name) else {
            return PyBytes::new(py, &[]).into();
        };

        if name.ends_with(".xml") {
            let xml = match self.files.decode_resource(raw) {
                Some(xml) => xml,
                None => {
                    println!("Could not decode file {}", name);
                    String::from("")
                }
            };
            let result = xml.as_bytes();
            PyBytes::new(py, result).into()
        } else {
            PyBytes::new(py, raw).into()
        }
    }

    /// Get file contents but without decoding xml files like AndroidManifest.xml or ARSC files
    pub fn get_raw_file(&self, py: Python, name: &str) -> PyObject {
        let result = self.files.raw_file(name).unwrap_or(&[]);
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
        self.files.file_names()
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
    m.add_class::<SplitApkSet>()?;
    Ok(())
}
