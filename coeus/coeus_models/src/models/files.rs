// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::{AndroidManifest, BinaryObject, DexFile, MultiDexFile};
use abxml::visitor::{Executor, ModelVisitor, XmlVisitor};
use coeus_macros::iterator;
use rayon::prelude::*;
use std::{collections::HashMap, io::Cursor, sync::Arc};

/// One entry in the source APK.  Keeping this separate from `binaries` is
/// intentional: `binaries` is the analysis index, while `archive` is the
/// ordered, editable representation used when an APK is written again.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub data: Vec<u8>,
    /// ZIP compression method (0 = stored, 8 = deflated).
    pub compression_method: u16,
    pub is_directory: bool,
}

impl ArchiveEntry {
    pub fn new(
        name: impl Into<String>,
        data: Vec<u8>,
        compression_method: u16,
        is_directory: bool,
    ) -> Self {
        Self {
            name: name.into(),
            data,
            compression_method,
            is_directory,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Files {
    pub multi_dex: Vec<MultiDexFile>,
    pub binaries: HashMap<String, Arc<BinaryObject>>,
    pub binary_resource_file: Vec<u8>,
    /// All top-level APK entries in their original order.
    pub archive: Vec<ArchiveEntry>,
    /// Best-effort decoded manifest, available even when an APK has no DEX.
    pub manifest_content: String,
    pub android_manifest: AndroidManifest,
    #[serde(skip_deserializing, skip_serializing)]
    pub arsc: Option<arsc::Arsc>,
}

impl Clone for Files {
    fn clone(&self) -> Self {
        Self {
            multi_dex: self.multi_dex.clone(),
            binaries: self.binaries.clone(),
            binary_resource_file: self.binary_resource_file.clone(),
            archive: self.archive.clone(),
            manifest_content: self.manifest_content.clone(),
            android_manifest: self.android_manifest.clone(),
            arsc: None,
        }
    }
}

impl Files {
    pub fn new(multi_dex: Vec<MultiDexFile>, binaries: HashMap<String, Arc<BinaryObject>>) -> Self {
        Self {
            multi_dex,
            binaries,
            binary_resource_file: vec![],
            archive: vec![],
            manifest_content: String::new(),
            android_manifest: AndroidManifest::default(),
            arsc: None,
        }
    }

    /// Return raw bytes for an archive entry.
    pub fn raw_file(&self, name: &str) -> Option<&[u8]> {
        self.binaries
            .get(name)
            .map(|object| object.data())
            .or_else(|| {
                self.archive
                    .iter()
                    .find(|entry| entry.name == name)
                    .map(|entry| entry.data.as_slice())
            })
    }

    /// Add or replace an APK entry and keep the analysis index in sync.
    pub fn set_file(&mut self, name: impl Into<String>, data: Vec<u8>) -> Result<(), String> {
        let name = name.into();
        if name.is_empty() || name.starts_with('/') || name.contains("../") {
            return Err("invalid APK entry name".to_string());
        }

        if name == "resources.arsc" {
            self.binary_resource_file = data.clone();
            self.arsc = None;
        }
        self.binaries
            .insert(name.clone(), Arc::new(BinaryObject::new(data.clone())));

        if let Some(entry) = self.archive.iter_mut().find(|entry| entry.name == name) {
            entry.data = data;
        } else {
            self.archive.push(ArchiveEntry::new(name, data, 8, false));
        }
        Ok(())
    }

    /// Add an APK entry. Existing files are rejected to avoid accidental edits.
    pub fn add_file(&mut self, name: impl Into<String>, data: Vec<u8>) -> Result<(), String> {
        let name = name.into();
        if self.raw_file(&name).is_some() {
            return Err(format!("APK entry already exists: {name}"));
        }
        self.set_file(name, data)
    }

    /// Remove a non-DEX APK entry. Parsed DEX files are kept in the model, so
    /// removing one through this API would otherwise leave a stale analysis.
    pub fn remove_file(&mut self, name: &str) -> Result<(), String> {
        if name.ends_with(".dex") {
            return Err(
                "removing parsed DEX files is not supported; edit or rebuild the DEX instead"
                    .to_string(),
            );
        }
        self.binaries.remove(name);
        self.archive.retain(|entry| entry.name != name);
        if name == "resources.arsc" {
            self.binary_resource_file.clear();
            self.arsc = None;
        }
        Ok(())
    }

    pub fn file_names(&self) -> Vec<String> {
        let mut names = self
            .archive
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        let mut additional = self
            .binaries
            .keys()
            .filter(|name| !names.iter().any(|current| current == *name))
            .cloned()
            .collect::<Vec<_>>();
        additional.sort();
        names.extend(additional);
        names
    }

    pub fn dex_file_from_identifier(&self, identifier: &str) -> Option<Arc<DexFile>> {
        iterator!(self.multi_dex)
            .filter_map(|md| md.dex_file_from_identifier(identifier))
            .collect::<Vec<_>>()
            .first()
            .cloned()
    }

    pub fn get_multi_dex_from_dex_identifier(
        &self,
        identifier: &str,
    ) -> Option<(&MultiDexFile, Arc<DexFile>)> {
        iterator!(self.multi_dex)
            .filter_map(|md| {
                if let Some(df) = md.dex_file_from_identifier(identifier) {
                    Some((md, df))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .first()
            .cloned()
    }
    pub fn decode_resource(&self, binary_xml: &[u8]) -> Option<String> {
        let android_resources_content = abxml::STR_ARSC.to_owned();

        let mut visitor = ModelVisitor::default();
        Executor::arsc(&self.binary_resource_file, &mut visitor).ok()?;
        Executor::arsc(&android_resources_content, &mut visitor).ok()?;
        let mut visitor = XmlVisitor::new(visitor.get_resources());
        let _ = Executor::xml(Cursor::new(&binary_xml), &mut visitor);
        visitor.into_string().ok()
    }
    pub fn load_arsc(&mut self) -> Result<(), String> {
        let Ok(arsc) = arsc::parse_from(Cursor::new(&self.binary_resource_file)) else {
            return Err("Could not load arsc".to_string());
        };
        self.arsc = Some(arsc);
        Ok(())
    }
    pub fn get_string_from_resource(&self, id: u32) -> Option<(String, HashMap<String, String>)> {
        let Some(arsc) = self.arsc.as_ref() else {
            return None;
        };
        let Some(pkg) = arsc
            .packages
            .iter()
            .find(|p| p.id == ((id & 0xff_00_00_00) >> 24))
        else {
            return None;
        };
        let Some(ty) = pkg
            .types
            .iter()
            .find(|ty| ty.id == ((id & 0x00_ff_00_00) >> 16) as usize)
        else {
            return None;
        };
        if pkg.type_names.strings[ty.id - 1] != "string" {
            return None;
        }
        let mut localized_strings = HashMap::new();
        let mut entry_name = String::default();

        for resource in &ty.configs {
            if let Some(entry) = resource
                .resources
                .resources
                .iter()
                .find(|r| r.spec_id == (id as usize) & 0xff_ff)
            {
                let locale = if &resource.id[8..10] == [0, 0] {
                    "default".to_string()
                } else if let Ok(locale) = std::str::from_utf8(&resource.id[8..10]) {
                    locale.to_string()
                } else {
                    continue;
                };
                if let Some(name) = pkg.key_names.strings.get(entry.name_index) {
                    entry_name = name.to_string();
                }

                match &entry.value {
                    arsc::ResourceValue::Plain(a) => {
                        if a.is_string() {
                            if let Some(val) = arsc.global_string_pool.strings.get(a.data_index) {
                                localized_strings.insert(locale.to_string(), val.to_string());
                            }
                        }
                    }
                    _ => continue,
                }
            }
        }
        Some((entry_name, localized_strings))
    }

    pub fn get_mipmap_file_name_from_resource(
        &self,
        id: u32,
    ) -> Option<(String, HashMap<String, String>)> {
        let Some(arsc) = self.arsc.as_ref() else {
            return None;
        };
        let Some(pkg) = arsc
            .packages
            .iter()
            .find(|p| p.id == ((id & 0xff_00_00_00) >> 24))
        else {
            return None;
        };

        let Some(ty) = pkg
            .types
            .iter()
            .find(|ty| ty.id == ((id & 0x00_ff_00_00) >> 16) as usize)
        else {
            return None;
        };

        let mut resource_map: HashMap<String, String> = HashMap::new();
        let mut entry_name = String::default();

        for resource in &ty.configs {
            if let Some(entry) = resource
                .resources
                .resources
                .iter()
                .find(|r| r.spec_id == (id as usize) & 0xff_ff)
            {
                let den: u16 = ((resource.id[15] as u16) << 8) + resource.id[14] as u16;

                let density = match den {
                    160 => "MDPI".to_string(),
                    240 => "HDPI".to_string(),
                    320 => "XHDPI".to_string(),
                    480 => "XXHDPI".to_string(),
                    640 => "XXXHDPI".to_string(),
                    65534 => {
                        let version = resource.id[24].to_string();
                        let mut any = "ANYDPI-v".to_string();
                        any.push_str(&version);
                        any
                    }
                    _ => den.to_string(),
                };

                if let Some(name) = pkg.key_names.strings.get(entry.name_index) {
                    entry_name = name.to_string();
                }

                match &entry.value {
                    arsc::ResourceValue::Plain(a) => {
                        if a.is_string() {
                            if let Some(val) = arsc.global_string_pool.strings.get(a.data_index) {
                                resource_map.insert(density.to_string(), val.to_string());
                            }
                        }
                    }
                    _ => continue,
                }
            }
        }

        Some((entry_name, resource_map))
    }
}
