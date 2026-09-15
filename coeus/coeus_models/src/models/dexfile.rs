// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use coeus_macros::iterator;
use std::path::Path;
use std::{collections::HashMap, sync::Arc};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

use super::{Class, DexHeader, Field, Method, MethodData, Proto, StringEntry};

#[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize)]
pub struct DexFile {
    #[serde(skip_serializing)]
    pub identifier: String,
    /// Original DEX bytes.  The parsed tables are an analysis view; keeping
    /// these bytes lets the encoder preserve sections it does not model yet.
    #[serde(skip_serializing, skip_deserializing)]
    pub raw_data: Vec<u8>,
    pub file_name: String,
    pub header: DexHeader,
    #[serde(skip_serializing)]
    pub strings: Vec<StringEntry>,
    #[serde(skip_serializing)]
    pub types: Vec<u32>,
    #[serde(skip_serializing)]
    pub methods: Vec<Arc<Method>>,
    #[serde(skip_serializing)]
    pub protos: Vec<Arc<Proto>>,
    #[serde(skip_serializing)]
    pub fields: Vec<Arc<Field>>,
    #[serde(skip_serializing)]
    pub classes: Vec<Arc<Class>>,
    pub interface_table: HashMap<String, Vec<Arc<Class>>>,
    pub superclass_table: HashMap<String, Vec<Arc<Class>>>,
}

impl PartialEq for DexFile {
    fn eq(&self, other: &Self) -> bool {
        self.identifier == other.identifier
    }
}

impl DexFile {
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    pub fn get_identifier(&self) -> &str {
        &self.identifier
    }

    pub fn get_implementations_for(&self, class: &Class) -> Vec<(Arc<DexFile>, Arc<Class>)> {
        let self_clone = Arc::new(self.clone());
        if let Some(impls) = self.interface_table.get(&class.class_name) {
            return impls
                .iter()
                .map(|c| (self_clone.clone(), c.clone()))
                .collect();
        }
        vec![]
    }
    pub fn get_subclasses_for(&self, class: &Class) -> Vec<(Arc<DexFile>, Arc<Class>)> {
        let self_clone = Arc::new(self.clone());
        if let Some(subclasses) = self.superclass_table.get(&class.class_name) {
            return subclasses
                .iter()
                .map(|c| (self_clone.clone(), c.clone()))
                .collect();
        }
        vec![]
    }
    pub fn get_string<T>(&self, string_idx: T) -> Option<&str>
    where
        T: Into<usize>,
    {
        self.strings
            .get(string_idx.into())
            .map(|se| se.to_str().ok())
            .flatten()
    }

    pub fn find_string_index(&self, value: &str) -> Option<u32> {
        self.strings
            .iter()
            .position(|entry| entry.to_str().ok() == Some(value))
            .map(|index| index as u32)
    }

    pub fn find_method_index(
        &self,
        class_name: &str,
        method_name: &str,
        proto_type: &str,
    ) -> Option<u32> {
        self.methods.iter().position(|method| {
            self.get_type_name(method.class_idx as usize) == Some(class_name)
                && method.method_name == method_name
                && self
                    .protos
                    .get(method.proto_idx as usize)
                    .map(|proto| proto.to_string(self) == proto_type)
                    .unwrap_or(false)
        }).map(|index| index as u32)
    }

    pub fn get_dex_name(&self) -> &str {
        Path::new(&self.file_name)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
    }

    pub fn get_type_name<T>(&self, type_idx: T) -> Option<&str>
    where
        T: Into<usize>,
    {
        match self.types.get(type_idx.into()) {
            Some(idx) => self.get_string(*idx as usize),
            None => None,
        }
    }

    pub fn get_class_name<T>(&self, class_idx: T) -> Option<&str>
    where
        T: Into<u32> + Copy,
    {
        self.classes
            .iter()
            .find(|c| c.class_idx == class_idx.into())
            .map(|c| c.class_name.as_str())
    }

    pub fn get_field_name<T>(&self, field_idx: T) -> Option<&str>
    where
        T: Into<u32> + Copy,
    {
        match self
            .fields
            .get(field_idx.into() as usize)
            .map(|f| f.name_idx)
        {
            Some(idx) => self.get_string(idx as usize),
            None => None,
        }
    }

    pub fn get_method_name<T>(&self, method_idx: T) -> Option<&str>
    where
        T: Into<u32> + Copy,
    {
        self.methods
            .get(method_idx.into() as usize)
            .map(|m| m.method_name.as_str())
    }

    pub fn get_proto_name<T>(&self, proto_idx: T) -> Option<&str>
    where
        T: Into<u32> + Copy,
    {
        match self
            .protos
            .get(proto_idx.into() as usize)
            .map(|p| p.shorty_idx)
        {
            Some(idx) => self.get_string(idx as usize),
            None => None,
        }
    }

    pub fn get_methods_for_type<T>(&self, type_idx: T) -> Vec<Arc<Method>>
    where
        T: Into<u32> + Copy + Sync,
    {
        iterator!(self.methods)
            .filter(|m| self.types[m.class_idx as usize] == type_idx.into())
            .map(|m| m.clone())
            .collect()
    }

    pub fn get_method_by_idx<T>(&self, method_idx: T) -> Option<Arc<MethodData>>
    where
        T: Into<u32> + Copy + Sync,
    {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(class) = self
            .classes
            .par_iter()
            .find_first(|c| c.codes.iter().any(|c| c.method_idx == method_idx.into()))
        {
            class
                .codes
                .par_iter()
                .find_first(|c| c.method_idx == method_idx.into())
                .cloned()
        } else {
            None
        }

        #[cfg(target_arch = "wasm32")]
        if let Some(class) = self.classes.iter().find(|c| {
            c.codes
                .iter()
                .find(|c| c.method_idx == method_idx.into())
                .is_some()
        }) {
            class
                .codes
                .iter()
                .find(|c| c.method_idx == method_idx.into())
        } else {
            None
        }
    }

    pub fn get_method_by_name_and_prototype(
        &self,
        class_name: &str,
        method_name: &str,
        proto_type: &str,
    ) -> Option<Arc<MethodData>> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(class) = self
            .classes
            .par_iter()
            .find_first(|c| c.class_name == class_name)
        {
            class
                .codes
                .par_iter()
                .find_first(|code| {
                    code.name == method_name
                        && code.code.is_some()
                        && proto_type == self.protos[code.method.proto_idx as usize].to_string(self)
                })
                .cloned()
        } else {
            None
        }

        #[cfg(target_arch = "wasm32")]
        if let Some(class) = self.classes.iter().find(|c| c.class_name == class_name) {
            class
                .codes
                .iter()
                .find(|code| code.name == method_name && code.code.is_some())
        } else {
            None
        }
    }

    pub fn get_class_by_type<T>(&self, type_idx: T) -> Option<Arc<Class>>
    where
        T: Into<u32> + Copy + Sync,
    {
        #[cfg(not(target_arch = "wasm32"))]
        return self
            .classes
            .par_iter()
            .find_first(|c| c.class_idx == type_idx.into())
            .cloned();
        #[cfg(target_arch = "wasm32")]
        return self
            .classes
            .iter()
            .find(|c| c.class_idx == type_idx.into())
            .cloned();
    }

    pub fn get_class_by_type_name_idx<T>(&self, type_name_idx: T) -> Option<Arc<Class>>
    where
        T: Into<u32> + Copy + Sync,
    {
        #[cfg(not(target_arch = "wasm32"))]
        return self
            .classes
            .par_iter()
            .find_first(|c| self.types[c.class_idx as usize] == type_name_idx.into())
            .cloned();
        #[cfg(target_arch = "wasm32")]
        return self
            .classes
            .iter()
            .find(|c| c.class_idx == type_name_idx.into())
            .cloned();
    }

    pub fn get_class_by_name(&self, class_name: &str) -> Option<Arc<Class>> {
        #[cfg(not(target_arch = "wasm32"))]
        return self
            .classes
            .par_iter()
            .find_first(|c| c.class_name == class_name)
            .cloned();
        #[cfg(target_arch = "wasm32")]
        return self
            .classes
            .iter()
            .find(|c| c.class_name == class_name)
            .cloned();
    }

    pub fn get_class_contains_name(&self, class_name: &str) -> Option<Arc<Class>> {
        #[cfg(not(target_arch = "wasm32"))]
        return self
            .classes
            .par_iter()
            .find_first(|c| c.class_name.contains(class_name))
            .cloned();
        #[cfg(target_arch = "wasm32")]
        return self
            .classes
            .iter()
            .find(|c| c.class_name.contains(class_name))
            .cloned();
    }

    pub fn get_classes_containing_name(&self, class_name: &str) -> Vec<Arc<Class>> {
        iterator!(self.classes)
            .filter(|c| c.class_name.contains(class_name))
            .cloned()
            .collect()
    }
}
