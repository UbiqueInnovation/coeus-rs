// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::borrow::Cow;

use goblin::Object;
use regex::Regex;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryObject {
    #[serde(skip_serializing_if = "BinaryObject::vec_too_large")]
    data: Vec<u8>,
    //object_cache: Option<Object<'a>>,
}

impl BinaryObject {
    pub fn vec_too_large(arr: &[u8]) -> bool {
        arr.len() > 10_000
    }
}

impl std::fmt::Debug for BinaryObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = &mut f.debug_struct("BinaryObject");
        f = f.field("data_length", &self.data.len());
        match self.object_no_cache() {
            Some(Object::Elf(_)) => {
                f = f.field("type", &"ELF");
            }
            Some(Object::Archive(_)) => {
                f = f.field("type", &"ARCHIVE");
            }
            Some(Object::PE(_)) => {
                f = f.field("type", &"PE");
            }
            Some(Object::Mach(_)) => {
                f = f.field("type", &"MACH");
            }
            Some(Object::Unknown(magic)) => {
                let bytes = magic.to_ne_bytes();
                let magic_string = String::from_utf8_lossy(&bytes);
                f = f.field("type", &magic_string);
            }
            _ => f = f.field("type", &"unknown"),
        }
        f.finish()
    }
}

impl<'a> BinaryObject {
    pub fn new(data: Vec<u8>) -> Self {
        BinaryObject { data }
    }

    pub fn is_match(&self, reg: &Regex) -> bool {
        let lossy_utf = String::from_utf8_lossy(&self.data);
        reg.is_match(&lossy_utf)
    }
    pub fn get_utf8_lossy(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.data)
    }

    pub fn object(&'a mut self) -> Option<Object> {
        Object::parse(self.data.as_ref()).ok()
    }
    pub fn object_no_cache(&'a self) -> Option<Object> {
        Object::parse(self.data.as_ref()).ok()
    }
    pub fn data(&'a self) -> &[u8] {
        &self.data
    }
}
