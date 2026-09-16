// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Exposes global getters for the `Files` model.
use rhai::{module_resolvers::StaticModuleResolver, plugin::*};

#[export_module]
pub mod global {
    use crate::models::Files;
    use rhai::{Array, Map};

    #[rhai_fn(get = "multi_dex")]
    pub fn get_multi_dex(files: &mut Files) -> Array {
        let mut array = vec![];
        for md in &files.multi_dex {
            array.push(Dynamic::from(md.clone()));
        }
        array
    }
    #[rhai_fn(get = "binaries")]
    pub fn get_binaries(files: &mut Files) -> Map {
        let mut map = Map::new();
        for md in &files.binaries {
            map.insert(md.0.into(), Dynamic::from(md.1.to_owned()));
        }
        map
    }
}

pub fn register_models_module(engine: &mut Engine, _resolver: &mut StaticModuleResolver) {
    let global_module = exported_module!(global);
    engine.register_global_module(global_module.into());
}
