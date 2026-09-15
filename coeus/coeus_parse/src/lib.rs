// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
// 
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! This module provides functions to extract zips and parse dex files. Further it provides functions to obtain and work on graphs, especially the information-graph.
pub mod dex;
pub mod extraction;
pub mod apk;

#[cfg(feature = "rhai-script")]
pub mod scripting;

pub use coeus_emulation;
