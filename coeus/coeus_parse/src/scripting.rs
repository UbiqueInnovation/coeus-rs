// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! This module exposes functions to rhai, such as loadind and parsing a zip/dex file. It also provides a loading function for the wasm target, where the file can be provided as a base64 encoded string.
use rhai::{module_resolvers::StaticModuleResolver, plugin::*};

// #[cfg(feature = "graphviz")]
// macro_rules! to_c_string {
//     ($str:expr) => {
//         std::ffi::CString::new($str).unwrap().as_ptr()
//     };
// }

#[export_module]
pub mod global {

    use crate::dex::graph::{callgraph::callgraph_for_method, Subgraph, Supergraph};

    use petgraph::{dot::Dot, graph::NodeIndex};
    use rhai::{Array, ImmutableString};

    #[rhai_fn(name = "reg_from_file")]
    pub fn load_regex_from_file(path: &str) -> Array {
        let mut array = vec![];
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                array.push(line.into());
            }
        }
        array
    }

    #[rhai_fn(name = "write_to_file", return_raw)]
    pub fn write_to_file(file_name: &str, content: &str) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Ok(_) = std::fs::write(file_name, content) {
            Ok(().into())
        } else {
            Err("Could not save file".into())
        }
    }

    #[rhai_fn(name = "call_graph", return_raw)]
    pub fn call_graph_from_string(
        supergraph: &mut Supergraph,
        function_name: ImmutableString,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Some(method_key) = supergraph
            .class_node_mapping
            .keys()
            .find(|k| k.contains(function_name.as_str()))
        {
            let node_index = supergraph.class_node_mapping[method_key];
            Ok(Dynamic::from(callgraph_for_method(
                &supergraph.super_graph,
                node_index,
            )))
        } else {
            Err("No node found matching function_name".into())
        }
    }

    #[rhai_fn(name = "get_dynamic_strings", return_raw)]
    pub fn get_dynamic_strings(
        supergraph: &mut Supergraph,
        function_name: ImmutableString,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Ok(strs) = crate::dex::graph::analysis::dynamic::get_dynamic_strings(
            &supergraph.super_graph,
            function_name.as_str(),
        ) {
            Ok(Dynamic::from(strs))
        } else {
            Err("Something went wrong with finding dynamic strings".into())
        }
    }

    #[rhai_fn(name = "contains_node", name = "contains")]
    pub fn contains_node(subgraph: &mut Subgraph, class: NodeIndex) -> bool {
        subgraph.super_sub_mapping.contains_key(&class)
    }
    pub fn contains(supergraph: &mut Supergraph, key: ImmutableString) -> bool {
        supergraph
            .class_node_mapping
            .keys()
            .any(|k| k.contains(key.as_str()))
    }
    #[rhai_fn(name = "print", name = "to_string", name = "to_debug", name = "debug")]
    pub fn to_string_subgraph(subgraph: &mut Subgraph) -> String {
        format!("{:?}", Dot::new(&subgraph.sub_graph))
    }
    #[rhai_fn(name = "print", name = "to_string", name = "to_debug", name = "debug")]
    pub fn to_string_supergraph(supergraph: &mut Supergraph) -> String {
        format!("{:?}", Dot::new(&supergraph.super_graph))
    }
    // #[cfg(all(not(target_arch = "wasm32"), feature = "graphviz"))]
    // use graphviz_sys::{
    //     agclose, agmemread, gvContext, gvFreeContext, gvFreeLayout, gvLayout, gvRenderFilename,
    // };

    // pub fn build_svg(_file_name: &str, _svg: &str) {
    //     if cfg!(all(not(target_arch = "wasm32"), feature = "graphviz"))
    //     {
    //         unsafe {
    //             let gvc = gvContext();
    //             if gvc.is_null() {
    //                 log::error!("fatal no gv context");
    //                 return;
    //             }
    //             let svg = _svg.replace("graph {", "graph {\noverlap=false;\n");
    //             let g = agmemread(to_c_string!(svg));

    //             if g.is_null() {
    //                 log::error!("no graph");
    //                 gvFreeContext(gvc);
    //                 return;
    //             }
    //             gvLayout(gvc, g, to_c_string!("neato"));
    //             gvRenderFilename(gvc, g, to_c_string!("svg"), to_c_string!(_file_name));

    //             if !gvc.is_null() && !g.is_null() {
    //                 gvFreeLayout(gvc, g);

    //                 agclose(g);

    //                 gvFreeContext(gvc);
    //             }
    //         }
    //     } else {
    //         panic!("Coeus was built without graphivz support");
    //     }
    // }
}

#[export_module]
#[cfg(target_arch = "wasm32")]
pub mod wasm_module {
    use crate::{
        dex::{parse_dex, parse_dex_buf, ArrayView},
        extraction::{check_for_dex_signature, check_for_zip_signature, extract_single_threaded},
    };
    use coeus_models::models::{AndroidManifest, Files, MultiDexFile};
    use std::collections::HashMap;

    #[rhai_fn(name = "load_file_from_base64", name = "load_file", return_raw)]
    pub fn load_file_from_base64(
        data: &str,
        build_graph: bool,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        load_file_from_base64_max_depth(data, build_graph, 0)
    }
    #[rhai_fn(name = "load_file_from_base64", name = "load_file", return_raw)]
    pub fn load_file_from_base64_max_depth(
        data: &str,
        build_graph: bool,
        max_depth: i64,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let zip_bytes = base64::decode(data).unwrap_or(vec![]);

        let ptr = zip_bytes.as_slice();
        let found_files: Files = if check_for_zip_signature(ptr) {
            extract_single_threaded(
                "<in_memory_archive>",
                &ArrayView::new(&zip_bytes),
                build_graph,
                parse_dex_buf,
                1,
                max_depth as u32,
            )
        } else if check_for_dex_signature(ptr) {
            log::debug!("found dex");
            let coeus_file = parse_dex(
                "<in_memory_dex>",
                ArrayView::new(&zip_bytes).get_cursor(),
                build_graph,
            )
            .unwrap();
            let multi_dex = MultiDexFile::new(AndroidManifest::default(), coeus_file, vec![]);
            Files::new(vec![multi_dex], HashMap::new())
        } else {
            log::debug!("nothing");
            Files::new(vec![], HashMap::new())
        };
        Ok(Dynamic::from(found_files))
    }
}

#[export_module]
pub mod dex_module {
    use coeus_models::models::{Files, MultiDexFile};
    use rhai::{Dynamic, EvalAltResult, ImmutableString};

    pub fn print_manifest(coeus_file: &mut MultiDexFile) -> String {
        serde_json::to_string(&coeus_file.android_manifest).unwrap_or(String::from("ERROR"))
    }

    #[rhai_fn(name = "load_file", return_raw)]
    pub fn load_file_max_depth(
        path: &str,
        build_graph: bool,
        max_depth: i64,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let found_files = crate::extraction::load_file(path, build_graph, max_depth)
            .expect("Could not load files");
        Ok(Dynamic::from(found_files))
    }

    #[rhai_fn(name = "load_file", return_raw)]
    pub fn load_file_rhai(path: &str, build_graph: bool) -> Result<Dynamic, Box<EvalAltResult>> {
        load_file_max_depth(path, build_graph, 0)
    }
    pub fn get_apk_info(files: &mut Files) -> String {
        serde_json::to_string(files).unwrap_or(String::from(""))
    }
}

pub fn register_parse_module(engine: &mut Engine, resolver: &mut StaticModuleResolver) {
    let global_module = exported_module!(global);
    engine.register_global_module(global_module.into());
    #[cfg(target_arch = "wasm32")]
    {
        let other_global = exported_module!(wasm_module);
        engine.register_global_module(other_global.into());
    }
    let vm_module = exported_module!(dex_module);
    resolver.insert("coeus_parse", vm_module);
}
