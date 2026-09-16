// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use rhai::{module_resolvers::StaticModuleResolver, plugin::*};

#[export_module]
pub mod global {
    use std::{convert::TryInto, sync::Arc};

    use crate::analysis::{ClassEvidences, Context, Evidence};
    use coeus_models::models::{Class, DexFile, MultiDexFile};
    use coeus_parse::{
        dex::graph::{
            callgraph::{callgraph, callgraph_for_method},
            InfoNode, Subgraph, Supergraph,
        },
        scripting::global::to_string_subgraph,
    };
    use rhai::Array;

    #[rhai_fn(name = "push", name = "+=")]
    pub fn push_context(list: &mut Array, item: Context) {
        list.push(Dynamic::from(item));
    }
    #[rhai_fn(name = "insert")]
    pub fn insert_context(list: &mut Array, position: i64, item: Context) {
        if position <= 0 {
            list.insert(0, Dynamic::from(item));
        } else if (position as usize) >= list.len() - 1 {
            list.push(Dynamic::from(item));
        } else {
            list.insert(position as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "pad")]
    pub fn pad_context(list: &mut Array, len: i64, item: Context) {
        if len as usize > list.len() {
            list.resize(len as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "==")]
    pub fn equals_context(item1: &mut Context, item: Context) -> bool {
        match (item1, item) {
            (Context::DexClass(c, f), Context::DexClass(c1, f1)) => {
                c.class_idx == c1.class_idx && f.identifier == f1.identifier
            }
            (Context::DexField(c, f), Context::DexField(c1, f1)) => {
                c.name_idx == c1.name_idx && f.identifier == f1.identifier
            }
            (Context::DexMethod(c, f), Context::DexMethod(c1, f1)) => {
                c.method_idx == c1.method_idx && f.identifier == f1.identifier
            }
            (Context::DexProto(c, f), Context::DexProto(c1, f1)) => {
                c.shorty_idx == c1.shorty_idx && f.identifier == f1.identifier
            }
            (Context::DexString(_, f), Context::DexString(_, f1)) => f.identifier == f1.identifier,
            _ => false,
        }
    }
    #[rhai_fn(name = "print", name = "to_string", name = "to_debug", name = "debug")]
    pub fn print_context(context: &mut Context) -> String {
        format!("{:?}", context).replace("\n", "\\n")
    }

    #[rhai_fn(name = "push", name = "+=")]
    pub fn push_evidence(list: &mut Array, item: Evidence) {
        list.push(Dynamic::from(item));
    }
    #[rhai_fn(name = "insert")]
    pub fn insert_evidence(list: &mut Array, position: i64, item: Evidence) {
        if position <= 0 {
            list.insert(0, Dynamic::from(item));
        } else if (position as usize) >= list.len() - 1 {
            list.push(Dynamic::from(item));
        } else {
            list.insert(position as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "pad")]
    pub fn pad_evidence(list: &mut Array, len: i64, item: Evidence) {
        if len as usize > list.len() {
            list.resize(len as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "==")]
    pub fn equals_evidence(item1: &mut Evidence, item: Evidence) -> bool {
        match (item1, item) {
            (Evidence::String(se1), Evidence::String(se2)) => {
                se1.content == se2.content && equals_context(&mut se1.context, se2.context)
            }
            (Evidence::BytePattern(be1), Evidence::BytePattern(be2)) => *be1 == be2,
            _ => false,
        }
    }

    #[rhai_fn(name = "print", name = "to_string", name = "to_debug", name = "debug")]
    pub fn print_evidence(context: &mut Evidence) -> String {
        format!("{:?}", context)
    }

    #[rhai_fn(name = "getClass")]
    pub fn class_from_evidence(item: &mut Evidence) -> ImmutableString {
        let location = item.get_location();
        if let Some(clazz) = location.get_class() {
            return clazz.class_name.clone().into();
        }
        return "".into();
    }
    #[rhai_fn(name = "getContext")]
    pub fn context_from_evidence(item: &mut Evidence) -> Context {
        item.get_context().unwrap().to_owned()
    }

    #[rhai_fn(name = "printStaticData")]
    pub fn print_class_static_data_from_evidence(item: &mut Evidence) {
        let c = item.get_context().unwrap();
        let (class, dex_file): (Arc<Class>, Arc<DexFile>) = c.try_into().unwrap();
        if let Some(class_data) = &class.class_data {
            for field in &class_data.static_fields {
                if let Some(item) = class.get_data_for_static_field(field.field_idx) {
                    print!("{} = ", dex_file.get_field_name(field.field_idx).unwrap());
                    match item.value_type {
                        coeus_models::models::ValueType::Byte => {
                            let value: u8 = (item.to_owned()).try_into().unwrap();
                            println!("{:?}", value)
                        }
                        coeus_models::models::ValueType::Short => {
                            let value: u16 = (item.to_owned()).try_into().unwrap();
                            println!("{:?}", value)
                        }
                        coeus_models::models::ValueType::Char => {
                            let value: char = (item.to_owned()).try_into().unwrap();
                            println!("{:?}", value)
                        }
                        coeus_models::models::ValueType::Int => {
                            let value: u32 = (item.to_owned()).try_into().unwrap();
                            println!("{:?}", value)
                        }
                        coeus_models::models::ValueType::Long => {
                            let value: u64 = (item.to_owned()).try_into().unwrap();
                            println!("{:?}", value)
                        }
                        coeus_models::models::ValueType::Float => println!(""),
                        coeus_models::models::ValueType::Double => println!(""),
                        coeus_models::models::ValueType::MethodType => println!(""),
                        coeus_models::models::ValueType::MethodHandle => println!(""),
                        coeus_models::models::ValueType::String => {
                            println!("{:?}", item.try_get_string(dex_file.as_ref()))
                        }
                        coeus_models::models::ValueType::Type => println!(""),
                        coeus_models::models::ValueType::Field => println!(""),
                        coeus_models::models::ValueType::Method => println!(""),
                        coeus_models::models::ValueType::Enum => println!(""),
                        coeus_models::models::ValueType::Array => println!(""),
                        coeus_models::models::ValueType::Annotation => println!(""),
                        coeus_models::models::ValueType::Null => println!(""),
                        coeus_models::models::ValueType::Boolean => {
                            let value: bool = (item.to_owned()).try_into().unwrap();
                            println!("{:?}", value)
                        }
                    };
                }
            }
        }
    }

    #[rhai_fn(name = "push", name = "+=")]
    pub fn push_class_evidence(list: &mut Array, item: ClassEvidences) {
        list.push(Dynamic::from(item));
    }
    #[rhai_fn(name = "insert")]
    pub fn insert_class_evidence(list: &mut Array, position: i64, item: ClassEvidences) {
        if position <= 0 {
            list.insert(0, Dynamic::from(item));
        } else if (position as usize) >= list.len() - 1 {
            list.push(Dynamic::from(item));
        } else {
            list.insert(position as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "pad")]
    pub fn pad_class_evidence(list: &mut Array, len: i64, item: ClassEvidences) {
        if len as usize > list.len() {
            list.resize(len as usize, Dynamic::from(item));
        }
    }
    #[rhai_fn(name = "==")]
    pub fn equals_class_evidence(item1: &mut ClassEvidences, item: ClassEvidences) -> bool {
        item1.class.class_name == item.class.class_name
    }

    #[rhai_fn(name = "print", name = "to_string", name = "to_debug", name = "debug")]
    pub fn print_class_evidence(context: &mut ClassEvidences) -> String {
        format!("{}", context.class.class_name)
    }
    #[rhai_fn(name = "to_json", return_raw)]
    pub fn export_json_class_evidences(evidences: Array) -> Result<Dynamic, Box<EvalAltResult>> {
        let evidences: Vec<ClassEvidences> = evidences
            .into_iter()
            .filter_map(|e| e.try_cast::<ClassEvidences>())
            .collect();
        if let Ok(export) = serde_json::to_string(&evidences) {
            Ok(export.into())
        } else {
            Err("Could not serialize".into())
        }
    }

    #[rhai_fn(name = "sub_graph", return_raw)]
    pub fn sub_graph(
        supergraph: &mut Supergraph,
        class: ClassEvidences,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let class_name = class.class.class_name;
        if let Some(node_index) = supergraph.class_node_mapping.get(&class_name) {
            Ok(Dynamic::from(coeus_parse::dex::graph::subgraph_for_node(
                &supergraph.super_graph,
                *node_index,
            )))
        } else {
            if let Some(node_index) = supergraph
                .class_node_mapping
                .get(&format!("T{}", class_name))
            {
                Ok(Dynamic::from(coeus_parse::dex::graph::subgraph_for_node(
                    &supergraph.super_graph,
                    *node_index,
                )))
            } else {
                Err("Class name is not in supergraph".into())
            }
        }
    }
    #[rhai_fn(name = "sub_graph", return_raw)]
    pub fn sub_graph_for_string(
        supergraph: &mut Supergraph,
        key: ImmutableString,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Some(node_index) = supergraph
            .class_node_mapping
            .iter()
            .find(|(k, _)| k.contains(key.as_str()))
            .map(|(_k, n)| n)
        {
            Ok(Dynamic::from(coeus_parse::dex::graph::subgraph_for_node(
                &supergraph.super_graph,
                *node_index,
            )))
        } else {
            Err("Key not found".into())
        }
    }
    pub fn get_neighbours(
        supergraph: &mut Supergraph,
        multi_dex: MultiDexFile,
        key: ImmutableString,
    ) -> Array {
        let mut result = vec![];
        if let Some(&node_index) = supergraph
            .class_node_mapping
            .iter()
            .find(|(k, _n)| k.contains(key.as_str()))
            .map(|(_k, n)| n)
        {
            let neighbours = supergraph.super_graph.neighbors_undirected(node_index);
            for neighbour in neighbours {
                if let Some(weight) = supergraph.super_graph.node_weight(neighbour) {
                    if let InfoNode::MethodNode(m, _) = weight {
                        if let Some(dex) = multi_dex
                            .methods()
                            .iter()
                            .find(|(_, method)| method == m)
                            .map(|(dex, _)| dex)
                        {
                            let evidence = Evidence::String(crate::analysis::StringEvidence {
                                content: m.method_name.clone(),
                                place: crate::analysis::Location::DexMethod(
                                    m.method_idx as u32,
                                    dex.clone(),
                                ),
                                context: Context::DexMethod(m.clone(), dex.clone()),
                                confidence_level: crate::analysis::ConfidenceLevel::High,
                            });
                            result.push(Dynamic::from(evidence));
                        }
                    }
                }
            }
        }
        result
    }
    #[rhai_fn(name = "call_graph", return_raw)]
    pub fn call_graph(
        supergraph: &mut Supergraph,
        class: ClassEvidences,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let class_name = &class.class.class_name;
        if let Some(node_index) = supergraph.class_node_mapping.get(class_name) {
            Ok(Dynamic::from(callgraph(
                &supergraph.super_graph,
                &class.class,
                *node_index,
            )))
        } else {
            if let Some(node_index) = supergraph
                .class_node_mapping
                .get(&format!("T{}", class_name))
            {
                Ok(Dynamic::from(callgraph(
                    &supergraph.super_graph,
                    &class.class,
                    *node_index,
                )))
            } else {
                Err("Class name is not in supergraph".into())
            }
        }
    }

    #[rhai_fn(name = "call_graph", return_raw)]
    pub fn call_graph_from_evidence(
        supergraph: &mut Supergraph,
        _: MultiDexFile,
        function_name: Evidence,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Some(Context::DexMethod(method, f)) = function_name.get_context() {
            let file = f.clone();
            let type_name = file.get_type_name(method.class_idx).unwrap_or("UNKNOWN");
            let fqdn = format!(
                "{}->{}_{}",
                type_name, method.method_name, method.proto_name
            );
            if let Some(method_key) = supergraph
                .class_node_mapping
                .keys()
                .find(|k| k.contains(&fqdn))
            {
                let node_index = supergraph.class_node_mapping[method_key];
                Ok(Dynamic::from(callgraph_for_method(
                    &supergraph.super_graph,
                    node_index,
                )))
            } else {
                Err("No node found matching function_name".into())
            }
        } else {
            Err("Evidence must be a Method".into())
        }
    }
    #[rhai_fn(name = "call_graph", return_raw)]
    pub fn call_graph_for_string(
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
            Err(format!("No node found matching {}", function_name).into())
        }
    }

    #[rhai_fn(name = "get_class_node", return_raw)]
    pub fn get_class_node(
        supergraph: &mut Supergraph,
        class: ClassEvidences,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Some(node) = supergraph.class_node_mapping.get(&class.class.class_name) {
            Ok(Dynamic::from(*node))
        } else {
            //fallback to type node
            if let Some(node) = supergraph
                .class_node_mapping
                .get(&format!("T{}", class.class.class_name))
            {
                Ok(Dynamic::from(*node))
            } else {
                Err("Node not found".into())
            }
        }
    }
    #[rhai_fn(name = "get_type_node", return_raw)]
    pub fn get_type_node(
        supergraph: &mut Supergraph,
        class: ClassEvidences,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Some(node) = supergraph
            .class_node_mapping
            .get(&format!("T{}", class.class.class_name))
        {
            Ok(Dynamic::from(*node))
        } else {
            Err("Node not found".into())
        }
    }
    #[rhai_fn(name = "contains_node")]
    pub fn contains_node_supergraph(supergraph: &mut Supergraph, class: ClassEvidences) -> bool {
        supergraph
            .class_node_mapping
            .contains_key(&class.class.class_name)
            || supergraph
                .class_node_mapping
                .contains_key(&format!("T{}", class.class.class_name))
    }

    pub fn evidences(ce: &mut ClassEvidences) -> Array {
        let mut array = vec![];
        for ev in &ce.evidences {
            array.push(Dynamic::from(ev.clone()));
        }
        array
    }
    pub fn has_runtime_signature(ce: &mut ClassEvidences) -> bool {
        ce.class.class_name.starts_with("Landroid")
            || ce.class.class_name.starts_with("Lcom/google")
    }
    pub fn has_at_least(ce: &mut ClassEvidences, n: i64) -> bool {
        ce.evidences.len() > n as usize
    }

    pub fn add_subgraph(evidences: &mut ClassEvidences, mut subgraph: Subgraph) {
        let encoded = base64::encode(to_string_subgraph(&mut subgraph));
        evidences.subgraph = Some(encoded);
    }
    pub fn add_link(evidences: &mut ClassEvidences, evidence: ClassEvidences) {
        evidences.linked.push(evidence);
    }
}

macro_rules! evidences {
    ($function:expr) => {
        let mut array = Array::new();
        let evidences = $function;
        for e in evidences {
            array.push(Dynamic::from(e));
        }
        array
    };
}

#[export_module]
pub mod dex_module {
    use std::{collections::HashMap, sync::Arc};

    use crate::analysis::{
        dex::{self, get_methods_for_type_owned},
        native::{find_binary_pattern_in_elf, BinaryContent},
        ClassEvidences, ConfidenceLevel, Context, Evidence, InstructionEvidence, Location,
    };
    use coeus_macros::iterator;
    use coeus_models::models::{BinaryObject, Files, MultiDexFile};

    use coeus_parse::dex::graph::information_graph::build_information_graph;
    #[cfg(not(target_arch = "wasm32"))]
    use rayon::iter::ParallelIterator;
    use regex::Regex;
    use rhai::{Array, Dynamic, EvalAltResult, ImmutableString};

    pub mod png {

        pub const IEND: [&str; 12] = [
            "00", "00", "00", "00", "I", "E", "N", "D", "*", "*", "*", "*",
        ];
        #[rhai_fn(name = "data_after_iend")]
        pub fn data_after_iend_u64(min_data: i64) -> Array {
            data_after_iend(min_data as usize)
        }
        pub fn data_after_iend(min_data: usize) -> Array {
            let mut data = vec![];
            for i in 0usize..(12usize + min_data) {
                if i >= 12 {
                    data.push("*".into());
                } else {
                    data.push(IEND[i].into());
                }
            }
            data
        }
    }
    pub mod zip {
        pub const END_OF_CENTRAL_DIRECTORY: [&str; 22] = [
            "50", "4b", "05", "06", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*",
            "*", "*", "*", "*", "*", "*",
        ];

        pub const LOCAL_FILE_HEADER: [&str; 30] = [
            "50", "4b", "03", "04", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*",
            "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*", "*",
        ];
        pub fn end_of_central_directory() -> Array {
            END_OF_CENTRAL_DIRECTORY
                .iter()
                .map(|e| (*e).into())
                .collect()
        }
        pub fn local_file_header() -> Array {
            LOCAL_FILE_HEADER.iter().map(|e| (*e).into()).collect()
        }
    }

    pub fn get_disassembly(coeus_file: &mut MultiDexFile, ce: ClassEvidences) -> String {
        ce.class.get_disassembly(coeus_file)
    }
    #[rhai_fn(name = "get_disassembly")]
    pub fn get_disassembly_from_string(
        coeus_file: &mut MultiDexFile,
        class_name: ImmutableString,
    ) -> String {
        if let Some((_, class)) = coeus_file
            .classes()
            .iter()
            .find(|(_f, c)| c.class_name == class_name)
        {
            class.get_disassembly(coeus_file)
        } else {
            String::from("")
        }
    }
    pub fn print_manifest(coeus_file: &mut MultiDexFile) -> String {
        serde_json::to_string(&coeus_file.android_manifest).unwrap_or(String::from("ERROR"))
    }

    #[rhai_fn(name = "export_json", return_raw)]
    pub fn export_json(evidences: Array) -> Result<Dynamic, Box<EvalAltResult>> {
        let evidences: Vec<Evidence> = evidences
            .into_iter()
            .filter_map(|e| e.try_cast::<Evidence>())
            .collect();
        if let Ok(export) = serde_json::to_string(&evidences) {
            Ok(export.into())
        } else {
            Err("Could not serialize".into())
        }
    }

    pub const DEFAULT_NON_INTERESTING_CLASSES: [&str; 12] = [
        "Lj$/time",
        "Lkotlin/",
        "Lkotlinx/",
        "Landroidx/",
        "Lcom/sun",
        "Landroid/app",
        "Landroid/widget",
        // "Landroid/content",
        "Lcom/google/protobuf",
        "Lcom/google/android",
        "Lokhttp3/internal",
        "okio",
        "Lorg/bouncycastle/",
    ];
    pub fn get_non_interesting_classes() -> Array {
        DEFAULT_NON_INTERESTING_CLASSES
            .iter()
            .map(|c| Dynamic::from(c.to_string()))
            .collect()
    }

    #[rhai_fn(name = "build_super_graph", return_raw)]
    pub fn build_super_graph(
        dex: &mut MultiDexFile,
        files: Files,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Ok(graph) = build_information_graph(
            dex,
            Arc::new(files.binaries),
            &DEFAULT_NON_INTERESTING_CLASSES,
            Some(&vec![]),
            None,
        ) {
            Ok(Dynamic::from(graph))
        } else {
            Err("Could not generate supergraph".into())
        }
    }
    #[rhai_fn(name = "build_super_graph_no_emulation", return_raw)]
    pub fn build_super_graph_no_emulation(
        dex: &mut MultiDexFile,
        files: Files,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        if let Ok(graph) = build_information_graph(
            dex,
            Arc::new(files.binaries),
            &DEFAULT_NON_INTERESTING_CLASSES,
            None,
            None,
        ) {
            Ok(Dynamic::from(graph))
        } else {
            Err("Could not generate supergraph".into())
        }
    }

    #[rhai_fn(name = "build_super_graph", return_raw)]
    pub fn build_super_graph_with_classes(
        dex: &mut MultiDexFile,
        files: Files,
        excluded_classes: Array,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let excluded_classes_orig = excluded_classes
            .into_iter()
            .map(|c| {
                c.into_immutable_string()
                    .unwrap_or(ImmutableString::from(""))
            })
            .collect::<Vec<_>>();
        let excluded_classes = excluded_classes_orig
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>();

        if let Ok(graph) = build_information_graph(
            dex,
            Arc::new(files.binaries),
            &excluded_classes,
            Some(&vec![]),
            None,
        ) {
            Ok(Dynamic::from(graph))
        } else {
            Err("Could not generate supergraph".into())
        }
    }
    #[rhai_fn(name = "build_super_graph", return_raw)]
    pub fn build_super_graph_with_classes_and_emulate_code(
        dex: &mut MultiDexFile,
        files: Files,
        excluded_classes: Array,
        emulate_code: Array,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        let excluded_classes_orig = excluded_classes
            .into_iter()
            .map(|c| c.into_immutable_string().unwrap_or("".into()))
            .collect::<Vec<_>>();
        let excluded_classes = excluded_classes_orig
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>();
        let emulate_code = emulate_code
            .into_iter()
            .map(|c| c.cast::<ClassEvidences>())
            .map(|c| c.class.class_name)
            .collect::<Vec<String>>();
        let borrowed_emulate_code = emulate_code
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<&str>>();
        if let Ok(graph) = build_information_graph(
            dex,
            Arc::new(files.binaries),
            &excluded_classes,
            Some(&borrowed_emulate_code),
            None,
        ) {
            Ok(Dynamic::from(graph))
        } else {
            Err("Could not generate supergraph".into())
        }
    }
    pub fn gather_evidences(_: &mut Files, evidences: Array) -> Array {
        let mut class_evidences = HashMap::new();
        evidences
            .into_iter()
            .map(|e| e.cast::<Evidence>())
            .for_each(|evidence| {
                if let Some((class, _)) = dex::get_class_for_owned_evidence(&evidence) {
                    let entry =
                        class_evidences
                            .entry(class.class_name.clone())
                            .or_insert(ClassEvidences {
                                class: (*class).clone(),
                                subgraph: None,
                                linked: vec![],
                                evidences: vec![],
                            });
                    entry.evidences.push(evidence);
                }
            });
        let class_evidences = class_evidences.values();
        class_evidences
            .into_iter()
            .map(|ce| Dynamic::from(ce.to_owned()))
            .collect()
    }

    #[rhai_fn(name = "bin_scan", name = "find_binary_pattern")]
    pub fn find_bin_pattern(files: &mut Files, pattern: Array) -> Array {
        let pattern: Vec<BinaryContent> = pattern
            .into_iter()
            .map(|c| {
                let _c = c.into_immutable_string().unwrap_or("".into());
                let c = _c.as_str();
                if c == "*" {
                    return BinaryContent::Wildcard;
                }
                if c.len() == 2 {
                    if let Ok(parse) = u8::from_str_radix(c, 16) {
                        return BinaryContent::Byte(parse);
                    }
                }
                return BinaryContent::Char(c.chars().next().unwrap_or('0'));
            })
            .collect();
        evidences! {
            find_binary_pattern_in_elf(&pattern, &files.binaries)
        }
    }

    #[rhai_fn(name = "string_from_bin")]
    pub fn get_string_from_bin_pattern(evidence: &mut Evidence) -> String {
        if let Evidence::BytePattern(ev) = evidence {
            if let Location::NativePattern(resource, _) = &ev.place {
                return resource.clone();
            }
        }
        "".to_string()
    }

    #[rhai_fn(name = "bin_scan", name = "find_binary_pattern")]
    pub fn find_bin_pattern_on_file(
        files: &mut Files,
        file_pattern: &str,
        pattern: Array,
    ) -> Array {
        let reg = Regex::new(file_pattern).unwrap();
        let pattern: Vec<BinaryContent> = pattern
            .into_iter()
            .map(|c| {
                let _c = c.into_immutable_string().unwrap_or("".into());
                let c = _c.as_str();
                if c == "*" {
                    return BinaryContent::Wildcard;
                }
                if c.len() == 2 {
                    if let Ok(parse) = u8::from_str_radix(c, 16) {
                        return BinaryContent::Byte(parse);
                    }
                }
                return BinaryContent::Char(c.chars().next().unwrap());
            })
            .collect();
        let map: HashMap<String, Arc<BinaryObject>> = files
            .binaries
            .iter()
            .filter(|(k, _)| reg.is_match(k))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        evidences! {
            find_binary_pattern_in_elf(&pattern,  &map)
        }
    }
    #[rhai_fn(name = "find_classes")]
    pub fn find_classes_by_name(files: &mut Files, reg: ImmutableString) -> Array {
        let mut array = Array::new();

        let evidences = crate::analysis::find_classes(&Regex::new(&reg).unwrap(), files);
        for e in evidences {
            array.push(Dynamic::from(e.clone()));
        }
        array
    }
    #[rhai_fn(name = "find_string_matches")]
    pub fn find_string_matches_one(files: &mut Files, reg: ImmutableString) -> Array {
        let mut array = Array::new();
        let evidences = crate::analysis::find_all_matches(&Regex::new(&reg).unwrap(), &files);
        for e in evidences {
            array.push(Dynamic::from(e.clone()));
        }
        array
    }
    pub fn find_string_matches(files: &mut Files, regs: Array) -> Array {
        let mut array = Array::new();
        for reg in regs {
            array.extend(find_string_matches_one(
                files,
                reg.cast::<ImmutableString>(),
            ));
        }
        array
    }

    #[rhai_fn(name = "match_method_names", name = "find_method_names")]
    pub fn match_method_names_one(files: &mut Files, reg: ImmutableString) -> Array {
        evidences! {
            crate::analysis::dex::find_string_matches_for_method_name(&Regex::new(&reg).unwrap(), &files.multi_dex)
        }
    }
    #[rhai_fn(name = "match_method_names", name = "find_method_names")]
    pub fn match_method_names(files: &mut Files, regs: Array) -> Array {
        let mut array = Array::new();
        for reg in regs {
            array.extend(match_method_names_one(files, reg.cast::<ImmutableString>()));
        }
        array
    }
    #[rhai_fn(name = "match_prototype", name = "find_prototype")]
    pub fn match_prototype_one(files: &mut Files, reg: ImmutableString) -> Array {
        evidences! {
            crate::analysis::dex::find_string_matches_for_proto(&Regex::new(&reg).unwrap(), &files.multi_dex)
        }
    }
    #[rhai_fn(name = "match_prototype", name = "find_prototype")]
    pub fn match_prototype(files: &mut Files, regs: Array) -> Array {
        let mut array = Array::new();
        for reg in regs {
            array.extend(match_prototype_one(files, reg.cast::<ImmutableString>()));
        }
        array
    }
    #[rhai_fn(name = "match_field_name", name = "find_field_name")]
    pub fn match_field_names_one(files: &mut Files, reg: ImmutableString) -> Array {
        evidences! {
            crate::analysis::dex::find_string_matches_for_field_name(&Regex::new(&reg).unwrap(), &files.multi_dex)
        }
    }
    #[rhai_fn(name = "match_field_name", name = "find_field_name")]
    pub fn match_field_names(files: &mut Files, regs: Array) -> Array {
        let mut array = Array::new();
        for reg in regs {
            array.extend(match_field_names_one(files, reg.cast::<ImmutableString>()));
        }
        array
    }
    #[rhai_fn(name = "match_static_data", name = "find_static_data")]
    pub fn match_static_data_one(files: &mut Files, reg: ImmutableString) -> Array {
        evidences! {
            crate::analysis::dex::find_string_matches_for_static_data(&Regex::new(&reg).unwrap(), &files.multi_dex)
        }
    }
    #[rhai_fn(name = "match_static_data", name = "find_static_data")]
    pub fn match_static_data(files: &mut Files, regs: Array) -> Array {
        let mut array = Array::new();
        for reg in regs {
            array.extend(match_static_data_one(files, reg.cast::<ImmutableString>()));
        }
        array
    }

    pub fn find_methods_with_instructions(files: &mut Files, instructions: Array) -> Array {
        let mut array = vec![];
        let instruction_strings = instructions
            .iter()
            .cloned()
            .map(|i| i.cast::<String>())
            .collect::<Vec<String>>();
        let instructions = instructions
            .into_iter()
            .map(|i| Regex::new(&i.cast::<String>()).unwrap())
            .collect::<Vec<Regex>>();

        let context: Vec<_> = iterator! {
                        files
                        .multi_dex
        }
        .flat_map(|df| {
            let classes = df.classes();
            iterator!(classes)
                .flat_map(|(f, class)| class.codes.iter().map(|c| (f, c)).collect::<Vec<_>>())
                .filter(|(_, code)| code.code.is_some())
                .filter(|(_, m)| {
                    let mnemonics: Vec<_> = m
                        .code
                        .as_ref()
                        .unwrap()
                        .insns
                        .iter()
                        .map(|(_, _, c)| c.mnemonic_from_opcode())
                        .collect();
                    for instruction in &instructions {
                        if !mnemonics
                            .iter()
                            .any(|mnemonic| instruction.is_match(mnemonic))
                        {
                            return false;
                        }
                    }
                    true
                })
                .map(|(file, m)| {
                    Evidence::Instructions(InstructionEvidence {
                        confidence_level: ConfidenceLevel::High,
                        instructions: instruction_strings.clone(),
                        context: Context::DexMethod(m.method.clone(), file.clone()),
                        place: Location::DexMethod(m.method.method_idx as u32, file.clone()),
                    })
                })
                .collect::<Vec<Evidence>>()
        })
        .collect();

        for c in context {
            array.push(Dynamic::from(c));
        }
        array
    }
    pub fn find_array_data() {
        todo! {}
    }
    #[rhai_fn(name = "find_methods_for_type")]
    pub fn find_methods_for_type_one(files: &mut Files, evidence: Evidence) -> Array {
        let context = match evidence {
            Evidence::String(se) => se.context,
            Evidence::Instructions(ins) => ins.context,
            Evidence::CrossReference(cross) => cross.place_context,
            _ => panic!("Only string implemented"),
        };
        get_methods_for_type_owned(&context, files)
            .into_iter()
            .map(|e| Dynamic::from(e))
            .collect()
    }
    #[rhai_fn(name = "find_methods_for_type")]
    pub fn find_methods_for_type(files: &mut Files, evidences: Array) -> Array {
        let mut array = vec![];
        for ev in evidences {
            array.extend(find_methods_for_type_one(files, ev.cast::<Evidence>()));
        }
        array
    }

    #[rhai_fn(name = "find_cross_reference")]

    pub fn find_cross_reference_one(files: &mut Files, evidence: Evidence) -> Array {
        find_cross_reference_many(files, vec![Dynamic::from(evidence)])
    }
    #[rhai_fn(name = "find_cross_reference")]
    pub fn find_cross_reference_many(files: &mut Files, evidences: Array) -> Array {
        let contexts = evidences
            .into_iter()
            .map(|e| {
                let evidence = e.cast::<Evidence>();
                let context = match evidence {
                    Evidence::String(se) => se.context,
                    Evidence::Instructions(ins) => ins.context,
                    Evidence::CrossReference(cross) => cross.place_context,
                    _ => panic!("Only string implemented"),
                };
                context
            })
            .collect::<Vec<_>>();

        let references = crate::analysis::dex::find_cross_reference_array(&contexts, files);

        references
            .into_iter()
            .map(|refe| Dynamic::from(refe))
            .collect()
    }
}

pub fn register_analysis_module(engine: &mut Engine, resolver: &mut StaticModuleResolver) {
    let global_module = exported_module!(global);
    engine.register_global_module(global_module.into());

    let coeus_module = exported_module!(dex_module);
    resolver.insert("coeus_analysis", coeus_module);
}
