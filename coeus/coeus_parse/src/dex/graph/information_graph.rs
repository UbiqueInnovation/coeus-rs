// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use coeus_emulation::vm::{
    runtime::{JavaArray, JavaObject, ObjectClass, StringClass},
    Breakpoint, ClassInstance, Register, Value, VM,
};
use coeus_macros::iterator;
use coeus_models::models::{
    AccessFlags, BinaryObject, Class, Instruction, InstructionOffset, InstructionSize,
    MultiDexFile, ValueType,
};
use petgraph::{
    graph::{DiGraph, NodeIndex},
    Direction, Graph,
};
use rayon::iter::ParallelIterator;
use std::{
    collections::HashMap,
    sync::{
        mpsc::{Receiver, Sender},
        Arc,
    },
};

use super::{
    analysis::{
        dynamic::discover_dynamicnodes,
        r#static::{
            flow::Flow,
            models::{StaticRegister, StaticRegisterData},
        },
    },
    ChangeSet, InfoNode, Supergraph,
};

/// Find implementations of interfaces
pub fn find_implementations(
    super_graph: &Supergraph,
    interface_identifier: &str,
) -> Vec<Arc<Class>> {
    let mut classes = vec![];
    if let Some(node) = super_graph.class_node_mapping.get(interface_identifier) {
        let nodes = super_graph
            .super_graph
            .neighbors_directed(*node, Direction::Outgoing);
        for n in nodes {
            if let Some(InfoNode::ClassNode(c)) = super_graph.super_graph.node_weight(n) {
                classes.push(c.clone());
            }
        }
    }
    classes
}

/// Build the super graph containing nodes from various pools and
/// connect them in a directional graph.
/// returns a tuple of a hashmap storing graph node indices for class names
/// and the corresponding super graph
pub fn build_information_graph(
    multi_dex_file: &MultiDexFile,
    resources: Arc<HashMap<String, Arc<BinaryObject>>>,
    exclude_classes: &[&str],
    emulate_classes: Option<&[&str]>,
    cancelation: Option<(Sender<Supergraph>, Receiver<bool>)>,
) -> Result<Supergraph, Box<dyn std::error::Error>> {
    let classes = multi_dex_file.classes();
    let mut g: Graph<InfoNode, i32> = DiGraph::new();
    let mut interfaces = HashMap::new();

    let mut all_mappings: HashMap<String, NodeIndex> = HashMap::new();

    let (string_type_idices, byte_array_type) =
        prepare_mappings(multi_dex_file, &mut g, &mut all_mappings, exclude_classes);

    build_inheritance(
        &classes,
        exclude_classes,
        cancelation,
        &mut all_mappings,
        &mut g,
        &mut interfaces,
    );
    // let all_lock = Arc::new(Mutex::new((&mut g, &mut interfaces, &mut all_mappings)));
    let nodes_to_add: Vec<ChangeSet> = iterator!(classes)
        .flat_map(|(f, class)| {
            // if we have codes, that means we actually have the instructions for this method
            let nodes_to_add: Vec<ChangeSet> = iterator!(class.codes)
                .flat_map(|code| {
                    let mut vm = VM::new(
                        multi_dex_file.primary.clone(),
                        multi_dex_file.secondary.iter().cloned().collect(),
                        resources.clone(),
                    );
                    vm.set_breakpoint(Breakpoint::ArrayUse);
                    vm.set_breakpoint(Breakpoint::StringUse);
                    vm.set_breakpoint(Breakpoint::StringReturn);
                    vm.set_breakpoint(Breakpoint::ArrayReturn);

                    let type_name = f.get_type_name(code.method.class_idx).unwrap();
                    let fqdn = format!(
                        "{}->{}_{}",
                        type_name, code.method.method_name, code.method.proto_name
                    );
                    if !all_mappings.contains_key(&fqdn) {
                        return vec![];
                    }
                    let method_node_index = *(&all_mappings[&fqdn]);

                    // if let Ok(mut all) = all_lock.lock() {}

                    let method_proto = f.get_proto_name(code.method.proto_idx);

                    // let method_index = code.method.method_idx;
                    let method_name = &code.method.method_name;
                    let access_flags = code.access_flags.clone();
                    let discover_dynamic = emulate_classes
                        .map(|classes| {
                            classes.is_empty() || classes.contains(&class.class_name.as_str())
                        })
                        .unwrap_or(false);
                    // let's search all instructions an connect various nodes with this method.
                    let mut discoveries = vec![];
                    // let mut add_nodes = vec![];
                    // let mut add_edges = vec![];
                    let mut nodes_to_add: Vec<_> = vec![];
                    let all_mappings = &all_mappings;
                    let mut args = vec![];
                    if let Some(the_code) = &code.code {
                        let the_proto = &f.protos[code.method.proto_idx as usize];
                        if let Some(proto) = method_proto {
                            // #[cfg(not(target_arch = "wasm32"))]
                            if discover_dynamic {
                                    // simulate the function and make a node for every array contained
                                    vm.reset();

                                    //non static classes contain a self argument as the first element
                                    if !access_flags.contains(AccessFlags::STATIC) {
                                        args.push(
                                            vm.new_instance(
                                                class.class_name.clone(),
                                                Value::Object(ClassInstance::new(class.clone())),
                                            )
                                            .unwrap(),
                                        );
                                    }
                                    let protos = proto.chars().skip(1).collect::<Vec<_>>();
                                    for (i, arg_type) in the_proto.arguments.iter().enumerate() {
                                        let shorty = protos[i];
                                        if matches!(shorty, 'I' | 'F' | 'B') {
                                            args.push(Register::Literal(10));
                                            continue;
                                        }
                                        if shorty == 'L' {
                                            if string_type_idices.contains(arg_type) {
                                                args.push(
                                                    vm.new_instance(
                                                        StringClass::class_name().to_string(),
                                                        Value::Object(StringClass::new(
                                                            "test".to_string(),
                                                        )),
                                                    )
                                                    .unwrap(),
                                                );
                                            } else if *arg_type == byte_array_type {
                                                args.push(
                                                    vm.new_instance(
                                                        JavaArray::class_name().to_string(),
                                                        Value::Array(vec![0, 1, 2, 3, 4]),
                                                    )
                                                    .unwrap(),
                                                );
                                            } else {
                                                args.push(
                                                    vm.new_instance(
                                                        ObjectClass::class_name().to_string(),
                                                        Value::Object(ObjectClass::new()),
                                                    )
                                                    .unwrap(),
                                                );
                                            }
                                        }
                                    }

                                    discoveries = discover_dynamicnodes(
                                        &mut vm,
                                        &args,
                                        &code,
                                        &f.identifier,
                                        method_node_index,
                                        &all_mappings,
                                    );
                            }
                        }

                        // TODO maybe control it with a switch?

                        if method_name == "<clinit>" && discover_dynamic {
                            if let Some(class_data) = class.class_data.as_ref() {
                                for field in &class_data.static_fields {
                                    vm.set_breakpoint(Breakpoint::FieldSet(field.field_idx as u16));
                                }
                            }

                            discoveries = discover_dynamicnodes(
                                &mut vm,
                                &[],
                                &code,
                                &f.identifier,
                                method_node_index,
                                &all_mappings,
                            );

                            vm.clear_breakpoints();
                            vm.set_breakpoint(Breakpoint::ArrayUse);
                            vm.set_breakpoint(Breakpoint::StringUse);
                            vm.set_breakpoint(Breakpoint::StringReturn);
                            vm.set_breakpoint(Breakpoint::ArrayReturn);
                        }

                        let mut static_registers: Vec<StaticRegister> =
                            Vec::with_capacity(the_code.register_size as usize);
                        let parameter_offset = the_code.register_size - the_code.ins_size;
                        for register in 0..the_code.register_size {
                            let is_argument = register >= parameter_offset;
                            let static_register = StaticRegister {
                                register: register as u8,
                                out_arg_number: 0,
                                argument_number: if is_argument {
                                    (register - parameter_offset) as u8
                                } else {
                                    0
                                },
                                is_argument,
                                is_array: false,
                                ty: if is_argument {
                                    Some(format!(
                                        "{:?}",
                                        args.get((register - parameter_offset) as usize)
                                    ))
                                } else {
                                    None
                                },
                                data: Some(StaticRegisterData::Object),
                                transformation: None,
                                inner_data: vec![],
                                split_data: vec![],
                                last_branch: None,
                            };
                            static_registers.push(static_register);
                        }

                        let tmp: HashMap<InstructionOffset, (InstructionSize, Instruction)> =
                            the_code
                                .insns
                                .iter()
                                .map(|(size, offset, instruction)| {
                                    (*offset, (*size, instruction.clone()))
                                })
                                .collect();
                        // if class.class_name == "Lch/admin/bag/covidcertificate/sdk/android/data/PrepopulatedRevokedCertificatesDbConfig;" {
                        let mut flow = Flow::new(&tmp);
                        flow.new_branch(Some(InstructionOffset(0)), static_registers);
                        let mut iterations = 0;
                        let break_points = vm.get_breakpoints_clone();
                        vm.reset();
                        while flow.next_instruction(
                            f.clone(),
                            method_node_index,
                            &mut nodes_to_add,
                            class.clone(),
                            all_mappings,
                            &mut vm,
                        ) {
                            iterations += 1;
                            if iterations > 80 {
                                break;
                            }
                        }

                        break_points.into_iter().for_each(|a| vm.set_breakpoint(a));
                        // }
                    }
                    nodes_to_add.into_iter().chain(discoveries).collect()
                })
                .collect::<_>();
            nodes_to_add
        })
        .collect::<Vec<_>>();
    add_to_graph(&mut g, &mut all_mappings, nodes_to_add);

    // class_nodes.extend(type_nodes);
    Ok(Supergraph {
        class_node_mapping: all_mappings,
        super_graph: g,
    })
}

fn add_to_graph(
    graph: &mut Graph<InfoNode, i32>,
    mappings: &mut HashMap<String, NodeIndex>,
    nodes_to_add: Vec<ChangeSet>,
) {
    // for (origin, intermediate, is_argument, key, node) in discoveries {
    //     let node_index = graph
    //         .neighbors(origin)
    //         .find(|a| graph[*a] == node)
    //         .unwrap_or_else(|| graph.add_node(node));
    //     if let Some(key) = key {
    //         mappings.entry(key).or_insert_with(|| node_index);
    //     }

    //     if let Some(intermediate) = intermediate {
    //         if is_argument {
    //             nodes_to_add.push(ChangeSet::AddEdge {
    //                 start: node_index,
    //                 end: intermediate,
    //             });
    //         } else {
    //             nodes_to_add.push(ChangeSet::AddEdge {
    //                 start: intermediate,
    //                 end: node_index,
    //             });
    //         }
    //     }

    //     if is_argument {
    //         if !graph.contains_edge(origin, node_index) {
    //             graph.add_edge(origin, node_index, 1);
    //         }
    //     } else {
    //         if !graph.contains_edge(node_index, origin) {
    //             graph.add_edge(node_index, origin, 1);
    //         }
    //     }
    // }

    for node in nodes_to_add {
        match node {
            ChangeSet::AddEdge { start, end } => {
                if !graph.contains_edge(start, end) {
                    graph.add_edge(start, end, 1);
                }
            }
            ChangeSet::AddNodeTo { origin, node, key } => {
                let node_index = graph
                    .neighbors(origin)
                    .find(|a| graph[*a] == node)
                    .unwrap_or_else(|| graph.add_node(node));
                if let Some(key) = key {
                    mappings.entry(key).or_insert_with(|| node_index);
                }
                if !graph.contains_edge(node_index, origin) {
                    graph.add_edge(node_index, origin, 1);
                }
            }
            ChangeSet::AddNodeFrom {
                destination,
                node,
                key,
            } => {
                let node_index = graph
                    .neighbors(destination)
                    .find(|a| graph[*a] == node)
                    .unwrap_or_else(|| graph.add_node(node));
                if let Some(key) = key {
                    mappings.entry(key).or_insert_with(|| node_index);
                }
                if !graph.contains_edge(destination, node_index) {
                    graph.add_edge(destination, node_index, 1);
                }
            }
            ChangeSet::AddNodeFromTo {
                origin,
                destination,
                node,
                key,
            } => {
                let node_index = graph
                    .neighbors(destination)
                    .find(|a| graph[*a] == node)
                    .unwrap_or_else(|| graph.add_node(node));
                if let Some(key) = key {
                    mappings.entry(key).or_insert_with(|| node_index);
                }
                if !graph.contains_edge(origin, node_index) {
                    graph.add_edge(origin, node_index, 1);
                }
                if !graph.contains_edge(node_index, destination) {
                    graph.add_edge(node_index, destination, 1);
                }
            }
        }
    }
}

fn build_inheritance(
    classes: &Vec<(
        Arc<coeus_models::models::DexFile>,
        Arc<coeus_models::models::Class>,
    )>,
    exclude_classes: &[&str],
    cancelation: Option<(Sender<Supergraph>, Receiver<bool>)>,
    all_mappings: &mut HashMap<String, NodeIndex>,
    g: &mut Graph<InfoNode, i32>,
    interfaces: &mut HashMap<u32, Vec<(String, String, NodeIndex)>>,
) {
    for (f, class) in classes.iter() {
        if exclude_classes.iter().any(|c| class.class_name.contains(c)) {
            continue;
        }
        if let Some(cancelation) = cancelation.as_ref() {
            if let Ok(should_cancel) = cancelation.1.try_recv() {
                if should_cancel {
                    log::warn!("Got cancel signal, aborting");
                    break;
                }
            }
        }
        //if the class name occurs multiple times (TODO: find out why; probably usage in another dex file) just reuse the node.
        let class_node_idx = if let Some(&_) = all_mappings.get(class.class_name.as_str()) {
            // node_index
            continue;
        } else {
            let class_node_idx = g.add_node(InfoNode::ClassNode(class.clone()));
            all_mappings.insert(class.class_name.clone(), class_node_idx);
            class_node_idx
        };

        //connect to class type
        let class_type = format!("T{}", f.get_type_name(class.class_idx as usize).unwrap());
        if !all_mappings.contains_key(&class_type) {
            log::error!("{} not found", class_type);
            continue;
        };

        //make a double connection from type to class (not directed..)
        let class_type_node_index = all_mappings[&class_type];
        g.add_edge(class_node_idx, class_type_node_index, 1);
        //g.add_edge(class_type_node_index, class_node_idx, 1);

        //connect super type
        let super_identifier = format!("T{}", f.get_type_name(class.super_class as usize).unwrap());
        if class.super_class != 0xff_ff_ff_ff && all_mappings.contains_key(&super_identifier) {
            let type_node_index = all_mappings[&super_identifier];
            g.add_edge(class_type_node_index, type_node_index, 1);
            //g.add_edge(type_node_index, class_type_node_index, 1);
        }
        //check if we have an interface definition
        let is_interface = class.access_flags.contains(AccessFlags::INTERFACE);
        if is_interface {
            //if so initialize it
            interfaces.entry(class.class_idx).or_insert_with(Vec::new);
        }
        //let all interface point to us
        for interface in &class.interfaces {
            let interface_identifier =
                format!("T{}", f.get_type_name(*interface as usize).unwrap());
            if let Some(&interface_node) = all_mappings.get(&interface_identifier) {
                g.add_edge(interface_node, class_type_node_index, 1);
            }
        }
        // If we have class data, we can search through static default values and link them to fields
        if let Some(class_data) = &class.class_data {
            for (field, value) in class_data.static_fields.iter().zip(&class.static_fields) {
                if matches!(value.value_type, ValueType::String) {
                    let fi = &f.fields[field.field_idx as usize];
                    if let Some(string) = f.get_string(value.get_string_id() as usize) {
                        let string = format!("SN_{}", string);
                        let string_node_index = all_mappings[&string];
                        let field_identifier =
                            format!("F{}_{}_{}", f.identifier, fi.class_idx, fi.name_idx);
                        let field_node_index = all_mappings[&field_identifier];
                        g.add_edge(string_node_index, field_node_index, 1);
                        g.add_edge(field_node_index, string_node_index, 1);
                    }
                }
            }
        }
        for code in &class.codes {
            let type_name = f.get_type_name(code.method.class_idx).unwrap();
            let fqdn = format!(
                "{}->{}_{}",
                type_name, code.method.method_name, code.method.proto_name
            );
            let method_node_index = *(&all_mappings[&fqdn]);

            if is_interface {
                //for every interface we need to add a reference to the function sucht that later on
                // we can use the function definition in a invoke-interface
                interfaces.entry(class.class_idx).and_modify(|e| {
                    e.push((
                        code.method.method_name.to_string(),
                        code.method.proto_name.to_string(),
                        method_node_index,
                    ))
                });
            } else if !class.interfaces.is_empty() {
                //check all interfaces for...
                for &interface in &class.interfaces {
                    if let Some(interface_functions) = interfaces.get(&(interface as u32)) {
                        // same name and proto type
                        // TODO: maybe we should use a string here instead of the index since we have multiple dex files
                        let interface_node_index: Vec<NodeIndex> = interface_functions
                            .iter()
                            .filter_map(|(name, proto, idx)| {
                                if *name == code.method.method_name
                                    && *proto == code.method.proto_name
                                {
                                    Some(*idx)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        // just a non unwrap way of adding the edge for the node
                        // hopefully we onlly have one node
                        for n_idx in interface_node_index {
                            g.add_edge(n_idx, method_node_index, 1);
                        }
                    }
                }
            }

            g.add_edge(class_node_idx, method_node_index, 1);
        }
    }
}

fn prepare_mappings(
    multi_dex_file: &MultiDexFile,
    g: &mut Graph<InfoNode, i32>,
    all_mappings: &mut HashMap<String, NodeIndex>,
    exclude_classes: &[&str],
) -> (Vec<u16>, u16) {
    let mut string_type_idices = vec![];
    if let Some((_, type_idx)) = multi_dex_file.get_type_idx_for_string("Ljava/lang/String;") {
        string_type_idices.push(type_idx);
    }
    let byte_array_type =
        if let Some((_, type_idx)) = multi_dex_file.get_type_idx_for_string("Ljava/lang/String;") {
            type_idx
        } else {
            0
        };
    let types = multi_dex_file.types_enumerated();
    for (index, file, &ty) in types {
        if let Some(type_name) = file.get_string(ty as usize) {
            if type_name == "Ljava/lang/String;" {
                string_type_idices.push(index as u16);
            } else if type_name == "Ljava/lang/Object;" {
                continue;
            }
            let type_identifier = format!("T{}", type_name);
            let type_node_index = g.add_node(InfoNode::TypeNode(type_name.to_string()));
            all_mappings.insert(type_identifier, type_node_index);
        } else {
            log::error!("name non utf8");
            let type_node_index =
                g.add_node(InfoNode::TypeNode(format!("{}_{}", file.identifier, ty)));
            all_mappings.insert(format!("TUNKNOWN_TYPE_{}", ty), type_node_index);
        }
    }
    for (file, field, _) in multi_dex_file.fields() {
        let field_identifier = format!(
            "F{}_{}_{}",
            file.identifier, field.class_idx, field.name_idx
        );
        let field_node_index = g.add_node(InfoNode::FieldNode(
            field.clone(),
            file.strings[field.name_idx as usize]
                .to_str()
                .unwrap_or("INVALID_UTF8")
                .to_string(),
        ));
        all_mappings.insert(field_identifier, field_node_index);
    }
    for (file, method, _) in multi_dex_file.methods() {
        let type_name = file.get_type_name(method.class_idx).unwrap();
        let fqdn = format!(
            "{}->{}_{}",
            type_name, method.method_name, method.proto_name
        );
        let name = format!(
            "{}->{}{} (midx: {})",
            type_name, method.method_name, method.proto_name, method.method_idx,
        );

        if exclude_classes.iter().any(|c| type_name.contains(c)) {
            continue;
        }

        let method_node_index = g.add_node(InfoNode::MethodNode(method.clone(), name));
        all_mappings.insert(fqdn, method_node_index);
    }
    for (_, string, _) in multi_dex_file.strings() {
        if let Ok(the_string) = string.to_str() {
            let the_string_key = format!("SN_{}", the_string);
            let _ = all_mappings
                .entry(the_string_key)
                .or_insert_with(|| g.add_node(InfoNode::StringNode(the_string.to_string())));
        }
    }
    (string_type_idices, byte_array_type)
}
