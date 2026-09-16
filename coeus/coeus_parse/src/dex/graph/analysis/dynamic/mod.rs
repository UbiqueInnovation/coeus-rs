// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use coeus_emulation::vm::{runtime::StringClass, Register, VMException, Value, VM};
use coeus_macros::iterator;
use coeus_models::models::MethodData;
use petgraph::{graph::NodeIndex, Graph};
use rayon::iter::ParallelIterator;
use std::collections::HashMap;

use crate::dex::graph::{ChangeSet, InfoNode};

pub fn get_dynamic_strings(
    graph: &Graph<InfoNode, i32>,
    _name: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // let regex = Regex::new(name)?;

    let mut evidences = vec![];

    for node in graph.node_weights() {
        let dynamic_string =
            if let InfoNode::DynamicArgumentNode(s) | InfoNode::DynamicReturnNode(s) = &node {
                s.clone()
            } else {
                continue;
            };
        evidences.push(dynamic_string);
    }
    Ok(evidences)
}
pub fn discover_dynamicnodes(
    vm: &mut VM,
    args: &[Register],
    method: &MethodData,
    dex_file: &str,
    method_node_index: NodeIndex,
    all_mappings: &HashMap<String, NodeIndex>,
) -> Vec<ChangeSet> {
    let method_index = method.method_idx;
    let code = method.code.as_ref().unwrap();
    // let mut mappings = vec![];
    let mut changes: Vec<ChangeSet> = vec![];

    let mut status = vm.start(method_index, dex_file, code, args.to_vec());
    let mut errors = 0;
    loop {
        match &status {
            &Err(VMException::Breakpoint(pc, method, context)) => {
                let registers = vm.get_registers();

                match context {
                    coeus_emulation::vm::BreakpointContext::ResultObjectRegister(reg) => {
                        if let Some(reg) = registers.get(reg as usize) {
                            if let Value::Object(obj) = vm.get_instance(reg.clone()) {
                                let string = format!("{}", obj);
                                let string_key = format!("DR_{}", string);
                                if !string.is_empty()
                                    && string != "NEW INSTANCE"
                                    && string != "test"
                                {
                                    // TODO: fix for correct method key
                                    let method = &vm.get_current_state().current_dex_file.methods
                                        [method as usize];
                                    let intermediate = iterator!(all_mappings)
                                        .find_any(|(key, _)| {
                                            key.ends_with(&format!(
                                                "{}_{}",
                                                method.method_name, method.proto_name
                                            )) && key.contains("->")
                                        })
                                        .map(|(_, &idx)| idx);
                                    if let Some(middle_man) = intermediate {
                                        changes.push(ChangeSet::AddNodeFromTo {
                                            node: InfoNode::DynamicReturnNode(string.clone()),
                                            key: Some(string_key),
                                            origin: method_node_index,
                                            destination: middle_man,
                                        });
                                    } else {
                                        changes.push(ChangeSet::AddNodeTo {
                                            origin: method_node_index,
                                            node: InfoNode::DynamicReturnNode(string.clone()),
                                            key: Some(string_key),
                                        });
                                    }
                                    // mappings.push((
                                    //     method_node_index,
                                    //     intermediate,
                                    //     false,
                                    //     Some(string_key),
                                    //     InfoNode::DynamicReturnNode(string.clone()),
                                    // ));
                                    // let string_node = all_mappings.entry(string_key).or_insert_with(|| g.add_node(InfoNode::DynamicReturnNode(string.clone()))).to_owned();
                                    // if let Some((_, the_idx)) =
                                    //     all_mappings.iter().find(|(key, _)| {
                                    //         key.ends_with(&format!("_{}", method))
                                    //             && key.contains("->")
                                    //     })
                                    // {
                                    //     if !g.contains_edge(*the_idx, string_node) {
                                    //         g.add_edge(*the_idx, string_node, 1);
                                    //     }
                                    // }
                                    // if !g.contains_edge(string_node, method_node_index) {
                                    //     g.add_edge(string_node, method_node_index, 1);
                                    // }
                                }
                            }
                        }
                    }
                    coeus_emulation::vm::BreakpointContext::FieldSet(reg, field_idx) => {
                        let current_state = vm.get_current_state();
                        let current_dex_file = &current_state.current_dex_file;
                        if let Some(field) = current_dex_file.fields.get(field_idx as usize) {
                            let field_identifier = format!(
                                "F{}_{}_{}",
                                current_dex_file.identifier, field.class_idx, field.name_idx
                            );
                            if let Some(field_index) = all_mappings.get(&field_identifier) {
                                if let Some(string_field) =
                                    vm.get_instance(registers[reg as usize].clone()).as_string()
                                {
                                    changes.push(ChangeSet::AddNodeFrom {
                                        destination: *field_index,
                                        key: Some(format!("DA_{}", string_field)),
                                        node: InfoNode::DynamicArgumentNode(string_field.clone()),
                                    });
                                    // mappings.push((
                                    //     *field_index,
                                    //     None,
                                    //     true,
                                    //     Some(format!("DA_{}", string_field)),
                                    //     InfoNode::DynamicArgumentNode(string_field),
                                    // ));
                                }
                            }
                        }
                    }
                    coeus_emulation::vm::BreakpointContext::ArrayReg(reg, method_ref)
                    | coeus_emulation::vm::BreakpointContext::StringReg(reg, method_ref) => {
                        match vm.get_instance(registers[reg as usize].clone()) {
                            Value::Array(a) => {
                                //only add arrays not equivalent to our initial state
                                if a != [0, 1, 2, 3, 4] {
                                    //if method == method_index as u32 {
                                    let intermediate = iterator!(all_mappings)
                                        .find_any(|(key, _)| {
                                            key.ends_with(&format!("_{}", method_ref))
                                                && key.contains("->")
                                        })
                                        .map(|(_, &idx)| idx);
                                    if let Some(middle_man) = intermediate {
                                        changes.push(ChangeSet::AddNodeFromTo {
                                            node: InfoNode::ArrayNode(
                                                (&a[..std::cmp::min(32, a.len())]).to_vec(),
                                            ),
                                            key: None,
                                            destination: method_node_index,
                                            origin: middle_man,
                                        });
                                    } else {
                                        changes.push(ChangeSet::AddNodeFrom {
                                            destination: method_node_index,
                                            node: InfoNode::ArrayNode(
                                                (&a[..std::cmp::min(32, a.len())]).to_vec(),
                                            ),
                                            key: None,
                                        });
                                    }
                                    // mappings.push((
                                    //     method_node_index,
                                    //     intermediate,
                                    //     true,
                                    //     None,
                                    //     InfoNode::ArrayNode(
                                    //         (&a[..std::cmp::min(32, a.len())]).to_vec(),
                                    //     ),
                                    // ));
                                }
                            }
                            Value::Object(class_instance)
                                if class_instance.class.class_name == StringClass::class_name() =>
                            {
                                //only add arrays not equivalent to our initial state
                                let string = format!("{}", class_instance);
                                if !string.is_empty()
                                    && string != "test"
                                    && string != "NEW INSTANCE"
                                {
                                    if method == method_index as u32 {
                                        let intermediate = iterator!(all_mappings)
                                            .find_any(|(key, _)| {
                                                key.ends_with(&format!("_{}", method_ref))
                                                    && key.contains("->")
                                            })
                                            .map(|(_, &idx)| idx);

                                        let string_key = format!("DA_{}", string);
                                        if let Some(middle_man) = intermediate {
                                            changes.push(ChangeSet::AddNodeFromTo {
                                                node: InfoNode::DynamicArgumentNode(string.clone()),
                                                key: Some(string_key),
                                                destination: method_node_index,
                                                origin: middle_man,
                                            });
                                        } else {
                                            changes.push(ChangeSet::AddNodeFrom {
                                                destination: method_node_index,
                                                node: InfoNode::DynamicArgumentNode(string.clone()),
                                                key: Some(string_key),
                                            });
                                        }
                                        // mappings.push((
                                        //     method_node_index,
                                        //     intermediate,
                                        //     true,
                                        //     Some(string_key),
                                        //     InfoNode::DynamicArgumentNode(string.clone()),
                                        // ));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
                log::debug!("Continue execution");
                status = vm.continue_execution(pc);
                log::debug!("Execution halted");
            }
            Err(VMException::NoInstructionAtAddress(..)) => {
                //log::warn!("No instruction");
                // if method.method_idx == 53962 {
                //     let state = vm.get_current_state();
                //     log::error!("{:#?}", state);
                //     log::error!("{:#?}", vm.get_stack_frames());
                // }
                break;
            }
            Err(err) => {
                let state = vm.get_current_state();
                let new_pc = state.pc + state.current_instruction_size;

                log::debug!("Encountered error during execution");
                log::debug!("{:#?}", err);
                log::debug!("{:#?}", state);
                /*
                log::debug!("{:#?}", vm.get_stack_frames());*/

                status = vm.continue_execution(new_pc);
                errors += 1;
                if errors > 10 {
                    break;
                }
            }
            _ => {
                break;
            }
        }
    }
    return changes;
}
