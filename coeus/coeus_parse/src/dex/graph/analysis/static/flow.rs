// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose, Engine as _};
use coeus_emulation::vm::{runtime::StringClass, VM};
use coeus_models::models::{
    Class, DexFile, Instruction, InstructionOffset, InstructionSize, TestFunction,
};
use petgraph::graph::NodeIndex;

use crate::dex::graph::{ChangeSet, InfoNode};

use super::models::{FunctionTransformation, StaticRegister, StaticRegisterData};

/**
   After a branching instruction, a new branch is inserted. Each branch keeps track of the static registers encountered during that flow
*/
#[derive(Clone, Debug)]
pub struct Branch {
    id: u32,
    next: Option<InstructionOffset>,
    registers: Vec<StaticRegister>,
    last_method: Option<FunctionTransformation>,
    last_zero_branch_register: Option<(bool, StaticRegister)>,
    last_branch_register: Option<(StaticRegister, StaticRegister)>,
}

/**
A Flow represents the execution of a function. Here we check the flow statically, by inspecting the instructions but still having a strict top-down flow.
   Whereas emulation strictly follows one branch, we try to follow multiple branches.
*/
#[derive(Clone)]
pub struct Flow<'a> {
    branches: Vec<Branch>,
    instructions: &'a HashMap<InstructionOffset, (InstructionSize, Instruction)>,
    total_branches: u32,
    already_branched: Vec<InstructionOffset>,
}

impl<'a> Flow<'a> {
    /// Start a new flow
    pub fn new(instructions: &HashMap<InstructionOffset, (InstructionSize, Instruction)>) -> Flow {
        Flow {
            branches: vec![],
            instructions,
            total_branches: 0,
            already_branched: vec![],
        }
    }
    /// Start a new branch with the specified options
    pub fn new_branch(
        &mut self,
        next_instruction: Option<InstructionOffset>,
        registers: Vec<StaticRegister>,
    ) {
        let id: u32 = rand::random();

        self.total_branches += 1;
        self.branches.push(Branch {
            id,
            next: next_instruction,
            registers,
            last_method: None,
            last_branch_register: None,
            last_zero_branch_register: None,
        })
    }
    /// Fork from an existing branch
    fn fork(&mut self, mut branch: Branch) {
        let id: u32 = rand::random();
        self.total_branches += 1;
        branch.id = id;
        self.branches.push(branch);
    }
    /// Analyse each instruction by itself and start new branches on branching instructions
    pub fn next_instruction(
        &mut self,
        f: Arc<DexFile>,
        method_node_index: NodeIndex,
        nodes_to_add: &mut Vec<ChangeSet>,
        class: Arc<Class>,
        all_mappings: &HashMap<String, NodeIndex>,
        vm: &mut VM,
    ) -> bool {
        if self.branches.len() <= 0 {
            return false;
        }

        let mut finished_branches = vec![];
        let mut new_branches = vec![];
        self.branches.retain(|b| b.next.is_some());

        for branch in self.branches.iter_mut() {
            let instr =
                if let Some(next_instr) = self.instructions.get(branch.next.as_ref().unwrap()) {
                    next_instr
                } else {
                    log::debug!(
                        "{:?}",
                        self.instructions
                            .iter()
                            .map(|(offset, (size, _))| (offset, size.0 / 2))
                            .collect::<Vec<_>>()
                    );
                    finished_branches.push(branch.id);
                    continue;
                };
            let pc = branch.next.unwrap();
            branch.next = Some(pc + (instr.0 .0 / 2));

            match instr.1 {
                Instruction::Throw(_) => {
                    finished_branches.push(branch.id);
                    continue;
                }
                Instruction::PackedSwitch(_, table_offset)
                | Instruction::SparseSwitch(_, table_offset) => {
                    if let Some((_, Instruction::PackedSwitchData(switch))) =
                        self.instructions.get(&(pc + table_offset))
                    {
                        for (_, offset) in &switch.targets {
                            if self.total_branches < 200 {
                                let mut new_branch = branch.clone();
                                new_branch.next = Some(pc + *offset as i32);
                                new_branches.push(new_branch);
                            }
                        }
                    }
                    if let Some((_, Instruction::SparseSwitchData(switch))) =
                        self.instructions.get(&(pc + table_offset))
                    {
                        for (_, offset) in &switch.targets {
                            if self.total_branches < 200 {
                                let mut new_branch = branch.clone();
                                new_branch.next = Some(pc + *offset as i32);
                                new_branches.push(new_branch);
                            }
                        }
                    }
                }
                Instruction::Test(_, a, b, offset) if !self.already_branched.contains(&pc) => {
                    self.already_branched.push(pc);
                    let a: u32 = a.into();
                    let b: u32 = b.into();
                    let register_a = branch.registers[a as usize].clone();
                    let register_b = branch.registers[b as usize].clone();
                    branch.last_branch_register = Some((register_a, register_b));
                    if self.total_branches < 200 {
                        let mut new_branch = branch.clone();
                        new_branch.next = Some(pc + offset as i32);
                        new_branches.push(new_branch);
                    }
                }
                Instruction::TestZero(t, reg, offset) if !self.already_branched.contains(&pc) => {
                    self.already_branched.push(pc);
                    let offset_bool = if let TestFunction::Equal = t {
                        true
                    } else {
                        false
                    };
                    let register = branch.registers[reg as usize].clone();
                    let dead_branch = if let Some(transformation) = &register.transformation {
                        if transformation.return_type == "Z" {
                            vm.reset();
                            match transformation.run_transformation(vm) {
                                Ok(data) => {
                                    if let StaticRegisterData::Literal(lit) = data {
                                        log::warn!("Found dead branch");
                                        (true, lit == 1)
                                    } else {
                                        (false, false)
                                    }
                                }
                                Err(e) => {
                                    log::debug!("{:?}", e);
                                    (false, false)
                                }
                            }
                        } else {
                            (false, false)
                        }
                    } else {
                        (false, false)
                    };
                    if !dead_branch.0 {
                        branch.last_zero_branch_register = Some((!offset_bool, register.clone()));
                        if self.total_branches < 200 {
                            let mut new_branch = branch.clone();
                            new_branch.next = Some(pc + offset as i32);
                            branch.last_zero_branch_register =
                                Some((offset_bool, register.clone()));
                            new_branches.push(new_branch);
                        }
                    } else {
                        let is_one = dead_branch.1;
                        if is_one && !offset_bool {
                            branch.next = Some(pc + offset as i32);
                        }
                    }
                }
                Instruction::Return(..) | Instruction::ReturnVoid => {
                    finished_branches.push(branch.id)
                }
                Instruction::Goto8(offset) => {
                    branch.next = Some(pc + offset as i32);
                }
                Instruction::Goto16(offset) => {
                    branch.next = Some(pc + offset as i32);
                }
                Instruction::Goto32(offset) => {
                    branch.next = Some(pc + offset as i32);
                }
                // All invocations should point to the other function
                Instruction::InvokeVirtual(_, method, ref regs)
                | Instruction::InvokeSuper(_, method, ref regs)
                | Instruction::InvokeDirect(_, method, ref regs)
                | Instruction::InvokeStatic(_, method, ref regs)
                | Instruction::InvokeInterface(_, method, ref regs) => {
                    if method as usize > f.methods.len() {
                        log::warn!("{} out of bounds", method);
                        continue;
                    };
                    let method = &f.methods[method as usize];

                    let type_name = f.get_type_name(method.class_idx).unwrap();

                    let internal_type_name = format!("T{}", type_name);
                    // build function identifier for hash map lookup
                    let fqdn = format!(
                        "{}->{}_{}",
                        type_name, method.method_name, method.proto_name
                    );
                    log::debug!("{:?} [{}]", instr.1, fqdn);

                    let mut result = vec![];
                    let other_node = if let Some(&other_method_node_index) = all_mappings.get(&fqdn)
                    {
                        // only add one edge
                        result.push(ChangeSet::AddEdge {
                            start: method_node_index,
                            end: other_method_node_index,
                        });
                        if let Some(&other_type) = all_mappings.get(&internal_type_name) {
                            result.push(ChangeSet::AddEdge {
                                start: other_method_node_index,
                                end: other_type,
                            });
                        }
                        Some(other_method_node_index)
                    } else {
                        None
                    };
                    let mut arguments = vec![];
                    let mut i = 0;
                    let mut depends_on_argument = false;
                    for &arg in regs {
                        let mut stat = branch.registers[arg as usize].clone();
                        if stat.is_argument {
                            depends_on_argument = true;
                        }
                        stat.out_arg_number = i;
                        i += 1;
                        arguments.push(stat.clone());
                        if let Some(other_node) = other_node {
                            if stat.data.is_some() {
                                stat.last_branch = branch
                                    .last_zero_branch_register
                                    .as_ref()
                                    .and_then(|a| Some((a.0, a.1.transformation.clone())));
                                // log::error!("{:?}", stat.transformation);
                                result.push(ChangeSet::AddNodeFromTo {
                                    origin: method_node_index,
                                    destination: other_node,
                                    node: InfoNode::StaticArgumentNode(stat, branch.id),
                                    key: None,
                                });
                            }
                        } else {
                            result.push(ChangeSet::AddNodeTo {
                                origin: method_node_index,
                                node: InfoNode::StaticArgumentNode(stat, branch.id),
                                key: None,
                            });
                        }
                    }
                    let mut arraycopy = false;
                    if method.method_name.to_lowercase().contains("arraycopy") {
                        if let Some(arg) = arguments.get(2) {
                            if arg.is_array {
                                let static_register = StaticRegister {
                                    register: arguments[0].register,
                                    out_arg_number: arguments[0].out_arg_number,
                                    argument_number: 0,
                                    is_argument: arguments[0].is_argument,
                                    is_array: true,
                                    ty: arguments[0].ty.clone(),
                                    data: arguments[0].data.clone(),
                                    transformation: arguments[0].transformation.clone(),
                                    inner_data: arguments[0].inner_data.clone(),
                                    split_data: vec![],
                                    last_branch: None,
                                };
                                arraycopy = true;
                                branch.registers[arg.register as usize] = static_register;
                            }
                        }
                    }
                    if !arraycopy {
                        let proto_type = &f.protos[method.proto_idx as usize];
                        let return_type_name = f.get_type_name(proto_type.return_type_idx as usize);
                        branch.last_method = Some(FunctionTransformation {
                            dex_file: f.clone(),
                            class_name: f
                                .get_type_name(method.class_idx)
                                .unwrap_or("UNKNOWN_CLASS")
                                .to_string(),
                            method: method.clone(),
                            input_register: arguments,
                            return_type: return_type_name.unwrap_or("V").to_string(),
                            depends_on_argument,
                        });
                    }

                    nodes_to_add.extend(result);
                }
                Instruction::InvokeVirtualRange(_, method, _)
                | Instruction::InvokeSuperRange(_, method, _)
                | Instruction::InvokeDirectRange(_, method, _)
                | Instruction::InvokeStaticRange(_, method, _)
                | Instruction::InvokeInterfaceRange(_, method, _) => {
                    //TODO: why do we have indices larger than the array?
                    branch.last_method = None;
                    if method as usize > f.methods.len() {
                        continue;
                    };
                    let method = &f.methods[method as usize];

                    let type_name = f.get_type_name(method.class_idx).unwrap();
                    log::debug!("{:?} [{}]", instr.1, type_name);
                    let internal_type_name = format!("T{}", type_name);
                    // build function identifier for hash map lookup
                    let fqdn = format!(
                        "{}->{}_{}",
                        type_name, method.method_name, method.proto_name
                    );
                    let mut result = vec![];
                    if let Some(&other_method_node_index) = all_mappings.get(&fqdn) {
                        // only add one edge
                        result.push(ChangeSet::AddEdge {
                            start: method_node_index,
                            end: other_method_node_index,
                        });
                        if let Some(&other_type) = all_mappings.get(&internal_type_name) {
                            result.push(ChangeSet::AddEdge {
                                start: other_method_node_index,
                                end: other_type,
                            });
                        }
                    }
                    nodes_to_add.extend(result);
                }
                Instruction::Move(dst, src) | Instruction::MoveObject(dst, src) => {
                    let dst: u8 = (dst).into();
                    let src: u8 = (src).into();
                    branch.registers[dst as usize] = branch.registers[src as usize].clone();
                    continue;
                }

                Instruction::Move16(dst, src) | Instruction::MoveObject16(dst, src) => {
                    if branch.registers.len() <= dst as usize
                        || branch.registers.len() <= src as usize
                    {
                        continue;
                    }
                    branch.registers[dst as usize] = branch.registers[src as usize].clone();
                    continue;
                }

                Instruction::ConstLit4(dst, lit) => {
                    let dst: u8 = (dst).into();
                    let lit: i8 = lit.into();
                    branch.registers[dst as usize] = StaticRegister {
                        register: dst,
                        ty: Some("I".to_string()),
                        argument_number: 0,
                        is_array: false,
                        is_argument: false,
                        data: Some(StaticRegisterData::Literal(lit.into())),
                        transformation: None,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    continue;
                }
                Instruction::ConstLit16(dst, lit) => {
                    let dst = dst;
                    branch.registers[dst as usize] = StaticRegister {
                        register: dst,
                        argument_number: 0,
                        ty: Some("I".to_string()),
                        is_array: false,
                        is_argument: false,

                        data: Some(StaticRegisterData::Literal(lit.into())),
                        transformation: None,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    continue;
                }
                Instruction::ConstLit32(dst, lit) => {
                    let dst = dst;
                    branch.registers[dst as usize] = StaticRegister {
                        register: dst,
                        ty: Some("I".to_string()),
                        is_array: false,
                        is_argument: false,
                        argument_number: 0,
                        data: Some(StaticRegisterData::Literal(lit.into())),
                        transformation: None,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    continue;
                }

                Instruction::ConstString(dst, string) => {
                    // add string reference
                    let mut static_register = StaticRegister {
                        register: dst,
                        is_array: false,
                        ty: Some(StringClass::class_name().to_string()),
                        is_argument: false,
                        data: None,
                        transformation: None,
                        argument_number: 0,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    if let Some(the_string) = f.get_string(string) {
                        static_register.data = Some(StaticRegisterData::String {
                            content: the_string.to_string(),
                        });
                        let the_string = format!("SN_{}", the_string);
                        let string_node_index = all_mappings[&the_string];
                        // if !g.contains_edge(method_node_index, string_node_index) {
                        //     g.add_edge(method_node_index, string_node_index, 1);
                        // }
                        nodes_to_add.extend(vec![ChangeSet::AddEdge {
                            start: method_node_index,
                            end: string_node_index,
                        }]);
                    } else {
                        log::warn!("String {} not found", string);

                        static_register.data = Some(StaticRegisterData::String {
                            content: format!("String not found {}", string),
                        });
                    }
                    branch.registers[dst as usize] = static_register;
                    continue;
                }
                Instruction::ConstStringJumbo(dst, jmb) => {
                    let mut static_register = StaticRegister {
                        register: dst,
                        is_array: false,
                        ty: Some(StringClass::class_name().to_string()),
                        is_argument: false,
                        data: None,
                        transformation: None,
                        argument_number: 0,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    if let Some(the_string) = f.get_string(jmb as usize) {
                        static_register.data = Some(StaticRegisterData::String {
                            content: the_string.to_string(),
                        });
                    } else {
                        static_register.data = Some(StaticRegisterData::String {
                            content: format!("String not found {}", jmb),
                        });
                    }
                    continue;
                }

                Instruction::ConstClass(_, _) => {
                    continue;
                }

                Instruction::NewInstance(dst, ty) => {
                    let static_register = StaticRegister {
                        register: dst,
                        is_array: false,
                        argument_number: 0,
                        ty: f.get_type_name(ty).map(|s| s.to_string()),
                        is_argument: false,
                        data: None,
                        transformation: None,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    branch.registers[dst as usize] = static_register;
                }
                //TODO: link the register with the variable and the data
                Instruction::FillArrayData(dst, offset) => {
                    if let Some((_, Instruction::ArrayData(_, array_data))) =
                        self.instructions.get(&InstructionOffset(offset))
                    {
                        branch.registers[dst as usize] = StaticRegister {
                            register: dst,
                            argument_number: 0,
                            out_arg_number: 0,
                            ty: None,
                            is_array: true,
                            is_argument: false,
                            data: Some(StaticRegisterData::Array {
                                base64: general_purpose::STANDARD.encode(array_data),
                            }),
                            transformation: None,
                            inner_data: vec![],
                            split_data: vec![],
                            last_branch: None,
                        }
                    }
                    continue;
                }

                // all get and set funtions are connected to the corresponding field
                Instruction::StaticGet(dst, field)
                | Instruction::StaticGetWide(dst, field)
                | Instruction::StaticGetObject(dst, field)
                | Instruction::StaticGetBoolean(dst, field)
                | Instruction::StaticGetByte(dst, field)
                | Instruction::StaticGetChar(dst, field)
                | Instruction::StaticGetShort(dst, field) => {
                    if field as usize > f.fields.len() {
                        continue;
                    };
                    let data = class.get_data_for_static_field(field as u32).cloned();
                    let field = &f.fields[field as usize];
                    let class_name = f.get_type_name(field.class_idx);

                    let static_register = StaticRegister {
                        register: dst,
                        argument_number: 0,
                        ty: None,
                        is_argument: false,
                        is_array: false,
                        data: Some(StaticRegisterData::Field {
                            class_name: class_name.unwrap_or("CLASS NOT FOUND").to_string(),
                            field: field.clone(),
                            init_data: data,
                        }),
                        transformation: None,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    branch.registers[dst as usize] = static_register;
                    let field_identifier =
                        format!("F{}_{}_{}", f.identifier, field.class_idx, field.name_idx);
                    let field_node_index = all_mappings[&field_identifier];
                    // if !g.contains_edge(field_node_index, method_node_index) {
                    //     g.add_edge(field_node_index, method_node_index, 1);
                    // }
                    nodes_to_add.extend(vec![ChangeSet::AddEdge {
                        start: field_node_index,
                        end: method_node_index,
                    }]);
                }
                Instruction::ArrayPutByte(src, arr, index) => {
                    let val = if let Some(StaticRegisterData::Literal(val)) =
                        &branch.registers[src as usize].data
                    {
                        *val
                    } else {
                        0
                    };
                    if let &Some(StaticRegisterData::Literal(index)) =
                        &branch.registers[index as usize].data
                    {
                        let arr = &mut branch.registers[arr as usize];
                        if arr.is_array {
                            if arr.inner_data.len() > index as usize {
                                arr.inner_data[index as usize] = val as u8;
                            }
                        }
                    };
                }

                Instruction::NewArray(dst, size, ty) => {
                    let dst: u8 = dst.into();
                    let size: u8 = size.into();
                    let size = if let Some(StaticRegisterData::Literal(lit)) =
                        branch.registers[size as usize].data
                    {
                        usize::min(lit as usize, 100_000)
                    } else {
                        continue;
                    };
                    let array_register = StaticRegister {
                        register: dst,
                        argument_number: 0,
                        is_argument: false,
                        is_array: true,
                        ty: f.get_type_name(ty).map(|s| s.to_string()),
                        data: None,
                        transformation: None,
                        inner_data: vec![0; size as usize],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    branch.registers[dst as usize] = array_register;
                }

                Instruction::StaticPut(reg, field)
                | Instruction::StaticPutWide(reg, field)
                | Instruction::StaticPutObject(reg, field)
                | Instruction::StaticPutBoolean(reg, field)
                | Instruction::StaticPutByte(reg, field)
                | Instruction::StaticPutChar(reg, field)
                | Instruction::StaticPutShort(reg, field) => {
                    if field as usize > f.fields.len() {
                        continue;
                    };
                    let field = &f.fields[field as usize];
                    let field_identifier =
                        format!("F{}_{}_{}", f.identifier, field.class_idx, field.name_idx);
                    let field_node_index = all_mappings[&field_identifier];

                    nodes_to_add.extend(vec![ChangeSet::AddEdge {
                        start: method_node_index,
                        end: field_node_index,
                    }]);

                    let mut stat = branch.registers[reg as usize].clone();
                    stat.last_branch = branch
                        .last_zero_branch_register
                        .as_ref()
                        .and_then(|a| Some((a.0, a.1.transformation.clone())));

                    nodes_to_add.extend(vec![ChangeSet::AddNodeFrom {
                        destination: field_node_index,
                        node: InfoNode::StaticArgumentNode(stat, branch.id),
                        key: None,
                    }]);
                }

                Instruction::InstanceGet(dst, _, field)
                | Instruction::InstanceGetWide(dst, _, field)
                | Instruction::InstanceGetObject(dst, _, field)
                | Instruction::InstanceGetBoolean(dst, _, field)
                | Instruction::InstanceGetByte(dst, _, field)
                | Instruction::InstanceGetChar(dst, _, field)
                | Instruction::InstanceGetShort(dst, _, field) => {
                    let dst: u8 = (dst).into();
                    if field as usize > f.fields.len() {
                        continue;
                    };
                    let field = &f.fields[field as usize];
                    let class_name = f.get_type_name(field.class_idx);
                    let static_register = StaticRegister {
                        register: dst,
                        argument_number: 0,
                        ty: None,
                        is_argument: false,
                        is_array: false,
                        data: Some(StaticRegisterData::Field {
                            class_name: class_name.unwrap_or("CLASS NOT FOUND").to_string(),
                            field: field.clone(),
                            init_data: None,
                        }),
                        transformation: None,
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    branch.registers[dst as usize] = static_register;
                    let field_identifier =
                        format!("F{}_{}_{}", f.identifier, field.class_idx, field.name_idx);
                    let field_node_index = all_mappings[&field_identifier];
                    nodes_to_add.extend(vec![ChangeSet::AddEdge {
                        start: field_node_index,
                        end: method_node_index,
                    }]);
                }

                Instruction::InstancePut(_, _, field)
                | Instruction::InstancePutWide(_, _, field)
                | Instruction::InstancePutObject(_, _, field)
                | Instruction::InstancePutBoolean(_, _, field)
                | Instruction::InstancePutByte(_, _, field)
                | Instruction::InstancePutChar(_, _, field)
                | Instruction::InstancePutShort(_, _, field) => {
                    if field as usize > f.fields.len() {
                        continue;
                    };
                    let field = &f.fields[field as usize];
                    let field_identifier =
                        format!("F{}_{}_{}", f.identifier, field.class_idx, field.name_idx);
                    let field_node_index = all_mappings[&field_identifier];
                    // if !g.contains_edge(method_node_index, field_node_index) {
                    //     g.add_edge(method_node_index, field_node_index, 1);
                    // }
                    nodes_to_add.extend(vec![ChangeSet::AddEdge {
                        start: method_node_index,
                        end: field_node_index,
                    }]);
                }
                Instruction::MoveResultObject(dst) | Instruction::MoveResult(dst) => {
                    let static_register = StaticRegister {
                        argument_number: 0,
                        register: dst,
                        ty: None,
                        is_array: if let Some(last_method) = &branch.last_method {
                            last_method.return_type.starts_with("[")
                        } else {
                            false
                        },
                        is_argument: branch
                            .last_method
                            .as_ref()
                            .map(|lm| lm.depends_on_argument)
                            .unwrap_or(false),
                        data: None,
                        transformation: branch.last_method.clone(),
                        inner_data: vec![],
                        out_arg_number: 0,
                        split_data: vec![],
                        last_branch: None,
                    };
                    branch.registers[dst as usize] = static_register;
                    branch.last_method = None;
                    continue;
                }

                // these are special opcodes to define array data within instructions
                Instruction::ArrayData(_, ref data) => {
                    // let data = data.clone();
                    // let array_index = g.add_node(InfoNode::ArrayNode(data));
                    // g.add_edge(array_index, method_node_index, 1);
                    nodes_to_add.extend(vec![ChangeSet::AddNodeTo {
                        origin: method_node_index,
                        node: InfoNode::ArrayNode(data.clone()),
                        key: None,
                    }]);
                }
                _ => {
                    continue;
                }
            }
        }

        self.branches.retain(|b| !finished_branches.contains(&b.id));
        for b in new_branches {
            self.fork(b);
        }

        return true;
    }
}
