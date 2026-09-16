// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! This module provides functions to  register: (), is_argument: (), data: (), transformations: () register: (), is_argument: (), data: (), transformations: () register: (), is_argument: (), data: (), transformations: ()setup and work with graphs. Take a look a the `InfoNode` enum to get a feeling of what is contained in the graph. The `InfoNode` represents a Node-(Weight). The module also uses dex emulation to discover certain dynamic nodes, not directly present in the static dex file.

pub mod analysis;
pub mod callgraph;
pub mod information_graph;

use std::{collections::HashMap, fmt::Debug, sync::Arc};

use petgraph::{
    algo::kosaraju_scc,
    dot::Dot,
    graph::{DiGraph, NodeIndex},
    visit::Bfs,
    Graph,
};

use coeus_models::models::*;

use self::analysis::r#static::models::StaticRegister;

use super::get_string_from_idx;

/// An enum representing all possible nodes in the super graph
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum InfoNode {
    /// The type
    ClassNode(Arc<Class>),
    TypeNode(String),

    /// Methods
    MethodNode(Arc<Method>, String),
    CodeNode(CodeItem),

    /// Fields
    FieldNode(Arc<Field>, String),

    /// Constant data
    StringNode(String),
    /// Dynamically discovered Data such as return values, or values used as method parameters
    DynamicArgumentNode(String),
    DynamicReturnNode(String),
    /// Node storing array data
    ArrayNode(Vec<u8>),
    /// Static nodes
    StaticArgumentNode(StaticRegister, u32),
}

/// Debug implementation for displaying in the graph
impl Debug for InfoNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut df = f.debug_struct("InfoNode");
        match self {
            InfoNode::ClassNode(c) => df.field("class", &c.class_name).finish(),
            InfoNode::TypeNode(t) => df.field("type", &t).finish(),
            InfoNode::MethodNode(_m, fqdn) => df.field("method", fqdn).finish(),
            InfoNode::CodeNode(_) => df.field("code", &"").finish(),
            InfoNode::FieldNode(_, name) => df.field("field", name).finish(),
            InfoNode::StringNode(s) => df.field("string", s).finish(),
            InfoNode::DynamicArgumentNode(s) => df.field("dynamic_argument", s).finish(),
            InfoNode::DynamicReturnNode(s) => df.field("dynamic_return", s).finish(),
            InfoNode::ArrayNode(d) => df.field("array", d).finish(),
            InfoNode::StaticArgumentNode(s, ..) => {
                df.field("static_argument", &format!("{}", s)).finish()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Subgraph {
    pub super_sub_mapping: HashMap<NodeIndex, NodeIndex>,
    pub sub_graph: Graph<InfoNode, i32>,
}

impl Subgraph {
    pub fn to_dot(&self) -> String {
        format!("{:?}", Dot::new(&self.sub_graph))
    }
}

// unsafe impl Send for Supergraph{}
// unsafe impl Sync for Supergraph{}
#[derive(Debug, Clone)]
/// Struct holding a graph and a label to `NodeIndex` mapping. The node indices are stored efficiently, so to lookup certiain nodes, we need a mapping.
pub struct Supergraph {
    /// HashMap containing labels to node indices mapping
    pub class_node_mapping: HashMap<String, NodeIndex>,
    /// Actual "supergraph". This graph tries to cover the whole APK as a graph, representing connected nodes.
    pub super_graph: Graph<InfoNode, i32>,
}

impl Supergraph {
    /// Serialize the complete information graph in the same DOT format used
    /// by [`Subgraph::to_dot`].
    pub fn to_dot(&self) -> String {
        format!("{:?}", Dot::new(&self.super_graph))
    }
}

/// Get a subgraph starting from one NodeIndex
pub fn subgraph_for_node(graph: &Graph<InfoNode, i32>, start: NodeIndex<u32>) -> Subgraph {
    let mut sub_graph: Graph<InfoNode, i32> = DiGraph::new();
    let mut walker = Bfs::new(&graph, start);
    let mut node_mapping = HashMap::new();
    while let Some(next_node) = walker.next(&graph) {
        let weight = graph[next_node].clone();
        let new_node_index = if !node_mapping.contains_key(&next_node) {
            let new_index = sub_graph.add_node(weight.clone());
            node_mapping.insert(next_node, new_index);
            new_index
        } else {
            node_mapping[&next_node]
        };
        if matches!(weight, InfoNode::MethodNode(..)) {
            for n in graph.neighbors_directed(next_node, petgraph::Direction::Incoming) {
                if matches!(graph[n], InfoNode::FieldNode(..)) {
                    let weight = graph[n].clone();
                    let field_index = if !node_mapping.contains_key(&n) {
                        let field_index = sub_graph.add_node(weight);
                        node_mapping.insert(n, field_index);
                        field_index
                    } else {
                        node_mapping[&n]
                    };
                    if !sub_graph.contains_edge(field_index, new_node_index) {
                        sub_graph.add_edge(field_index, new_node_index, 1);
                    }

                    for constant in graph.neighbors(n) {
                        if matches!(
                            graph[constant],
                            InfoNode::StringNode(..)
                                | InfoNode::DynamicArgumentNode(..)
                                | InfoNode::StaticArgumentNode(..)
                        ) {
                            let weight = graph[constant].clone();
                            let constant_index = if !node_mapping.contains_key(&constant) {
                                let constant_index = sub_graph.add_node(weight);
                                if !sub_graph.contains_edge(constant_index, field_index) {
                                    sub_graph.add_edge(constant_index, field_index, 1);
                                }
                                constant_index
                            } else {
                                node_mapping[&constant]
                            };
                            node_mapping.insert(n, constant_index);
                        }
                    }
                }
            }
        }
    }
    let mut walker = Bfs::new(&graph, start);
    while let Some(next_node) = walker.next(&graph) {
        let outgoing_neighbours =
            graph.neighbors_directed(next_node, petgraph::Direction::Outgoing);
        let this_node = node_mapping[&next_node];
        for outgoing in outgoing_neighbours {
            let outgoing = node_mapping[&outgoing];
            if !sub_graph.contains_edge(this_node, outgoing) {
                sub_graph.add_edge(this_node, outgoing, 1);
            }
        }
    }
    Subgraph {
        super_sub_mapping: node_mapping,
        sub_graph,
    }
}

/// Get all nodes which are incomming nodes for `start`
pub fn get_method_neighbours(graph: &Graph<InfoNode, i32>, start: NodeIndex<u32>) -> Vec<InfoNode> {
    let mut nodes = vec![];
    for neighbour in graph.neighbors_directed(start, petgraph::Direction::Incoming) {
        if let Some(weight) = graph.node_weight(neighbour) {
            nodes.push(weight.to_owned());
        }
    }
    nodes
}

pub fn get_method_arguments(
    graph: &Graph<InfoNode, i32>,
    caller: NodeIndex<u32>,
    callee: NodeIndex<u32>,
) -> Vec<StaticRegister> {
    let mut arguments = vec![];
    for neighbour in graph.neighbors_directed(caller, petgraph::Direction::Outgoing) {
        if graph.contains_edge(neighbour, callee) {
            match graph.node_weight(neighbour) {
                Some(InfoNode::StaticArgumentNode(stat, ..)) => {
                    arguments.push(stat.clone());
                }
                _ => {}
            }
        }
    }
    return arguments;
}

/// Get all nodes which are outcoming nodes for `start`
pub fn get_data_context(graph: &Graph<InfoNode, i32>, start: NodeIndex<u32>) -> Vec<InfoNode> {
    let mut nodes = vec![];

    for neighbour in graph.neighbors_directed(start, petgraph::Direction::Outgoing) {
        if let Some(weight) = graph.node_weight(neighbour) {
            if !matches!(weight, InfoNode::StaticArgumentNode(..)) {
                nodes.push(weight.to_owned());
            }
        }
    }
    for neighbour in graph.neighbors_directed(start, petgraph::Direction::Incoming) {
        if let Some(weight) = graph.node_weight(neighbour) {
            if !matches!(weight, InfoNode::StaticArgumentNode(..)) {
                nodes.push(weight.to_owned());
            }
        }
    }
    nodes
}

pub fn find_incoming_arguments(
    graph: &Graph<InfoNode, i32>,
    start: NodeIndex<u32>,
    is_argument: bool,
    level: u32,
    max_level: i32,
) -> Vec<(u32, InfoNode)> {
    let mut nodes = vec![];
    if max_level > 0 && level as i32 > max_level {
        return nodes;
    }
    let start = if is_argument {
        let parent = graph
            .neighbors_directed(start, petgraph::Direction::Incoming)
            .next();
        if let Some(parent) = parent {
            parent
        } else {
            start
        }
    } else {
        start
    };

    for neighbour in graph.neighbors_directed(start, petgraph::Direction::Incoming) {
        if let Some(weight) = graph.node_weight(neighbour) {
            if let InfoNode::StaticArgumentNode(stat, ..) = weight {
                if stat.is_argument {
                    nodes.extend(find_incoming_arguments(
                        graph,
                        neighbour,
                        true,
                        level + 1,
                        max_level,
                    ));
                }
                nodes.push((level, weight.to_owned()));
            }
        }
    }
    nodes
}

/// Enum to track changes to the graph. This allows us to collect some changes in parallel and insert them sequentially (we need a lock on the graph)
pub enum ChangeSet {
    /// Add a `node` to the graph and add an edge from `origin` to `node`
    AddNodeTo {
        origin: NodeIndex,
        node: InfoNode,
        key: Option<String>,
    },
    /// Add a `node` to the graph and an edge from `node` to destination
    AddNodeFrom {
        destination: NodeIndex,
        node: InfoNode,
        key: Option<String>,
    },
    /// Add a `node to the graph and an edge from `origin` to `node` and `node` to `destination`
    AddNodeFromTo {
        origin: NodeIndex,
        destination: NodeIndex,
        node: InfoNode,
        key: Option<String>,
    },
    /// Add an edge from `start` to `end`
    AddEdge { start: NodeIndex, end: NodeIndex },
}

/// Build the call graph for a method with known instructions
pub fn build_graph(
    code: &CodeItem,
    config: &DexHeader,
    method: &EncodedMethod,
    strings: &[StringEntry],
    types: &[u32],
    methods: &[Arc<Method>],
) -> Option<Graph<(u32, Instruction), i32>> {
    if (method.code_off as u32) < config.data_off {
        return None;
    }

    let mut peekable = code.insns.iter();

    let mut g: Graph<(u32, Instruction), i32> = DiGraph::new();

    let first = peekable.next().unwrap();
    if let Instruction::Invoke(idx) = &first.2 {
        if let Some(method) = methods.get(*idx as usize) {
            let ins = Instruction::InvokeType(format!(
                "{}->{}",
                get_string_from_idx(types[method.class_idx as usize] as u16, &strings).unwrap(),
                method.get_function_name(&strings)
            ));
            g.add_node((0, ins));
        } else {
            g.add_node((0, first.2.to_owned()));
        }
    } else if let Instruction::NewInstance(_, idx) = &first.2 {
        if let Some(ty) = types.get(*idx as usize) {
            let ins = Instruction::NewInstanceType(format!("{}", ty));
            g.add_node((0, ins));
        } else {
            g.add_node((0, first.2.to_owned()));
        }
    } else {
        g.add_node((0, first.2.to_owned()));
    }

    let mut index = 1;
    let mut addr_index_map = HashMap::new();
    let mut still_to_insert = HashMap::new();
    let mut skip_edge = false;

    for (_, addr, p) in peekable {
        if let Instruction::Invoke(idx) = p {
            if let Some(method) = methods.get(*idx as usize) {
                let ins = Instruction::InvokeType(format!(
                    "{}->{}",
                    get_string_from_idx(types[method.class_idx as usize] as u16, &strings).unwrap(),
                    method.get_function_name(&strings)
                ));
                g.add_node((u32::from(*addr), ins));
            } else {
                g.add_node((u32::from(*addr), p.to_owned()));
            }
        } else if let Instruction::NewInstance(_, idx) = p {
            if let Some(ty) = types.get(*idx as usize) {
                let ins = Instruction::NewInstanceType(format!("{}", ty));
                g.add_node((u32::from(*addr), ins));
            } else {
                g.add_node((u32::from(*addr), p.to_owned()));
            }
        } else {
            g.add_node((u32::from(*addr), p.to_owned()));
        }
        if !skip_edge {
            g.add_edge(NodeIndex::new(index - 1), NodeIndex::new(index), 1);
        } else {
            skip_edge = false;
        }

        addr_index_map.insert(u32::from(*addr), index);

        if let Some(need_to_insert) = still_to_insert.get(&u32::from(*addr)) {
            for &ele in need_to_insert {
                g.add_edge(NodeIndex::new(ele), NodeIndex::new(index), 1);
            }
        }

        match p {
            Instruction::Test(_, _, _, addr_offset) => {
                if *addr_offset < 0 {
                    if let Some(goto_index) =
                        addr_index_map.get(&((i32::from(*addr) + *addr_offset as i32) as u32))
                    {
                        g.add_edge(NodeIndex::new(index), NodeIndex::new(*goto_index), 1);
                    }
                } else {
                    let indices = still_to_insert
                        .entry((i32::from(*addr) + *addr_offset as i32) as u32)
                        .or_insert_with(Vec::new);
                    indices.push(index);
                }
            }
            Instruction::TestZero(_, _, addr_offset) => {
                if *addr_offset < 0 {
                    if let Some(goto_index) =
                        addr_index_map.get(&((i32::from(*addr) + *addr_offset as i32) as u32))
                    {
                        g.add_edge(NodeIndex::new(index), NodeIndex::new(*goto_index), 1);
                    }
                } else {
                    let indices = still_to_insert
                        .entry((i32::from(*addr) + *addr_offset as i32) as u32)
                        .or_insert_with(Vec::new);
                    indices.push(index);
                }
            }
            Instruction::RemInt(..)
            | Instruction::RemIntDst(..)
            | Instruction::RemIntLit16(..)
            | Instruction::RemIntLit8(..)
            | Instruction::RemLong(..)
            | Instruction::RemLongDst(..) => {}

            Instruction::XorInt(..)
            | Instruction::XorIntDst(..)
            | Instruction::XorIntDstLit16(..)
            | Instruction::XorIntDstLit8(..)
            | Instruction::XorLong(..)
            | Instruction::XorLongDst(..) => {}

            Instruction::ArrayGetByte(..) => {}
            Instruction::ArrayPutByte(..) => {}

            Instruction::Goto8(addr_offset) => {
                skip_edge = true;
                if *addr_offset < 0 {
                    if let Some(goto_index) =
                        addr_index_map.get(&((i32::from(*addr) + *addr_offset as i32) as u32))
                    {
                        g.add_edge(NodeIndex::new(index), NodeIndex::new(*goto_index), 1);
                    }
                } else {
                    let indices = still_to_insert
                        .entry((i32::from(*addr) + *addr_offset as i32) as u32)
                        .or_insert_with(Vec::new);
                    indices.push(index);
                }
            }
            Instruction::Goto16(addr_offset) => {
                skip_edge = true;
                if *addr_offset < 0 {
                    if let Some(goto_index) =
                        addr_index_map.get(&((i32::from(*addr) + *addr_offset as i32) as u32))
                    {
                        g.add_edge(NodeIndex::new(index), NodeIndex::new(*goto_index), 1);
                    }
                } else {
                    let indices = still_to_insert
                        .entry((i32::from(*addr) + *addr_offset as i32) as u32)
                        .or_insert_with(Vec::new);
                    indices.push(index);
                }
            }
            Instruction::Goto32(addr_offset) => {
                skip_edge = true;
                if *addr_offset < 0 {
                    if let Some(goto_index) =
                        addr_index_map.get(&((i32::from(*addr) + *addr_offset as i32) as u32))
                    {
                        g.add_edge(NodeIndex::new(index), NodeIndex::new(*goto_index), 1);
                    }
                } else {
                    let indices = still_to_insert
                        .entry((i32::from(*addr) + *addr_offset as i32) as u32)
                        .or_insert_with(Vec::new);
                    indices.push(index);
                }
            }
            Instruction::Return(..) | Instruction::ReturnVoid => {
                skip_edge = true;
            }

            _ => {}
        }

        index += 1;
    }

    Some(g)
}

/// Use the Debug implementation to print the graph in a dot-style manner to a file
pub fn print_dot_for_graph(g: &Graph<(u32, Instruction), i32>, file_path: &str) {
    std::fs::write(file_path, format!("{:?}", Dot::new(g))).unwrap();
}

/// Print all strongly connected parts of the graph
pub fn print_strongly_connected_sub_graphs(g: &Graph<(u32, Instruction), i32>, file_path: &str) {
    let res = kosaraju_scc(&g);
    let mut subgraph_number = 0;
    for mut r in res {
        if r.iter().count() > 1 {
            r.sort_by(|a, b| {
                (g.node_weight(*a).unwrap().0)
                    .partial_cmp(&(g.node_weight(*b).unwrap()).0)
                    .unwrap()
            });
            let mut index_iterator = r.iter();
            let mut subgraph: Graph<(u32, Instruction), u32> = Graph::new();
            let last_index = index_iterator.next().unwrap().to_owned();
            let first_weight = g.node_weight(last_index).unwrap();

            subgraph.add_node(first_weight.to_owned());
            let mut last_index = 0;

            for index in index_iterator {
                subgraph.add_node(g.node_weight(*index).unwrap().to_owned());
                subgraph.add_edge(
                    NodeIndex::new(last_index),
                    NodeIndex::new(last_index + 1),
                    1,
                );
                last_index += 1;
            }
            subgraph.add_edge(NodeIndex::new(last_index), NodeIndex::new(0), 1);

            std::fs::write(
                format!("{}_{}.dot", file_path, subgraph_number),
                format!("{:?}", Dot::new(&subgraph)),
            )
            .unwrap();
            subgraph_number += 1;
        }
    }
}
