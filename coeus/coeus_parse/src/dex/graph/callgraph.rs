// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use coeus_models::models::Class;
use petgraph::{
    graph::{DiGraph, NodeIndex},
    visit::{Bfs, IntoNeighborsDirected, NodeFiltered, Reversed},
    Graph,
};

use super::{InfoNode, Subgraph};

/**
Try to get a sound callgraph for a class. This method tries to find all parent nodes, which possibly could connect, as well as child nodes. It does this with static analysis,
hence the sound graph should be sound, but not unique.
*/
pub fn callgraph(graph: &Graph<InfoNode, i32>, class: &Class, start: NodeIndex<u32>) -> Subgraph {
    let filtered_graph = NodeFiltered::from_fn(graph, |node| {
        graph.node_weight(node).map(|m| matches!(m,InfoNode::MethodNode(..))|| matches!(m,InfoNode::ClassNode(c) if c.class_idx == class.class_idx && c.dex_identifier == class.dex_identifier)).unwrap_or(false)
    });
    let backwards = Reversed(graph);
    let backwards_filtered = NodeFiltered::from_fn(backwards, |node| {
        graph
            .node_weight(node)
            .map(|m| matches!(m, InfoNode::MethodNode(..)) || matches!(m,InfoNode::ClassNode(c) if c.class_idx == class.class_idx && c.dex_identifier == class.dex_identifier))
            .unwrap_or(false)
    });

    let mut sub_graph: Graph<InfoNode, i32> = DiGraph::new();
    let mut node_mapping = HashMap::new();

    let mut walker_down = Bfs::new(&filtered_graph, start);
    let mut walker_up = Bfs::new(&backwards_filtered, start);

    //walk down and insert all nodes and edges as usual
    while let Some(next_node) = walker_down.next(&filtered_graph) {
        let weight = graph[next_node].clone();
        let new_index = sub_graph.add_node(weight);
        node_mapping.insert(next_node, new_index);
    }
    let mut walker_down = Bfs::new(&filtered_graph, start);
    while let Some(next_node) = walker_down.next(&filtered_graph) {
        let outgoing_neighbours =
            filtered_graph.neighbors_directed(next_node, petgraph::Direction::Outgoing);
        let this_node = node_mapping[&next_node];
        for outgoing in outgoing_neighbours {
            if let Some(&outgoing) = node_mapping.get(&outgoing) {
                sub_graph.add_edge(this_node, outgoing, 1);
            }
        }
    }
    // now do the same, but walk the graph backwards...
    while let Some(next_node) = walker_up.next(&backwards_filtered) {
        if next_node == start {
            continue;
        }
        let weight = graph[next_node].clone();
        let new_index = sub_graph.add_node(weight);
        node_mapping.insert(next_node, new_index);
    }
    //... important here, we need to reverse the edge since the backwards edge points in the wrong direction
    let mut walker_up = Bfs::new(&backwards_filtered, start);
    while let Some(next_node) = walker_up.next(&backwards_filtered) {
        let outgoing_neighbours =
            backwards_filtered.neighbors_directed(next_node, petgraph::Direction::Outgoing);
        let this_node = node_mapping[&next_node];
        for outgoing in outgoing_neighbours {
            if let Some(&outgoing) = node_mapping.get(&outgoing) {
                if !sub_graph.contains_edge(outgoing, this_node) {
                    sub_graph.add_edge(outgoing, this_node, 1);
                }
            }
        }
    }
    Subgraph {
        super_sub_mapping: node_mapping,
        sub_graph,
    }
}

//TODO: fix code duplication
/// Try to get the callgraph for a method. The function tries to find all possible parents as well as all possible childs.
pub fn callgraph_for_method(
    graph: &Graph<InfoNode, i32>,
    start: NodeIndex<u32>,
    ignore_methods: &[String],
) -> Subgraph {
    let filtered_graph = NodeFiltered::from_fn(graph, |node| {
        graph
            .node_weight(node)
            .map(|m| {
                matches!(
                    m,
                    InfoNode::MethodNode(..)
                        | InfoNode::ArrayNode(..)
                        | InfoNode::DynamicArgumentNode(..) // | InfoNode::DynamicReturnNode(..)
                        | InfoNode::StaticArgumentNode(..)
                ) && (!matches!(m, InfoNode::MethodNode(method, _) if ignore_methods.contains(&method.method_name)))
            })
            .unwrap_or(false)
    });
    let filtered_return = NodeFiltered::from_fn(graph, |node| {
        graph
            .node_weight(node)
            .map(|m| {
                matches!(
                    m,
                    InfoNode::MethodNode(..) | InfoNode::DynamicReturnNode(..) | InfoNode::StringNode(..) 
                ) && (!matches!(m, InfoNode::MethodNode(method, _) if ignore_methods.contains(&method.method_name)))
            })
            .unwrap_or(false)
    });
    let backwards = Reversed(graph);
    let backwards_filtered = NodeFiltered::from_fn(backwards, |node| {
        graph
            .node_weight(node)
            .map(|m| {
                matches!(
                    m,
                    InfoNode::MethodNode(..)
                        | InfoNode::ArrayNode(..)
                        | InfoNode::DynamicArgumentNode(..)
                        | InfoNode::DynamicReturnNode(..)
                        | InfoNode::StaticArgumentNode(..)
                ) && (!matches!(m, InfoNode::MethodNode(method, _) if ignore_methods.contains(&method.method_name)))
            })
            .unwrap_or(false)
    });

    let mut sub_graph: Graph<InfoNode, i32> = DiGraph::new();
    let mut node_mapping = HashMap::new();

    let mut walker_down = Bfs::new(&filtered_graph, start);
    let mut walker_up = Bfs::new(&backwards_filtered, start);

    //walk down and insert all nodes and edges as usual
    while let Some(next_node) = walker_down.next(&filtered_graph) {
        let weight = graph[next_node].clone();
        let new_index = sub_graph.add_node(weight);
        node_mapping.insert(next_node, new_index);
    }
    let mut walker_down = Bfs::new(&filtered_graph, start);
    while let Some(next_node) = walker_down.next(&filtered_graph) {
        let outgoing_neighbours =
            filtered_graph.neighbors_directed(next_node, petgraph::Direction::Outgoing);
        let this_node = node_mapping[&next_node];
        for outgoing in outgoing_neighbours {
            if let Some(&outgoing) = node_mapping.get(&outgoing) {
                if !sub_graph.contains_edge(this_node, outgoing) {
                    sub_graph.add_edge(this_node, outgoing, 1);
                }
            }
        }

        //get dynamic return value
        let incoming = filtered_return.neighbors_directed(next_node, petgraph::Direction::Incoming);
        for inc in incoming {
            if let Some(&inc) = node_mapping.get(&inc) {
                if !sub_graph.contains_edge(inc, this_node) {
                    sub_graph.add_edge(inc, this_node, 1);
                }
            } else {
                let weight = graph[inc].clone();
                if matches!(weight, InfoNode::DynamicReturnNode(..)) {
                    let new_index = sub_graph.add_node(weight);
                    node_mapping.insert(inc, new_index);
                    if !sub_graph.contains_edge(new_index, this_node) {
                        sub_graph.add_edge(new_index, this_node, 1);
                    }
                }
            }
        }
    }
    // now do the same, but walk the graph backwards...
    while let Some(next_node) = walker_up.next(&backwards_filtered) {
        if next_node == start {
            continue;
        }
        let weight = graph[next_node].clone();
        let new_index = sub_graph.add_node(weight);
        node_mapping.insert(next_node, new_index);
    }

    let mut walker_up = Bfs::new(&backwards_filtered, start);
    while let Some(next_node) = walker_up.next(&backwards_filtered) {
        let outgoing_neighbours =
            backwards_filtered.neighbors_directed(next_node, petgraph::Direction::Outgoing);
        let this_node = node_mapping[&next_node];
        for outgoing in outgoing_neighbours {
            if let Some(&outgoing) = node_mapping.get(&outgoing) {
                if !sub_graph.contains_edge(outgoing, this_node) {
                    sub_graph.add_edge(outgoing, this_node, 1);
                }
            }
        }
    }
    Subgraph {
        super_sub_mapping: node_mapping,
        sub_graph,
    }
}
