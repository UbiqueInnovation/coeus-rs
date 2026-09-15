// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! This module provides parsing methods to decode the dex file into a DexFile struct.
pub mod encode;
pub mod graph;

use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
};

use coeus_macros::iterator;
use coeus_models::models::*;

use self::graph::build_graph;

#[cfg(not(target_arch = "wasm32"))]
use rayon::iter::ParallelIterator;

const NO_INDEX: u32 = 0xffffffff;

pub trait ReadSeek: Read + Seek {}

impl<T> ReadSeek for T where T: Read + Seek {}

pub struct ArrayView<'a, T> {
    data: &'a [T],
}

impl<'a, T> ArrayView<'a, T> {
    pub fn from_vec(data: &[T]) -> ArrayView<T> {
        ArrayView { data }
    }
    pub fn new(data: &[T]) -> ArrayView<T> {
        ArrayView { data }
    }
    pub fn get_cursor(&self) -> Cursor<&[T]> {
        Cursor::new(self.data)
    }
}

pub fn parse_dex<R: Read>(file_name: &str, mut f: R, should_build_graph: bool) -> Option<DexFile> {
    let mut buffer = vec![];
    f.read_to_end(&mut buffer).expect("Could not read dex file");
    parse_dex_buf(file_name, &ArrayView::new(&buffer), should_build_graph)
}

pub fn parse_dex_buf(
    file_name: &str,
    buffer: &ArrayView<u8>,
    should_build_graph: bool,
) -> Option<DexFile> {
    let mut pool_cursor = buffer.get_cursor();
    let config: DexHeader = DexHeader::from_bytes(&mut pool_cursor);

    pool_cursor
        .seek(SeekFrom::Start(config.string_ids_off as u64))
        .ok()?;

    let strings = parse_string_table(
        config.string_ids_off,
        config.string_ids_size,
        &mut pool_cursor,
    );

    pool_cursor
        .seek(SeekFrom::Start(config.type_ids_off as u64))
        .ok()?;

    let types = parse_type_table(config.type_ids_size, &mut pool_cursor);

    pool_cursor
        .seek(SeekFrom::Start(config.proto_ids_off as u64))
        .ok()?;

    let protos = parse_proto_table(config.proto_ids_size, &mut pool_cursor);

    pool_cursor
        .seek(SeekFrom::Start(config.method_ids_off as u64))
        .ok()?;

    let methods = parse_method_table(
        config.method_ids_size,
        &strings,
        &protos,
        &types,
        &mut pool_cursor,
    );

    pool_cursor
        .seek(SeekFrom::Start(config.fields_ids_off as u64))
        .ok()?;

    let fields = parse_fields_table(config.fields_ids_size, &mut pool_cursor, &strings);

    let mut class_cursor = buffer.get_cursor();
    class_cursor
        .seek(SeekFrom::Start(config.class_defs_off as u64))
        .ok()?;

    let classes = parse_class_def_table(config.class_defs_size, &mut class_cursor);

    let mut ret_classes = Vec::with_capacity(classes.len());
    let vec_lock = Arc::new(Mutex::new(&mut ret_classes));
    let v_table = Mutex::new(HashMap::new());
    let s_table = Mutex::new(HashMap::new());

    iterator!(classes).for_each(|class| {
        //class is not here, but still link it (e.g. sdk stuff)
        if class.class_data_off < config.data_off {
            let the_class = Arc::new(Class {
                dex_identifier: format!("{:02x?}", config.signature),
                class_idx: class.class_idx,
                access_flags: AccessFlags::from_bits(class.access_flags as u64)
                    .expect("wrong access flags"),
                super_class: class.superclass_idx,
                class_name: get_string_from_idx(types[class.class_idx as usize] as u16, &strings)
                    .unwrap_or_else(|| {
                        log::error!("Could not resolve class name");
                        "-UNKONWN-".to_string()
                    }),
                class_data: None,
                codes: vec![],
                static_fields: vec![],
                interfaces: vec![],
                annotations_off: class.annotations_off,
                annotations: vec![],
                method_annotations: vec![],
                field_annotations: vec![],
            });
            if let Ok(mut ret_classes) = vec_lock.lock() {
                ret_classes.push(the_class.clone());
            };
            if let Some(flags) = AccessFlags::from_bits(class.access_flags as u64) {
                if flags.contains(AccessFlags::INTERFACE) {
                    if let Ok(mut table_lock) = v_table.lock() {
                        table_lock.insert(the_class.class_name.clone(), vec![]);
                    }
                }
            }
            return;
        }
        let vec_lock = Arc::clone(&vec_lock);

        let mut class_data_cursor = buffer.get_cursor();
        class_data_cursor
            .seek(SeekFrom::Start(class.class_data_off as u64))
            .unwrap();
        let class_data = Some(ClassData::from_bytes(&mut class_data_cursor));

        let static_fields = {
            if class.static_values_off == 0 {
                vec![]
            } else {
                class_data_cursor
                    .seek(SeekFrom::Start(class.static_values_off as u64))
                    .unwrap();
                EncodedArray::from_bytes(&mut class_data_cursor).into_items()
            }
        };

        let interfaces = {
            if class.interfaces_off == 0 {
                vec![]
            } else {
                class_data_cursor
                    .seek(SeekFrom::Start(class.interfaces_off as u64))
                    .unwrap();
                let size = u32::from_bytes(&mut class_data_cursor);
                let mut interfaces = vec![];
                for _ in 0..size {
                    let type_idx = u16::from_bytes(&mut class_data_cursor);
                    interfaces.push(type_idx);
                }
                interfaces
            }
        };
        let annotations;
        let method_annotations;
        let field_annotations: Vec<AnnotationField>;

        if class.annotations_off == 0 {
            annotations = vec![];
            method_annotations = vec![];
            field_annotations = vec![];
        } else {
            class_data_cursor
                .seek(SeekFrom::Start(class.annotations_off as u64))
                .unwrap();
            let annotations_directory_item =
                AnnotationsDirectoryItem::from_bytes(&mut class_data_cursor);

            annotations = 'annotations: {
                if annotations_directory_item.class_annotations_off == 0 {
                    break 'annotations vec![];
                }

                class_data_cursor
                    .seek(SeekFrom::Start(
                        annotations_directory_item.class_annotations_off as u64,
                    ))
                    .unwrap();
                let annotation_set_item: AnnotationSetItem =
                    AnnotationSetItem::from_bytes(&mut class_data_cursor);

                let mut annotations: Vec<Annotation> = vec![];
                for annotation in &annotation_set_item.entries {
                    class_data_cursor
                        .seek(SeekFrom::Start(annotation.annotation_off as u64))
                        .unwrap();

                    let annotation_item: AnnotationItem =
                        AnnotationItem::from_bytes(&mut class_data_cursor);
                    let encoded_annotation: EncodedAnnotation = annotation_item.annotation;

                    let mut annotation_elements_data: Vec<AnnotationElementsData> = vec![];
                    for annotation_element in &encoded_annotation.elements {
                        let name = annotation_element.name_idx;
                        let encoded_item = &annotation_element.value;

                        //TODO: check other values and subannotations
                        let val = encoded_item.to_string_with_string_indexer(|idx| {
                            get_string_from_idx(idx, &strings).unwrap_or_else(|| String::new())
                        });

                        let data = AnnotationElementsData {
                            name: get_string_from_idx(name as u16, &strings).unwrap_or_else(|| {
                                log::error!("Could not resolve class name");
                                "-UNKONWN-".to_string()
                            }),
                            value: val,
                        };

                        annotation_elements_data.push(data);
                    }

                    let class_name = get_string_from_idx(
                        types[encoded_annotation.type_idx as usize] as u16,
                        &strings,
                    )
                    .unwrap_or_else(|| {
                        log::error!("Could not resolve class name");
                        "-UNKONWN- Class".to_string()
                    });

                    let annotation: Annotation = Annotation {
                        visibility: annotation_item.visibility,
                        type_idx: encoded_annotation.type_idx,
                        class_name,
                        elements: annotation_elements_data,
                    };

                    annotations.push(annotation);
                }

                annotations
            };

            method_annotations = 'method_annotations: {
                if annotations_directory_item.class_annotations_off == 0 {
                    break 'method_annotations vec![];
                }

                class_data_cursor
                    .seek(SeekFrom::Start(class.annotations_off as u64))
                    .unwrap();

                let mut m_annotations: Vec<AnnotationMethod> = vec![];

                for method_annotation in &annotations_directory_item.method_annotations {
                    let m_annotations_off = method_annotation.annotations_off;

                    class_data_cursor
                        .seek(SeekFrom::Start(m_annotations_off as u64))
                        .unwrap();

                    let annotation_set_item = AnnotationSetItem::from_bytes(&mut class_data_cursor);

                    for j in 0..annotation_set_item.size {
                        class_data_cursor
                            .seek(SeekFrom::Start(
                                annotation_set_item.entries[j as usize].annotation_off as u64,
                            ))
                            .unwrap();

                        let annotation_item: AnnotationItem =
                            AnnotationItem::from_bytes(&mut class_data_cursor);
                        let encoded_annotation: EncodedAnnotation = annotation_item.annotation;

                        let mut annotation_elements_data: Vec<AnnotationElementsData> = vec![];
                        for annotation in &encoded_annotation.elements {
                            let name = annotation.name_idx;
                            let encoded_item = &annotation.value;

                            //TODO: check other values and subannotations
                            let val = encoded_item.to_string_with_string_indexer(|idx| {
                                get_string_from_idx(idx, &strings).unwrap_or_else(|| String::new())
                            });

                            let data = AnnotationElementsData {
                                name: get_string_from_idx(name as u16, &strings).unwrap_or_else(
                                    || {
                                        log::error!("Could not resolve class name");
                                        "-UNKONWN-".to_string()
                                    },
                                ),
                                value: val,
                            };
                            annotation_elements_data.push(data);
                        }

                        let class_name = get_string_from_idx(
                            types[encoded_annotation.type_idx as usize] as u16,
                            &strings,
                        )
                        .unwrap_or_else(|| {
                            log::error!("Could not resolve class name");
                            "-UNKONWN- Class".to_string()
                        });

                        let m_annotation: AnnotationMethod = AnnotationMethod {
                            method_idx: method_annotation.method_idx,
                            visibility: annotation_item.visibility,
                            type_idx: encoded_annotation.type_idx,
                            class_name,
                            elements: annotation_elements_data,
                        };

                        m_annotations.push(m_annotation);
                    }
                }

                m_annotations
            };

            field_annotations = 'field_annotations: {
                if annotations_directory_item.class_annotations_off == 0 {
                    break 'field_annotations vec![];
                }

                class_data_cursor
                    .seek(SeekFrom::Start(class.annotations_off as u64))
                    .unwrap();

                let mut f_annotations: Vec<AnnotationField> = vec![];

                for field_annotation in &annotations_directory_item.field_annotations {
                    let f_annotations_off = field_annotation.annotations_off;

                    class_data_cursor
                        .seek(SeekFrom::Start(f_annotations_off as u64))
                        .unwrap();

                    let annotation_set_item = AnnotationSetItem::from_bytes(&mut class_data_cursor);

                    for j in 0..annotation_set_item.size {
                        class_data_cursor
                            .seek(SeekFrom::Start(
                                annotation_set_item.entries[j as usize].annotation_off as u64,
                            ))
                            .unwrap();

                        let annotation_item: AnnotationItem =
                            AnnotationItem::from_bytes(&mut class_data_cursor);
                        let encoded_annotation: EncodedAnnotation = annotation_item.annotation;

                        let mut annotation_elements_data: Vec<AnnotationElementsData> = vec![];
                        for annotation in &encoded_annotation.elements {
                            let name = annotation.name_idx;
                            let encoded_item = &annotation.value;

                            //TODO: check other values and subannotations
                            let val = encoded_item.to_string_with_string_indexer(|idx| {
                                get_string_from_idx(idx, &strings).unwrap_or_else(|| String::new())
                            });

                            let data = AnnotationElementsData {
                                name: get_string_from_idx(name as u16, &strings).unwrap_or_else(
                                    || {
                                        log::error!("Could not resolve class name");
                                        "-UNKONWN-".to_string()
                                    },
                                ),
                                value: val,
                            };
                            annotation_elements_data.push(data);
                        }

                        let class_name = get_string_from_idx(
                            types[encoded_annotation.type_idx as usize] as u16,
                            &strings,
                        )
                        .unwrap_or_else(|| {
                            log::error!("Could not resolve class name");
                            "-UNKONWN- Class".to_string()
                        });

                        let f_annotation: AnnotationField = AnnotationField {
                            field_idx: field_annotation.field_idx,
                            visibility: annotation_item.visibility,
                            type_idx: encoded_annotation.type_idx,
                            class_name,
                            elements: annotation_elements_data,
                        };

                        f_annotations.push(f_annotation);
                    }
                }

                f_annotations
            };
        }
        let class_name = get_string_from_idx(types[class.class_idx as usize] as u16, &strings)
            .unwrap_or_else(|| {
                log::error!("Could not resolve class name");
                "-UNKONWN-".to_string()
            });
        let mut the_class = Class {
            dex_identifier: format!("{:02x?}", config.signature),
            class_idx: class.class_idx,
            access_flags: AccessFlags::from_bits(class.access_flags as u64)
                .expect("accessflags wrong"),
            super_class: class.superclass_idx,
            class_name: class_name.clone(),
            class_data,
            codes: vec![],
            static_fields,
            interfaces,
            annotations_off: class.annotations_off,
            annotations,
            method_annotations,
            field_annotations,
        };

        //todo we need the native functions (NO_INDEX since no instructions)
        for method in &the_class.class_data.as_ref().unwrap().virtual_methods {
            //only try to parse of code if it is in the data section
            let new_m = methods[method.method_idx as usize].clone();
            if (method.code_off as u32) < config.data_off {
                the_class.codes.push(Arc::new(MethodData {
                    method_idx: new_m.method_idx as u32,
                    name: new_m.method_name.clone(),
                    method: new_m,
                    access_flags: method.access_flags,
                    code: None,
                    call_graph: None,
                }));
                continue;
            }
            let mut class_method_cursor = buffer.get_cursor();
            class_method_cursor
                .seek(SeekFrom::Start(method.code_off as u64))
                .unwrap();
            let mut code = CodeItem::from_bytes(&mut class_method_cursor);
            code.code_off = method.code_off as u32;

            the_class.codes.push(Arc::new(MethodData {
                method_idx: new_m.method_idx as u32,
                access_flags: method.access_flags,
                name: new_m.method_name.clone(),
                method: new_m,
                call_graph: if should_build_graph {
                    build_graph(&code, &config, method, &strings, &types, &methods)
                } else {
                    None
                },
                code: Some(code),
            }));
        }
        for method in &the_class.class_data.as_ref().unwrap().direct_methods {
            //only try to parse of code if it is in the data section
            let new_m = methods[method.method_idx as usize].clone();
            if (method.code_off as u32) < config.data_off {
                the_class.codes.push(Arc::new(MethodData {
                    method_idx: new_m.method_idx as u32,
                    access_flags: method.access_flags,
                    name: new_m.method_name.clone(),
                    method: new_m,
                    code: None,
                    call_graph: None,
                }));
                continue;
            }
            let mut class_method_cursor = buffer.get_cursor();
            class_method_cursor
                .seek(SeekFrom::Start(method.code_off as u64))
                .unwrap();
            let mut code = CodeItem::from_bytes(&mut class_method_cursor);
            code.code_off = method.code_off as u32;

            the_class.codes.push(Arc::new(MethodData {
                method_idx: new_m.method_idx as u32,
                access_flags: method.access_flags,
                name: new_m.method_name.clone(),
                method: new_m,
                call_graph: if should_build_graph {
                    build_graph(&code, &config, method, &strings, &types, &methods)
                } else {
                    None
                },
                code: Some(code),
            }));
        }
        let the_class = Arc::new(the_class);

        if let Ok(mut lock) = s_table.lock() {
            if !lock.contains_key(&class_name) {
                lock.insert(class_name, vec![]);
            }
            if class.superclass_idx < NO_INDEX {
                let super_class =
                    get_string_from_idx(types[class.superclass_idx as usize] as u16, &strings)
                        .unwrap_or_else(|| {
                            log::error!("Could not resolve class name");
                            "-UNKONWN-".to_string()
                        });
                let entry = lock.entry(super_class).or_default();
                entry.push(the_class.clone());
            }
        }

        if let Ok(mut v_table) = v_table.lock() {
            for &type_idx in &the_class.interfaces {
                if let Some(iface_name) =
                    get_string_from_idx(types[type_idx as usize] as u16, &strings)
                {
                    let entry = v_table.entry(iface_name).or_default();

                    entry.push(the_class.clone());
                }
            }
        }
        if let Ok(mut ret_classes) = vec_lock.lock() {
            ret_classes.push(the_class);
        };
    });
    let v_table = v_table.into_inner().unwrap();
    let s_table = s_table.into_inner().unwrap();
    Some(DexFile {
        identifier: format!("{:02x?}", config.signature),
        raw_data: buffer.data.to_vec(),
        file_name: file_name.to_string(),
        header: config,
        strings,
        types,
        protos,
        methods,
        fields,
        classes: ret_classes,
        interface_table: v_table,
        superclass_table: s_table,
    })
}

fn get_string_from_idx<T>(idx: T, strings: &[StringEntry]) -> Option<String>
where
    T: Into<usize>,
{
    strings
        .get(idx.into())
        .map(|se| se.to_str().ok())
        .flatten()
        .map(|s| s.to_owned())
}

fn parse_fields_table(
    fields_ids_size: u32,
    pool_cursor: &mut Cursor<&[u8]>,
    strings: &[StringEntry],
) -> Vec<Arc<Field>> {
    let mut fields = Vec::with_capacity(fields_ids_size as usize);
    for _ in 0..fields_ids_size {
        let mut field = Field::from_bytes(pool_cursor);
        if let Some(name) = get_string_from_idx(field.name_idx as usize, strings) {
            field.name = name;
        }
        fields.push(Arc::new(field));
    }
    fields
}

fn parse_class_def_table<T: Read + Seek>(
    class_defs_size: u32,
    buffer: &mut T,
) -> Vec<Arc<ClassDefItem>> {
    let mut classes = Vec::with_capacity(class_defs_size as usize);
    for _ in 0..class_defs_size {
        let class = ClassDefItem::from_bytes(buffer);
        //log::debug!("{} {:?}", types[class.class_idx as usize], class);
        classes.push(Arc::new(class));
    }
    classes
}

fn parse_proto_table<T: Read + Seek>(proto_ids_size: u32, buffer: &mut T) -> Vec<Arc<Proto>> {
    let mut protos = vec![];
    for _ in 0..proto_ids_size {
        let proto = Arc::new(Proto::from_bytes(buffer));
        protos.push(proto);
    }
    protos
}

fn parse_method_table<T: Read + Seek>(
    method_ids_size: u32,
    strings: &[StringEntry],
    protos: &[Arc<Proto>],
    types: &[u32],
    buffer: &mut T,
) -> Vec<Arc<Method>> {
    let mut methods = Vec::with_capacity(method_ids_size as usize);
    for i in 0..method_ids_size {
        let mut method = Method::from_bytes(buffer);
        method.method_name = strings[method.name_idx as usize].to_str_lossy().to_string();

        let proto = &protos[method.proto_idx as usize];
        let return_type = strings[types[proto.return_type_idx as usize] as usize]
            .to_str_lossy()
            .to_string();
        let arg_string = proto
            .arguments
            .iter()
            .map(|arg_type| {
                strings[types[*arg_type as usize] as usize]
                    .to_str_lossy()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("");
        method.proto_name = format!("({}){}", arg_string, return_type);
        method.method_idx = i as u16;
        methods.push(Arc::new(method));
    }
    methods
}

fn parse_type_table<T: Read + Seek>(type_ids_size: u32, buffer: &mut T) -> Vec<u32> {
    let mut type_names = Vec::with_capacity(type_ids_size as usize);
    for _ in 0..type_ids_size {
        let index = u32::from_bytes(buffer);
        type_names.push(index);
    }
    type_names
}

fn parse_string_table<T: Read + Seek>(
    start: u32,
    string_table_entries: u32,
    buffer: &mut T,
) -> Vec<StringEntry> {
    let mut strings = Vec::with_capacity(string_table_entries as usize);
    let mut offset = start;
    for _ in 0..string_table_entries {
        let size = u32::from_bytes(buffer);
        buffer.seek(SeekFrom::Start(size as u64)).unwrap();
        let se = StringEntry::from_bytes(buffer);
        strings.push(se);

        offset += 4;
        buffer.seek(SeekFrom::Start(offset as u64)).unwrap();
    }
    strings
}
