//! Regression tests for edit operands and cached navigation against a real DEX.
use super::*;
use coeus::coeus_models::models::{InstructionOffset, InstructionSize};

fn fixture() -> RustBackend {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/runtime-functions/classes.dex");
    let mut backend = RustBackend::new();
    backend.session = Some(Session::Single(
        NativeAnalysis::new(path.to_str().unwrap()).unwrap(),
    ));
    backend
}

fn fixture_method(backend: &RustBackend) -> MethodObject {
    let file = &backend.analysis().unwrap().files.multi_dex[0].primary;
    let data = file
        .classes
        .iter()
        .flat_map(|class| &class.codes)
        .find(|data| data.method.method_name == "doPrint")
        .unwrap();
    method_object(file, &data.method).unwrap()
}

fn build(factory: &str, arguments: Value) -> Result<Instruction, String> {
    build_instruction(
        factory,
        &arguments,
        CodeTarget {
            offset: 0,
            position: TargetPosition::After,
        },
    )
}

#[test]
fn register_operands_support_names_and_enforce_encoding_limits() {
    for register in ["7", "007", "v7", " v007 "] {
        assert!(matches!(
            build("const_lit32", json!({"register":register,"value":"1"})).unwrap(),
            Instruction::ConstLit32(7, 1)
        ));
    }
    assert!(matches!(
        build(
            "move_from16",
            json!({"register":"v255","source_register":"v65535"})
        )
        .unwrap(),
        Instruction::MoveFrom16(255, 65535)
    ));
    for (factory, arguments) in [
        ("return_value", json!({"register":"v256"})),
        ("return_value", json!({"register":"vv7"})),
        ("instance_get", json!({"register":"v16"})),
        ("if_eq", json!({"left_register":"v16"})),
        ("move_from16", json!({"source_register":"v65536"})),
        (
            "invoke_static",
            json!({"register_count":"v2","registers":"v1 v2"}),
        ),
        (
            "invoke_static",
            json!({"register_count":"1","registers":"v16"}),
        ),
        (
            "invoke_static_range",
            json!({"register_count":"256","first_register":"v1"}),
        ),
        (
            "invoke_static_range",
            json!({"register_count":"2","first_register":"v65535"}),
        ),
    ] {
        assert!(
            build(factory, arguments.clone()).is_err(),
            "{factory}: {arguments}"
        );
    }
    assert!(
        matches!(build("invoke_static", json!({"register_count":"2","registers":"{v1, 02}","method_index":"3"})).unwrap(), Instruction::InvokeStatic(_, 3, registers) if registers == vec![1,2])
    );
    assert!(matches!(
        build(
            "invoke_static_range",
            json!({"register_count":"2","first_register":"v300","method_index":"3"})
        )
        .unwrap(),
        Instruction::InvokeStaticRange(2, 3, 300)
    ));
    assert_eq!(
        script_instruction(
            "move_from16",
            &json!({"register":"v007","source_register":"0300"})
        )
        .unwrap(),
        "DexInstruction.move_from16(7, 300)"
    );
}

#[test]
fn options_prefill_only_actual_destinations_and_preserve_pool_indexes() {
    let mut backend = fixture();
    let template = fixture_method(&backend);
    for (instruction, destination) in [
        (Instruction::ConstLit32(7, 1), "v7"),
        (Instruction::MoveFrom16(200, 300), "v200"),
        (Instruction::Return(7), "v0"),
        (
            Instruction::InvokeStaticRange(1, template.method.method_idx, 7),
            "v0",
        ),
    ] {
        let mut method = template.clone();
        let data = Arc::make_mut(method.data.as_mut().unwrap());
        data.code.as_mut().unwrap().insns = vec![(
            InstructionSize(6),
            InstructionOffset(0),
            instruction.clone(),
        )];
        let id = backend.store(ObjectEntry {
            object: NativeObject::Method(method),
            evidence: None,
        });
        let response = backend.edit_options(&json!({"id":id,"offset":0})).unwrap();
        let options = response["options"].as_array().unwrap();
        for label in ["const literal", "move/from16", "iget", "sget"] {
            let option = options
                .iter()
                .find(|option| option["label"] == label)
                .unwrap();
            let argument = option["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["name"] == "register")
                .unwrap();
            assert_eq!(argument["value"], destination, "{label}");
            assert_eq!(argument["kind"], "register");
        }
        if let Some(index) = invoke_method_index(&instruction) {
            let invoke = options
                .iter()
                .find(|option| option["label"] == "invoke-static/range")
                .unwrap();
            let arguments = invoke["arguments"].as_array().unwrap();
            assert_eq!(
                arguments
                    .iter()
                    .find(|a| a["name"] == "method_index")
                    .unwrap()["value"],
                index.to_string()
            );
            assert_eq!(
                arguments
                    .iter()
                    .find(|a| a["name"] == "register_count")
                    .unwrap()["kind"],
                "integer"
            );
        }
    }
}

#[test]
fn named_register_edit_reparses_and_invalidates_the_lookup_cache() {
    let mut backend = fixture();
    let method = fixture_method(&backend);
    let offset = method.instructions()[0].offset;
    let id = backend.store(ObjectEntry {
        object: NativeObject::Method(method),
        evidence: None,
    });
    let before = backend.lookup_index().unwrap();
    let options = backend
        .edit_options(&json!({"id":id,"offset":offset}))
        .unwrap();
    let option = options["options"]
        .as_array()
        .unwrap()
        .iter()
        .find(|option| option["label"] == "const literal")
        .unwrap();
    let description = backend
        .call(
            json!({"op":"apply_edit","id":option["id"],"arguments":{"register":"v0","value":"1"}}),
        )
        .unwrap();
    assert!(description["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["text"].as_str().unwrap().contains("const v0, 0x1")));
    assert!(!Arc::ptr_eq(&before, &backend.lookup_index().unwrap()));
    assert!(backend
        .session_script()
        .contains("DexInstruction.const_lit32(0,"));
}

#[test]
fn xrefs_distinguish_overloads_include_range_calls_and_deduplicate_callers() {
    let mut backend = fixture();
    let template = fixture_method(&backend);
    let mut file = template.file.as_ref().clone();
    let mut overload = template.method.as_ref().clone();
    overload.method_idx = file.methods.len() as u16;
    overload.proto_name = "(J)J".into();
    let overload_index = overload.method_idx;
    file.methods.push(Arc::new(overload));
    let mut callers = Vec::new();
    for (name, target) in [
        ("callsTarget", template.method.method_idx),
        ("callsOverload", overload_index),
    ] {
        let mut method = template.method.as_ref().clone();
        method.method_idx = file.methods.len() as u16;
        method.method_name = name.into();
        let method = Arc::new(method);
        file.methods.push(method.clone());
        let mut data = template.data.as_ref().unwrap().as_ref().clone();
        data.method_idx = method.method_idx as u32;
        data.method = method;
        data.name = name.into();
        data.code.as_mut().unwrap().insns = vec![
            (
                InstructionSize(6),
                InstructionOffset(0),
                Instruction::InvokeStaticRange(1, target, 0),
            ),
            (
                InstructionSize(6),
                InstructionOffset(3),
                Instruction::InvokeStaticRange(1, target, 0),
            ),
        ];
        callers.push(Arc::new(data));
    }
    let class = file
        .classes
        .iter_mut()
        .find(|class| class.class_idx == template.class.class_idx)
        .unwrap();
    Arc::make_mut(class).codes = callers;
    Arc::make_mut(&mut backend.analysis_mut().unwrap().files).multi_dex[0].primary = Arc::new(file);
    let lookup = backend.lookup_index().unwrap();
    for _ in 0..2 {
        let callers = lookup.callers(&template);
        assert_eq!(callers.len(), 1);
        assert!(object_label(&callers[0]).contains("->callsTarget("));
    }
    let files = Arc::make_mut(&mut backend.analysis_mut().unwrap().files);
    let file = Arc::make_mut(&mut files.multi_dex[0].primary);
    let class = file
        .classes
        .iter_mut()
        .find(|class| class.class_idx == template.class.class_idx)
        .unwrap();
    Arc::make_mut(class).codes.clear();
    assert!(backend
        .lookup_index()
        .unwrap()
        .callers(&template)
        .is_empty());
}

#[test]
fn parameter_labels_work_in_method_class_and_edit_views() {
    let mut backend = fixture();
    let template = fixture_method(&backend);
    // Two locals and three incoming words (receiver plus a wide argument).
    let files = Arc::make_mut(&mut backend.analysis_mut().unwrap().files);
    let file = Arc::make_mut(&mut files.multi_dex[0].primary);
    let class = file
        .classes
        .iter_mut()
        .find(|class| class.class_idx == template.class.class_idx)
        .unwrap();
    let class = Arc::make_mut(class);
    let data = class
        .codes
        .iter_mut()
        .find(|data| data.method.method_idx == template.method.method_idx)
        .unwrap();
    let data = Arc::make_mut(data);
    let code = data.code.as_mut().unwrap();
    code.register_size = 5;
    code.ins_size = 3;
    code.insns = vec![(
        InstructionSize(2),
        InstructionOffset(0),
        Instruction::Move(u4::new(3), u4::new(2)),
    )];
    let method = fixture_method(&backend);
    assert_eq!(method.parameter_layout(), Some((2, 3)));
    let id = backend.store(ObjectEntry {
        object: NativeObject::Method(method.clone()),
        evidence: None,
    });
    let description = backend.describe(id.clone()).unwrap();
    assert!(description["code"]
        .as_str()
        .unwrap()
        .contains("move p1, p0"));
    assert_eq!(description["instructions"][0]["text"], "move p1, p0");
    let class = backend
        .describe(value_string(&description["class_target"], "id"))
        .unwrap();
    assert!(class["code"].as_str().unwrap().contains("move p1, p0"));
    assert_eq!(
        class["code"].as_str().unwrap().lines().count(),
        class["line_targets"].as_array().unwrap().len()
    );
    let options = backend.edit_options(&json!({"id":id,"offset":0})).unwrap();
    let option = options["options"]
        .as_array()
        .unwrap()
        .iter()
        .find(|option| option["label"] == "const literal")
        .unwrap();
    let argument = &option["arguments"][0];
    assert_eq!(argument["value"], "p1");
    assert_eq!(argument["parameter_base"], 2);
    assert_eq!(argument["parameter_count"], 3);
    assert_eq!(
        method
            .normalize_edit_arguments(
                &json!({"register":"p1","registers":"v0, p0 p2","value":"p1"})
            )
            .unwrap(),
        json!({"register":"3","registers":"0, 2, 4","value":"p1"})
    );
    assert!(method
        .normalize_edit_arguments(&json!({"register":"p3"}))
        .is_err());
}

#[test]
fn parameter_edit_is_saved_and_replayed_as_the_physical_register() {
    let mut backend = fixture();
    let file = &backend.analysis().unwrap().files.multi_dex[0].primary;
    let data = file
        .classes
        .iter()
        .flat_map(|class| &class.codes)
        .find(|data| {
            data.code
                .as_ref()
                .is_some_and(|code| code.ins_size > 0 && !code.insns.is_empty())
        })
        .unwrap();
    let method = method_object(file, &data.method).unwrap();
    let (base, count) = method.parameter_layout().unwrap();
    assert!(count > 0);
    let offset = method.instructions()[0].offset;
    let id = backend.store(ObjectEntry {
        object: NativeObject::Method(method),
        evidence: None,
    });
    let options = backend
        .edit_options(&json!({"id":id,"offset":offset}))
        .unwrap();
    let option = options["options"]
        .as_array()
        .unwrap()
        .iter()
        .find(|option| option["label"] == "const literal")
        .unwrap();
    backend
        .call(
            json!({"op":"apply_edit","id":option["id"],"arguments":{"register":"p0","value":"1"}}),
        )
        .unwrap();
    let NativeObject::Method(edited) = &backend.entry(&id).unwrap().object else {
        panic!("expected method");
    };
    assert!(
        matches!(edited.instructions()[0].instruction, Instruction::ConstLit32(register, 1) if register as u32 == base)
    );
    assert_eq!(
        backend.session_events.last().unwrap()["arguments"]["register"],
        base.to_string()
    );
    assert!(backend
        .session_script()
        .contains(&format!("DexInstruction.const_lit32({base},")));
}
