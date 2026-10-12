use super::*;

fn option(value: &str) -> EditOption {
    EditOption {
        id: "replacement".to_string(),
        group: "Constants".to_string(),
        label: "const/4".to_string(),
        action: "replace".to_string(),
        width: 1,
        arguments: vec![EditArgument {
            name: "destination_register".to_string(),
            label: "Destination register".to_string(),
            kind: "register".to_string(),
            value: value.to_string(),
            picker: None,
        }],
    }
}

fn app() -> CoeusApp {
    let mut app = CoeusApp::with_bridge(Err("No backend required for popup tests".to_string()));
    app.tab = Tab::Code;
    app.code_view_tab = CodeViewTab::Edit;
    app.code.method_id = Some("apk-method".to_string());
    app.code.edit_form = Some(option("v3"));
    app
}

fn emulation_editor() -> EmulationEditor {
    EmulationEditor {
        method_id: "emulation-method".to_string(),
        method_label: "Example.run()".to_string(),
        arguments: Vec::new(),
        guesses: Vec::new(),
        code: String::new(),
        instructions: Vec::new(),
        selected_offset: None,
        edit_options: Vec::new(),
        edit_form: Some(option("")),
        edit_dex_name: "classes.dex".to_string(),
        edit_available: true,
        edit_reason: String::new(),
    }
}

fn frame(ctx: &egui::Context, app: &mut CoeusApp, events: Vec<egui::Event>) {
    let _ = ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(1000.0, 800.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            app.show_edit_configuration(ctx);
            app.show_edit_picker(ctx);
        },
    );
}

fn key(key: Key) -> egui::Event {
    egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::NONE,
    }
}

fn focus_register(ctx: &egui::Context, emulation: bool) {
    ctx.memory_mut(|memory| {
        memory.request_focus(egui::Id::new((
            "edit-configuration-argument",
            emulation,
            "replacement",
            "destination_register",
        )));
    });
}

#[test]
fn escape_dismisses_only_the_active_emulation_configuration() {
    let ctx = egui::Context::default();
    let mut app = app();
    app.code_view_tab = CodeViewTab::Emulation;
    app.emulation_editor = Some(emulation_editor());
    frame(&ctx, &mut app, vec![key(Key::Escape)]);
    assert!(app.emulation_editor.as_ref().unwrap().edit_form.is_none());
    assert_eq!(
        app.code.edit_form.as_ref().unwrap().arguments[0].value,
        "v3"
    );
    assert_eq!(app.next_request_id, 0);
}

#[test]
fn escape_in_a_picker_preserves_the_configuration() {
    let ctx = egui::Context::default();
    let mut app = app();
    let mut picker = EditPicker::new(
        "type_index".to_string(),
        "Type".to_string(),
        SearchKind::Classes,
        "classes.dex".to_string(),
        false,
    );
    picker.searched = true;
    app.edit_picker = Some(picker);
    frame(&ctx, &mut app, vec![key(Key::Escape)]);
    assert!(app.edit_picker.is_none());
    assert_eq!(
        app.code.edit_form.as_ref().unwrap().arguments[0].value,
        "v3"
    );
    assert_eq!(app.next_request_id, 0);
}

#[test]
fn typed_emulation_values_stay_with_the_emulation_copy() {
    let ctx = egui::Context::default();
    let mut app = app();
    app.code_view_tab = CodeViewTab::Emulation;
    app.emulation_editor = Some(emulation_editor());
    frame(&ctx, &mut app, Vec::new());
    focus_register(&ctx, true);
    frame(&ctx, &mut app, vec![egui::Event::Text("v7".to_string())]);
    assert_eq!(
        app.emulation_editor
            .as_ref()
            .unwrap()
            .edit_form
            .as_ref()
            .unwrap()
            .arguments[0]
            .value,
        "v7"
    );
    assert_eq!(
        app.code.edit_form.as_ref().unwrap().arguments[0].value,
        "v3"
    );
    frame(&ctx, &mut app, vec![key(Key::Enter)]);
    assert_eq!(app.next_request_id, 1);
    app.finish(
        1,
        "apply_edit".to_string(),
        Err("Invalid instruction width".to_string()),
    );
    assert_eq!(
        app.emulation_editor
            .as_ref()
            .unwrap()
            .edit_form
            .as_ref()
            .unwrap()
            .arguments[0]
            .value,
        "v7"
    );
    assert_eq!(
        app.code.edit_form.as_ref().unwrap().arguments[0].value,
        "v3"
    );
}

#[test]
fn enter_requires_popup_field_focus_and_a_valid_register() {
    let ctx = egui::Context::default();
    let mut app = app();
    frame(&ctx, &mut app, Vec::new());
    frame(&ctx, &mut app, vec![key(Key::Enter)]);
    assert_eq!(
        app.next_request_id, 0,
        "An unrelated Enter must not apply an edit"
    );
    app.code.edit_form.as_mut().unwrap().arguments[0].value = "vv3".to_string();
    focus_register(&ctx, false);
    frame(&ctx, &mut app, vec![key(Key::Enter)]);
    assert_eq!(
        app.next_request_id, 0,
        "Malformed registers must not be submitted"
    );
    app.code.edit_form.as_mut().unwrap().arguments[0].value = "v3".to_string();
    focus_register(&ctx, false);
    frame(&ctx, &mut app, vec![key(Key::Enter)]);
    assert_eq!(app.next_request_id, 1);
}

#[test]
fn escape_can_dismiss_configuration_during_an_unrelated_request() {
    let ctx = egui::Context::default();
    let mut app = app();
    let (_sender, receiver) = mpsc::channel();
    app.pending.push(PendingRequest {
        request_id: 1,
        operation: "xrefs".to_string(),
        receiver,
    });
    frame(&ctx, &mut app, vec![key(Key::Escape)]);
    assert!(app.code.edit_form.is_none());
    assert_eq!(app.pending.len(), 1);
}

#[test]
fn disassembly_does_not_consume_keys_for_a_hidden_edit_form() {
    let ctx = egui::Context::default();
    let mut app = app();
    app.code_view_tab = CodeViewTab::Source;
    frame(&ctx, &mut app, vec![key(Key::Escape)]);
    assert!(app.code.edit_form.is_some());
    assert_eq!(app.next_request_id, 0);
}
