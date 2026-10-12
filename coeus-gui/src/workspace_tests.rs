use super::*;

fn app_without_backend() -> CoeusApp {
    let mut app = CoeusApp::with_bridge(Err(
        "No backend needed for workspace state tests".to_string()
    ));
    app.last_error = None;
    app
}

fn method_description(id: &str, code: &str) -> Value {
    json!({
        "id": id,
        "kind": "method",
        "label": "Lexample/App;->run()V",
        "code": code,
        "instructions": [],
    })
}

#[test]
fn start_is_the_initial_and_loaded_workspace() {
    let mut app = app_without_backend();
    assert!(app.tab == Tab::Start);
    app.tab = Tab::Code;
    app.xrefs_target = Some(ResultRow {
        id: "old-method".to_string(),
        kind: "method".to_string(),
        label: "Lold/App;->run()V".to_string(),
        note_key: String::new(),
        is_alias: false,
    });
    app.finish(
        1,
        "load".to_string(),
        Ok(json!({"path": "/tmp/example.apk", "package": "example.app", "manifest": "<manifest package='example.app'/>"})),
    );
    assert!(app.tab == Tab::Start);
    assert!(app.xrefs_target.is_none());
    assert!(app.described_result.is_none());
    assert_eq!(app.manifest_xml, "<manifest package='example.app'/>");
}

#[test]
fn reload_bypasses_and_invalidates_cached_class_and_method_descriptions() {
    let mut app = app_without_backend();
    app.description_cache.insert(
        "method".to_string(),
        method_description("method", ".method run()V\nreturn-void\n.end method"),
    );
    app.description_cache.insert(
        "class".to_string(),
        json!({"id": "class", "kind": "class", "code": ".class Lexample/App;"}),
    );
    app.request(
        "describe",
        json!({"op": "describe", "id": "method", "reload": true}),
    );
    assert!(app.description_cache.is_empty());
    // Without a backend, only a stale cache hit could open a description.
    assert!(app.described_result.is_none());
    assert!(app.tab == Tab::Start);
}

#[test]
fn empty_method_listing_is_not_cached_and_a_retry_can_replace_it() {
    let mut app = app_without_backend();
    app.latest_view_request = 7;
    app.finish(
        7,
        "describe".to_string(),
        Ok(method_description("method", "")),
    );
    assert!(!app.description_cache.contains_key("method"));
    assert!(app.code.lines.is_empty());

    app.latest_view_request = 8;
    app.finish(
        8,
        "describe".to_string(),
        Ok(method_description(
            "method",
            ".method run()V\nreturn-void\n.end method",
        )),
    );
    assert!(app.description_cache.contains_key("method"));
    assert_eq!(app.code.lines.len(), 3);
}

#[test]
fn stale_search_success_and_failure_cannot_replace_latest_results() {
    let mut app = app_without_backend();
    app.latest_search_request = 20;
    app.submitted_search = Some("current".to_string());
    app.finish(
        19,
        "search".to_string(),
        Ok(json!({"count": 1, "results": [{"id": "old", "kind": "class", "label": "LOld;"}]})),
    );
    app.finish(19, "search".to_string(), Err("old failure".to_string()));
    assert!(app.results.is_empty());
    assert!(app.completed_search.is_none());
    assert!(app.last_error.is_none());
    app.finish(
        20,
        "search".to_string(),
        Ok(json!({"count": 1, "results": [{"id": "new", "kind": "class", "label": "LNew;"}]})),
    );
    assert_eq!(app.results[0].id, "new");
    assert_eq!(app.completed_search.as_deref(), Some("current"));
}

#[test]
fn stale_cross_references_cannot_overwrite_the_latest_target() {
    let mut app = app_without_backend();
    app.latest_xrefs_request = 30;
    app.finish(
        29,
        "xrefs".to_string(),
        Ok(json!({"results": [{"id": "old", "kind": "method", "label": "LOld;->run()V"}]})),
    );
    app.finish(29, "xrefs".to_string(), Err("old failure".to_string()));
    assert!(app.xrefs.is_empty());
    assert!(!app.xrefs_loaded);
    assert!(app.xrefs_error.is_none());
    app.finish(30, "xrefs".to_string(), Ok(json!({"results": []})));
    assert!(app.xrefs_loaded);
    assert!(app.xrefs.is_empty());
}

#[test]
fn class_navigation_targets_are_available_without_selecting_a_method() {
    let mut app = app_without_backend();
    app.apply_description(&json!({
        "id": "class", "kind": "class", "label": "Lexample/App;",
        "code": ".class Lexample/App;\n.method run()V\n.end method",
        "line_targets": [
            [{"id": "class", "kind": "class", "label": "Lexample/App;"}],
            [{"id": "method", "kind": "method", "label": "Lexample/App;->run()V"}],
            []
        ]
    }));
    assert!(app.code.method_id.is_none());
    assert_eq!(app.code.line_targets[0][0].kind, "class");
    assert_eq!(app.code.line_targets[1][0].id, "method");
    assert_eq!(
        app.code.line_targets[1][0].note_key,
        "method:Lexample/App;->run()V"
    );
}

#[test]
fn requesting_cross_references_prevents_late_disassembly_from_stealing_focus() {
    let mut app = app_without_backend();
    app.latest_view_request = 40;
    app.request_xrefs(ResultRow {
        id: "target".to_string(),
        kind: "method".to_string(),
        label: "Lexample/App;->run()V".to_string(),
        note_key: String::new(),
        is_alias: false,
    });
    app.finish(
        40,
        "describe".to_string(),
        Ok(method_description("previous", "return-void")),
    );
    assert!(app.tab == Tab::Xrefs);
    assert!(app.described_result.is_none());
    assert_eq!(app.xrefs_target.as_ref().unwrap().id, "target");
}

fn class_listing() -> CoeusApp {
    let mut app = app_without_backend();
    app.apply_description(&json!({
        "id": "class", "kind": "class", "label": "Lexample/App;",
        "code": ".class Lexample/App;\n.method public run()Z\ninvoke-static {}, Lexample/Other;->check(Z)Z #0x0\n.end method",
        "line_method_ids": [null, "run", "run", "run"],
        "line_method_keys": [null, "Lexample/App;->run()Z", "Lexample/App;->run()Z", "Lexample/App;->run()Z"],
        "line_targets": [
            [{"id": "class", "kind": "class", "label": "Lexample/App;"}],
            [{"id": "run", "kind": "method", "label": "Lexample/App;->run()Z"}],
            [{"id": "other-class", "kind": "class", "label": "Lexample/Other;"},
             {"id": "check", "kind": "method", "label": "Lexample/Other;->check(Z)Z"}],
            []
        ]
    }));
    app
}

fn render_listing(
    app: &mut CoeusApp,
    ctx: &egui::Context,
    events: Vec<egui::Event>,
) -> (egui::FullOutput, Option<CodeInteraction>) {
    let mut interaction = None;
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(1200.0, 800.0),
            )),
            time: Some(ctx.input(|input| input.time) + 0.02),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| interaction = app.render_code_lines(ui));
        },
    );
    (output, interaction)
}

fn text_position(output: &egui::FullOutput, line_prefix: &str, token: &str) -> Option<egui::Pos2> {
    output.shapes.iter().find_map(|shape| {
        let egui::epaint::Shape::Text(text) = &shape.shape else {
            return None;
        };
        let line = text.galley.text();
        if !line.starts_with(line_prefix) {
            return None;
        }
        let start = line.find(token)?;
        let start = line[..start].chars().count();
        let left = text
            .galley
            .pos_from_ccursor(egui::text::CCursor::new(start));
        let right = text
            .galley
            .pos_from_ccursor(egui::text::CCursor::new(start + token.chars().count()));
        Some(text.pos + egui::vec2((left.min.x + right.min.x) / 2.0, left.center().y))
    })
}

fn click_listing(app: &mut CoeusApp, ctx: &egui::Context, point: egui::Pos2) -> CodeInteraction {
    let event = |pressed| egui::Event::PointerButton {
        pos: point,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    render_listing(
        app,
        ctx,
        vec![egui::Event::PointerMoved(point), event(true)],
    );
    render_listing(app, ctx, vec![event(false)])
        .1
        .expect("click should select the exact symbol")
}

#[test]
fn plain_clicks_distinguish_class_method_and_declaration_names_in_class_listing() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = class_listing();
    render_listing(&mut app, &ctx, vec![]);
    let output = render_listing(&mut app, &ctx, vec![]).0;
    let class = text_position(&output, "invoke-static", "Lexample/Other;").unwrap();
    let method = text_position(&output, "invoke-static", "check").unwrap();
    let declaration = text_position(&output, ".method", "run").unwrap();
    assert!(
        matches!(click_listing(&mut app, &ctx, class).action, Some(CodeAction::Navigate(target)) if target.id == "other-class")
    );
    assert!(
        matches!(click_listing(&mut app, &ctx, method).action, Some(CodeAction::Navigate(target)) if target.id == "check")
    );
    assert!(
        matches!(click_listing(&mut app, &ctx, declaration).action, Some(CodeAction::Xrefs(target)) if target.id == "run")
    );
}

#[test]
fn collapsed_functions_hide_bodies_and_search_reveals_the_match() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = class_listing();
    app.code.collapsed_methods.insert(1);
    let collapsed = render_listing(&mut app, &ctx, vec![]).0;
    assert!(text_position(&collapsed, "invoke-static", "check").is_none());
    assert!(text_position(&collapsed, ".method", "Boolean").is_some());
    app.code.search_query = "check".to_string();
    app.refresh_code_search(true);
    let expanded = render_listing(&mut app, &ctx, vec![]).0;
    assert!(text_position(&expanded, "invoke-static", "check").is_some());
    assert!(!app.code.collapsed_methods.contains(&1));
}

#[test]
fn late_manifest_class_resolution_does_not_interrupt_cross_references() {
    let mut app = app_without_backend();
    app.latest_view_request = 99;
    app.request_xrefs(ResultRow {
        id: "target".into(),
        kind: "method".into(),
        label: "Lexample/App;->run()V".into(),
        note_key: String::new(),
        is_alias: false,
    });
    app.finish(99, "resolve".to_string(), Ok(json!({"id":"old-class"})));
    assert!(app.tab == Tab::Xrefs);
    assert!(app.selected_id.is_none());
}

#[test]
fn generated_keystore_populates_and_reveals_both_signing_passwords() {
    let mut app = app_without_backend();
    app.finish(
        1,
        "generate_keystore".to_string(),
        Ok(json!({
            "path": "/tmp/debug.keystore", "store_password": "generated-test-password",
            "key_password": "generated-test-password"
        })),
    );
    assert_eq!(app.deploy.keystore, "/tmp/debug.keystore");
    assert_eq!(app.deploy.store_password, "generated-test-password");
    assert_eq!(app.deploy.store_password, app.deploy.key_password);
    assert!(app.deploy.show_passwords);
}

#[test]
fn method_edits_and_reload_keep_the_instruction_editor_open() {
    let mut app = app_without_backend();
    app.edit_after_describe = Some("method".to_string());
    let description = method_description("method", ".method run()V\n.end method");
    app.apply_description(&description);
    assert!(app.code_view_tab == CodeViewTab::Edit);
    app.apply_description(&description);
    assert!(app.code_view_tab == CodeViewTab::Edit);
    app.apply_description(&method_description(
        "another-method",
        ".method other()V\n.end method",
    ));
    assert!(app.code_view_tab == CodeViewTab::Source);
}

#[test]
fn changing_code_objects_discards_pending_edit_controls_for_the_previous_method() {
    let mut app = app_without_backend();
    app.latest_edit_request = 9;
    app.apply_description(&json!({"id":"class", "kind":"class", "label":"Lexample/App;", "code":".class Lexample/App;"}));
    app.finish(
        9,
        "edit_options".to_string(),
        Ok(json!({"available":true,"dex":"old.dex","options":[]})),
    );
    assert!(!app.code.edit_available);
    assert!(app.code.edit_dex_name.is_empty());
}

#[test]
fn relative_apks_and_device_apps_have_a_usable_keystore_directory() {
    let mut app = app_without_backend();
    app.path = "app.apk".to_string();
    assert_eq!(app.source_directory().as_deref(), Some("."));
    app.path = "ADB:example.app".to_string();
    assert_eq!(app.source_directory().as_deref(), Some("."));
}
