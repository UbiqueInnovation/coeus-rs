use super::*;

impl CoeusApp {
    pub(super) fn request_xrefs(&mut self, target: ResultRow) {
        self.pending_note_navigation = None;
        self.xrefs.clear();
        self.xrefs_loaded = false;
        self.xrefs_error = None;
        self.xrefs_target = Some(target.clone());
        self.tab = Tab::Xrefs;
        // A slow earlier disassembly must not take focus back from this view.
        self.latest_view_request = 0;
        self.request("xrefs", json!({"op":"xrefs", "id":target.id}));
    }

    pub(super) fn request_target_xrefs(&mut self, target: NavigationTarget) {
        self.request_xrefs(ResultRow {
            id: target.id,
            kind: target.kind,
            label: target.label,
            note_key: target.note_key,
            is_alias: false,
        });
    }

    pub(super) fn show_search(&mut self, ui: &mut egui::Ui) {
        theme::eyebrow(ui, "EXPLORE");
        ui.heading("Search");
        ui.label("Find methods, classes, fields and strings throughout the loaded APK.");
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            for kind in [
                SearchKind::Any,
                SearchKind::Methods,
                SearchKind::Classes,
                SearchKind::Fields,
                SearchKind::Strings,
            ] {
                ui.selectable_value(&mut self.search_kind, kind, kind.label());
            }
        });
        let invalid = search_validation(&self.search).err();
        let searching = self
            .pending
            .iter()
            .any(|request| request.operation == "search");
        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .id_salt("full-workspace-search")
                    .desired_width((ui.available_width() - 110.0).max(120.0))
                    .hint_text("Search with a regular expression"),
            );
            if self.focus_search {
                response.request_focus();
                self.focus_search = false;
            }
            let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
            let clicked = ui
                .add_enabled(
                    !searching && self.info.is_some() && invalid.is_none(),
                    theme::primary(if searching { "Searching…" } else { "Search" }),
                )
                .clicked();
            if (clicked || submit)
                && !searching
                && self.info.is_some()
                && search_validation(&self.search).is_ok()
            {
                self.request(
                    "search",
                    json!({"op":"search", "kind":self.search_kind.api_name(), "query":self.search}),
                );
            }
        });
        if let Some(error) = search_validation(&self.search).err() {
            ui.colored_label(theme::ERROR, error);
        } else {
            ui.label(
                RichText::new("Regular expressions · onCreate|decrypt · .* for all")
                    .small()
                    .color(theme::MUTED),
            );
        }
        ui.horizontal_wrapped(|ui| {
            for (label, query, kind) in [
                (
                    "Entry points",
                    "onCreate|onStart|onResume",
                    SearchKind::Methods,
                ),
                (
                    "Cryptography",
                    "encrypt|decrypt|Cipher",
                    SearchKind::Methods,
                ),
                ("URLs", "https?://", SearchKind::Strings),
            ] {
                if ui
                    .add_enabled(!searching && self.info.is_some(), egui::Button::new(label))
                    .clicked()
                {
                    self.search = query.to_string();
                    self.search_kind = kind;
                    self.request(
                        "search",
                        json!({"op":"search", "kind":kind.api_name(), "query":query}),
                    );
                }
            }
        });
        ui.add_space(12.0);
        ui.separator();
        if searching {
            ui.spinner();
        } else if self.results.is_empty() {
            if let Some(query) = &self.completed_search {
                theme::empty_state(
                    ui,
                    "No matches",
                    &format!(
                        "No results for {query:?}. Try a broader expression or a different type."
                    ),
                );
            } else {
                theme::empty_state(ui, "Find your starting point", "Enter a query above or choose a suggested search. Click a result to open it; right-click for cross-references.");
            }
        } else {
            ui.label(
                RichText::new(format!(
                    "{} of {} results",
                    self.results.len(),
                    self.result_count
                ))
                .strong(),
            );
            self.show_explorer_results(ui, self.results.clone());
        }
    }

    pub(super) fn show_xrefs(&mut self, ui: &mut egui::Ui) {
        theme::eyebrow(ui, "EXPLORE / REFERENCES");
        ui.heading("Cross-references");
        let Some(target) = self.xrefs_target.clone() else {
            theme::empty_state(ui, "Choose an object", "Click a function's declaration name in the disassembly, use Cross-references in the code toolbar, or right-click a class, method, field or string.");
            return;
        };
        ui.label(
            RichText::new(self.display_label(&target.kind, &target.label))
                .monospace()
                .color(theme::ACCENT),
        );
        ui.horizontal(|ui| {
            if ui.button("Open target").clicked() {
                self.selected_id = Some(target.id.clone());
                self.request("describe", json!({"op":"describe", "id":target.id}));
            }
            let loading = self.pending.iter().any(|request| {
                request.operation == "xrefs" && request.request_id == self.latest_xrefs_request
            });
            if ui
                .add_enabled(!loading, egui::Button::new("Refresh references"))
                .clicked()
            {
                self.request_xrefs(target.clone());
            }
        });
        ui.separator();
        if let Some(error) = &self.xrefs_error {
            ui.colored_label(theme::ERROR, error);
        } else if !self.xrefs_loaded {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Finding cross-references…");
            });
        } else if self.xrefs.is_empty() {
            theme::empty_state(ui, "No cross-references found", "No indexed references to this object were found in the loaded APK. Android entry points may be invoked by the system.");
        } else {
            ui.label(RichText::new(format!("{} cross-reference(s)", self.xrefs.len())).strong());
            self.show_explorer_results(ui, self.xrefs.clone());
        }
    }

    pub(super) fn show_explorer_results(&mut self, ui: &mut egui::Ui, rows: Vec<ResultRow>) {
        let mut action = None;
        for result in rows {
            ui.push_id(&result.id, |ui| {
                let label = self.display_label(&result.kind, &result.label);
                let response = ui
                    .horizontal(|ui| {
                        let response = result_row(
                            ui,
                            &result,
                            &label,
                            self.selected_id.as_ref() == Some(&result.id),
                            (ui.available_width() - 70.0).max(100.0),
                        )
                        .on_hover_text(&result.label);
                        self.show_note_chip(ui, &result.kind, &result.note_key, &label);
                        response
                    })
                    .inner;
                if response.clicked() {
                    action = Some(SearchAction::Open(result.clone()));
                }
                response.context_menu(|ui| {
                    if ui.button("Open code").clicked() {
                        action = Some(SearchAction::Open(result.clone()));
                        ui.close_menu();
                    }
                    if ui.button("Cross-references").clicked() {
                        action = Some(SearchAction::Xrefs(result.clone()));
                        ui.close_menu();
                    }
                    if ui.button("Add / edit note").clicked() {
                        action = Some(SearchAction::EditNote(result.clone()));
                        ui.close_menu();
                    }
                    if matches!(result.kind.as_str(), "class" | "method")
                        && ui.button("Assign alias").clicked()
                    {
                        action = Some(SearchAction::EditAlias(result.clone()));
                        ui.close_menu();
                    }
                });
            });
        }
        match action {
            Some(SearchAction::Open(result)) => {
                self.selected_id = Some(result.id.clone());
                self.request("describe", json!({"op":"describe", "id":result.id}));
            }
            Some(SearchAction::Xrefs(result)) => self.request_xrefs(result),
            Some(SearchAction::EditNote(result)) => self.open_note_editor(&result),
            Some(SearchAction::EditAlias(result)) => self.open_alias_editor(&result),
            None => {}
        }
    }

    pub(super) fn show_string_editor(&mut self, ui: &mut egui::Ui) {
        ui.heading("String pool editor");
        ui.label("Replace this DEX string-pool entry and update its references.");
        ui.label(RichText::new(format!("Original: {}", self.string_editor.original)).monospace());
        ui.add(
            egui::TextEdit::multiline(&mut self.string_editor.replacement)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        if ui
            .add_enabled(!self.busy(), theme::primary("Apply string replacement"))
            .clicked()
        {
            if let Some(id) = self.string_editor.id.clone() {
                self.request(
                    "replace_string",
                    json!({"op":"replace_string", "id":id, "value":self.string_editor.replacement}),
                );
            }
        }
    }
}
