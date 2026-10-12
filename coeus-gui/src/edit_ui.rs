use super::*;

impl CoeusApp {
    pub(super) fn show_edit_configuration(&mut self, ctx: &egui::Context) {
        if self.tab != Tab::Code || self.code_view_tab == CodeViewTab::Source {
            return;
        }
        let emulation = self.code_view_tab == CodeViewTab::Emulation;
        let (form, selected, dex, method_id) = if emulation {
            let Some(editor) = &self.emulation_editor else {
                return;
            };
            (
                editor.edit_form.clone(),
                editor
                    .instructions
                    .iter()
                    .find(|row| Some(row.offset) == editor.selected_offset)
                    .cloned(),
                editor.edit_dex_name.clone(),
                Some(editor.method_id.clone()),
            )
        } else {
            (
                self.code.edit_form.clone(),
                self.code
                    .instructions
                    .iter()
                    .find(|row| Some(row.offset) == self.code.selected_offset)
                    .cloned(),
                self.code.edit_dex_name.clone(),
                self.code.method_id.clone(),
            )
        };
        let Some(mut form) = form else {
            return;
        };
        let picker_open = self.edit_picker.is_some();
        let busy = self.busy();
        let applying = self
            .pending
            .iter()
            .any(|request| request.operation == "apply_edit");
        let mut open = true;
        let mut cancel = false;
        let mut apply = false;
        let mut picker = None;
        if !picker_open
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::Escape))
        {
            open = false;
        }
        egui::Window::new(format!("Configure {}", form.label))
            .id(egui::Id::new(("instruction-configuration", emulation)))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(540.0)
            .default_pos(ctx.screen_rect().center() - Vec2::new(270.0, 160.0))
            .enabled(!picker_open)
            .show(ctx, |ui| {
                if let Some(selected) = &selected {
                    ui.label(
                        RichText::new(format!(
                            "{} at @0x{:x}",
                            form.action.replace('_', " "),
                            selected.offset
                        ))
                        .strong(),
                    );
                    ui.label(RichText::new(&selected.text).monospace().small());
                }
                if emulation {
                    ui.colored_label(theme::WARNING, "Changes apply to the emulation copy.");
                }
                ui.separator();
                if form.arguments.iter().any(|argument| {
                    argument.kind == "register" || edit_arguments::is_register(&argument.name)
                }) {
                    ui.label(
                        RichText::new("Registers accept a number or a name, for example 3 or v3.")
                            .small()
                            .color(theme::MUTED),
                    );
                }
                let mut valid = true;
                let mut submit = false;
                ui.add_enabled_ui(!applying, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("edit-configuration-fields")
                        .max_height((ctx.screen_rect().height() * 0.5).max(120.0))
                        .show(ui, |ui| {
                            for argument in &mut form.arguments {
                                ui.push_id(&argument.name, |ui| {
                                    ui.label(&argument.label);
                                    ui.horizontal(|ui| {
                                        let register = argument.kind == "register"
                                            || edit_arguments::is_register(&argument.name);
                                        let response = ui.add(
                                            egui::TextEdit::singleline(&mut argument.value)
                                                .id(egui::Id::new((
                                                    "edit-configuration-argument",
                                                    emulation,
                                                    &form.id,
                                                    &argument.name,
                                                )))
                                                .desired_width(if argument.kind == "text" {
                                                    360.0
                                                } else {
                                                    220.0
                                                })
                                                .hint_text(if register { "3 or v3" } else { "" }),
                                        );
                                        submit |= response.lost_focus()
                                            && ui.input(|input| input.key_pressed(Key::Enter));
                                        if let Some(kind) = argument.picker {
                                            if ui.button("Choose…").clicked() {
                                                picker = Some(EditPicker::new(
                                                    argument.name.clone(),
                                                    argument.label.clone(),
                                                    kind,
                                                    dex.clone(),
                                                    emulation,
                                                ));
                                            }
                                        }
                                    });
                                    if argument.kind == "register"
                                        || edit_arguments::is_register(&argument.name)
                                    {
                                        if let Err(error) = edit_arguments::register_number(
                                            &argument.value,
                                            u16::MAX as u32,
                                        ) {
                                            valid = false;
                                            ui.colored_label(theme::ERROR, error);
                                        }
                                    }
                                    ui.add_space(6.0);
                                });
                            }
                        });
                });
                ui.separator();
                ui.horizontal(|ui| {
                    apply = ui
                        .add_enabled(
                            valid && !busy,
                            theme::primary(if emulation {
                                "Apply to emulation copy"
                            } else {
                                "Apply replacement"
                            }),
                        )
                        .clicked();
                    cancel = ui.button("Cancel").clicked();
                });
                apply |= submit && valid && !busy && !picker_open;
                if busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(if applying {
                            "Applying changes…"
                        } else {
                            "Waiting for the current operation…"
                        });
                    });
                }
            });
        if !open || cancel {
            if emulation {
                if let Some(editor) = &mut self.emulation_editor {
                    editor.edit_form = None;
                }
            } else {
                self.code.edit_form = None;
            }
            self.edit_picker = None;
            return;
        }
        // Keep values on backend failure so the user can correct and retry.
        if emulation {
            if let Some(editor) = &mut self.emulation_editor {
                editor.edit_form = Some(form.clone());
            }
        } else {
            self.code.edit_form = Some(form.clone());
        }
        if let Some(picker) = picker {
            self.edit_picker = Some(picker);
        }
        if apply && !busy && !picker_open {
            let arguments = form
                .arguments
                .into_iter()
                .map(|argument| (argument.name, Value::String(argument.value)))
                .collect::<serde_json::Map<_, _>>();
            self.request("apply_edit", json!({"op":"apply_edit", "id":form.id, "arguments":arguments, "emulation":emulation, "method_id":method_id}));
        }
    }
}

#[cfg(test)]
#[path = "edit_ui_tests.rs"]
mod tests;
