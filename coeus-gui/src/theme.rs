use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};

pub const BACKGROUND: Color32 = Color32::from_rgb(17, 21, 29);
pub const SURFACE: Color32 = Color32::from_rgb(23, 29, 39);
pub const RAISED: Color32 = Color32::from_rgb(32, 40, 53);
pub const BORDER: Color32 = Color32::from_rgb(49, 61, 78);
pub const TEXT: Color32 = Color32::from_rgb(226, 233, 243);
pub const MUTED: Color32 = Color32::from_rgb(154, 170, 190);
pub const ACCENT: Color32 = Color32::from_rgb(119, 184, 255);
pub const SUCCESS: Color32 = Color32::from_rgb(116, 211, 172);
pub const WARNING: Color32 = Color32::from_rgb(243, 200, 120);
pub const ERROR: Color32 = Color32::from_rgb(255, 151, 151);

pub fn install(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style()).clone();
    style
        .text_styles
        .insert(egui::TextStyle::Heading, FontId::proportional(23.0));
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, FontId::proportional(12.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, FontId::monospace(13.0));
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(10.0, 6.0);
    style.spacing.interact_size = Vec2::new(32.0, 30.0);
    style.spacing.window_margin = egui::Margin::same(16);
    style.visuals = egui::Visuals::dark();
    let visuals = &mut style.visuals;
    visuals.panel_fill = BACKGROUND;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = BACKGROUND;
    visuals.faint_bg_color = SURFACE;
    visuals.code_bg_color = SURFACE;
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.window_corner_radius = egui::CornerRadius::same(12);
    visuals.menu_corner_radius = egui::CornerRadius::same(8);
    visuals.selection.bg_fill = Color32::from_rgb(40, 74, 111);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    visuals.hyperlink_color = ACCENT;
    visuals.warn_fg_color = WARNING;
    visuals.error_fg_color = ERROR;
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = egui::CornerRadius::same(6);
        widget.fg_stroke = Stroke::new(1.0, TEXT);
        widget.bg_stroke = Stroke::new(1.0, BORDER);
    }
    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.noninteractive.weak_bg_fill = BACKGROUND;
    visuals.widgets.inactive.bg_fill = RAISED;
    visuals.widgets.inactive.weak_bg_fill = RAISED;
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(44, 59, 78);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(44, 59, 78);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.bg_fill = Color32::from_rgb(40, 74, 111);
    visuals.widgets.active.weak_bg_fill = Color32::from_rgb(40, 74, 111);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.open = visuals.widgets.active;
    ctx.set_style(style);
}

pub fn panel() -> egui::Frame {
    egui::Frame::new().fill(SURFACE).inner_margin(14)
}

pub fn workspace() -> egui::Frame {
    egui::Frame::new().fill(BACKGROUND).inner_margin(20)
}

pub fn card() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(12)
        .inner_margin(20)
}

pub fn primary(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(BACKGROUND))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(0.0, 36.0))
}

pub fn eyebrow(ui: &mut egui::Ui, label: &str) {
    ui.label(RichText::new(label).size(11.0).strong().color(MUTED));
}

pub fn empty_state(ui: &mut egui::Ui, title: &str, description: &str) {
    ui.add_space(24.0);
    card().show(ui, |ui| {
        ui.set_width((ui.available_width() - 4.0).max(1.0));
        ui.label(RichText::new(title).size(19.0).strong());
        ui.add_space(4.0);
        ui.label(RichText::new(description).color(MUTED));
    });
}
