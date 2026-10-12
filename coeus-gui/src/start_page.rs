use std::sync::Arc;

use eframe::egui::{self, RichText};
use serde_json::{json, Value};

use crate::{theme, value_string, value_u64, CoeusApp, Tab};

const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManifestActivity {
    name: String,
    target: Option<String>,
    alias: bool,
    launcher: bool,
    enabled: bool,
    exported: Option<String>,
}

impl ManifestActivity {
    fn code_class(&self) -> Option<&str> {
        if self.alias {
            self.target.as_deref()
        } else {
            Some(&self.name)
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ManifestOverview {
    package: String,
    version_name: Option<String>,
    application: Option<String>,
    activities: Vec<ManifestActivity>,
}

struct ManifestCache {
    source: String,
    overview: Result<ManifestOverview, String>,
}

impl CoeusApp {
    pub(crate) fn show_start(&mut self, ui: &mut egui::Ui) {
        let Some(info) = self.info.as_ref() else {
            self.show_welcome(ui);
            return;
        };
        let metadata_package = value_string(info, "package");
        let archive_files = value_u64(info, "files");
        let dex_count = info
            .get("dex")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        // Reparse only when the manifest changes, including unapplied editor
        // changes. Keeping this in UI memory avoids work on every repaint.
        let cache = ui.data_mut(|data| {
            let id = egui::Id::new("start-manifest-overview");
            if let Some(cache) = data.get_temp::<Arc<ManifestCache>>(id) {
                if cache.source == self.manifest_xml {
                    return cache;
                }
            }
            let cache = Arc::new(ManifestCache {
                source: self.manifest_xml.clone(),
                overview: parse_manifest_overview(&self.manifest_xml),
            });
            data.insert_temp(id, cache.clone());
            cache
        });
        let overview = cache.overview.as_ref().ok();
        let package = overview
            .filter(|manifest| !manifest.package.is_empty())
            .map_or(metadata_package.as_str(), |manifest| &manifest.package);

        theme::eyebrow(ui, "START");
        ui.heading(if package.is_empty() {
            "Loaded application"
        } else {
            package
        });
        ui.label(RichText::new(&self.path).small().color(theme::MUTED));
        ui.horizontal_wrapped(|ui| {
            if let Some(version) = overview.and_then(|manifest| manifest.version_name.as_ref()) {
                ui.label(RichText::new(format!("Version {version}")).color(theme::MUTED));
                ui.separator();
            }
            ui.label(RichText::new(format!("{dex_count} DEX files")).color(theme::MUTED));
            ui.separator();
            ui.label(RichText::new(format!("{archive_files} archive files")).color(theme::MUTED));
            if self.split_mode {
                ui.separator();
                ui.label(
                    RichText::new(format!("{} split APKs", self.split_members.len()))
                        .color(theme::MUTED),
                );
            }
        });
        if self.manifest_dirty {
            ui.label(
                RichText::new("The shortcuts below reflect your unapplied manifest edits.")
                    .small()
                    .color(theme::WARNING),
            );
        }
        ui.add_space(16.0);

        let launcher = overview.and_then(|manifest| {
            manifest.activities.iter().find(|activity| {
                activity.launcher && activity.enabled && activity.code_class().is_some()
            })
        });
        let application = overview.and_then(|manifest| manifest.application.as_deref());
        theme::card().show(ui, |ui| {
            ui.set_width((ui.available_width() - 4.0).max(1.0));
            ui.label(RichText::new("Quick actions").size(19.0).strong());
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(!package.is_empty(), egui::Button::new("Copy package name"))
                    .clicked()
                {
                    ui.ctx().copy_text(package.to_string());
                    self.status = "Package name copied".to_string();
                }
                if ui
                    .add_enabled(launcher.is_some(), theme::primary("Go to main activity"))
                    .on_hover_text(
                        "Open the first enabled launcher activity; aliases open their target class",
                    )
                    .clicked()
                {
                    if let Some(class) = launcher.and_then(ManifestActivity::code_class) {
                        self.open_manifest_class(class);
                    }
                }
                if ui
                    .add_enabled(
                        application.is_some(),
                        egui::Button::new("Go to Application"),
                    )
                    .on_hover_text("Open the custom Application class declared in the manifest")
                    .clicked()
                {
                    if let Some(class) = application {
                        self.open_manifest_class(class);
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                if ui.button("Search code").clicked() {
                    self.tab = Tab::Search;
                    self.sidebar_collapsed = false;
                    self.focus_search = true;
                }
                if ui.button("View manifest").clicked() {
                    self.tab = Tab::Manifest;
                }
                if ui.button("Sign & install").clicked() {
                    self.tab = Tab::Deploy;
                }
                if ui
                    .add_enabled(!self.busy(), egui::Button::new("Save project…"))
                    .clicked()
                {
                    self.save_project_dialog();
                }
                if ui.button("Pull APK from device…").clicked() {
                    self.tab = Tab::Adb;
                }
            });
        });
        ui.add_space(16.0);

        match &cache.overview {
            Ok(manifest) => {
                theme::card().show(ui, |ui| {
                    ui.set_width((ui.available_width() - 4.0).max(1.0));
                    ui.label(RichText::new("Application entry point").size(19.0).strong());
                    if let Some(class) = &manifest.application {
                        if ui.link(RichText::new(class).monospace()).clicked() {
                            self.open_manifest_class(class);
                        }
                    } else {
                        ui.label(
                            RichText::new("Uses the default android.app.Application class.")
                                .color(theme::MUTED),
                        );
                    }
                });
                ui.add_space(16.0);
                theme::card().show(ui, |ui| {
                    ui.set_width((ui.available_width() - 4.0).max(1.0));
                    ui.label(
                        RichText::new(format!("Activities & aliases ({})", manifest.activities.len()))
                            .size(19.0)
                            .strong(),
                    );
                    ui.label(RichText::new("Select an activity to open its class. Aliases open the target activity.").color(theme::MUTED));
                    if !manifest.activities.iter().any(|activity| activity.launcher) {
                        ui.label(RichText::new("No launcher activity is declared in this manifest.").small().color(theme::MUTED));
                    }
                    if manifest.activities.is_empty() {
                        ui.label("No activities are declared in this manifest.");
                    }
                    for (index, activity) in manifest.activities.iter().enumerate() {
                        ui.push_id(index, |ui| {
                            ui.add_space(8.0);
                            ui.separator();
                            ui.horizontal_wrapped(|ui| {
                                let response = ui.add_enabled(
                                    activity.code_class().is_some(),
                                    egui::Link::new(RichText::new(&activity.name).monospace()),
                                );
                                if response.clicked() {
                                    if let Some(class) = activity.code_class() {
                                        self.open_manifest_class(class);
                                    }
                                }
                                if activity.launcher {
                                    ui.label(RichText::new("Launcher").small().color(theme::SUCCESS));
                                }
                                if activity.alias {
                                    ui.label(RichText::new("Alias").small().color(theme::MUTED));
                                }
                                if !activity.enabled {
                                    ui.label(RichText::new("Disabled").small().color(theme::WARNING));
                                }
                                if let Some(exported) = &activity.exported {
                                    ui.label(RichText::new(format!("Exported: {exported}")).small().color(theme::MUTED));
                                }
                                if ui.small_button("Copy name").clicked() {
                                    ui.ctx().copy_text(activity.name.clone());
                                    self.status = "Activity name copied".to_string();
                                }
                            });
                            if activity.alias {
                                ui.label(
                                    RichText::new(match &activity.target {
                                        Some(target) => format!("Target: {target}"),
                                        None => "No target activity is declared".to_string(),
                                    })
                                    .small()
                                    .color(theme::MUTED),
                                );
                            }
                        });
                    }
                });
            }
            Err(error) => {
                theme::empty_state(ui, "Manifest shortcuts are unavailable", error);
                if ui.button("Open manifest").clicked() {
                    self.tab = Tab::Manifest;
                }
            }
        }
    }

    fn open_manifest_class(&mut self, class: &str) {
        self.pending_note_navigation = None;
        self.request(
            "resolve",
            json!({"op": "resolve", "kind": "class", "label": class_descriptor(class)}),
        );
        self.status = format!("Opening {class}…");
    }
}

fn android_attribute<'a>(node: roxmltree::Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attribute((ANDROID_NAMESPACE, name))
}

fn qualified_class_name(package: &str, name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() || name.starts_with(['@', '?']) || name.chars().any(char::is_whitespace) {
        return None;
    }
    if name.starts_with('.') {
        (!package.is_empty()).then(|| format!("{package}{name}"))
    } else if name.contains('.') {
        Some(name.to_string())
    } else {
        (!package.is_empty()).then(|| format!("{package}.{name}"))
    }
}

fn class_descriptor(class: &str) -> String {
    format!("L{};", class.replace('.', "/"))
}

fn manifest_enabled(node: roxmltree::Node<'_, '_>) -> bool {
    !android_attribute(node, "enabled")
        .is_some_and(|enabled| enabled.eq_ignore_ascii_case("false") || enabled == "0")
}

fn parse_manifest_overview(source: &str) -> Result<ManifestOverview, String> {
    let document = roxmltree::Document::parse(source)
        .map_err(|error| format!("The manifest could not be read: {error}"))?;
    let manifest = document.root_element();
    if !manifest.has_tag_name("manifest") {
        return Err("Expected a <manifest> root element.".to_string());
    }
    let package = manifest
        .attribute("package")
        .unwrap_or_default()
        .to_string();
    let mut overview = ManifestOverview {
        package,
        version_name: android_attribute(manifest, "versionName").map(str::to_string),
        ..ManifestOverview::default()
    };
    let Some(application) = manifest
        .children()
        .find(|node| node.has_tag_name("application"))
    else {
        return Ok(overview);
    };
    overview.application = android_attribute(application, "name")
        .and_then(|name| qualified_class_name(&overview.package, name));
    for node in application
        .children()
        .filter(|node| node.has_tag_name("activity") || node.has_tag_name("activity-alias"))
    {
        let Some(name) = android_attribute(node, "name")
            .and_then(|name| qualified_class_name(&overview.package, name))
        else {
            continue;
        };
        let alias = node.has_tag_name("activity-alias");
        let launcher = node
            .children()
            .filter(|child| child.has_tag_name("intent-filter"))
            .any(|filter| {
                let main = filter.children().any(|child| {
                    child.has_tag_name("action")
                        && android_attribute(child, "name") == Some("android.intent.action.MAIN")
                });
                let launcher = filter.children().any(|child| {
                    child.has_tag_name("category")
                        && matches!(
                            android_attribute(child, "name"),
                            Some(
                                "android.intent.category.LAUNCHER"
                                    | "android.intent.category.LEANBACK_LAUNCHER"
                            )
                        )
                });
                main && launcher
            });
        overview.activities.push(ManifestActivity {
            name,
            target: alias
                .then(|| {
                    android_attribute(node, "targetActivity")
                        .and_then(|name| qualified_class_name(&overview.package, name))
                })
                .flatten(),
            alias,
            launcher,
            enabled: manifest_enabled(application) && manifest_enabled(node),
            exported: android_attribute(node, "exported").map(str::to_string),
        });
    }
    Ok(overview)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_names_resolve_to_exact_dex_descriptors() {
        for name in [".MainActivity", "MainActivity", "com.example.MainActivity"] {
            let class = qualified_class_name("com.example", name).unwrap();
            assert_eq!(class, "com.example.MainActivity");
            assert_eq!(class_descriptor(&class), "Lcom/example/MainActivity;");
        }
        assert_eq!(
            qualified_class_name("com.example", "other.App$Nested").as_deref(),
            Some("other.App$Nested")
        );
        assert!(qualified_class_name("", ".Main").is_none());
        assert!(qualified_class_name("com.example", "@string/app").is_none());
        assert!(qualified_class_name("com.example", "").is_none());
    }

    #[test]
    fn manifest_supports_namespaces_aliases_and_entity_decoding() {
        let manifest = parse_manifest_overview(r#"
            <manifest xmlns:a="http://schemas.android.com/apk/res/android" package="com.example" a:versionName="1 &amp; 2">
                <!-- <activity a:name=".Ignored"/> -->
                <application a:name="App">
                    <activity a:name=".Main" a:exported="true"/>
                    <activity-alias a:name="Launcher" a:targetActivity=".Main">
                        <intent-filter>
                            <action a:name="android.intent.action.MAIN"/>
                            <category a:name="android.intent.category.LAUNCHER"/>
                        </intent-filter>
                    </activity-alias>
                    <activity a:name="other.Secondary" a:enabled="false"/>
                </application>
            </manifest>"#).unwrap();
        assert_eq!(manifest.application.as_deref(), Some("com.example.App"));
        assert_eq!(manifest.version_name.as_deref(), Some("1 & 2"));
        assert_eq!(manifest.activities.len(), 3);
        assert_eq!(manifest.activities[0].exported.as_deref(), Some("true"));
        let alias = &manifest.activities[1];
        assert!(alias.alias && alias.launcher && alias.enabled);
        assert_eq!(alias.name, "com.example.Launcher");
        assert_eq!(alias.code_class(), Some("com.example.Main"));
        assert!(!manifest.activities[2].enabled);
    }

    #[test]
    fn launcher_action_and_category_must_belong_to_the_same_filter() {
        let manifest = parse_manifest_overview(r#"
            <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
                <application android:enabled="false">
                    <activity android:name=".NotLauncher">
                        <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
                        <intent-filter><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
                    </activity>
                    <activity android:name=".Television">
                        <intent-filter>
                            <action android:name="android.intent.action.MAIN"/>
                            <category android:name="android.intent.category.LEANBACK_LAUNCHER"/>
                        </intent-filter>
                    </activity>
                    <activity-alias android:name=".MissingTarget"/>
                </application>
            </manifest>"#).unwrap();
        assert!(!manifest.activities[0].launcher);
        assert!(manifest.activities[1].launcher);
        assert!(manifest.activities.iter().all(|activity| !activity.enabled));
        assert_eq!(manifest.activities[2].code_class(), None);
    }

    #[test]
    fn unavailable_or_invalid_manifests_are_reported_without_fake_components() {
        assert!(parse_manifest_overview("<manifest>").is_err());
        assert!(parse_manifest_overview("<resources/>").is_err());
        let manifest = parse_manifest_overview("<manifest package='com.example'/>").unwrap();
        assert!(manifest.application.is_none());
        assert!(manifest.activities.is_empty());
    }
}
