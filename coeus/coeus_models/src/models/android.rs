// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Android-specific models.
//! Used to parse the AndroidManifest, etc.

fn default_as_false() -> bool {
    false
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
/// A non-exhaustive representation of the AndroidManifest
pub struct AndroidManifest {
    #[serde(rename = "versionCode")]
    /// Version code
    pub version_code: String,
    #[serde(rename = "versionName")]
    /// version name
    pub version_name: String,
    /// Android package name
    pub package: String,
    #[serde(rename = "$value", default)]
    /// Represents the content of the manifest. Defines usage, permissions, sdk used and the application itself
    pub content: Vec<Usages>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidSdk {
    #[serde(rename = "minSdkVersion")]
    /// Min sdk version this apk was bundled for
    pub min_sdk_version: String,
    #[serde(rename = "targetSdkVersion")]
    /// Target SDK version this apk was bundled for
    pub target_sdk_version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidPermission {
    name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidFeature {
    name: Option<String>,
    #[serde(default = "default_as_false")]
    required: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PermissionLevel {
    Normal,
    Dangerous,
    Signature,
    SignatureOrSystem,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidApplication {
    #[serde(rename = "allowBackup", default = "default_as_false")]
    pub allow_backup: bool,
    #[serde(default = "default_as_false")]
    pub debuggable: bool,
    #[serde(rename = "usesCleartextTraffic", default = "default_as_false")]
    pub uses_cleartext_traffic: bool,
    #[serde(rename = "networkSecurityConfig")]
    pub network_security_config: Option<String>,
    #[serde(rename = "$value")]
    pub activities: Vec<ContentType>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Usages {
    /// Used Android permissions
    #[serde(rename = "uses-permission")]
    #[serde(alias = "permission")]
    #[serde(alias = "uses-permission-sdk-23")]
    UsesPermission(AndroidPermission),
    /// If features are required
    #[serde(rename = "uses-feature")]
    UsesFeature(AndroidFeature),
    /// which SDK was used to compile
    #[serde(rename = "uses-sdk")]
    UsesSdk(AndroidSdk),
    /// Information on the Application itself
    #[serde(rename = "application")]
    Application(AndroidApplication),
    #[serde(rename = "queries")]
    Queries(AndroidQuery),
    #[serde(rename = "supports-screens")]
    Unknown(Unknown),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidQuery {
    #[serde(rename = "$value")]
    pub packages: Vec<QueryType>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum QueryType {
    #[serde(rename = "package")]
    AndroidPackage(AndroidPackage),
    #[serde(rename = "intent")]
    AndroidIntent(AndroidIntentFilter),
    #[serde(alias = "provider")]
    Unknown(Unknown),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidPackage {
    pub name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ContentType {
    #[serde(rename = "activity-alias")]
    ActivityAlias(AndroidActivity),
    #[serde(rename = "activity")]
    Activity(AndroidActivity),
    #[serde(rename = "receiver")]
    #[serde(alias = "intent-filter")]
    #[serde(alias = "uses-library")]
    #[serde(alias = "meta-data")]
    #[serde(alias = "service")]
    #[serde(alias = "provider")]
    Unknown(Unknown),
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Unknown {
    // #[serde(rename = "intent-filter", default)]
    // intent_filters : Vec<AndroidIntentFilter>
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidActivity {
    pub name: String,
    pub theme: Option<String>,
    #[serde(rename = "parentActivityName")]
    pub parent_activity_name: Option<String>,
    #[serde(rename = "intent-filter", default)]
    pub intent_filters: Vec<AndroidIntentFilter>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidIntentFilter {
    #[serde(rename = "$value")]
    pub content: Vec<IntentContent>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidIntentAction {
    pub name: String,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidIntentCategory {
    pub name: String,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AndroidIntentData {
    pub name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IntentContent {
    #[serde(rename = "action")]
    Action(AndroidIntentAction),
    #[serde(rename = "category")]
    Category(AndroidIntentCategory),
    #[serde(rename = "data")]
    Data(Unknown),
}
