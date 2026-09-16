//! APK round-tripping helpers.
//!
//! The parser in [`crate::extraction`] is deliberately analysis-friendly and
//! keeps the original archive entries as well.  This module is the write side
//! of that contract: it can add/replace files and can perform small, safe
//! edits to Android's binary XML format without requiring the Android SDK.

use coeus_models::models::{AndroidManifest, ArchiveEntry, Files};
use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
    fs::File,
    io::{Cursor, Write},
    path::Path,
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

const NETWORK_SECURITY_RESOURCE_NAME: &str = "coeus_network_security_config";
const NETWORK_SECURITY_RESOURCE_PATH: &str = "res/xml/coeus_network_security_config.xml";

/// Minimal network-security configuration used by the convenience helper.
/// It deliberately contains both the system and user trust stores.
pub const NETWORK_SECURITY_CONFIG_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"#;

/// Repackage an analysed APK into `output`.
pub fn repack<P: AsRef<Path>>(files: &Files, output: P) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(output)?;
    let bytes = repack_to_bytes(files)?;
    file.write_all(&bytes)?;
    Ok(())
}

/// Repackage an analysed APK in memory.
pub fn repack_to_bytes(files: &Files) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(&mut output);
    let mut names = HashSet::new();

    // Files created through `Files::new` do not have an archive list.  Build a
    // deterministic fallback in that case so the writer remains useful for
    // callers constructing a Files value themselves.
    let fallback;
    let entries = if files.archive.is_empty() {
        fallback = files
            .binaries
            .iter()
            .map(|(name, object)| ArchiveEntry::new(name.clone(), object.data().to_vec(), 8, false))
            .collect::<Vec<_>>();
        &fallback
    } else {
        &files.archive
    };

    for entry in entries {
        if !names.insert(entry.name.clone()) || is_signature_entry(&entry.name) {
            continue;
        }

        // The analysis index is authoritative after an edit.  This also
        // covers the manifest and resources.arsc, which are indexed specially.
        let data = files.raw_file(&entry.name).unwrap_or(&entry.data);
        // Android requires the resource table of APKs targeting Android 11+
        // to be stored (never deflated) and aligned to a four-byte boundary.
        // With extractNativeLibs=false, native libraries must also remain
        // stored and page-aligned. Force these properties even for files
        // added through Files::add_file, whose default archive method is
        // deflated. `zip` emits the required ZIP extra field when an
        // alignment is set, so this is handled as part of normal repacking.
        let is_resource_table = entry.name == "resources.arsc";
        let is_native_library = is_native_library_entry(&entry.name);
        let method = if is_resource_table || is_native_library {
            CompressionMethod::Stored
        } else {
            match entry.compression_method {
                0 => CompressionMethod::Stored,
                8 => CompressionMethod::Deflated,
                _ => CompressionMethod::Stored,
            }
        };
        let options = SimpleFileOptions::default()
            .compression_method(method)
            // ZIP alignment matters for every uncompressed entry after an
            // archive is rebuilt, not only for resources.arsc.
            .with_alignment(if is_native_library {
                // The APK's arm64 libraries use 16 KiB PT_LOAD alignment.
                // 16 KiB also satisfies the older 4 KiB requirement.
                16_384
            } else if matches!(method, CompressionMethod::Stored) {
                4
            } else {
                1
            });
        if entry.is_directory || entry.name.ends_with('/') {
            writer.add_directory(&entry.name, options)?;
        } else {
            writer.start_file(&entry.name, options)?;
            writer.write_all(data)?;
        }
    }

    writer.finish()?;
    Ok(output.into_inner())
}

/// Replace the complete top-level Android manifest from its textual XML form.
///
/// Android manifests are stored as AXML in an APK.  This function parses the
/// supplied text, resolves resource references against the APK's resource
/// table, writes a valid AXML document, and refreshes both manifest views in
/// [`Files`].  Unsupported unresolved references are rejected instead of being
/// silently converted to strings.
pub fn set_manifest_xml(files: &mut Files, xml: &str) -> Result<(), String> {
    set_xml_resource(files, "AndroidManifest.xml", xml)
}

/// Replace an Android binary-XML resource from textual XML.
///
/// The resource must already be represented by the APK's resource table when
/// Android code refers to it by `@type/name`; the network-security convenience
/// function below also creates that table entry when needed.
pub fn set_xml_resource(files: &mut Files, path: &str, xml: &str) -> Result<(), String> {
    let document = XmlDocument::parse(xml)?;
    let binary = encode_xml_document(&document, &|value| lookup_resource_reference(files, value))?;
    if path.ends_with("AndroidManifest.xml") {
        install_manifest(files, binary)
    } else {
        files.set_file(path, binary)
    }
}

/// Add a bundled network-security resource and wire it into the manifest.
///
/// The resource is added to `resources.arsc` when the input APK does not
/// already contain it, then the application gets both
/// `android:usesCleartextTraffic="true"` and a typed
/// `android:networkSecurityConfig` reference.  This is intentionally a
/// single operation so the manifest can never point at a resource that was
/// not added to the output APK.
pub fn allow_plaintext_and_user_certificates(files: &mut Files) -> Result<(), String> {
    let resource_id = ensure_xml_resource(
        files,
        NETWORK_SECURITY_RESOURCE_NAME,
        NETWORK_SECURITY_RESOURCE_PATH,
    )?;
    let network_document = XmlDocument::parse(NETWORK_SECURITY_CONFIG_XML)?;
    let network_binary = encode_xml_document(&network_document, &|_| None)?;
    files.set_file(NETWORK_SECURITY_RESOURCE_PATH, network_binary)?;
    let name = manifest_entry_name(files)?;
    let raw = files
        .raw_file(&name)
        .ok_or_else(|| "AndroidManifest.xml has no raw bytes".to_string())?;
    let binary = set_binary_xml_attribute(raw, "application", "usesCleartextTraffic", "true")?;
    let binary = set_binary_xml_attribute(
        &binary,
        "application",
        "networkSecurityConfig",
        &format!("@0x{resource_id:08x}"),
    )?;
    install_manifest(files, binary)
}

fn manifest_entry_name(files: &Files) -> Result<String, String> {
    files
        .archive
        .iter()
        .find(|entry| {
            entry.name == "AndroidManifest.xml" || entry.name.ends_with("/AndroidManifest.xml")
        })
        .map(|entry| entry.name.clone())
        .or_else(|| {
            files
                .binaries
                .keys()
                .find(|name| name.ends_with("AndroidManifest.xml"))
                .cloned()
        })
        .ok_or_else(|| "AndroidManifest.xml not found".to_string())
}

fn install_manifest(files: &mut Files, binary: Vec<u8>) -> Result<(), String> {
    let name = manifest_entry_name(files)?;
    files.set_file(name, binary.clone())?;
    let (manifest_content, manifest) = decode_binary_manifest(&binary, &files.binary_resource_file);
    if manifest_content.trim().is_empty() {
        return Err("the generated AndroidManifest.xml could not be decoded".to_string());
    }
    files.manifest_content = manifest_content.clone();
    files.android_manifest = manifest.clone();
    for multi_dex in &mut files.multi_dex {
        multi_dex.manifest_content = manifest_content.clone();
        multi_dex.android_manifest = manifest.clone();
    }
    Ok(())
}

/// Edit the top-level Android manifest and refresh the decoded analysis view.
pub fn set_manifest_attribute(
    files: &mut Files,
    element: &str,
    attribute: &str,
    value: &str,
) -> Result<(), String> {
    let name = manifest_entry_name(files)?;
    let raw = files
        .raw_file(&name)
        .ok_or_else(|| "AndroidManifest.xml has no raw bytes".to_string())?;
    let edited = set_binary_xml_attribute(raw, element, attribute, value)?;
    files.set_file(name, edited.clone())?;

    let (manifest_content, manifest) = decode_binary_manifest(&edited, &files.binary_resource_file);
    files.manifest_content = manifest_content.clone();
    files.android_manifest = manifest.clone();
    for multi_dex in &mut files.multi_dex {
        multi_dex.manifest_content = manifest_content.clone();
        multi_dex.android_manifest = manifest.clone();
    }
    Ok(())
}

/// Change the Android package name in the manifest and refresh the parsed
/// manifest view. This changes the install identity, but intentionally does
/// not rename DEX class descriptors or other package-qualified strings.
pub fn set_package_name(files: &mut Files, package_name: &str) -> Result<(), String> {
    if !is_valid_package_name(package_name) {
        return Err(format!("invalid Android package name: {package_name}"));
    }
    set_manifest_attribute(files, "manifest", "package", package_name)?;
    // serde_xml_rs does not consistently expose XML attributes in this
    // non-exhaustive model, so keep the convenience API's parsed value
    // authoritative as well.
    files.android_manifest.package = package_name.to_string();
    for multi_dex in &mut files.multi_dex {
        multi_dex.android_manifest.package = package_name.to_string();
    }
    Ok(())
}

fn is_valid_package_name(package_name: &str) -> bool {
    !package_name.is_empty()
        && package_name.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_alphabetic())
                && segment
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        })
}

pub(crate) fn decode_binary_manifest(
    binary_manifest: &[u8],
    binary_resources: &[u8],
) -> (String, AndroidManifest) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decode_binary_manifest_inner(binary_manifest, binary_resources)
    }));
    match result {
        Ok(value) => value,
        Err(_) => {
            log::warn!("abxml rejected the APK resource table while decoding the manifest");
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decode_binary_manifest_inner(binary_manifest, &[])
            }))
            .unwrap_or_default()
        }
    }
}

fn decode_binary_manifest_inner(
    binary_manifest: &[u8],
    _binary_resources: &[u8],
) -> (String, AndroidManifest) {
    let content = decode_axml_document(binary_manifest).unwrap_or_default();
    let manifest = serde_xml_rs::from_str(&content).unwrap_or_default();
    (content, manifest)
}

/// Decode Android's binary XML without requiring every resource reference to
/// be present in an `arsc` model.  In particular, newer manifest attributes
/// can be unknown to an older resource decoder; dropping their parent element
/// makes the resulting text impossible to edit safely.  Unknown typed values
/// are emitted in a lossless internal form and accepted by the encoder below.
fn decode_axml_document(input: &[u8]) -> Result<String, String> {
    let document = AxmlDocument::parse(input)?;
    let mut namespaces = BTreeMap::<String, String>::new();
    for chunk in &document.chunks {
        if chunk.kind != 0x0100 || chunk.bytes.len() < 24 {
            continue;
        }
        let prefix_index = read_u32(&chunk.bytes, 16);
        let prefix = if prefix_index == u32::MAX {
            String::new()
        } else {
            document
                .strings
                .get(prefix_index as usize)
                .cloned()
                .ok_or_else(|| "invalid AXML namespace prefix".to_string())?
        };
        let uri = document
            .strings
            .get(read_u32(&chunk.bytes, 20) as usize)
            .cloned()
            .ok_or_else(|| "invalid AXML namespace URI".to_string())?;
        namespaces.insert(uri, prefix);
    }

    let mut stack = Vec::<XmlNode>::new();
    let mut root = None;
    for chunk in &document.chunks {
        match chunk.kind {
            0x0102 => {
                let header = chunk.header_size;
                if chunk.bytes.len() < header + 14 {
                    return Err("truncated AXML start-element chunk".to_string());
                }
                let namespace_index = read_u32(&chunk.bytes, header);
                let name_index = read_u32(&chunk.bytes, header + 4);
                let attributes_start = header + read_u16(&chunk.bytes, header + 8) as usize;
                let attribute_size = read_u16(&chunk.bytes, header + 10) as usize;
                let attribute_count = read_u16(&chunk.bytes, header + 12) as usize;
                if attribute_size < 20
                    || attributes_start
                        .checked_add(attribute_count.saturating_mul(attribute_size))
                        .is_none_or(|end| end > chunk.bytes.len())
                {
                    return Err("invalid AXML attribute table".to_string());
                }
                let local_name = document
                    .strings
                    .get(name_index as usize)
                    .cloned()
                    .ok_or_else(|| "invalid AXML element name".to_string())?;
                let namespace = if namespace_index == u32::MAX {
                    None
                } else {
                    Some(
                        document
                            .strings
                            .get(namespace_index as usize)
                            .cloned()
                            .ok_or_else(|| "invalid AXML element namespace".to_string())?,
                    )
                };
                let mut attributes = Vec::with_capacity(attribute_count);
                for index in 0..attribute_count {
                    let offset = attributes_start + index * attribute_size;
                    let namespace_index = read_u32(&chunk.bytes, offset);
                    let name_index = read_u32(&chunk.bytes, offset + 4);
                    let data_type = chunk.bytes[offset + 15];
                    let data = read_u32(&chunk.bytes, offset + 16);
                    let name = document
                        .strings
                        .get(name_index as usize)
                        .cloned()
                        .ok_or_else(|| "invalid AXML attribute name".to_string())?;
                    let namespace = if namespace_index == u32::MAX {
                        None
                    } else {
                        Some(
                            document
                                .strings
                                .get(namespace_index as usize)
                                .cloned()
                                .ok_or_else(|| "invalid AXML attribute namespace".to_string())?,
                        )
                    };
                    let value = decode_axml_value(&document.strings, data_type, data)?;
                    attributes.push(XmlAttribute {
                        local_name: name,
                        namespace,
                        value,
                    });
                }
                stack.push(XmlNode {
                    local_name,
                    namespace,
                    attributes,
                    children: Vec::new(),
                });
            }
            0x0103 => {
                let node = stack
                    .pop()
                    .ok_or_else(|| "AXML end-element without start-element".to_string())?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Element(node));
                } else if root.replace(node).is_some() {
                    return Err("AXML document contains multiple roots".to_string());
                }
            }
            0x0104 => {
                let header = chunk.header_size;
                if chunk.bytes.len() < header + 4 {
                    return Err("truncated AXML text chunk".to_string());
                }
                let string_index = read_u32(&chunk.bytes, header);
                let text = document
                    .strings
                    .get(string_index as usize)
                    .cloned()
                    .ok_or_else(|| "invalid AXML text string".to_string())?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(XmlChild::Text(text));
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err("AXML document has unclosed elements".to_string());
    }
    let root = root.ok_or_else(|| "AXML document has no root element".to_string())?;
    let document = XmlDocument {
        root,
        namespaces: namespaces
            .into_iter()
            .map(|(uri, prefix)| (prefix, uri))
            .collect(),
    };
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
    append_xml_text(&mut output, &document.root, &document.namespaces, true);
    Ok(output)
}

fn decode_axml_value(strings: &[String], data_type: u8, data: u32) -> Result<String, String> {
    match data_type {
        0x00 => Ok("@raw:0x00:0x00000000".to_string()),
        0x01 => Ok(format!("@0x{data:08x}")),
        0x02 => Ok(format!("?0x{data:08x}")),
        0x03 => strings
            .get(data as usize)
            .cloned()
            .ok_or_else(|| "invalid AXML string value".to_string()),
        0x10 => Ok(format!("0x{data:08x}")),
        0x12 => Ok(if data == 0 { "false" } else { "true" }.to_string()),
        0x11..=0x1f => Ok(format!("@raw:0x{data_type:02x}:0x{data:08x}")),
        _ => Err(format!("unsupported AXML value type 0x{data_type:02x}")),
    }
}

fn append_xml_text(
    output: &mut String,
    node: &XmlNode,
    namespaces: &[(String, String)],
    root: bool,
) {
    output.push('<');
    append_xml_name(
        output,
        node.namespace.as_deref(),
        &node.local_name,
        namespaces,
    );
    if root {
        for (prefix, uri) in namespaces {
            output.push(' ');
            if prefix.is_empty() {
                output.push_str("xmlns");
            } else {
                output.push_str("xmlns:");
                output.push_str(prefix);
            }
            output.push_str("=\"");
            escape_xml(output, uri, true);
            output.push('"');
        }
    }
    for attribute in &node.attributes {
        output.push(' ');
        append_xml_name(
            output,
            attribute.namespace.as_deref(),
            &attribute.local_name,
            namespaces,
        );
        output.push_str("=\"");
        escape_xml(output, &attribute.value, true);
        output.push('"');
    }
    if node.children.is_empty() {
        output.push_str(" />");
        return;
    }
    output.push('>');
    for child in &node.children {
        match child {
            XmlChild::Element(child) => append_xml_text(output, child, namespaces, false),
            XmlChild::Text(text) => escape_xml(output, text, false),
        }
    }
    output.push_str("</");
    append_xml_name(
        output,
        node.namespace.as_deref(),
        &node.local_name,
        namespaces,
    );
    output.push('>');
}

fn append_xml_name(
    output: &mut String,
    namespace: Option<&str>,
    local_name: &str,
    namespaces: &[(String, String)],
) {
    if let Some(namespace) = namespace {
        if let Some((prefix, _)) = namespaces.iter().find(|(_, uri)| uri == namespace) {
            if !prefix.is_empty() {
                output.push_str(prefix);
                output.push(':');
            }
        }
    }
    output.push_str(local_name);
}

fn escape_xml(output: &mut String, value: &str, attribute: bool) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' if attribute => output.push_str("&quot;"),
            _ => output.push(character),
        }
    }
}

fn is_signature_entry(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("META-INF/")
        && (upper.ends_with(".SF")
            || upper.ends_with(".RSA")
            || upper.ends_with(".DSA")
            || upper.ends_with(".EC")
            || upper.ends_with("MANIFEST.MF"))
}

fn is_native_library_entry(name: &str) -> bool {
    name.starts_with("lib/") && name.ends_with(".so")
}

#[derive(Debug, Clone)]
struct XmlDocument {
    root: XmlNode,
    namespaces: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct XmlNode {
    local_name: String,
    namespace: Option<String>,
    attributes: Vec<XmlAttribute>,
    children: Vec<XmlChild>,
}

#[derive(Debug, Clone)]
struct XmlAttribute {
    local_name: String,
    namespace: Option<String>,
    value: String,
}

#[derive(Debug, Clone)]
enum XmlChild {
    Element(XmlNode),
    Text(String),
}

impl XmlDocument {
    fn parse(xml: &str) -> Result<Self, String> {
        use xml::reader::{EventReader, XmlEvent};

        let reader = EventReader::new(xml.as_bytes());
        let mut stack: Vec<XmlNode> = Vec::new();
        let mut root = None;
        let mut namespaces = BTreeMap::<String, String>::new();
        for event in reader {
            let event = event.map_err(|error| format!("invalid XML: {error}"))?;
            match event {
                XmlEvent::StartElement {
                    name,
                    attributes,
                    namespace,
                } => {
                    for (prefix, uri) in namespace.0 {
                        namespaces.insert(prefix, uri);
                    }
                    let node = XmlNode {
                        local_name: name.local_name,
                        namespace: name.namespace,
                        attributes: attributes
                            .into_iter()
                            .map(|attribute| XmlAttribute {
                                local_name: attribute.name.local_name,
                                namespace: attribute.name.namespace,
                                value: attribute.value,
                            })
                            .collect(),
                        children: Vec::new(),
                    };
                    stack.push(node);
                }
                XmlEvent::EndElement { .. } => {
                    let node = stack
                        .pop()
                        .ok_or_else(|| "XML has an unmatched closing element".to_string())?;
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(XmlChild::Element(node));
                    } else if root.replace(node).is_some() {
                        return Err("XML contains more than one root element".to_string());
                    }
                }
                XmlEvent::Characters(text) | XmlEvent::CData(text) => {
                    if !text.is_empty() {
                        if let Some(parent) = stack.last_mut() {
                            if !text.trim().is_empty() {
                                parent.children.push(XmlChild::Text(text));
                            }
                        } else if !text.trim().is_empty() {
                            return Err("text is not allowed outside the XML root".to_string());
                        }
                    }
                }
                XmlEvent::Whitespace(_)
                | XmlEvent::Comment(_)
                | XmlEvent::ProcessingInstruction { .. }
                | XmlEvent::StartDocument { .. }
                | XmlEvent::EndDocument => {}
            }
        }
        if !stack.is_empty() {
            return Err("XML has an unclosed element".to_string());
        }
        let root = root.ok_or_else(|| "XML has no root element".to_string())?;
        Ok(Self {
            root,
            namespaces: namespaces.into_iter().collect(),
        })
    }
}

fn encode_xml_document<F>(document: &XmlDocument, resolver: &F) -> Result<Vec<u8>, String>
where
    F: Fn(&str) -> Option<u32>,
{
    let mut strings = Vec::new();
    let mut add_string = |value: &str| {
        if !strings.iter().any(|current: &String| current == value) {
            strings.push(value.to_string());
        }
    };
    for (prefix, uri) in &document.namespaces {
        if !prefix.is_empty() {
            add_string(prefix);
        }
        add_string(uri);
    }
    gather_xml_strings(&document.root, &mut add_string);

    let string_index = |value: &str, strings: &[String]| {
        strings
            .iter()
            .position(|current| current == value)
            .map(|index| index as u32)
    };
    let mut resource_ids = vec![0u32; strings.len()];
    for (index, string) in strings.iter().enumerate() {
        resource_ids[index] = known_android_attribute_id(string);
    }

    let mut output = encode_axml_string_pool(&strings)?;
    if resource_ids.iter().any(|id| *id != 0) {
        let mut chunk = Vec::with_capacity(8 + resource_ids.len() * 4);
        push_u16(&mut chunk, 0x0180);
        push_u16(&mut chunk, 8);
        push_u32(&mut chunk, (8 + resource_ids.len() * 4) as u32);
        for id in resource_ids {
            push_u32(&mut chunk, id);
        }
        output.extend_from_slice(&chunk);
    }

    let namespace_map = document
        .namespaces
        .iter()
        .map(|(prefix, uri)| {
            let uri_index = string_index(uri, &strings)
                .ok_or_else(|| format!("namespace URI was not added to the string pool: {uri}"))?;
            let prefix_index = if prefix.is_empty() {
                u32::MAX
            } else {
                string_index(prefix, &strings).ok_or_else(|| {
                    format!("namespace prefix was not added to the string pool: {prefix}")
                })?
            };
            Ok((prefix.clone(), uri.clone(), prefix_index, uri_index))
        })
        .collect::<Result<Vec<_>, String>>()?;
    for (_, _, prefix_index, uri_index) in &namespace_map {
        append_namespace_chunk(&mut output, true, *prefix_index, *uri_index);
    }
    append_xml_node(&mut output, &document.root, &strings, resolver)?;
    for (_, _, prefix_index, uri_index) in namespace_map.iter().rev() {
        append_namespace_chunk(&mut output, false, *prefix_index, *uri_index);
    }

    let total_size = 8 + output.len();
    let mut document_bytes = Vec::with_capacity(total_size);
    push_u16(&mut document_bytes, 0x0003);
    push_u16(&mut document_bytes, 8);
    push_u32(&mut document_bytes, total_size as u32);
    document_bytes.extend_from_slice(&output);
    Ok(document_bytes)
}

fn gather_xml_strings<F>(node: &XmlNode, add_string: &mut F)
where
    F: FnMut(&str),
{
    add_string(&node.local_name);
    if let Some(namespace) = &node.namespace {
        add_string(namespace);
    }
    for attribute in &node.attributes {
        add_string(&attribute.local_name);
        if let Some(namespace) = &attribute.namespace {
            add_string(namespace);
        }
        add_string(&attribute.value);
    }
    for child in &node.children {
        match child {
            XmlChild::Element(child) => gather_xml_strings(child, add_string),
            XmlChild::Text(text) => add_string(text),
        }
    }
}

fn known_android_attribute_id(name: &str) -> u32 {
    match name {
        "theme" => 0x0101_0000,
        "label" => 0x0101_0001,
        "icon" => 0x0101_0002,
        "permission" => 0x0101_0006,
        "enabled" => 0x0101_000e,
        "debuggable" => 0x0101_000f,
        "exported" => 0x0101_0010,
        "authorities" => 0x0101_0018,
        "mimeType" => 0x0101_0026,
        "scheme" => 0x0101_0027,
        "host" => 0x0101_0028,
        "port" => 0x0101_0029,
        "path" => 0x0101_002a,
        "pathPrefix" => 0x0101_002b,
        "pathPattern" => 0x0101_002c,
        "value" => 0x0101_0024,
        "versionCode" => 0x0101_021b,
        "versionName" => 0x0101_021c,
        "minSdkVersion" => 0x0101_020c,
        "targetSdkVersion" => 0x0101_0270,
        "testOnly" => 0x0101_0272,
        "allowBackup" => 0x0101_0280,
        "required" => 0x0101_028e,
        "supportsRtl" => 0x0101_03af,
        "extractNativeLibs" => 0x0101_04ea,
        "fullBackupContent" => 0x0101_04eb,
        "networkSecurityConfig" => 0x0101_0527,
        "usesCleartextTraffic" => 0x0101_04ec,
        "roundIcon" => 0x0101_052c,
        "appComponentFactory" => 0x0101_057a,
        "dataExtractionRules" => 0x0101_063e,
        "compileSdkVersion" => 0x0101_0572,
        "compileSdkVersionCodename" => 0x0101_0573,
        "name" => 0x0101_0003,
        _ => 0,
    }
}

fn append_namespace_chunk(output: &mut Vec<u8>, start: bool, prefix: u32, uri: u32) {
    push_u16(output, if start { 0x0100 } else { 0x0101 });
    push_u16(output, 16);
    push_u32(output, 24);
    push_u32(output, 0);
    push_u32(output, u32::MAX);
    push_u32(output, prefix);
    push_u32(output, uri);
}

fn append_xml_node<F>(
    output: &mut Vec<u8>,
    node: &XmlNode,
    strings: &[String],
    resolver: &F,
) -> Result<(), String>
where
    F: Fn(&str) -> Option<u32>,
{
    let node_name = string_index_required(strings, &node.local_name)?;
    let node_namespace = node
        .namespace
        .as_deref()
        .map(|namespace| string_index_required(strings, namespace))
        .transpose()?
        .unwrap_or(u32::MAX);
    let mut attributes = Vec::with_capacity(node.attributes.len());
    for attribute in &node.attributes {
        let namespace = attribute
            .namespace
            .as_deref()
            .map(|namespace| string_index_required(strings, namespace))
            .transpose()?
            .unwrap_or(u32::MAX);
        let name = string_index_required(strings, &attribute.local_name)?;
        let value = encode_attribute_value(&attribute.value, strings, resolver)?;
        attributes.push((namespace, name, value));
    }

    let chunk_size = 36 + attributes.len() * 20;
    push_u16(output, 0x0102);
    push_u16(output, 16);
    push_u32(output, chunk_size as u32);
    push_u32(output, 0);
    push_u32(output, u32::MAX);
    push_u32(output, node_namespace);
    push_u32(output, node_name);
    push_u16(output, 20);
    push_u16(output, 20);
    push_u16(output, attributes.len() as u16);
    push_u16(output, 0);
    push_u16(output, 0);
    push_u16(output, 0);
    for (namespace, name, value) in attributes {
        push_u32(output, namespace);
        push_u32(output, name);
        push_u32(output, value.raw);
        push_u16(output, 8);
        output.push(0);
        output.push(value.data_type);
        push_u32(output, value.data);
    }

    for child in &node.children {
        match child {
            XmlChild::Element(child) => append_xml_node(output, child, strings, resolver)?,
            XmlChild::Text(text) => append_cdata_chunk(output, text, strings)?,
        }
    }
    push_u16(output, 0x0103);
    push_u16(output, 16);
    push_u32(output, 24);
    push_u32(output, 0);
    push_u32(output, u32::MAX);
    push_u32(output, node_namespace);
    push_u32(output, node_name);
    Ok(())
}

struct EncodedAttributeValue {
    raw: u32,
    data_type: u8,
    data: u32,
}

fn encode_attribute_value<F>(
    value: &str,
    strings: &[String],
    resolver: &F,
) -> Result<EncodedAttributeValue, String>
where
    F: Fn(&str) -> Option<u32>,
{
    if value == "true" || value == "false" {
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type: 0x12,
            data: u32::from(value == "true"),
        });
    }
    if let Ok(number) = value.parse::<i32>() {
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type: 0x10,
            data: number as u32,
        });
    }
    if let Some(number) = value.strip_prefix("0x") {
        if let Ok(number) = u32::from_str_radix(number, 16) {
            return Ok(EncodedAttributeValue {
                raw: u32::MAX,
                data_type: 0x10,
                data: number,
            });
        }
    }
    if let Some(number) = value.strip_prefix("?0x") {
        let number = u32::from_str_radix(number, 16)
            .map_err(|_| format!("invalid attribute reference: {value}"))?;
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type: 0x02,
            data: number,
        });
    }
    if let Some(number) = value.strip_prefix("@flags:") {
        let number = number
            .parse::<i32>()
            .map_err(|_| format!("invalid flags value: {value}"))?;
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type: 0x10,
            data: number as u32,
        });
    }
    if value == "@null" {
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type: 0,
            data: 0,
        });
    }
    if let Some(raw) = value.strip_prefix("@raw:") {
        let (data_type, data) = raw
            .split_once(':')
            .ok_or_else(|| format!("invalid raw AXML value: {value}"))?;
        let data_type = parse_hex_byte(data_type)
            .ok_or_else(|| format!("invalid raw AXML type: {data_type}"))?;
        let data = parse_hex_u32(data).ok_or_else(|| format!("invalid raw AXML data: {data}"))?;
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type,
            data,
        });
    }
    if let Some(number) = value.strip_prefix("@flags:") {
        let number = number
            .parse::<i32>()
            .map_err(|_| format!("invalid flags value: {value}"))?;
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type: 0x10,
            data: number as u32,
        });
    }
    if let Some(reference) = value.strip_prefix('@') {
        if let Some(number) = reference.strip_prefix("0x") {
            let number = u32::from_str_radix(number, 16)
                .map_err(|_| format!("invalid resource reference: {value}"))?;
            return Ok(EncodedAttributeValue {
                raw: u32::MAX,
                data_type: 0x01,
                data: number,
            });
        }
        let resource_id = resolver(value)
            .ok_or_else(|| format!("resource reference cannot be resolved: {value}"))?;
        return Ok(EncodedAttributeValue {
            raw: u32::MAX,
            data_type: 0x01,
            data: resource_id,
        });
    }
    if value.starts_with('?') {
        return Err(format!("theme reference cannot be resolved: {value}"));
    }
    let index = string_index_required(strings, value)?;
    Ok(EncodedAttributeValue {
        raw: index,
        data_type: 0x03,
        data: index,
    })
}

fn append_cdata_chunk(output: &mut Vec<u8>, text: &str, strings: &[String]) -> Result<(), String> {
    let index = string_index_required(strings, text)?;
    push_u16(output, 0x0104);
    push_u16(output, 16);
    push_u32(output, 28);
    push_u32(output, 0);
    push_u32(output, u32::MAX);
    push_u32(output, index);
    push_u16(output, 8);
    output.push(0);
    output.push(0x03);
    push_u32(output, index);
    Ok(())
}

fn string_index_required(strings: &[String], value: &str) -> Result<u32, String> {
    strings
        .iter()
        .position(|current| current == value)
        .map(|index| index as u32)
        .ok_or_else(|| format!("string was not added to the AXML string pool: {value}"))
}

fn encode_axml_string_pool(strings: &[String]) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut offsets = Vec::with_capacity(strings.len());
    for string in strings {
        offsets.push(data.len() as u32);
        append_uleb128(&mut data, string.encode_utf16().count() as u32);
        append_uleb128(&mut data, string.len() as u32);
        data.extend_from_slice(string.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let string_start = 28 + strings.len() * 4;
    let total_size = string_start + data.len();
    let mut output = Vec::with_capacity(total_size);
    push_u16(&mut output, 0x0001);
    push_u16(&mut output, 28);
    push_u32(&mut output, total_size as u32);
    push_u32(&mut output, strings.len() as u32);
    push_u32(&mut output, 0);
    push_u32(&mut output, 0x0000_0100);
    push_u32(&mut output, string_start as u32);
    push_u32(&mut output, 0);
    for offset in offsets {
        push_u32(&mut output, offset);
    }
    output.extend_from_slice(&data);
    Ok(output)
}

fn lookup_resource_reference(files: &Files, reference: &str) -> Option<u32> {
    let reference = reference.strip_prefix('@')?;
    if let Some(value) = reference.strip_prefix("0x") {
        return u32::from_str_radix(value, 16).ok();
    }
    let (package_name, reference) = reference
        .split_once(':')
        .map_or((None, reference), |(package, reference)| {
            (Some(package), reference)
        });
    let (type_name, entry_name) = reference.split_once('/')?;
    let table = arsc::parse_from(Cursor::new(&files.binary_resource_file)).ok()?;
    for package in &table.packages {
        if package_name.is_some_and(|name| name != package.name) {
            continue;
        }
        if package_name.is_none() && package.id == 1 {
            continue;
        }
        let Some(type_id) = package
            .type_names
            .strings
            .iter()
            .position(|name| name == type_name)
            .map(|index| index + 1)
        else {
            continue;
        };
        let Some(type_entry) = package.types.get(type_id - 1) else {
            continue;
        };
        for config in &type_entry.configs {
            if let Some(entry) = config.resources.resources.iter().find(|entry| {
                package
                    .key_names
                    .strings
                    .get(entry.name_index)
                    .map(String::as_str)
                    == Some(entry_name)
            }) {
                return Some((package.id << 24) | ((type_id as u32) << 16) | entry.spec_id as u32);
            }
        }
    }
    None
}

fn ensure_xml_resource(files: &mut Files, name: &str, path: &str) -> Result<u32, String> {
    if files.binary_resource_file.is_empty() {
        return ensure_xml_resource_from_structured_arsc(files, name, path);
    }

    let (bytes, resource_id) =
        add_xml_resource_to_binary_table(&files.binary_resource_file, name, path)?;
    files.set_file("resources.arsc", bytes)?;
    Ok(resource_id)
}

fn ensure_xml_resource_from_structured_arsc(
    files: &mut Files,
    name: &str,
    path: &str,
) -> Result<u32, String> {
    let mut table = if files.binary_resource_file.is_empty() {
        let package_name = manifest_package_name(files).unwrap_or_else(|| "coeus".to_string());
        arsc::Arsc {
            global_string_pool: arsc::StringPool {
                flags: 0x0000_0100,
                strings: Vec::new(),
                styles: Vec::new(),
            },
            packages: vec![arsc::Package {
                id: 0x7f,
                name: package_name,
                type_names: arsc::StringPool {
                    flags: 0x0000_0100,
                    strings: Vec::new(),
                    styles: Vec::new(),
                },
                last_public_type: 0,
                types: Vec::new(),
                key_names: arsc::StringPool {
                    flags: 0x0000_0100,
                    strings: Vec::new(),
                    styles: Vec::new(),
                },
                last_public_key: 0,
            }],
        }
    } else {
        arsc::parse_from(Cursor::new(&files.binary_resource_file))
            .map_err(|error| format!("could not parse resources.arsc: {error}"))?
    };

    let package_index = table
        .packages
        .iter()
        .position(|package| package.id != 1)
        .or_else(|| (!table.packages.is_empty()).then_some(0))
        .ok_or_else(|| "resources.arsc contains no package".to_string())?;
    let path_index = pool_index(&mut table.global_string_pool, path);
    let package = &mut table.packages[package_index];
    let key_index = pool_index(&mut package.key_names, name) as usize;
    let type_id = if let Some(index) = package
        .type_names
        .strings
        .iter()
        .position(|type_name| type_name == "xml")
    {
        index + 1
    } else {
        package.type_names.strings.push("xml".to_string());
        package
            .types
            .push(arsc::Type::with_id(package.types.len() + 1));
        package.type_names.strings.len()
    };
    while package.types.len() < type_id {
        package
            .types
            .push(arsc::Type::with_id(package.types.len() + 1));
    }
    package.last_public_type = package.last_public_type.max(type_id as u32);
    package.last_public_key = package
        .last_public_key
        .max(package.key_names.strings.len() as u32);

    let type_entry = &mut package.types[type_id - 1];
    let existing_spec_id = type_entry.configs.iter_mut().find_map(|config| {
        config
            .resources
            .resources
            .iter_mut()
            .find(|entry| entry.name_index == key_index)
            .map(|entry| {
                match &mut entry.value {
                    arsc::ResourceValue::Plain(value) => {
                        value.size = 8;
                        value.zero = 0;
                        value.r#type = 0x03;
                        value.data_index = path_index as usize;
                    }
                    arsc::ResourceValue::Bag { .. } => {}
                }
                entry.spec_id
            })
    });
    if let Some(spec_id) = existing_spec_id {
        if type_entry
            .configs
            .iter()
            .flat_map(|config| config.resources.resources.iter())
            .any(|entry| entry.name_index == key_index && entry.is_bag())
        {
            return Err(format!("resource already exists as a bag: {name}"));
        }
        return write_resource_table(files, table, package_index, type_id, spec_id);
    }

    let spec_id = type_entry
        .specs
        .as_ref()
        .map(|specs| specs.specs.len())
        .unwrap_or(0);
    if let Some(specs) = &mut type_entry.specs {
        specs.specs.push(arsc::Spec::new(0, spec_id));
    } else {
        type_entry.specs = Some(arsc::Specs {
            type_id,
            res0: 0,
            res1: 0,
            specs: vec![arsc::Spec::new(0, spec_id)],
            header_size: 0x0010,
        });
    }

    if type_entry.configs.is_empty() {
        type_entry.configs.push(arsc::Config {
            type_id,
            res0: 0,
            res1: 0,
            id: default_config_id(),
            resources: arsc::Resources {
                resources: vec![new_xml_resource_entry(key_index, path_index, spec_id)],
                missing_entries: 0,
            },
            header_size: 0x0054,
        });
    } else {
        for config in &mut type_entry.configs {
            config
                .resources
                .resources
                .push(new_xml_resource_entry(key_index, path_index, spec_id));
        }
    }
    write_resource_table(files, table, package_index, type_id, spec_id)
}

fn manifest_package_name(files: &Files) -> Option<String> {
    if !files.android_manifest.package.is_empty() {
        return Some(files.android_manifest.package.clone());
    }
    let document = XmlDocument::parse(&files.manifest_content).ok()?;
    document
        .root
        .attributes
        .iter()
        .find(|attribute| attribute.namespace.is_none() && attribute.local_name == "package")
        .map(|attribute| attribute.value.clone())
}

fn pool_index(pool: &mut arsc::StringPool, value: &str) -> u32 {
    if let Some(index) = pool.strings.iter().position(|current| current == value) {
        index as u32
    } else {
        let index = pool.strings.len() as u32;
        pool.strings.push(value.to_string());
        index
    }
}

fn default_config_id() -> Vec<u8> {
    let mut id = vec![0u8; 64];
    id[0..4].copy_from_slice(&64u32.to_le_bytes());
    id
}

fn new_xml_resource_entry(
    name_index: usize,
    path_index: u32,
    spec_id: usize,
) -> arsc::ResourceEntry {
    arsc::ResourceEntry {
        flags: 0,
        name_index,
        value: arsc::ResourceValue::Plain(arsc::Value {
            size: 8,
            zero: 0,
            r#type: 0x03,
            data_index: path_index as usize,
        }),
        spec_id,
    }
}

fn write_resource_table(
    files: &mut Files,
    table: arsc::Arsc,
    package_index: usize,
    type_id: usize,
    spec_id: usize,
) -> Result<u32, String> {
    let package = table
        .packages
        .get(package_index)
        .ok_or_else(|| "resource package disappeared while writing".to_string())?;
    let resource_id = (package.id << 24) | ((type_id as u32) << 16) | spec_id as u32;
    let mut bytes = Vec::new();
    arsc::write_to(&table, &mut bytes)
        .map_err(|error| format!("could not write resources.arsc: {error}"))?;
    files.set_file("resources.arsc", bytes)?;
    Ok(resource_id)
}

/// `arsc` 0.1.x does not preserve sparse entry IDs when it parses a resource
/// table.  That is especially common for XML resources (for example IDs 0, 6
/// and 7).  Rewriting such a table through the structured model can therefore
/// corrupt existing references.  This small binary patcher only appends the
/// strings, spec, and entry needed for a new XML resource and leaves all
/// existing bytes and IDs intact.
fn add_xml_resource_to_binary_table(
    input: &[u8],
    name: &str,
    path: &str,
) -> Result<(Vec<u8>, u32), String> {
    let root_header = checked_u16(input, 2, "resources.arsc header")? as usize;
    let root_size = checked_u32(input, 4, "resources.arsc size")? as usize;
    if root_header < 12 || root_size != input.len() || checked_u32(input, 8, "package count")? == 0
    {
        return Err("invalid resources.arsc table header".to_string());
    }

    let global_start = root_header;
    let global_size = chunk_size(input, global_start)?;
    let global_end = global_start
        .checked_add(global_size)
        .ok_or_else(|| "global resource string pool overflows".to_string())?;
    if global_end > input.len() || checked_u16(input, global_start, "global string pool")? != 1 {
        return Err("resources.arsc has no valid global string pool".to_string());
    }

    let mut package_ranges = Vec::new();
    let mut offset = global_end;
    while offset < input.len() {
        let size = chunk_size(input, offset)?;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "resource package overflows".to_string())?;
        if end > input.len() {
            return Err("resource package extends beyond resources.arsc".to_string());
        }
        if checked_u16(input, offset, "resource package")? == 0x0200 {
            package_ranges.push((offset, end));
        }
        offset = end;
    }
    if package_ranges.is_empty() {
        return Err("resources.arsc contains no package".to_string());
    }

    // First resolve an already existing resource.  This avoids needlessly
    // changing the table when an APK already bundles the convenience file.
    for &(start, end) in &package_ranges {
        if let Some(resource_id) = find_xml_resource_id(&input[start..end], name)? {
            return Ok((input.to_vec(), resource_id));
        }
    }

    let (global_chunk, path_index) = append_string_pool_string(
        &input[global_start..global_end],
        path,
        "global resource string pool",
    )?;

    let mut output = Vec::with_capacity(input.len() + global_chunk.len() - global_size);
    output.extend_from_slice(&input[..global_start]);
    output.extend_from_slice(&global_chunk);

    let mut resource_id = None;
    offset = global_end;
    while offset < input.len() {
        let size = chunk_size(input, offset)?;
        let end = offset + size;
        let chunk = &input[offset..end];
        if checked_u16(chunk, 0, "resource table chunk")? == 0x0200 && resource_id.is_none() {
            let package_id = checked_u32(chunk, 8, "resource package ID")?;
            let (patched, id) = add_xml_resource_to_package(chunk, name, path_index)?;
            resource_id = Some((package_id << 24) | id);
            output.extend_from_slice(&patched);
        } else {
            output.extend_from_slice(chunk);
        }
        offset = end;
    }

    let resource_id = resource_id.ok_or_else(|| {
        "resources.arsc has no application resource package with an XML type".to_string()
    })?;
    if output.len() > u32::MAX as usize {
        return Err("resources.arsc is too large".to_string());
    }
    let output_size = output.len() as u32;
    write_u32(&mut output, 4, output_size);
    Ok((output, resource_id))
}

fn add_xml_resource_to_package(
    input: &[u8],
    name: &str,
    path_index: u32,
) -> Result<(Vec<u8>, u32), String> {
    let package_header = checked_u16(input, 2, "resource package header")? as usize;
    let package_size = checked_u32(input, 4, "resource package size")? as usize;
    if package_header < 0x0120 || package_size != input.len() {
        return Err("invalid resource package bounds".to_string());
    }
    let type_pool_offset = checked_u32(input, 268, "type string pool offset")? as usize;
    let key_pool_offset = checked_u32(input, 276, "key string pool offset")? as usize;
    let type_pool_end = type_pool_offset
        .checked_add(chunk_size(input, type_pool_offset)? as usize)
        .ok_or_else(|| "type string pool overflows package".to_string())?;
    let key_pool_end = key_pool_offset
        .checked_add(chunk_size(input, key_pool_offset)? as usize)
        .ok_or_else(|| "key string pool overflows package".to_string())?;
    if type_pool_end > input.len()
        || key_pool_end > input.len()
        || checked_u16(input, type_pool_offset, "type string pool")? != 1
        || checked_u16(input, key_pool_offset, "key string pool")? != 1
    {
        return Err("invalid resource package string pools".to_string());
    }

    let type_names = parse_resource_string_pool(&input[type_pool_offset..type_pool_end])?;
    let key_names = parse_resource_string_pool(&input[key_pool_offset..key_pool_end])?;
    let Some(xml_type_id) = type_names
        .iter()
        .position(|value| value == "xml")
        .map(|i| i + 1)
    else {
        return Err("resources.arsc has no XML resource type".to_string());
    };
    let key_index = key_names
        .iter()
        .position(|value| value == name)
        .map(|index| index as u32)
        .unwrap_or(key_names.len() as u32);

    let chunks = package_chunk_ranges(input, package_header)?;
    let mut spec_count = None;
    let mut has_xml_config = false;
    for &(start, end) in &chunks {
        let kind = checked_u16(input, start, "package child chunk")?;
        if kind == 0x0202 && checked_u8(input, start + 8, "type spec ID")? as usize == xml_type_id {
            spec_count = Some(checked_u32(input, start + 12, "type spec count")? as usize);
        } else if kind == 0x0201
            && checked_u8(input, start + 8, "resource type ID")? as usize == xml_type_id
        {
            has_xml_config = true;
        }
        if end > input.len() {
            return Err("resource package child exceeds package".to_string());
        }
    }
    let spec_count = spec_count.ok_or_else(|| "XML resource type has no spec chunk".to_string())?;
    if !has_xml_config {
        return Err("XML resource type has no configuration chunk".to_string());
    }
    let new_entry_id = spec_count;

    let mut output = Vec::with_capacity(input.len() + 256);
    output.extend_from_slice(&input[..package_header]);
    let mut key_pool_written = false;
    let mut default_config_seen = false;
    for &(start, end) in &chunks {
        let kind = checked_u16(input, start, "package child chunk")?;
        let child = &input[start..end];
        if start == key_pool_offset {
            let (pool, _) = append_string_pool_string(child, name, "key resource string pool")?;
            output.extend_from_slice(&pool);
            key_pool_written = true;
        } else if kind == 0x0202
            && checked_u8(input, start + 8, "type spec ID")? as usize == xml_type_id
        {
            let mut patched = child.to_vec();
            let old_count = checked_u32(child, 12, "type spec count")? as usize;
            if old_count != new_entry_id {
                return Err("resource type spec count changed while patching".to_string());
            }
            patched.extend_from_slice(&0u32.to_le_bytes());
            write_u32(&mut patched, 12, (old_count + 1) as u32);
            let patched_size = patched.len() as u32;
            write_u32(&mut patched, 4, patched_size);
            output.extend_from_slice(&patched);
        } else if kind == 0x0201
            && checked_u8(input, start + 8, "resource type ID")? as usize == xml_type_id
        {
            let is_default = is_default_resource_config(child)?;
            let should_add = is_default && !default_config_seen;
            if should_add {
                default_config_seen = true;
            }
            let patched =
                expand_resource_config(child, new_entry_id, key_index, path_index, should_add)?;
            output.extend_from_slice(&patched);
        } else {
            output.extend_from_slice(child);
        }
    }
    if !key_pool_written {
        return Err("key string pool was not found in resource package".to_string());
    }
    if !default_config_seen {
        return Err("resource package has no default XML configuration".to_string());
    }
    let output_size = output.len() as u32;
    write_u32(&mut output, 4, output_size);
    let resource_id = ((xml_type_id as u32) << 16) | new_entry_id as u32;
    Ok((output, resource_id))
}

fn find_xml_resource_id(package: &[u8], name: &str) -> Result<Option<u32>, String> {
    let package_header = checked_u16(package, 2, "resource package header")? as usize;
    let package_id = checked_u32(package, 8, "resource package ID")?;
    let type_pool_offset = checked_u32(package, 268, "type string pool offset")? as usize;
    let key_pool_offset = checked_u32(package, 276, "key string pool offset")? as usize;
    let type_pool_end = type_pool_offset + chunk_size(package, type_pool_offset)? as usize;
    let key_pool_end = key_pool_offset + chunk_size(package, key_pool_offset)? as usize;
    let type_names = parse_resource_string_pool(&package[type_pool_offset..type_pool_end])?;
    let key_names = parse_resource_string_pool(&package[key_pool_offset..key_pool_end])?;
    let Some(key_index) = key_names.iter().position(|value| value == name) else {
        return Ok(None);
    };
    let Some(xml_type_id) = type_names
        .iter()
        .position(|value| value == "xml")
        .map(|i| i + 1)
    else {
        return Ok(None);
    };
    for (start, end) in package_chunk_ranges(package, package_header)? {
        if checked_u16(package, start, "package child chunk")? != 0x0201
            || checked_u8(package, start + 8, "resource type ID")? as usize != xml_type_id
        {
            continue;
        }
        let count = checked_u32(package, start + 12, "resource entry count")? as usize;
        let entry_start = checked_u32(package, start + 16, "resource entry start")? as usize;
        let header_size = checked_u16(package, start + 2, "resource type header")? as usize;
        let offsets_start = start + header_size;
        let sparse = checked_u8(package, start + 9, "resource type flags")? & 0x01 != 0;
        for entry_id in 0..count {
            let raw_offset = checked_u32(
                package,
                offsets_start + entry_id * 4,
                "resource entry offset",
            )?;
            let (entry_id, entry_offset) = if sparse {
                (((raw_offset & 0xffff) as usize), ((raw_offset >> 16) * 4))
            } else {
                (entry_id, raw_offset)
            };
            if !sparse && entry_offset == u32::MAX {
                continue;
            }
            let entry = start
                .checked_add(entry_start)
                .and_then(|base| base.checked_add(entry_offset as usize))
                .ok_or_else(|| "resource entry overflows package".to_string())?;
            if checked_u32(package, entry + 4, "resource entry name")? as usize == key_index {
                return Ok(Some(
                    (package_id << 24) | ((xml_type_id as u32) << 16) | entry_id as u32,
                ));
            }
        }
        let _ = end;
    }
    Ok(None)
}

fn expand_resource_config(
    input: &[u8],
    entry_id: usize,
    key_index: u32,
    path_index: u32,
    add_entry: bool,
) -> Result<Vec<u8>, String> {
    let header_size = checked_u16(input, 2, "resource config header")? as usize;
    let old_count = checked_u32(input, 12, "resource entry count")? as usize;
    let entry_start = checked_u32(input, 16, "resource entry start")? as usize;
    let sparse = checked_u8(input, 9, "resource type flags")? & 0x01 != 0;
    if entry_start < header_size || entry_start > input.len() {
        return Err("invalid resource config entry table".to_string());
    }
    if sparse {
        if entry_id > u16::MAX as usize {
            return Err("new sparse XML resource ID is too large".to_string());
        }
        for index in 0..old_count {
            let offset = checked_u32(input, header_size + index * 4, "sparse resource entry")?;
            if (offset & 0xffff) as usize == entry_id {
                return Err("new XML resource ID is already occupied".to_string());
            }
        }
        if !add_entry {
            return Ok(input.to_vec());
        }
    } else if entry_id < old_count {
        let offset = checked_u32(input, header_size + entry_id * 4, "resource entry offset")?;
        if offset != u32::MAX {
            return Err("new XML resource ID is already occupied".to_string());
        }
    }
    let new_count = if sparse {
        old_count + 1
    } else {
        old_count.max(entry_id + 1)
    };
    let added_slots = new_count - old_count;
    let entry_data = &input[entry_start..];
    let delta = added_slots * 4;
    let mut output = Vec::with_capacity(input.len() + delta + if add_entry { 16 } else { 0 });
    output.extend_from_slice(&input[..header_size]);
    for index in 0..old_count {
        let offset = checked_u32(input, header_size + index * 4, "resource entry offset")?;
        if sparse {
            output.extend_from_slice(&offset.to_le_bytes());
        } else {
            output.extend_from_slice(&offset.to_le_bytes());
        }
    }
    if sparse {
        let entry_offset = entry_data.len() / 4;
        if entry_offset > u16::MAX as usize {
            return Err("sparse XML resource data is too large".to_string());
        }
        output.extend_from_slice(&(entry_id as u16).to_le_bytes());
        output.extend_from_slice(&(entry_offset as u16).to_le_bytes());
    } else {
        for index in old_count..new_count {
            let offset = if add_entry && index == entry_id {
                entry_data.len() as u32
            } else {
                u32::MAX
            };
            output.extend_from_slice(&offset.to_le_bytes());
        }
    }
    output.extend_from_slice(entry_data);
    if add_entry {
        output.extend_from_slice(&resource_entry_bytes(key_index, path_index));
    }
    write_u32(&mut output, 16, (entry_start + delta) as u32);
    write_u32(&mut output, 12, new_count as u32);
    let output_size = output.len() as u32;
    write_u32(&mut output, 4, output_size);
    Ok(output)
}

fn resource_entry_bytes(key_index: u32, path_index: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&8u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&key_index.to_le_bytes());
    bytes.extend_from_slice(&8u16.to_le_bytes());
    bytes.push(0);
    bytes.push(0x03);
    bytes.extend_from_slice(&path_index.to_le_bytes());
    bytes
}

fn is_default_resource_config(input: &[u8]) -> Result<bool, String> {
    let header_size = checked_u16(input, 2, "resource config header")? as usize;
    if header_size < 24 || header_size > input.len() {
        return Err("invalid resource config header size".to_string());
    }
    // The first four bytes of ResTable_config contain its size.  All fields
    // after that are zero for the default configuration.
    Ok(input[24..header_size].iter().all(|byte| *byte == 0))
}

fn append_string_pool_string(
    input: &[u8],
    value: &str,
    description: &str,
) -> Result<(Vec<u8>, u32), String> {
    let (strings, flags, string_start, style_start, style_count) =
        parse_string_pool_metadata(input, description)?;
    if let Some(index) = strings.iter().position(|current| current == value) {
        return Ok((input.to_vec(), index as u32));
    }
    let utf8 = flags & 0x0000_0100 != 0;
    let encoded = encode_resource_string(value, utf8)?;
    let old_string_data_end = if style_count == 0 {
        input.len()
    } else {
        style_start
    };
    if old_string_data_end < string_start || old_string_data_end > input.len() {
        return Err(format!("invalid {description} string data bounds"));
    }
    let old_count = strings.len();
    let offsets_start = 28usize;
    let old_style_offsets_start = offsets_start + old_count * 4;
    let old_string_data = &input[string_start..old_string_data_end];
    let style_offsets = &input[old_style_offsets_start..string_start];
    let styles = if style_count == 0 {
        &input[input.len()..]
    } else {
        &input[style_start..]
    };
    let mut output = Vec::with_capacity(input.len() + 4 + encoded.len() + 4);
    let mut header = input[..28].to_vec();
    write_u32(&mut header, 8, (old_count + 1) as u32);
    write_u32(&mut header, 16, flags);
    let new_string_start = string_start + 4;
    write_u32(&mut header, 20, new_string_start as u32);
    output.extend_from_slice(&header);
    let mut new_string_data = old_string_data.to_vec();
    let new_index_offset = new_string_data.len() as u32;
    new_string_data.extend_from_slice(&encoded);
    while new_string_data.len() % 4 != 0 {
        new_string_data.push(0);
    }
    let new_style_start = if style_count == 0 {
        0
    } else {
        new_string_start + new_string_data.len()
    };
    write_u32(&mut output, 24, new_style_start as u32);
    output.extend_from_slice(&input[offsets_start..old_style_offsets_start]);
    output.extend_from_slice(&new_index_offset.to_le_bytes());
    output.extend_from_slice(style_offsets);
    output.extend_from_slice(&new_string_data);
    output.extend_from_slice(styles);
    let output_size = output.len() as u32;
    write_u32(&mut output, 4, output_size);
    Ok((output, old_count as u32))
}

fn encode_resource_string(value: &str, utf8: bool) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    if utf8 {
        append_resource_length(&mut output, value.chars().count())?;
        append_resource_length(&mut output, value.len())?;
        output.extend_from_slice(value.as_bytes());
        output.push(0);
    } else {
        let units = value.encode_utf16().collect::<Vec<_>>();
        if units.len() > 0x7fff {
            return Err("resource string is too long".to_string());
        }
        output.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for unit in units {
            output.extend_from_slice(&unit.to_le_bytes());
        }
        output.extend_from_slice(&0u16.to_le_bytes());
    }
    Ok(output)
}

fn append_resource_length(output: &mut Vec<u8>, value: usize) -> Result<(), String> {
    if value > 0x7fff {
        return Err("resource string is too long".to_string());
    }
    if value > 0x7f {
        output.push(((value >> 8) as u8) | 0x80);
        output.push(value as u8);
    } else {
        output.push(value as u8);
    }
    Ok(())
}

fn parse_resource_string_pool(input: &[u8]) -> Result<Vec<String>, String> {
    Ok(parse_string_pool_metadata(input, "string pool")?.0)
}

fn parse_string_pool_metadata(
    input: &[u8],
    description: &str,
) -> Result<(Vec<String>, u32, usize, usize, usize), String> {
    if input.len() < 28 || checked_u16(input, 0, description)? != 1 {
        return Err(format!("invalid {description}"));
    }
    let count = checked_u32(input, 8, description)? as usize;
    let style_count = checked_u32(input, 12, description)? as usize;
    let flags = checked_u32(input, 16, description)?;
    let string_start = checked_u32(input, 20, description)? as usize;
    let style_start = checked_u32(input, 24, description)? as usize;
    let offsets_end = 28usize
        .checked_add(count * 4)
        .and_then(|end| end.checked_add(style_count * 4))
        .ok_or_else(|| format!("{description} offsets overflow"))?;
    let string_end = if style_count == 0 {
        input.len()
    } else {
        style_start
    };
    if offsets_end > input.len() || string_start < offsets_end || string_end > input.len() {
        return Err(format!("invalid {description} offsets"));
    }
    let utf8 = flags & 0x0000_0100 != 0;
    let mut strings = Vec::with_capacity(count);
    for index in 0..count {
        let offset = checked_u32(input, 28 + index * 4, description)? as usize;
        let mut cursor = string_start
            .checked_add(offset)
            .ok_or_else(|| format!("{description} string offset overflow"))?;
        if cursor >= string_end {
            return Err(format!("invalid {description} string offset"));
        }
        let value = if utf8 {
            let _chars = read_resource_length(input, &mut cursor, string_end)?;
            let bytes = read_resource_length(input, &mut cursor, string_end)?;
            let end = cursor
                .checked_add(bytes)
                .ok_or_else(|| format!("{description} string overflow"))?;
            if end >= string_end {
                return Err(format!("invalid {description} UTF-8 string"));
            }
            let value = std::str::from_utf8(&input[cursor..end])
                .map_err(|_| format!("invalid UTF-8 in {description}"))?
                .to_string();
            if input[end] != 0 {
                return Err(format!("unterminated {description} string"));
            }
            value
        } else {
            let length = checked_u16(input, cursor, description)? as usize;
            cursor += 2;
            let end = cursor
                .checked_add(length * 2)
                .ok_or_else(|| format!("{description} UTF-16 string overflow"))?;
            if end + 2 > string_end {
                return Err(format!("invalid {description} UTF-16 string"));
            }
            let mut units = Vec::with_capacity(length);
            for position in (cursor..end).step_by(2) {
                units.push(checked_u16(input, position, description)?);
            }
            String::from_utf16(&units).map_err(|_| format!("invalid UTF-16 in {description}"))?
        };
        strings.push(value);
    }
    Ok((strings, flags, string_start, style_start, style_count))
}

fn read_resource_length(input: &[u8], cursor: &mut usize, end: usize) -> Result<usize, String> {
    if *cursor >= end {
        return Err("truncated resource string length".to_string());
    }
    let first = input[*cursor];
    *cursor += 1;
    if first & 0x80 == 0 {
        Ok(first as usize)
    } else if *cursor < end {
        let second = input[*cursor];
        *cursor += 1;
        Ok((((first & 0x7f) as usize) << 8) | second as usize)
    } else {
        Err("truncated resource string length".to_string())
    }
}

fn package_chunk_ranges(input: &[u8], header_size: usize) -> Result<Vec<(usize, usize)>, String> {
    let package_size = input.len();
    let mut ranges = Vec::new();
    let mut offset = header_size;
    while offset < package_size {
        let size = chunk_size(input, offset)?;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "package child chunk overflows".to_string())?;
        if end > package_size {
            return Err("package child chunk exceeds package".to_string());
        }
        ranges.push((offset, end));
        offset = end;
    }
    Ok(ranges)
}

fn chunk_size(input: &[u8], offset: usize) -> Result<usize, String> {
    let size = checked_u32(input, offset + 4, "resource chunk size")? as usize;
    if size < 8 {
        return Err("resource chunk has an invalid size".to_string());
    }
    Ok(size)
}

fn checked_u8(input: &[u8], offset: usize, description: &str) -> Result<u8, String> {
    input
        .get(offset)
        .copied()
        .ok_or_else(|| format!("truncated {description}"))
}

fn checked_u16(input: &[u8], offset: usize, description: &str) -> Result<u16, String> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or_else(|| format!("truncated {description}"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn checked_u32(input: &[u8], offset: usize, description: &str) -> Result<u32, String> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or_else(|| format!("truncated {description}"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Set an attribute on an element in an Android binary XML document.
///
/// `value` accepts `true`/`false`, a signed decimal integer, or a string.  A
/// missing attribute is added.  The implementation is intentionally scoped to
/// the well-defined AXML chunks used by manifests and preserves unknown XML
/// chunks byte-for-byte.
pub fn set_binary_xml_attribute(
    input: &[u8],
    element: &str,
    attribute: &str,
    value: &str,
) -> Result<Vec<u8>, String> {
    let mut document = AxmlDocument::parse(input)?;
    let attribute_string_index = document.ensure_string(attribute)?;
    let value_kind = ValueKind::parse(value, &mut document)?;
    let mut changed = false;

    let existing_attribute_index = document.string_index(attribute);
    for index in 0..document.chunks.len() {
        if document.chunks[index].kind != 0x0102 || document.chunks[index].bytes.len() < 36 {
            continue;
        }
        let chunk_header_size = document.chunks[index].header_size;
        let element_name = document
            .strings
            .get(read_u32(&document.chunks[index].bytes, chunk_header_size + 4) as usize)
            .map(String::as_str);
        if element_name != Some(element) {
            continue;
        }
        let namespace_index = if element == "manifest" && attribute == "package" {
            // `package` is an unqualified manifest attribute, unlike
            // `android:*` attributes on the same element.
            u32::MAX
        } else {
            document.android_namespace_index(&document.chunks[index])
        };
        if set_start_element_attribute(
            &mut document.chunks[index].bytes,
            chunk_header_size,
            existing_attribute_index,
            attribute_string_index,
            namespace_index,
            &value_kind,
            &document.strings,
        )? {
            changed = true;
        }
    }
    if !changed {
        return Err(format!("element not found in binary XML: {element}"));
    }
    document.rebuild()
}

enum ValueKind {
    Boolean(bool),
    Integer(i32),
    Reference(u32),
    String(u32),
    Raw { data_type: u8, data: u32 },
}

impl ValueKind {
    fn parse(value: &str, document: &mut AxmlDocument) -> Result<Self, String> {
        if let Some(raw) = value.strip_prefix("@raw:") {
            let (data_type, data) = raw
                .split_once(':')
                .ok_or_else(|| format!("invalid raw AXML value: {value}"))?;
            let data_type = parse_hex_byte(data_type)
                .ok_or_else(|| format!("invalid raw AXML type: {data_type}"))?;
            let data =
                parse_hex_u32(data).ok_or_else(|| format!("invalid raw AXML data: {data}"))?;
            return Ok(Self::Raw { data_type, data });
        }
        match value {
            "true" => Ok(Self::Boolean(true)),
            "false" => Ok(Self::Boolean(false)),
            value if value.starts_with("@0x") => u32::from_str_radix(&value[3..], 16)
                .map(Self::Reference)
                .map_err(|_| format!("invalid resource reference: {value}")),
            _ => match value.parse::<i32>() {
                Ok(value) => Ok(Self::Integer(value)),
                Err(_) => Ok(Self::String(document.ensure_string(value)?)),
            },
        }
    }
}

struct AxmlChunk {
    kind: u16,
    header_size: usize,
    bytes: Vec<u8>,
}

struct AxmlDocument {
    strings: Vec<String>,
    chunks: Vec<AxmlChunk>,
}

impl AxmlDocument {
    fn parse(input: &[u8]) -> Result<Self, String> {
        if input.len() < 8 || read_u16(input, 0) != 0x0003 {
            return Err("not an Android binary XML document".to_string());
        }
        let file_size = read_u32(input, 4) as usize;
        if file_size > input.len() || file_size < 8 {
            return Err("invalid Android binary XML size".to_string());
        }

        let mut offset = 8usize;
        let mut chunks = Vec::new();
        let mut strings = Vec::new();
        while offset < file_size {
            if offset + 8 > file_size {
                return Err("truncated Android binary XML chunk".to_string());
            }
            let kind = read_u16(input, offset);
            let chunk_header_size = read_u16(input, offset + 2) as usize;
            let chunk_size = read_u32(input, offset + 4) as usize;
            if chunk_header_size < 8
                || chunk_size < chunk_header_size
                || offset + chunk_size > file_size
            {
                return Err("invalid Android binary XML chunk size".to_string());
            }
            let bytes = input[offset..offset + chunk_size].to_vec();
            if kind == 0x0001 {
                strings = parse_string_pool(&bytes)?;
            }
            chunks.push(AxmlChunk {
                kind,
                header_size: chunk_header_size,
                bytes,
            });
            offset += chunk_size;
        }
        if strings.is_empty() && !chunks.iter().any(|chunk| chunk.kind == 0x0001) {
            return Err("Android binary XML has no string pool".to_string());
        }
        Ok(Self { strings, chunks })
    }

    fn ensure_string(&mut self, value: &str) -> Result<u32, String> {
        if let Some(index) = self.strings.iter().position(|entry| entry == value) {
            return Ok(index as u32);
        }
        let index = self.strings.len() as u32;
        self.strings.push(value.to_string());
        self.update_string_pool()?;
        self.update_resource_map(index, known_android_attribute_id(value));
        Ok(index)
    }

    fn string_index(&self, value: &str) -> Option<u32> {
        self.strings
            .iter()
            .position(|entry| entry == value)
            .map(|i| i as u32)
    }

    fn android_namespace_index(&self, start_element: &AxmlChunk) -> u32 {
        let header_size = start_element.header_size;
        let attr_start = header_size + read_u16(&start_element.bytes, header_size + 8) as usize;
        let attr_size = read_u16(&start_element.bytes, header_size + 10) as usize;
        let attr_count = read_u16(&start_element.bytes, header_size + 12) as usize;
        for index in 0..attr_count {
            let offset = attr_start + index * attr_size;
            if offset + 20 > start_element.bytes.len() || attr_size < 20 {
                break;
            }
            let namespace = read_u32(&start_element.bytes, offset);
            let name = read_u32(&start_element.bytes, offset + 4);
            if self.strings.get(name as usize).map(String::as_str) == Some("debuggable") {
                return namespace;
            }
        }
        self.chunks
            .iter()
            .find(|chunk| chunk.kind == 0x0100 && chunk.bytes.len() >= 24)
            .map(|chunk| read_u32(&chunk.bytes, chunk.header_size + 4))
            .unwrap_or(u32::MAX)
    }

    fn update_string_pool(&mut self) -> Result<(), String> {
        let Some(index) = self.chunks.iter().position(|chunk| chunk.kind == 0x0001) else {
            return Err("Android binary XML has no string pool".to_string());
        };
        self.chunks[index].bytes = encode_string_pool(&self.chunks[index].bytes, &self.strings)?;
        Ok(())
    }

    fn update_resource_map(&mut self, string_index: u32, resource_id: u32) {
        let Some(chunk) = self.chunks.iter_mut().find(|chunk| chunk.kind == 0x0180) else {
            return;
        };
        let required_size = 8 + (string_index as usize + 1) * 4;
        if chunk.bytes.len() < required_size {
            chunk.bytes.resize(required_size, 0);
        }
        write_u32(&mut chunk.bytes, string_index as usize * 4 + 8, resource_id);
        let chunk_size = chunk.bytes.len() as u32;
        write_u32(&mut chunk.bytes, 4, chunk_size);
    }

    fn rebuild(self) -> Result<Vec<u8>, String> {
        let total_size: usize = 8 + self
            .chunks
            .iter()
            .map(|chunk| chunk.bytes.len())
            .sum::<usize>();
        let mut output = Vec::with_capacity(total_size);
        output.extend_from_slice(&0x0003u16.to_le_bytes());
        output.extend_from_slice(&8u16.to_le_bytes());
        output.extend_from_slice(&(total_size as u32).to_le_bytes());
        for chunk in self.chunks {
            output.extend_from_slice(&chunk.bytes);
        }
        Ok(output)
    }
}

fn set_start_element_attribute(
    chunk: &mut Vec<u8>,
    header_size: usize,
    existing_attribute_index: Option<u32>,
    attribute_name: u32,
    namespace: u32,
    value: &ValueKind,
    strings: &[String],
) -> Result<bool, String> {
    if header_size + 20 > chunk.len() {
        return Err("invalid start-element chunk".to_string());
    }
    let attr_size = read_u16(chunk, header_size + 10) as usize;
    let attr_count = read_u16(chunk, header_size + 12) as usize;
    if attr_size < 20 {
        return Err("unsupported AXML attribute size".to_string());
    }
    let attr_start = header_size + read_u16(chunk, header_size + 8) as usize;
    let target = existing_attribute_index.and_then(|name_index| {
        (0..attr_count).find(|index| {
            let offset = attr_start + index * attr_size;
            offset + 20 <= chunk.len() && read_u32(chunk, offset + 4) == name_index
        })
    });
    let offset = if let Some(index) = target {
        attr_start + index * attr_size
    } else {
        let offset = attr_start + attr_count * attr_size;
        if offset != chunk.len() {
            return Err("start-element contains unsupported trailing data".to_string());
        }
        if attr_size != 20 {
            return Err("unsupported AXML start-element layout".to_string());
        }
        let mut attribute = vec![0u8; 20];
        write_u32(&mut attribute, 0, namespace);
        write_u32(&mut attribute, 4, attribute_name);
        write_attribute_value(&mut attribute, 0, value, strings);
        chunk.extend_from_slice(&attribute);
        write_u16(chunk, header_size + 12, (attr_count + 1) as u16);
        let chunk_size = chunk.len() as u32;
        write_u32(chunk, 4, chunk_size);
        return Ok(true);
    };
    // Updating an existing attribute must retain its original namespace. In
    // particular, the manifest's unqualified `package` attribute must not be
    // rewritten as `android:package`.
    let namespace = if target.is_some() {
        read_u32(chunk, offset)
    } else {
        namespace
    };
    write_u32(chunk, offset, namespace);
    write_u32(chunk, offset + 4, attribute_name);
    write_attribute_value(chunk, offset, value, strings);
    Ok(true)
}

fn write_attribute_value(chunk: &mut [u8], offset: usize, value: &ValueKind, strings: &[String]) {
    match value {
        ValueKind::Boolean(value) => {
            write_u32(chunk, offset + 8, u32::MAX);
            write_u16(chunk, offset + 12, 8);
            chunk[offset + 14] = 0;
            chunk[offset + 15] = 0x12;
            write_u32(chunk, offset + 16, u32::from(*value));
        }
        ValueKind::Integer(value) => {
            write_u32(chunk, offset + 8, u32::MAX);
            write_u16(chunk, offset + 12, 8);
            chunk[offset + 14] = 0;
            chunk[offset + 15] = 0x10;
            write_u32(chunk, offset + 16, *value as u32);
        }
        ValueKind::Reference(value) => {
            write_u32(chunk, offset + 8, u32::MAX);
            write_u16(chunk, offset + 12, 8);
            chunk[offset + 14] = 0;
            chunk[offset + 15] = 0x01;
            write_u32(chunk, offset + 16, *value);
        }
        ValueKind::String(index) => {
            let raw_value = if (*index as usize) < strings.len() {
                *index
            } else {
                u32::MAX
            };
            write_u32(chunk, offset + 8, raw_value);
            write_u16(chunk, offset + 12, 8);
            chunk[offset + 14] = 0;
            chunk[offset + 15] = 0x03;
            write_u32(chunk, offset + 16, *index);
        }
        ValueKind::Raw { data_type, data } => {
            write_u32(chunk, offset + 8, u32::MAX);
            write_u16(chunk, offset + 12, 8);
            chunk[offset + 14] = 0;
            chunk[offset + 15] = *data_type;
            write_u32(chunk, offset + 16, *data);
        }
    }
}

fn parse_string_pool(chunk: &[u8]) -> Result<Vec<String>, String> {
    if chunk.len() < 28 {
        return Err("truncated AXML string pool".to_string());
    }
    let count = read_u32(chunk, 8) as usize;
    let flags = read_u32(chunk, 16);
    let strings_start = read_u32(chunk, 20) as usize;
    let utf8 = flags & 0x100 != 0;
    let mut strings = Vec::with_capacity(count);
    for index in 0..count {
        let offset = read_u32(chunk, 28 + index * 4) as usize + strings_start;
        if offset >= chunk.len() {
            return Err("invalid AXML string offset".to_string());
        }
        if utf8 {
            let (_, position) = read_uleb128(chunk, offset)?;
            let (_, position) = read_uleb128(chunk, position)?;
            let end = chunk[position..]
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| "unterminated AXML string".to_string())?
                + position;
            strings.push(String::from_utf8_lossy(&chunk[position..end]).into_owned());
        } else {
            let length = read_u16(chunk, offset) as usize;
            let begin = offset + 2;
            let end = begin + length * 2;
            if end + 2 > chunk.len() {
                return Err("invalid UTF-16 AXML string".to_string());
            }
            let mut units = Vec::with_capacity(length);
            for bytes in chunk[begin..end].chunks_exact(2) {
                units.push(u16::from_le_bytes([bytes[0], bytes[1]]));
            }
            strings.push(String::from_utf16_lossy(&units));
        }
    }
    Ok(strings)
}

fn encode_string_pool(original: &[u8], strings: &[String]) -> Result<Vec<u8>, String> {
    if original.len() < 28 {
        return Err("truncated AXML string pool".to_string());
    }
    let header_size = read_u16(original, 2) as usize;
    let style_count = read_u32(original, 12);
    let flags = read_u32(original, 16);
    let old_strings_start = read_u32(original, 20) as usize;
    let old_styles_start = read_u32(original, 24) as usize;
    let old_count = read_u32(original, 8) as usize;
    if header_size < 28
        || header_size + old_count * 4 > original.len()
        || old_strings_start > original.len()
    {
        return Err("invalid AXML string pool header".to_string());
    }
    let data_end = if old_styles_start != 0 {
        old_styles_start
    } else {
        original.len()
    };
    let mut content_end = old_strings_start;
    for index in 0..old_count {
        let offset = old_strings_start + read_u32(original, header_size + index * 4) as usize;
        let (string_end, position) = if flags & 0x100 != 0 {
            let (_, position) = read_uleb128(original, offset)?;
            let (byte_length, position) = read_uleb128(original, position)?;
            (position + byte_length as usize, position)
        } else {
            if offset + 2 > original.len() {
                return Err("invalid UTF-16 AXML string".to_string());
            }
            (
                offset + 2 + read_u16(original, offset) as usize * 2,
                offset + 2 + read_u16(original, offset) as usize * 2,
            )
        };
        let end = if flags & 0x100 != 0 {
            string_end + 1
        } else {
            position + 2
        };
        content_end = content_end.max(end);
    }
    if data_end < content_end || data_end > original.len() {
        return Err("invalid AXML string data range".to_string());
    }

    let utf8 = flags & 0x100 != 0;
    let mut data = original[old_strings_start..content_end].to_vec();
    let existing_count = old_count.min(strings.len());
    for string in strings.iter().skip(existing_count) {
        if utf8 {
            let bytes = string.as_bytes();
            append_uleb128(&mut data, string.encode_utf16().count() as u32);
            append_uleb128(&mut data, bytes.len() as u32);
            data.extend_from_slice(bytes);
            data.push(0);
        } else {
            let units = string.encode_utf16().collect::<Vec<_>>();
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for unit in units {
                data.extend_from_slice(&unit.to_le_bytes());
            }
            data.extend_from_slice(&0u16.to_le_bytes());
        }
    }
    let old_tail = &original[content_end..data_end];
    data.extend_from_slice(old_tail);
    while data.len() % 4 != 0 {
        data.push(0);
    }

    let new_strings_start = header_size + strings.len() * 4;
    let styles = if old_styles_start != 0 {
        &original[old_styles_start..]
    } else {
        &[][..]
    };
    let new_styles_start = if old_styles_start != 0 {
        new_strings_start + data.len()
    } else {
        0
    };
    let total_size = new_strings_start + data.len() + styles.len();
    let mut output = vec![0u8; total_size];
    output[0..2].copy_from_slice(&1u16.to_le_bytes());
    output[2..4].copy_from_slice(&(header_size as u16).to_le_bytes());
    output[4..8].copy_from_slice(&(total_size as u32).to_le_bytes());
    output[8..12].copy_from_slice(&(strings.len() as u32).to_le_bytes());
    output[12..16].copy_from_slice(&style_count.to_le_bytes());
    output[16..20].copy_from_slice(&flags.to_le_bytes());
    output[20..24].copy_from_slice(&(new_strings_start as u32).to_le_bytes());
    output[24..28].copy_from_slice(&(new_styles_start as u32).to_le_bytes());
    for index in 0..strings.len() {
        let offset = if index < old_count {
            read_u32(original, header_size + index * 4)
        } else {
            data_offset_for_appended(
                original,
                old_strings_start,
                content_end,
                strings,
                index,
                flags,
            )?
        };
        write_u32(&mut output, header_size + index * 4, offset);
    }
    output[new_strings_start..new_strings_start + data.len()].copy_from_slice(&data);
    if !styles.is_empty() {
        output[new_strings_start + data.len()..].copy_from_slice(styles);
    }
    Ok(output)
}

fn data_offset_for_appended(
    original: &[u8],
    strings_start: usize,
    content_end: usize,
    strings: &[String],
    index: usize,
    flags: u32,
) -> Result<u32, String> {
    let old_count = read_u32(original, 8) as usize;
    let mut offset = (content_end - strings_start) as u32;
    for string in strings.iter().skip(old_count).take(index - old_count) {
        offset += if flags & 0x100 != 0 {
            uleb128_len(string.encode_utf16().count() as u32)
                + uleb128_len(string.as_bytes().len() as u32)
                + string.as_bytes().len() as u32
                + 1
        } else {
            2 + string.encode_utf16().count() as u32 * 2 + 2
        };
    }
    Ok(offset)
}

fn read_uleb128(bytes: &[u8], mut offset: usize) -> Result<(u32, usize), String> {
    let mut value = 0u32;
    let mut shift = 0;
    loop {
        if offset >= bytes.len() || shift > 28 {
            return Err("invalid AXML ULEB128".to_string());
        }
        let byte = bytes[offset];
        offset += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, offset));
        }
        shift += 7;
    }
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    u32::from_str_radix(value.strip_prefix("0x")?, 16).ok()
}

fn parse_hex_byte(value: &str) -> Option<u8> {
    parse_hex_u32(value).and_then(|value| u8::try_from(value).ok())
}

fn append_uleb128(bytes: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn uleb128_len(mut value: u32) -> u32 {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use coeus_models::models::Files;

    #[test]
    fn textual_manifest_round_trips_and_adds_network_resource() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.test">
            <application android:label="Example" android:debuggable="false">
                <activity android:name=".MainActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>"#;
        let document = XmlDocument::parse(xml).expect("parse XML");
        let binary = encode_xml_document(&document, &|_| None).expect("encode AXML");
        let mut files = Files::new(Vec::new(), std::collections::HashMap::new());
        files
            .set_file("AndroidManifest.xml", binary)
            .expect("add manifest");
        let (content, _) = decode_binary_manifest(
            files.raw_file("AndroidManifest.xml").unwrap(),
            &files.binary_resource_file,
        );
        assert!(content.contains("manifest"));
        files.manifest_content = content;

        allow_plaintext_and_user_certificates(&mut files).expect("add network config");
        let resource = files
            .raw_file(NETWORK_SECURITY_RESOURCE_PATH)
            .expect("network XML file");
        let (network_xml, _) = decode_binary_manifest(resource, &files.binary_resource_file);
        assert!(network_xml.contains("network-security-config"));
        assert!(network_xml.contains("cleartextTrafficPermitted"));
        assert!(files.manifest_content.contains("networkSecurityConfig"));
        assert!(files.manifest_content.contains("usesCleartextTraffic"));
        set_package_name(&mut files, "example.modified").expect("change package name");
        assert_eq!(files.android_manifest.package, "example.modified");
        assert!(files
            .raw_file("AndroidManifest.xml")
            .unwrap()
            .windows("example.modified".len())
            .any(|window| window == b"example.modified"));
        let table = arsc::parse_from(Cursor::new(&files.binary_resource_file)).expect("parse arsc");
        assert!(table.packages.iter().any(|package| {
            package.type_names.strings.iter().any(|name| name == "xml")
                && package
                    .key_names
                    .strings
                    .iter()
                    .any(|name| name == NETWORK_SECURITY_RESOURCE_NAME)
        }));
    }

    #[test]
    fn real_apk_can_be_edited_and_repacked() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/debugger_test/app-debug.apk");
        if !path.exists() {
            return;
        }
        let mut files =
            crate::extraction::load_file(path.to_str().unwrap(), false, -1).expect("load APK");
        set_manifest_attribute(&mut files, "application", "debuggable", "true")
            .expect("set debuggable");
        let manifest_text = files.manifest_content.clone();
        set_manifest_xml(&mut files, &manifest_text).expect("round-trip manifest text");
        allow_plaintext_and_user_certificates(&mut files).expect("network defaults");
        let output = repack_to_bytes(&files).expect("repack APK");
        let mut archive = zip::ZipArchive::new(Cursor::new(output)).expect("read repacked APK");
        {
            let manifest = archive
                .by_name("AndroidManifest.xml")
                .expect("manifest entry");
            assert!(!manifest.is_dir());
        }
        assert!(archive.by_name(NETWORK_SECURITY_RESOURCE_PATH).is_ok());
        {
            let resources = archive
                .by_name("resources.arsc")
                .expect("resource table entry");
            assert_eq!(resources.compression(), CompressionMethod::Stored);
            assert_eq!(resources.data_start() % 4, 0);
        }
        assert!(archive.by_name("classes.dex").is_ok());
    }

    #[test]
    fn added_native_libraries_are_stored_and_page_aligned() {
        let mut files = Files::new(Vec::new(), std::collections::HashMap::new());
        files
            .add_file("lib/arm64-v8a/libgadget.so", vec![0u8; 7])
            .expect("add native library");
        let output = repack_to_bytes(&files).expect("repack native library");
        let mut archive = zip::ZipArchive::new(Cursor::new(output)).expect("read APK");
        let library = archive
            .by_name("lib/arm64-v8a/libgadget.so")
            .expect("native library entry");
        assert_eq!(library.compression(), CompressionMethod::Stored);
        assert_eq!(library.data_start() % 16_384, 0);
    }
}
