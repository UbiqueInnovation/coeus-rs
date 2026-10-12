use std::ops::Range;

/// Decode a single DEX type, retaining the consumed byte length for safe rewriting.
fn decode_type(descriptor: &str, allow_void: bool) -> Option<(String, usize)> {
    let arrays = descriptor.bytes().take_while(|byte| *byte == b'[').count();
    let rest = descriptor.get(arrays..)?;
    let (name, consumed) = match rest.as_bytes().first()? {
        b'V' if allow_void && arrays == 0 => ("Unit".to_owned(), 1),
        b'Z' => ("Boolean".to_owned(), 1),
        b'B' => ("Byte".to_owned(), 1),
        b'S' => ("Short".to_owned(), 1),
        b'C' => ("Char".to_owned(), 1),
        b'I' => ("Int".to_owned(), 1),
        b'J' => ("Long".to_owned(), 1),
        b'F' => ("Float".to_owned(), 1),
        b'D' => ("Double".to_owned(), 1),
        b'L' => {
            let end = rest.find(';')?;
            let name = rest.get(1..end)?;
            if name.is_empty() || name.chars().any(char::is_whitespace) {
                return None;
            }
            (name.replace('/', "."), end + 1)
        }
        _ => return None,
    };
    Some((format!("{name}{}", "[]".repeat(arrays)), arrays + consumed))
}

/// Only rewrite known signature positions. Strings, comments and malformed DEX
/// descriptors remain verbatim, and source line numbers remain unchanged.
pub fn readable_line(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with(".method ") || trimmed.starts_with("invoke-") {
        let Some(open) = line.find('(') else {
            return line.to_owned();
        };
        let Some(close) = line[open + 1..].find(')').map(|at| at + open + 1) else {
            return line.to_owned();
        };
        let mut remaining = &line[open + 1..close];
        let mut arguments = Vec::new();
        while !remaining.is_empty() {
            let Some((argument, consumed)) = decode_type(remaining, false) else {
                return line.to_owned();
            };
            arguments.push(argument);
            remaining = &remaining[consumed..];
        }
        let Some((result, consumed)) = decode_type(&line[close + 1..], true) else {
            return line.to_owned();
        };
        let suffix = &line[close + 1 + consumed..];
        if !suffix.is_empty() && !suffix.starts_with(char::is_whitespace) {
            return line.to_owned();
        }
        return format!(
            "{}({}): {result}{suffix}",
            &line[..open],
            arguments.join(", ")
        );
    }
    if trimmed.starts_with(".field ") {
        if let Some(colon) = line.find(':') {
            if let Some((kind, consumed)) = decode_type(&line[colon + 1..], false) {
                let suffix = &line[colon + 1 + consumed..];
                if suffix.is_empty() || suffix.starts_with(char::is_whitespace) {
                    return format!("{}: {kind}{suffix}", &line[..colon]);
                }
            }
        }
    }
    line.to_owned()
}

/// Header-to-end ranges let collapsed bodies retain their original line indices.
pub fn method_sections(lines: &[String]) -> Vec<Range<usize>> {
    let mut sections = Vec::new();
    let mut start = None;
    for (index, line) in lines.iter().enumerate() {
        let line = line.trim_start();
        if line.starts_with(".method ") {
            if let Some(previous) = start.replace(index) {
                sections.push(previous..index);
            }
        } else if line.trim_end() == ".end method" {
            if let Some(start) = start.take() {
                sections.push(start..index + 1);
            }
        }
    }
    if let Some(start) = start {
        sections.push(start..lines.len());
    }
    sections
}

fn exact_occurrences(line: &str, value: &str) -> Vec<Range<usize>> {
    if value.is_empty() {
        return Vec::new();
    }
    line.match_indices(value)
        .map(|(start, _)| start..start + value.len())
        .collect()
}

/// Return just the clickable symbol, never the entire instruction or signature.
pub fn navigation_ranges(line: &str, kind: &str, label: &str) -> Vec<Range<usize>> {
    let code = line.split_once('#').map(|(code, _)| code).unwrap_or(line);
    match kind {
        "class" => {
            let mut ranges = exact_occurrences(code, label);
            if let Some((readable, consumed)) = decode_type(label, false) {
                if consumed == label.len() && readable != label {
                    // A parameter such as Foo must not steal clicks from a
                    // different parameter named FooFactory in the same line.
                    let identifier =
                        |ch: char| ch.is_alphanumeric() || matches!(ch, '_' | '$' | '.');
                    ranges.extend(
                        exact_occurrences(code, &readable)
                            .into_iter()
                            .filter(|range| {
                                !code[..range.start]
                                    .chars()
                                    .next_back()
                                    .is_some_and(identifier)
                                    && !code[range.end..].chars().next().is_some_and(identifier)
                            }),
                    );
                }
            }
            ranges
        }
        "method" | "field" => {
            let Some((owner, member)) = label.split_once("->") else {
                return Vec::new();
            };
            let name = member.split(['(', ':']).next().unwrap_or(member);
            if name.is_empty() {
                return Vec::new();
            }
            let reference = format!("{owner}->{name}");
            let mut ranges: Vec<_> = exact_occurrences(code, &reference)
                .into_iter()
                .map(|range| range.end - name.len()..range.end)
                .collect();
            let declaration = if kind == "method" {
                ".method "
            } else {
                ".field "
            };
            if code.trim_start().starts_with(declaration) {
                for range in exact_occurrences(code, name) {
                    let before = code[..range.start].chars().next_back();
                    let after = code[range.end..].chars().next();
                    if before.is_some_and(char::is_whitespace)
                        && after == Some(if kind == "method" { '(' } else { ':' })
                    {
                        ranges.push(range);
                    }
                }
            }
            ranges
        }
        "string" => exact_occurrences(code, label),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_decode_primitive_object_and_array_types() {
        assert_eq!(
            readable_line(".method public check(ZI[[BLjava/lang/String;)[Z"),
            ".method public check(Boolean, Int, Byte[][], java.lang.String): Boolean[]"
        );
        assert_eq!(
            readable_line(".method public <init>()V"),
            ".method public <init>(): Unit"
        );
        assert_eq!(
            readable_line(".field private enabled:Z = true"),
            ".field private enabled: Boolean = true"
        );
        assert_eq!(
            readable_line("invoke-virtual {v0}, Lapp/Test;->check(Z)Z #0x2"),
            "invoke-virtual {v0}, Lapp/Test;->check(Boolean): Boolean #0x2"
        );
    }

    #[test]
    fn malformed_descriptors_and_literal_values_stay_unchanged() {
        for line in [
            ".method broken(Lmissing)Z",
            ".method broken(V)Z",
            ".method broken()[V",
            ".method broken()Zjunk",
            ".field broken:Zjunk",
            "const-string v0, \"example(Z)Z\"",
            "# example(Z)Z",
        ] {
            assert_eq!(readable_line(line), line);
        }
    }

    #[test]
    fn class_and_method_click_regions_do_not_overlap() {
        let line = "invoke-virtual {v0}, Lapp/Test;->check(Boolean): Boolean #0x2";
        let classes = navigation_ranges(line, "class", "Lapp/Test;");
        let methods = navigation_ranges(line, "method", "Lapp/Test;->check(Z)Z");
        assert_eq!(&line[classes[0].clone()], "Lapp/Test;");
        assert_eq!(&line[methods[0].clone()], "check");
        assert!(classes[0].end < methods[0].start);
        assert_eq!(
            navigation_ranges(
                ".method public checker(): Unit",
                "method",
                "Lapp/Test;->check()V"
            ),
            Vec::<Range<usize>>::new()
        );
    }

    #[test]
    fn declaration_and_readable_parameter_types_are_clickable() {
        let line = ".method public check(java.lang.String): Boolean";
        let method = navigation_ranges(line, "method", "Lapp/Test;->check(Ljava/lang/String;)Z");
        let parameter = navigation_ranges(line, "class", "Ljava/lang/String;");
        assert_eq!(&line[method[0].clone()], "check");
        assert_eq!(&line[parameter[0].clone()], "java.lang.String");
        let field = ".field private enabled: Boolean";
        let ranges = navigation_ranges(field, "field", "Lapp/Test;->enabled");
        assert_eq!(&field[ranges[0].clone()], "enabled");
        let parameters = ".method call(app.FooFactory, app.Foo): Unit";
        let ranges = navigation_ranges(parameters, "class", "Lapp/Foo;");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, parameters.rfind("app.Foo").unwrap());
    }

    #[test]
    fn folds_preserve_source_line_indices_and_handle_missing_end() {
        let lines: Vec<_> = [
            ".class Lapp/Test;",
            ".method first()V",
            "return-void #0x0",
            ".end method",
            ".method second()V",
            "return-void #0x0",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(method_sections(&lines), vec![1..4, 4..6]);
    }
}
