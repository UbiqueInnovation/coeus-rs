pub fn is_register(name: &str) -> bool {
    name == "register" || name.ends_with("_register")
}

pub fn register_number(raw: &str, maximum: u32) -> Result<u32, String> {
    let raw = raw.trim();
    let digits = raw.strip_prefix('v').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Use a register number such as 3 or v3".to_string());
    }
    let value: u32 = digits
        .parse()
        .map_err(|_| "Register number is too large".to_string())?;
    if value > maximum {
        return Err(format!("Register must be between v0 and v{maximum}"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn register_numbers_accept_both_forms_without_truncation() {
        for raw in ["3", "v3", " v03 "] {
            assert_eq!(register_number(raw, 255), Ok(3));
        }
        for raw in ["v", "vv3", "v-1", "p3", "3x", "v256", "65536"] {
            assert!(register_number(raw, 255).is_err());
        }
        assert!(register_number("v16", 15).is_err());
        assert_eq!(register_number("v65535", 65535), Ok(65535));
    }
}

/// Resolve standard smali aliases against the selected method's incoming area.
pub fn resolve_register(
    raw: &str,
    maximum: u32,
    parameter_base: Option<u32>,
    parameter_count: Option<u32>,
) -> Result<u32, String> {
    let raw = raw.trim();
    if let Some(digits) = raw.strip_prefix('p') {
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("Use a parameter register such as p0".to_string());
        }
        let index: u32 = digits
            .parse()
            .map_err(|_| "Parameter register is too large".to_string())?;
        let (Some(base), Some(count)) = (parameter_base, parameter_count) else {
            return Err("Parameter registers are unavailable for this method".to_string());
        };
        if index >= count {
            return Err(if count == 0 {
                "This method has no parameter registers".to_string()
            } else {
                format!("Parameter register must be between p0 and p{}", count - 1)
            });
        }
        let number = base
            .checked_add(index)
            .ok_or_else(|| "Register number is too large".to_string())?;
        if number > maximum {
            return Err(format!("{raw} maps to v{number}, which exceeds v{maximum}"));
        }
        Ok(number)
    } else {
        register_number(raw, maximum)
    }
}

pub fn register_label(register: u32, base: u32, count: u32) -> String {
    if register >= base && register - base < count {
        format!("p{}", register - base)
    } else {
        format!("v{register}")
    }
}

/// Replace operand tokens only. Method/type names, quoted values, labels and
/// comments must keep their original spelling, including any literal "v123".
pub fn parameter_labels(text: &str, base: u32, count: u32) -> String {
    if count == 0 {
        return text.to_string();
    }
    text.split_inclusive('\n')
        .map(|line| {
            if line.trim_start().starts_with(['.', ':', '#']) {
                return line.to_string();
            }
            let bytes = line.as_bytes();
            let mut result = String::with_capacity(line.len());
            let mut index = 0;
            let mut copied = 0;
            let mut quote = None;
            while index < bytes.len() {
                let byte = bytes[index];
                if let Some(delimiter) = quote {
                    if byte == b'\\' {
                        index += 2;
                        continue;
                    }
                    if byte == delimiter {
                        quote = None;
                    }
                } else if byte == b'"' || byte == b'\'' {
                    quote = Some(byte);
                } else if byte == b'#' {
                    break;
                } else if byte == b'v'
                    && (index == 0 || matches!(bytes[index - 1], b' ' | b'\t' | b',' | b'{'))
                {
                    let mut end = index + 1;
                    while end < bytes.len() && bytes[end].is_ascii_digit() {
                        end += 1;
                    }
                    if end > index + 1
                        && (end == bytes.len()
                            || matches!(bytes[end], b' ' | b'\t' | b'\r' | b'\n' | b',' | b'}'))
                    {
                        if let Ok(number) = line[index + 1..end].parse::<u32>() {
                            result.push_str(&line[copied..index]);
                            result.push_str(&register_label(number, base, count));
                            copied = end;
                            index = end;
                            continue;
                        }
                    }
                }
                index += 1;
            }
            result.push_str(&line[copied..]);
            result
        })
        .collect()
}

#[cfg(test)]
mod parameter_tests {
    use super::*;
    #[test]
    fn aliases_start_at_first_incoming_word_and_preserve_other_text() {
        assert_eq!(parameter_labels(".method v3()V\nmove v0, v3\ninvoke-static {v3, v4}, Lv3;->v4()V\nconst-string v4, \"v3 \\\"v4\" # v3\n:v4 # v3\n", 3, 2),
            ".method v3()V\nmove v0, p0\ninvoke-static {p0, p1}, Lv3;->v4()V\nconst-string p1, \"v3 \\\"v4\" # v3\n:v4 # v3\n");
        assert_eq!(
            parameter_labels("invoke-static/range {v2 .. v4}, LExample;->test()V", 3, 2),
            "invoke-static/range {v2 .. p1}, LExample;->test()V"
        );
        assert_eq!(resolve_register("p0", 255, Some(3), Some(2)), Ok(3));
        assert_eq!(resolve_register("p1", 255, Some(3), Some(2)), Ok(4));
        assert!(resolve_register("p2", 255, Some(3), Some(2)).is_err());
        assert!(resolve_register("p0", 15, Some(16), Some(2)).is_err());
        assert!(resolve_register("p0", 255, None, None).is_err());
        assert!(resolve_register("p0", 255, Some(0), Some(0)).is_err());
    }
}
