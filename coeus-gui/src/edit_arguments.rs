pub fn is_register(name: &str) -> bool {
    name == "register" || name.ends_with("_register")
}

pub fn register_number(raw: &str, maximum: u32) -> Result<u32, String> {
    let raw = raw.trim();
    let digits = raw.strip_prefix('v').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Use a register number such as 3 or v3".to_string());
    }
    let value: u32 = digits.parse().map_err(|_| "Register number is too large".to_string())?;
    if value > maximum { return Err(format!("Register must be between v0 and v{maximum}")); }
    Ok(value)
}

/// Stores, calls, branches and returns read their first register; they do not
/// provide a destination default for a replacement that writes a register.
pub fn destination_register(mnemonic: &str, text: &str) -> Option<u32> {
    let writes = ["move", "const", "aget", "iget", "sget", "cmp", "neg", "not", "int-to-", "long-to-", "float-to-", "double-to-", "add-", "sub-", "rsub-", "mul-", "div-", "rem-", "and-", "or-", "xor-", "shl-", "shr-", "ushr-"]
        .iter().any(|prefix| mnemonic.starts_with(prefix))
        || matches!(mnemonic, "new-instance" | "new-array" | "array-length" | "instance-of" | "check-cast");
    if !writes { return None; }
    let operand = text.split_whitespace().nth(1)?.trim_end_matches(',');
    register_number(operand, u16::MAX as u32).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn register_numbers_accept_both_forms_without_truncation() {
        for raw in ["3", "v3", " v03 "] { assert_eq!(register_number(raw, 255), Ok(3)); }
        for raw in ["v", "vv3", "v-1", "p3", "3x", "v256", "65536"] { assert!(register_number(raw, 255).is_err()); }
        assert!(register_number("v16", 15).is_err());
        assert_eq!(register_number("v65535", 65535), Ok(65535));
    }
    #[test]
    fn only_instructions_that_write_registers_supply_destinations() {
        for (mnemonic, text) in [("const-string", "const-string v7, \"value\""), ("move/from16", "move/from16 v7, v300"), ("add-int/2addr", "add-int/2addr v7, v1"), ("iget", "iget v7, v2, LTest;->field:I")] {
            assert_eq!(destination_register(mnemonic, text), Some(7));
        }
        for mnemonic in ["invoke-static", "return", "iput", "sput", "aput", "if-eq", "throw", "filled-new-array"] {
            assert_eq!(destination_register(mnemonic, &format!("{mnemonic} v7, v1")), None);
        }
        assert!(!is_register("register_count"));
        assert!(!is_register("method_index"));
    }
}
