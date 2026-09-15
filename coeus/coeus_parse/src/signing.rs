//! Android SDK integration for APK signing and installed-package extraction.
//!
//! APK contents must be finalized before signing.  Coeus deliberately keeps
//! the cryptographic implementation in the Android SDK's `apksigner` tool and
//! exposes a small, platform-independent process wrapper here.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use regex::Regex;

const STORE_PASSWORD_ENV: &str = "COEUS_APKSIGNER_STORE_PASSWORD";
const KEY_PASSWORD_ENV: &str = "COEUS_APKSIGNER_KEY_PASSWORD";

fn command_failure(command: &str, output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let details = match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(": {stdout}"),
        (true, false) => format!(": {stderr}"),
        (false, false) => format!(": {stdout}\n{stderr}"),
    };
    format!("{command} failed with status {}{details}", output.status)
}

fn run_command(command: &mut Command, description: &str) -> Result<Output, String> {
    command
        .output()
        .map_err(|error| format!("could not execute {description}: {error}"))
}

fn resolve_apksigner(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }

    // Prefer the newest installed SDK build-tools version when the SDK root
    // is available.  Falling back to PATH keeps the API useful in CI and on
    // systems where the Android SDK is managed by another tool.
    let mut candidates = Vec::new();
    for variable in ["ANDROID_SDK_ROOT", "ANDROID_HOME"] {
        let Some(root) = std::env::var_os(variable) else {
            continue;
        };
        let build_tools = PathBuf::from(root).join("build-tools");
        let Ok(entries) = fs::read_dir(build_tools) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path().join(apksigner_name());
            if path.is_file() {
                candidates.push(path);
            }
        }
    }
    candidates.sort_by(|left, right| {
        version_key(right)
            .cmp(&version_key(left))
            .then_with(|| right.cmp(left))
    });
    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from(apksigner_name()))
}

fn apksigner_name() -> &'static str {
    if cfg!(windows) {
        "apksigner.bat"
    } else {
        "apksigner"
    }
}

fn version_key(path: &Path) -> Vec<u32> {
    path.parent()
        .and_then(Path::file_name)
        .map(|value| {
            value
                .to_string_lossy()
                .split('.')
                .map(|part| part.parse::<u32>().unwrap_or(0))
                .collect()
        })
        .unwrap_or_default()
}

/// Sign one already-written APK in place using the Android SDK's
/// `apksigner` tool.  The default tool configuration selects the compatible
/// APK signature schemes supported by the installed build-tools version.
pub fn sign_apk<P: AsRef<Path>>(
    apk: P,
    apksigner: Option<&Path>,
    keystore: &Path,
    alias: &str,
    store_password: &str,
    key_password: Option<&str>,
) -> Result<(), String> {
    if alias.is_empty() {
        return Err("signing key alias must not be empty".to_string());
    }
    let tool = resolve_apksigner(apksigner);
    let apk = apk.as_ref();
    let key_password = key_password.unwrap_or(store_password);
    let mut command = Command::new(&tool);
    command
        .arg("sign")
        .arg("--ks")
        .arg(keystore)
        .arg("--ks-key-alias")
        .arg(alias)
        .arg("--ks-pass")
        .arg(format!("env:{STORE_PASSWORD_ENV}"))
        .arg("--key-pass")
        .arg(format!("env:{KEY_PASSWORD_ENV}"))
        .arg(apk)
        .env(STORE_PASSWORD_ENV, store_password)
        .env(KEY_PASSWORD_ENV, key_password);
    let output = run_command(&mut command, "apksigner sign")?;
    if !output.status.success() {
        return Err(command_failure("apksigner sign", &output));
    }
    Ok(())
}

/// Verify one APK and return `apksigner`'s diagnostic output.
pub fn verify_apk<P: AsRef<Path>>(
    apk: P,
    apksigner: Option<&Path>,
) -> Result<String, String> {
    let tool = resolve_apksigner(apksigner);
    let mut command = Command::new(&tool);
    command.arg("verify").arg("--verbose").arg(apk.as_ref());
    let output = run_command(&mut command, "apksigner verify")?;
    if !output.status.success() {
        return Err(command_failure("apksigner verify", &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    } else {
        stdout
    })
}

fn adb_name(explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "adb.exe" } else { "adb" }))
}

fn parse_pm_path_output(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let path = line.strip_prefix("package:").unwrap_or(line).trim();
            (!path.is_empty() && path.ends_with(".apk")).then(|| path.to_string())
        })
        .collect()
}

fn adb_command(adb: &Path, serial: Option<&str>, args: &[&str]) -> Command {
    let mut command = Command::new(adb);
    if let Some(serial) = serial {
        command.args(["-s", serial]);
    }
    command.args(args);
    command
}

/// Return all APK paths reported by `pm path`, including the base and config
/// splits, for an installed package.
pub fn installed_apk_paths(
    package_name: &str,
    serial: Option<&str>,
    adb_path: Option<&Path>,
) -> Result<Vec<String>, String> {
    if package_name.is_empty() {
        return Err("package name must not be empty".to_string());
    }
    let adb = adb_name(adb_path);
    let mut command = adb_command(&adb, serial, &["shell", "pm", "path", package_name]);
    let output = run_command(&mut command, "adb shell pm path")?;
    if !output.status.success() {
        return Err(command_failure("adb shell pm path", &output));
    }
    let paths = parse_pm_path_output(&output.stdout);
    if paths.is_empty() {
        return Err(format!(
            "adb returned no APK paths for installed package {package_name}"
        ));
    }
    Ok(paths)
}

/// List installed package names, optionally filtering them with a regular
/// expression.  The returned values do not include adb's `package:` prefix.
pub fn list_installed_packages(
    package_regex: Option<&str>,
    serial: Option<&str>,
    adb_path: Option<&Path>,
) -> Result<Vec<String>, String> {
    let matcher = package_regex
        .map(Regex::new)
        .transpose()
        .map_err(|error| format!("invalid package regex: {error}"))?;
    let adb = adb_name(adb_path);
    let mut command = adb_command(&adb, serial, &["shell", "pm", "list", "packages"]);
    let output = run_command(&mut command, "adb shell pm list packages")?;
    if !output.status.success() {
        return Err(command_failure("adb shell pm list packages", &output));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("package:"))
        .filter(|package| matcher.as_ref().map_or(true, |regex| regex.is_match(package)))
        .map(str::to_string)
        .collect())
}

/// Pull all APKs belonging to an installed package into `output_dir`.
pub fn pull_installed_apks<P: AsRef<Path>>(
    package_name: &str,
    output_dir: P,
    serial: Option<&str>,
    adb_path: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("could not create ADB staging directory: {error}"))?;
    let remotes = installed_apk_paths(package_name, serial, adb_path)?;
    let adb = adb_name(adb_path);
    let mut local_paths = Vec::with_capacity(remotes.len());
    for remote in remotes {
        let name = Path::new(&remote)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("ADB returned an invalid APK path: {remote}"))?;
        let local = output_dir.join(name);
        if !local_paths.iter().all(|path: &PathBuf| path != &local) {
            return Err(format!("ADB returned duplicate APK name: {name}"));
        }
        let remote_arg = remote.as_str();
        let local_arg = local.to_string_lossy().into_owned();
        let mut command = adb_command(&adb, serial, &["pull", remote_arg, &local_arg]);
        let output = run_command(&mut command, "adb pull")?;
        if !output.status.success() {
            return Err(command_failure("adb pull", &output));
        }
        if !local.is_file() {
            return Err(format!("adb pull did not create {}", local.display()));
        }
        local_paths.push(local);
    }
    Ok(local_paths)
}

/// Install a complete split APK set using one `adb install-multiple` call.
pub fn install_apks(
    apks: &[PathBuf],
    serial: Option<&str>,
    adb_path: Option<&Path>,
    replace_existing: bool,
    allow_downgrade: bool,
) -> Result<String, String> {
    if apks.is_empty() {
        return Err("APK set must contain at least one APK".to_string());
    }
    let adb = adb_name(adb_path);
    let mut command = Command::new(&adb);
    if let Some(serial) = serial {
        command.args(["-s", serial]);
    }
    command.arg("install-multiple");
    if replace_existing {
        command.arg("-r");
    }
    if allow_downgrade {
        command.arg("-d");
    }
    for apk in apks {
        command.arg(apk);
    }
    let output = run_command(&mut command, "adb install-multiple")?;
    if !output.status.success() {
        return Err(command_failure("adb install-multiple", &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    } else {
        stdout
    })
}

/// Launch an installed package through Android's `monkey` command.
pub fn launch_package(
    package_name: &str,
    serial: Option<&str>,
    adb_path: Option<&Path>,
) -> Result<String, String> {
    if package_name.is_empty() {
        return Err("package name must not be empty".to_string());
    }
    let adb = adb_name(adb_path);
    let mut command = adb_command(
        &adb,
        serial,
        &["shell", "monkey", "-p", package_name, "1"],
    );
    let output = run_command(&mut command, "adb shell monkey")?;
    if !output.status.success() {
        return Err(command_failure("adb shell monkey", &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(if stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    } else {
        stdout
    })
}

#[cfg(test)]
mod tests {
    use super::parse_pm_path_output;

    #[test]
    fn parses_base_and_split_paths() {
        let output = b"package:/data/app/example/base.apk\npackage:/data/app/example/split_config.en.apk\n";
        assert_eq!(
            parse_pm_path_output(output),
            vec![
                "/data/app/example/base.apk".to_string(),
                "/data/app/example/split_config.en.apk".to_string()
            ]
        );
    }
}
