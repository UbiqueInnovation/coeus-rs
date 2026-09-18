// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use base64::{engine::general_purpose, Engine as _};
use std::{collections::HashMap, sync::Arc};

use lazy_static::lazy_static;

use coeus_models::models::{AccessFlags, Class, DexFile, Method};

use super::{ClassInstance, InternalObject, Register, VMException, Value, VM};

pub trait JavaObject {
    fn class_name() -> String;
    fn call(fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException>;
    fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let Some(Register::Reference(_, address)) = args.first() else {
            return Err(VMException::WrongNumberOfArguments);
        };
        if !matches!(vm.heap.get(address), Some(Value::Object(_))) {
            return Err(VMException::InvalidRegisterType);
        }
        // `<init>` initializes the object allocated by `new-instance`; it must
        // not replace that object with a second allocation.
        vm.current_state.return_reg = args[0].clone();
        Ok(())
    }
    fn cinit(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
        Ok(())
    }
}

fn runtime_class(class_name: &str) -> Arc<Class> {
    Arc::new(Class {
        dex_identifier: String::from("RUNTIME"),
        access_flags: AccessFlags::PUBLIC,
        super_class: 0xff_ff_ff_ff,
        class_name: class_name.to_string(),
        ..Default::default()
    })
}

fn string_argument(vm: &VM, args: &[Register], index: usize) -> Option<String> {
    args.get(index).and_then(|arg| match arg {
        Register::Reference(_, address) => vm.heap.get(address).and_then(Value::as_string),
        _ => None,
    })
}

fn return_string(vm: &mut VM, value: impl Into<String>) -> Result<(), VMException> {
    vm.current_state.return_reg = vm.new_instance(
        StringClass::class_name().to_string(),
        Value::Object(StringClass::new(value.into())),
    )?;
    Ok(())
}

fn return_stub_object(vm: &mut VM, class_name: &str) -> Result<(), VMException> {
    let class = VM_BUILTINS
        .get(class_name)
        .cloned()
        .unwrap_or_else(|| runtime_class(class_name));
    vm.current_state.return_reg = vm.new_instance(
        class_name.to_string(),
        Value::Object(ClassInstance::new(class)),
    )?;
    Ok(())
}

fn java_string_hash(value: &str) -> i32 {
    value
        .encode_utf16()
        .fold(0i32, |hash, character| hash.wrapping_mul(31).wrapping_add(character as i32))
}

fn internal_string(instance: &ClassInstance, key: &str) -> String {
    match instance.internal_state.get(key) {
        Some(InternalObject::String(value)) => value.clone(),
        _ => String::new(),
    }
}

fn set_internal_string(instance: &mut ClassInstance, key: &str, value: impl Into<String>) {
    instance
        .internal_state
        .insert(key.to_string(), InternalObject::String(value.into()));
}

fn set_internal_u32(instance: &mut ClassInstance, key: &str, value: u32) {
    instance
        .internal_state
        .insert(key.to_string(), InternalObject::U32(value));
}

fn url_parts(raw: &str) -> HashMap<String, InternalObject> {
    let mut state = HashMap::new();
    let (scheme, after_scheme) = raw
        .find("://")
        .map(|separator| (&raw[..separator], &raw[separator + 3..]))
        .unwrap_or(("", raw));
    let authority_end = after_scheme
        .find(|character| matches!(character, '/' | '?' | '#'))
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let remainder = &after_scheme[authority_end..];
    let user_info = authority
        .rsplit_once('@')
        .map(|(user_info, _)| user_info)
        .unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|end| &authority[1..end])
            .unwrap_or(authority)
    } else {
        authority.rsplit_once(':').map(|(host, _)| host).unwrap_or(authority)
    };
    let port = if authority.starts_with('[') {
        authority
            .find(']')
            .and_then(|end| authority[end + 1..].strip_prefix(':'))
    } else {
        authority.rsplit_once(':').and_then(|(_, port)| Some(port))
    };

    let (without_fragment, fragment) = remainder
        .split_once('#')
        .map(|(value, fragment)| (value, fragment))
        .unwrap_or((remainder, ""));
    let (path, query) = without_fragment
        .split_once('?')
        .map(|(path, query)| (path, query))
        .unwrap_or((without_fragment, ""));

    set_string(&mut state, "raw", raw);
    set_string(&mut state, "scheme", scheme);
    set_string(&mut state, "user_info", user_info);
    set_string(&mut state, "authority", authority);
    set_string(&mut state, "host", host);
    set_string(&mut state, "path", path);
    set_string(&mut state, "query", query);
    set_string(&mut state, "fragment", fragment);
    set_string(&mut state, "port", port.unwrap_or(""));
    state
}

fn set_string(state: &mut HashMap<String, InternalObject>, key: &str, value: &str) {
    state.insert(key.to_string(), InternalObject::String(value.to_string()));
}

fn url_string(vm: &VM, args: &[Register]) -> Option<String> {
    let Register::Reference(_, address) = args.first()? else {
        return None;
    };
    let Value::Object(instance) = vm.heap.get(address)? else {
        return None;
    };
    Some(internal_string(instance, "raw"))
}

fn return_url_component(
    vm: &mut VM,
    args: &[Register],
    component: &str,
) -> Result<(), VMException> {
    let value = args
        .first()
        .and_then(|receiver| match receiver {
            Register::Reference(_, address) => vm.heap.get(address),
            _ => None,
        })
        .and_then(|value| match value {
            Value::Object(instance) => match instance.internal_state.get(component) {
                Some(InternalObject::String(value)) => Some(value.clone()),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or_default();
    return_string(vm, value)
}

fn return_default_for_method(
    vm: &mut VM,
    method: &Method,
    args: &[Register],
) -> Result<(), VMException> {
    if method.method_name == "<init>" {
        if let Some(receiver) = args.first() {
            vm.current_state.return_reg = receiver.clone();
        }
        return Ok(());
    }

    let return_type = method
        .proto_name
        .rsplit_once(')')
        .map(|(_, return_type)| return_type)
        .unwrap_or("V");
    match return_type {
        "V" => {}
        "J" | "D" => vm.current_state.return_reg = Register::LiteralWide(0),
        "Z" => vm.current_state.return_reg = Register::Literal(0),
        "B" | "C" | "S" | "I" | "F" => vm.current_state.return_reg = Register::Literal(0),
        _ if return_type.starts_with('L') || return_type.starts_with('[') => {
            vm.current_state.return_reg = Register::Null
        }
        _ => return Err(VMException::LinkerError),
    }
    Ok(())
}

fn is_framework_class(class_name: &str) -> bool {
    class_name.starts_with("Landroid/")
        || class_name.starts_with("Landroidx/")
        || class_name.starts_with("Ljava/")
        || class_name.starts_with("Ljavax/")
        || class_name.starts_with("Lkotlin/")
        || class_name.starts_with("Lkotlinx/")
}

/// Return a lightweight class definition for framework classes that are
/// supplied by Android/ Kotlin at runtime and consequently absent from an
/// application's DEX files.
pub fn synthetic_class(class_name: &str) -> Option<Arc<Class>> {
    is_framework_class(class_name).then(|| runtime_class(class_name))
}

lazy_static! {
    pub static ref VM_BUILTINS: Arc<HashMap<String, Arc<Class>>> = {
        let mut map = HashMap::new();
        map.insert(
            StringBuilder::class_name().to_string(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_idx: 2317,
                class_name: "Ljava/lang/StringBuilder;".to_string(),
                ..Default::default()
            }),
        );
        map.insert(
            StringClass::class_name().to_string(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_idx: 2315,
                class_name: "Ljava/lang/String;".to_string(),
                ..Default::default()
            }),
        );
        map.insert(
            AndroidBase64::class_name().to_string(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: "Landroid/util/Base64;".to_string(),
                ..Default::default()
            }),
        );
        map.insert(
            ObjectClass::class_name().to_string(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: "Ljava/lang/Object;".to_string(),
                ..Default::default()
            }),
        );
        map.insert(
            MessageDigest::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: "Ljava/security/MessageDigest;".to_string(),
                ..Default::default()
            }),
        );
        map.insert(
            IvParameterSpec::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: "Ljavax/crypto/spec/IvParameterSpec;".to_string(),
                ..Default::default()
            }),
        );
        map.insert(
            SecretKeySpec::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: "Ljavax/crypto/spec/SecretKeySpec;".to_string(),
                ..Default::default()
            }),
        );
        map.insert(
            ClassObject::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: ClassObject::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            ClassLoader::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: ClassLoader::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Integer::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Integer::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Long::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Long::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            JavaArray::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: JavaArray::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            System::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: System::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Cipher::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Cipher::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            KeyGenerator::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: KeyGenerator::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            PrintWriter::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: PrintWriter::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Context::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Context::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            AssetManager::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: AssetManager::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            InputStream::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: InputStream::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            SharedPreferences::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: SharedPreferences::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            SecureRandom::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: SecureRandom::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Application::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Application::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Charset::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Charset::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Objects::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Objects::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Math::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Math::class_name(),
                ..Default::default()
            }),
        );
        map.insert(
            Debug::class_name(),
            Arc::new(Class {
                dex_identifier: String::from("RUNTIME"),
                access_flags: AccessFlags::PUBLIC,
                super_class: 0xff_ff_ff_ff,
                class_name: Debug::class_name(),
                ..Default::default()
            }),
        );

        // Framework classes are not present in an APK's DEX files.  Keep the
        // most commonly used ones in the builtin table so `new-instance` and
        // `const-class` can still be emulated without an Android boot class
        // path.
        for class_name in [
            URL::class_name(),
            URI::class_name(),
            URLConnection::class_name(),
            HttpURLConnection::class_name(),
            URLUtil::class_name(),
            Uri::class_name(),
            TextUtils::class_name(),
            Log::class_name(),
            SystemClock::class_name(),
            Bundle::class_name(),
            Intent::class_name(),
            Resources::class_name(),
            PackageManager::class_name(),
            Activity::class_name(),
            ConnectivityManager::class_name(),
            NetworkInfo::class_name(),
            Pair::class_name(),
            SharedPreferencesEditor::class_name(),
            SettingsSecure::class_name(),
            Process::class_name(),
            Looper::class_name(),
        ] {
            map.insert(class_name.clone(), runtime_class(&class_name));
        }

        Arc::new(map)
    };
}

macro_rules! runtime_impl {
    (package $package:literal;
        impl $class_name:ident {
        $(pub fn $function_name:ident ($vm:ident: &mut VM, $args:ident: &[Register]) -> Result<(), VMException> $function:block)*
    }) => {
        /// builtin for $class_name
        pub struct $class_name;
        #[allow(non_snake_case)]
        impl $class_name {
              $(fn $function_name ($vm: &mut VM, $args: &[Register]) -> Result<(), VMException> $function )*
        }
        impl JavaObject for $class_name {
            fn call(fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
                if fn_name == "<init>" {
                    return Self::init(vm, args);
                }
                if fn_name == "<clinit>" {
                    return Self::cinit(vm, args);
                }
                match fn_name {
                $(
                    stringify!($function_name) => {
                       Self::$function_name(vm, args)
                   }
                )*
                   _ =>  Err(VMException::LinkerError)
                }
            }

            fn class_name() -> String {
                format!("L{}/{};", ($package).replace("::", "/"),stringify!($class_name))
            }

        }
    };
    (
        class $class:literal;
        package $package:literal;
        impl $class_name:ident {
        $(pub fn $function_name:ident ($vm:ident: &mut VM, $args:ident: &[Register]) -> Result<(), VMException> $function:block)*
    }) => {
        /// builtin for $class_name
        pub struct $class_name;
        #[allow(non_snake_case)]
        impl $class_name {
              $(fn $function_name ($vm: &mut VM, $args: &[Register]) -> Result<(), VMException> $function )*
        }
        impl JavaObject for $class_name {
            fn call(fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
                if fn_name == "<init>" {
                    return Self::init(vm, args);
                }
                if fn_name == "<clinit>" {
                    return Self::cinit(vm, args);
                }
                match fn_name {
                $(
                    stringify!($function_name) => {
                       Self::$function_name(vm, args)
                   }
                )*
                   _ =>  Err(VMException::LinkerError)
                }
            }

            fn class_name() -> String {
                let package_name = ($package).replace("::", "/");
                if package_name == "" {
                    stringify!($class).replace("\"", "")
                } else {
                    format!("L{}/{};",package_name, stringify!($class).replace("\"", ""))
                }
            }

        }
    };

}

runtime_impl! {
    package "java::net";
    impl URL {
        pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let mut raw = args
                .iter()
                .skip(1)
                .filter_map(|arg| match arg {
                    Register::Reference(_, address) => vm.heap.get(address).and_then(Value::as_string),
                    _ => None,
                })
                .last()
                .unwrap_or_else(|| "https://example.invalid/".to_string());

            // URL(URL context, String spec) is common in framework code.  A
            // relative spec is useful to preserve even when it is not
            // possible to perform network I/O in the emulator.
            if !raw.contains("://") {
                if let Some(Register::Reference(_, context)) = args.get(1) {
                    if let Some(Value::Object(context)) = vm.heap.get(context) {
                        let base = internal_string(context, "raw");
                        if !base.is_empty() {
                            raw = format!("{}/{}", base.trim_end_matches('/'), raw);
                        }
                    }
                }
            }

            let Some(Register::Reference(_, address)) = args.first() else {
                return Err(VMException::InvalidRegisterType);
            };
            let Some(Value::Object(instance)) = vm.heap.get_mut(address) else {
                return Err(VMException::InvalidRegisterType);
            };
            instance.internal_state = url_parts(&raw);
            Ok(())
        }
        pub fn getProtocol(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "scheme")
        }
        pub fn getAuthority(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "authority")
        }
        pub fn getHost(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "host")
        }
        pub fn getUserInfo(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "user_info")
        }
        pub fn getPath(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "path")
        }
        pub fn getQuery(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "query")
        }
        pub fn getRef(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "fragment")
        }
        pub fn getFile(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let path = args
                .first()
                .and_then(|receiver| match receiver {
                    Register::Reference(_, address) => vm.heap.get(address),
                    _ => None,
                })
                .and_then(|value| match value {
                    Value::Object(instance) => {
                        let path = internal_string(instance, "path");
                        let query = internal_string(instance, "query");
                        Some(if query.is_empty() { path } else { format!("{}?{}", path, query) })
                    }
                    _ => None,
                })
                .unwrap_or_default();
            return_string(vm, path)
        }
        pub fn getPort(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let port = args
                .first()
                .and_then(|receiver| match receiver {
                    Register::Reference(_, address) => vm.heap.get(address),
                    _ => None,
                })
                .and_then(|value| match value {
                    Value::Object(instance) => internal_string(instance, "port").parse().ok(),
                    _ => None,
                })
                .unwrap_or(-1);
            vm.current_state.return_reg = Register::Literal(port);
            Ok(())
        }
        pub fn getDefaultPort(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let protocol = args
                .first()
                .and_then(|receiver| match receiver {
                    Register::Reference(_, address) => vm.heap.get(address),
                    _ => None,
                })
                .and_then(|value| match value {
                    Value::Object(instance) => Some(internal_string(instance, "scheme")),
                    _ => None,
                })
                .unwrap_or_default();
            let port = match protocol.as_str() {
                "http" => 80,
                "https" => 443,
                "ftp" => 21,
                _ => -1,
            };
            vm.current_state.return_reg = Register::Literal(port);
            Ok(())
        }
        pub fn toString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "raw")
        }
        pub fn toExternalForm(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "raw")
        }
        pub fn hashCode(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(
                url_string(vm, args)
                    .map(|value| java_string_hash(&value))
                    .unwrap_or_default(),
            );
            Ok(())
        }
        pub fn equals(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() != 2 {
                return Err(VMException::WrongNumberOfArguments);
            }
            let equal = url_string(vm, &args[..1]) == url_string(vm, &args[1..]);
            vm.current_state.return_reg = Register::Literal(i32::from(equal));
            Ok(())
        }
        pub fn openConnection(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let Some(Register::Reference(_, url_address)) = args.first() else {
                return Err(VMException::InvalidRegisterType);
            };
            let mut connection = ClassInstance::new(VM_BUILTINS[&URLConnection::class_name()].clone());
            set_internal_u32(&mut connection, "url", *url_address);
            vm.current_state.return_reg = vm.new_instance(
                URLConnection::class_name(),
                Value::Object(connection),
            )?;
            Ok(())
        }
        pub fn openStream(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = vm.new_instance(
                InputStream::class_name(),
                Value::Object(InputStream::new(Vec::new())),
            )?;
            Ok(())
        }
        pub fn toURI(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let raw = url_string(vm, args).unwrap_or_default();
            let mut uri = ClassInstance::new(VM_BUILTINS[&URI::class_name()].clone());
            uri.internal_state = url_parts(&raw);
            vm.current_state.return_reg = vm.new_instance(URI::class_name(), Value::Object(uri))?;
            Ok(())
        }
    }
}

runtime_impl! {
    package "java::net";
    impl URI {
        pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let raw = string_argument(vm, args, 1).unwrap_or_default();
            let Some(Register::Reference(_, address)) = args.first() else {
                return Err(VMException::InvalidRegisterType);
            };
            let Some(Value::Object(instance)) = vm.heap.get_mut(address) else {
                return Err(VMException::InvalidRegisterType);
            };
            instance.internal_state = url_parts(&raw);
            Ok(())
        }
        pub fn create(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let raw = string_argument(vm, args, 0).unwrap_or_default();
            let mut uri = ClassInstance::new(VM_BUILTINS[&URI::class_name()].clone());
            uri.internal_state = url_parts(&raw);
            vm.current_state.return_reg = vm.new_instance(URI::class_name(), Value::Object(uri))?;
            Ok(())
        }
        pub fn toString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "raw")
        }
        pub fn getScheme(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "scheme")
        }
        pub fn getAuthority(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "authority")
        }
        pub fn getHost(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "host")
        }
        pub fn getPath(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "path")
        }
        pub fn getQuery(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "query")
        }
        pub fn getPort(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let port = return_component(vm, args, "port").parse().unwrap_or(-1);
            vm.current_state.return_reg = Register::Literal(port);
            Ok(())
        }
        pub fn getFragment(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_url_component(vm, args, "fragment")
        }
        pub fn isAbsolute(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let absolute = !return_component(vm, args, "scheme").is_empty();
            vm.current_state.return_reg = Register::Literal(i32::from(absolute));
            Ok(())
        }
        pub fn isOpaque(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn normalize(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = args.first().cloned().unwrap_or(Register::Null);
            Ok(())
        }
    }
}

fn return_component(vm: &VM, args: &[Register], component: &str) -> String {
    args.first()
        .and_then(|receiver| match receiver {
            Register::Reference(_, address) => vm.heap.get(address),
            _ => None,
        })
        .and_then(|value| match value {
            Value::Object(instance) => match instance.internal_state.get(component) {
                Some(InternalObject::String(value)) => Some(value.clone()),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or_default()
}

runtime_impl! {
    package "java::net";
    impl URLConnection {
        pub fn connect(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }
        pub fn getURL(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let url = args.first().and_then(|receiver| match receiver {
                Register::Reference(_, address) => vm.heap.get(address),
                _ => None,
            });
            if let Some(Value::Object(connection)) = url {
                if let Some(InternalObject::U32(address)) = connection.internal_state.get("url") {
                    vm.current_state.return_reg = Register::Reference(URL::class_name(), *address);
                    return Ok(());
                }
            }
            vm.current_state.return_reg = Register::Null;
            Ok(())
        }
        pub fn getInputStream(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = vm.new_instance(
                InputStream::class_name(),
                Value::Object(InputStream::new(Vec::new())),
            )?;
            Ok(())
        }
    }
}

runtime_impl! {
    package "java::net";
    impl HttpURLConnection {
        pub fn connect(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }
        pub fn disconnect(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }
        pub fn getResponseCode(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(200);
            Ok(())
        }
    }
}

runtime_impl! {
    package "android::webkit";
    impl URLUtil {
        pub fn isHttpsUrl(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let is_https = string_argument(vm, args, 0)
                .map(|url| url.to_ascii_lowercase().starts_with("https://"))
                .unwrap_or(false);
            vm.current_state.return_reg = Register::Literal(i32::from(is_https));
            Ok(())
        }
        pub fn isHttpUrl(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let is_http = string_argument(vm, args, 0)
                .map(|url| url.to_ascii_lowercase().starts_with("http://"))
                .unwrap_or(false);
            vm.current_state.return_reg = Register::Literal(i32::from(is_http));
            Ok(())
        }
        pub fn isNetworkUrl(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let is_network = string_argument(vm, args, 0)
                .map(|url| {
                    let url = url.to_ascii_lowercase();
                    url.starts_with("http://") || url.starts_with("https://")
                })
                .unwrap_or(false);
            vm.current_state.return_reg = Register::Literal(i32::from(is_network));
            Ok(())
        }
        pub fn isValidUrl(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let valid = string_argument(vm, args, 0)
                .map(|url| url.contains("://"))
                .unwrap_or(false);
            vm.current_state.return_reg = Register::Literal(i32::from(valid));
            Ok(())
        }
        pub fn guessUrl(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_string(vm, string_argument(vm, args, 0).unwrap_or_default())
        }
        pub fn composeSearchUrl(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let query = string_argument(vm, args, 0).unwrap_or_default();
            let template = string_argument(vm, args, 1).unwrap_or_default();
            let placeholder = string_argument(vm, args, 2).unwrap_or_default();
            return_string(vm, template.replace(&placeholder, &query))
        }
    }
}

runtime_impl! {
    package "android::text";
    impl TextUtils {
        pub fn isEmpty(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let empty = string_argument(vm, args, 0).map(|value| value.is_empty()).unwrap_or(true);
            vm.current_state.return_reg = Register::Literal(i32::from(empty));
            Ok(())
        }
        pub fn equals(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let equal = string_argument(vm, args, 0) == string_argument(vm, args, 1);
            vm.current_state.return_reg = Register::Literal(i32::from(equal));
            Ok(())
        }
        pub fn htmlEncode(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_string(vm, string_argument(vm, args, 0).unwrap_or_default())
        }
        pub fn getTrimmedLength(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(
                string_argument(vm, args, 0)
                    .map(|value| value.trim().chars().count() as i32)
                    .unwrap_or(0),
            );
            Ok(())
        }
    }
}

runtime_impl! {
    package "android::util";
    impl Log {
        pub fn d(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn i(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn w(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn e(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn v(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn println(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn getStackTraceString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_string(vm, string_argument(vm, args, 0).unwrap_or_default())
        }
    }
}

runtime_impl! {
    package "android::os";
    impl SystemClock {
        pub fn elapsedRealtime(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::LiteralWide(now_millis());
            Ok(())
        }
        pub fn uptimeMillis(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::LiteralWide(now_millis());
            Ok(())
        }
        pub fn elapsedRealtimeNanos(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::LiteralWide(now_millis().saturating_mul(1_000_000));
            Ok(())
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
fn now_millis() -> i64 {
    instant::now() as i64
}

runtime_impl! {
    class "Bundle";
    package "android::os";
    impl Bundle {
        pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let Some(Register::Reference(_, address)) = args.first() else {
                return Err(VMException::InvalidRegisterType);
            };
            if let Some(Value::Object(bundle)) = vm.heap.get_mut(address) {
                bundle.internal_state.clear();
            }
            Ok(())
        }
        pub fn putString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            put_bundle_string(vm, args)
        }
        pub fn putCharSequence(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            put_bundle_string(vm, args)
        }
        pub fn putBoolean(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            put_bundle_i32(vm, args)
        }
        pub fn putInt(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            put_bundle_i32(vm, args)
        }
        pub fn putLong(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let Some(Register::Reference(_, address)) = args.first() else {
                return Err(VMException::InvalidRegisterType);
            };
            let Some(key) = string_argument(vm, args, 1) else {
                return Err(VMException::InvalidRegisterType);
            };
            let value = match args.get(2) {
                Some(Register::LiteralWide(value)) => *value,
                Some(Register::Literal(value)) => i64::from(*value),
                _ => 0,
            };
            if let Some(Value::Object(bundle)) = vm.heap.get_mut(address) {
                bundle.internal_state.insert(key, InternalObject::I64(value));
            }
            Ok(())
        }
        pub fn getString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let value = bundle_string(vm, args).or_else(|| string_argument(vm, args, 2));
            match value {
                Some(value) => return_string(vm, value),
                None => {
                    vm.current_state.return_reg = Register::Null;
                    Ok(())
                }
            }
        }
        pub fn getBoolean(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(bundle_i32(vm, args).unwrap_or_else(|| {
                match args.get(2) {
                    Some(Register::Literal(value)) => *value,
                    _ => 0,
                }
            }));
            Ok(())
        }
        pub fn getInt(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(bundle_i32(vm, args).unwrap_or_else(|| {
                match args.get(2) {
                    Some(Register::Literal(value)) => *value,
                    _ => 0,
                }
            }));
            Ok(())
        }
        pub fn getLong(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::LiteralWide(bundle_i64(vm, args).unwrap_or_else(|| {
                match args.get(2) {
                    Some(Register::LiteralWide(value)) => *value,
                    Some(Register::Literal(value)) => i64::from(*value),
                    _ => 0,
                }
            }));
            Ok(())
        }
        pub fn containsKey(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let present = bundle_key(vm, args)
                .map(|key| args.first().and_then(|receiver| match receiver {
                    Register::Reference(_, address) => vm.heap.get(address),
                    _ => None,
                }).map(|value| matches!(value, Value::Object(instance) if instance.internal_state.contains_key(&key))).unwrap_or(false))
                .unwrap_or(false);
            vm.current_state.return_reg = Register::Literal(i32::from(present));
            Ok(())
        }
        pub fn isEmpty(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let empty = args.first().and_then(|receiver| match receiver {
                Register::Reference(_, address) => vm.heap.get(address),
                _ => None,
            }).map(|value| matches!(value, Value::Object(instance) if instance.internal_state.is_empty())).unwrap_or(true);
            vm.current_state.return_reg = Register::Literal(i32::from(empty));
            Ok(())
        }
        pub fn size(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let size = args.first().and_then(|receiver| match receiver {
                Register::Reference(_, address) => vm.heap.get(address),
                _ => None,
            }).map(|value| match value { Value::Object(instance) => instance.internal_state.len() as i32, _ => 0 }).unwrap_or(0);
            vm.current_state.return_reg = Register::Literal(size);
            Ok(())
        }
        pub fn clear(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let Some(Register::Reference(_, address)) = args.first() {
                if let Some(Value::Object(bundle)) = vm.heap.get_mut(address) {
                    bundle.internal_state.clear();
                }
            }
            Ok(())
        }
    }
}

fn bundle_key(vm: &VM, args: &[Register]) -> Option<String> {
    string_argument(vm, args, 1)
}

fn put_bundle_string(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
    let Some(Register::Reference(_, address)) = args.first() else {
        return Err(VMException::InvalidRegisterType);
    };
    let Some(key) = string_argument(vm, args, 1) else {
        return Err(VMException::InvalidRegisterType);
    };
    let value = string_argument(vm, args, 2).unwrap_or_default();
    if let Some(Value::Object(bundle)) = vm.heap.get_mut(address) {
        set_internal_string(bundle, &key, value);
    }
    Ok(())
}

fn put_bundle_i32(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
    let Some(Register::Reference(_, address)) = args.first() else {
        return Err(VMException::InvalidRegisterType);
    };
    let Some(key) = string_argument(vm, args, 1) else {
        return Err(VMException::InvalidRegisterType);
    };
    let value = match args.get(2) {
        Some(Register::Literal(value)) => *value,
        _ => 0,
    };
    if let Some(Value::Object(bundle)) = vm.heap.get_mut(address) {
        bundle.internal_state.insert(key, InternalObject::I32(value));
    }
    Ok(())
}

fn bundle_string(vm: &VM, args: &[Register]) -> Option<String> {
    let key = bundle_key(vm, args)?;
    let Register::Reference(_, address) = args.first()? else {
        return None;
    };
    let Value::Object(bundle) = vm.heap.get(address)? else {
        return None;
    };
    match bundle.internal_state.get(&key) {
        Some(InternalObject::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn bundle_i32(vm: &VM, args: &[Register]) -> Option<i32> {
    let key = bundle_key(vm, args)?;
    let Register::Reference(_, address) = args.first()? else {
        return None;
    };
    let Value::Object(bundle) = vm.heap.get(address)? else {
        return None;
    };
    match bundle.internal_state.get(&key) {
        Some(InternalObject::I32(value)) => Some(*value),
        _ => None,
    }
}

fn bundle_i64(vm: &VM, args: &[Register]) -> Option<i64> {
    let key = bundle_key(vm, args)?;
    let Register::Reference(_, address) = args.first()? else {
        return None;
    };
    let Value::Object(bundle) = vm.heap.get(address)? else {
        return None;
    };
    match bundle.internal_state.get(&key) {
        Some(InternalObject::I64(value)) => Some(*value),
        Some(InternalObject::I32(value)) => Some(i64::from(*value)),
        _ => None,
    }
}

runtime_impl! {
    package "android::content";
    impl Intent {
        pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let action = string_argument(vm, args, 1);
            if let Some(Register::Reference(_, address)) = args.first() {
                if let Some(Value::Object(intent)) = vm.heap.get_mut(address) {
                    intent.internal_state.clear();
                    if let Some(action) = action {
                        set_internal_string(intent, "action", action);
                    }
                }
            }
            Ok(())
        }
        pub fn setAction(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let (Some(Register::Reference(_, address)), Some(action)) = (args.first(), string_argument(vm, args, 1)) {
                if let Some(Value::Object(intent)) = vm.heap.get_mut(address) {
                    set_internal_string(intent, "action", action);
                }
            }
            vm.current_state.return_reg = args.first().cloned().unwrap_or(Register::Null);
            Ok(())
        }
        pub fn getAction(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let value = args.first().and_then(|receiver| match receiver {
                Register::Reference(_, address) => vm.heap.get(address),
                _ => None,
            }).and_then(|value| match value {
                Value::Object(intent) => match intent.internal_state.get("action") {
                    Some(InternalObject::String(value)) => Some(value.clone()),
                    _ => None,
                },
                _ => None,
            });
            match value { Some(value) => return_string(vm, value), None => { vm.current_state.return_reg = Register::Null; Ok(()) } }
        }
        pub fn addFlags(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let (Some(Register::Reference(_, address)), Some(Register::Literal(flags))) = (args.first(), args.get(1)) {
                if let Some(Value::Object(intent)) = vm.heap.get_mut(address) {
                    let current = match intent.internal_state.get("flags") { Some(InternalObject::I32(value)) => *value, _ => 0 };
                    intent.internal_state.insert("flags".to_string(), InternalObject::I32(current | flags));
                }
            }
            vm.current_state.return_reg = args.first().cloned().unwrap_or(Register::Null);
            Ok(())
        }
        pub fn getFlags(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(match args.first() {
                Some(Register::Reference(_, address)) => match vm.heap.get(address) {
                    Some(Value::Object(intent)) => match intent.internal_state.get("flags") { Some(InternalObject::I32(value)) => *value, _ => 0 },
                    _ => 0,
                },
                _ => 0,
            });
            Ok(())
        }
        pub fn toUri(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let action = args.first().and_then(|receiver| match receiver {
                Register::Reference(_, address) => vm.heap.get(address),
                _ => None,
            }).and_then(|value| match value {
                Value::Object(intent) => match intent.internal_state.get("action") { Some(InternalObject::String(value)) => Some(value.clone()), _ => None },
                _ => None,
            }).unwrap_or_default();
            let mut uri = ClassInstance::new(VM_BUILTINS[&Uri::class_name()].clone());
            uri.internal_state = url_parts(&action);
            vm.current_state.return_reg = vm.new_instance(Uri::class_name(), Value::Object(uri))?;
            Ok(())
        }
    }
}

runtime_impl! {
    package "android::content::res";
    impl Resources {
        pub fn getString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_string(vm, format!("resource-{}", args.get(1).and_then(|value| match value { Register::Literal(value) => Some(*value), _ => None }).unwrap_or(0)))
        }
        pub fn getIdentifier(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
    }
}

runtime_impl! {
    package "android::content::pm";
    impl PackageManager {
        pub fn hasSystemFeature(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
        pub fn checkPermission(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
    }
}

runtime_impl! {
    package "android::app";
    impl Activity {
        pub fn finish(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }
        pub fn runOnUiThread(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }
        pub fn getIntent(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = vm.new_instance(
                Intent::class_name(),
                Value::Object(ClassInstance::new(VM_BUILTINS[&Intent::class_name()].clone())),
            )?;
            Ok(())
        }
    }
}

runtime_impl! {
    package "android::net";
    impl Uri {
        pub fn parse(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let raw = string_argument(vm, args, 0).unwrap_or_default();
            let mut uri = ClassInstance::new(VM_BUILTINS[&Uri::class_name()].clone());
            uri.internal_state = url_parts(&raw);
            vm.current_state.return_reg = vm.new_instance(Uri::class_name(), Value::Object(uri))?;
            Ok(())
        }
        pub fn toString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { return_url_component(vm, args, "raw") }
        pub fn getScheme(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { return_url_component(vm, args, "scheme") }
        pub fn getHost(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { return_url_component(vm, args, "host") }
        pub fn getPath(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { return_url_component(vm, args, "path") }
        pub fn getQuery(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { return_url_component(vm, args, "query") }
        pub fn getLastPathSegment(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let path = return_component(vm, args, "path");
            return_string(vm, path.trim_end_matches('/').rsplit('/').next().unwrap_or_default())
        }
        pub fn encode(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { return_string(vm, string_argument(vm, args, 0).unwrap_or_default()) }
        pub fn decode(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { return_string(vm, string_argument(vm, args, 0).unwrap_or_default()) }
    }
}

runtime_impl! {
    package "android::net";
    impl ConnectivityManager {
        pub fn getActiveNetworkInfo(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = vm.new_instance(
                NetworkInfo::class_name(),
                Value::Object(ClassInstance::new(VM_BUILTINS[&NetworkInfo::class_name()].clone())),
            )?;
            Ok(())
        }
    }
}

runtime_impl! {
    package "android::net";
    impl NetworkInfo {
        pub fn isConnected(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> { vm.current_state.return_reg = Register::Literal(1); Ok(()) }
        pub fn isAvailable(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> { vm.current_state.return_reg = Register::Literal(1); Ok(()) }
        pub fn getType(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> { vm.current_state.return_reg = Register::Literal(1); Ok(()) }
    }
}

runtime_impl! {
    package "android::util";
    impl Pair {
        pub fn create(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let mut pair = ClassInstance::new(VM_BUILTINS[&Pair::class_name()].clone());
            if let Some(Register::Reference(_, first)) = args.first() { set_internal_u32(&mut pair, "first", *first); }
            if let Some(Register::Reference(_, second)) = args.get(1) { set_internal_u32(&mut pair, "second", *second); }
            vm.current_state.return_reg = vm.new_instance(Pair::class_name(), Value::Object(pair))?;
            Ok(())
        }
    }
}

runtime_impl! {
    class "SharedPreferences$Editor";
    package "android::content";
    impl SharedPreferencesEditor {
        pub fn putString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { put_bundle_string(vm, args) }
        pub fn putBoolean(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { put_bundle_i32(vm, args) }
        pub fn putInt(vm: &mut VM, args: &[Register]) -> Result<(), VMException> { put_bundle_i32(vm, args) }
        pub fn apply(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> { Ok(()) }
        pub fn commit(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> { vm.current_state.return_reg = Register::Literal(1); Ok(()) }
    }
}

runtime_impl! {
    class "Settings$Secure";
    package "android::provider";
    impl SettingsSecure {
        pub fn getString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_string(vm, string_argument(vm, args, 1).unwrap_or_default())
        }
    }
}

runtime_impl! {
    package "android::os";
    impl Process {
        pub fn myPid(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> { vm.current_state.return_reg = Register::Literal(1); Ok(()) }
        pub fn myUid(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> { vm.current_state.return_reg = Register::Literal(1); Ok(()) }
    }
}

runtime_impl! {
    package "android::os";
    impl Looper {
        pub fn getMainLooper(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            return_stub_object(vm, &Self::class_name())
        }
    }
}

runtime_impl! {
    package "android::content";
    impl Context {
        pub fn getSharedPreferences(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
              let class = SharedPreferences::new();
            let reg = vm.new_instance(SharedPreferences::class_name(), Value::Object(class))?;
            vm.current_state.return_reg = reg;
            Ok(())
        }
        pub fn getAssets(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            let class = AssetManager::new();
            let reg = vm.new_instance(AssetManager::class_name(), Value::Object(class))?;
            vm.current_state.return_reg = reg;
            Ok(())
        }
        pub fn getPackageName(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            return_string(vm, "com.example.app")
        }
        pub fn getApplicationContext(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = args.first().cloned().unwrap_or(Register::Null);
            Ok(())
        }
        pub fn getResources(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            return_stub_object(vm, &Resources::class_name())
        }
        pub fn getPackageManager(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            return_stub_object(vm, &PackageManager::class_name())
        }
        pub fn getSystemService(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let service = string_argument(vm, args, 1).unwrap_or_default();
            if service == "connectivity" {
                return_stub_object(vm, &ConnectivityManager::class_name())
            } else {
                vm.current_state.return_reg = Register::Null;
                Ok(())
            }
        }
        pub fn getString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            Resources::getString(vm, args)
        }
        pub fn checkSelfPermission(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(0);
            Ok(())
        }
    }
}

runtime_impl! {
    package "java::nio::charset";
    impl Charset {
         pub fn forName(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            let class = Charset::new();
            let reg = vm.new_instance(Charset::class_name(), Value::Object(class))?;
            vm.current_state.return_reg = reg;
            Ok(())
        }
    }
}
impl Charset {
    pub fn new() -> ClassInstance {
        let ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci
    }
}
runtime_impl! {
    package "android::content";
    impl SharedPreferences {
        pub fn getString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let value = bundle_string(vm, args).or_else(|| string_argument(vm, args, 2));
            match value {
                Some(value) => return_string(vm, value),
                None => { vm.current_state.return_reg = Register::Null; Ok(()) }
            }
        }
        pub fn getBoolean(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(bundle_i32(vm, args).unwrap_or_else(|| match args.get(2) {
                Some(Register::Literal(value)) => *value,
                _ => 0,
            }));
            Ok(())
        }
        pub fn getInt(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(bundle_i32(vm, args).unwrap_or_else(|| match args.get(2) {
                Some(Register::Literal(value)) => *value,
                _ => 0,
            }));
            Ok(())
        }
        pub fn contains(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let present = bundle_key(vm, args)
                .and_then(|key| args.first().and_then(|receiver| match receiver {
                    Register::Reference(_, address) => vm.heap.get(address),
                    _ => None,
                }).map(|value| matches!(value, Value::Object(instance) if instance.internal_state.contains_key(&key))))
                .unwrap_or(false);
            vm.current_state.return_reg = Register::Literal(i32::from(present));
            Ok(())
        }
        pub fn edit(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            return_stub_object(vm, &SharedPreferencesEditor::class_name())
        }
    }
}
impl SharedPreferences {
    pub fn new() -> ClassInstance {
        let ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());

        ci
    }
}
runtime_impl! {
    package "android::content::res";
    impl AssetManager {
        pub fn open(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() == 2 {
            if let Register::Reference(_, string_ref) = &args[1] {
                let file_name = if let Some(Value::Object(string)) =  vm.heap.get(&string_ref) {string} else {return Err(VMException::InvalidRegisterType)};
                let file_name = format!("{}", file_name);

                for key in vm.resources.keys().filter(|k| k.contains("assets/")) {
                    let splits = key.split('/');
                    if let Some(file) = splits.last(){
                        if file == file_name {
                            let input_stream = InputStream::new(vm.resources[key].data().to_vec());
                            let reg = vm.new_instance(Charset::class_name(), Value::Object(input_stream))?;
                            vm.current_state.return_reg = reg;
                            return Ok(());
                        }
                    }
                }
            }
            }
            Err(VMException::InvalidRegisterType)
        }
    }
}
impl AssetManager {
    pub fn new() -> ClassInstance {
        let ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci
    }
}
runtime_impl! {
    package "java::io";
    impl InputStream {
        pub fn read(vm: &mut VM, args: &[Register]) -> Result<(),VMException> {
            if args.len() == 4 {
                if let (Register::Reference(_, stream),Register::Reference(_,array), Register::Literal(offset), Register::Literal(len)) = (&args[0], &args[1], &args[2], &args[3]) {
                    let input_part = {
                        if let Some(Value::Object(stream)) = vm.heap.get(&stream) {
                            if let Some(InternalObject::Vec(arr)) = stream.internal_state.get("buffer"){
                                (&arr[..std::cmp::min(arr.len(), *len as usize)]).to_vec()
                            } else {vec![]}

                        } else {vec![]}
                    };
                    if let Some(Value::Array(arr)) = vm.heap.get_mut(&array) {
                        let start = *offset as usize;
                        let end = start + input_part.len();
                        if start > arr.len() || end > arr.len() {
                            log::error!("slice out of bounds [{}..{}]", start, end);
                            return Err(VMException::InvalidRegisterType);
                        }
                        arr[start..end].copy_from_slice(&input_part);

                        vm.current_state.return_reg = Register::Literal(input_part.len() as i32);
                    }
                }
            }
            Ok(())
        }
    }
}

impl InputStream {
    pub fn new(buffer: Vec<u8>) -> ClassInstance {
        let mut ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci.internal_state
            .insert("buffer".to_string(), InternalObject::Vec(buffer));
        ci
    }
}

runtime_impl! {
    class "Object";
    package "java::lang";
    impl ObjectClass {
        pub fn getClass(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let Register::Reference(_, class_ptr) = &args[0] {
                if let Some(instance) = vm.heap.get(class_ptr) {
                    match instance {
                        Value::Object(class) => {
                            let clazz = ClassObject::new(class.class.clone());
                            if let Ok(reg) = vm.new_instance(ClassObject::class_name(), Value::Object(clazz)) {
                                vm.current_state.return_reg = reg;
                                return Ok(());
                            }
                        },
                        _ => {}
                    }
                }
            }
            Err(VMException::InvalidRegisterType)
        }
        pub fn hashCode(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let Some(Register::Reference(_, address)) = args.first() else {
                return Err(VMException::InvalidRegisterType);
            };
            if !vm.heap.contains_key(address) {
                return Err(VMException::InvalidMemoryAddress(*address));
            }
            // Object.hashCode is identity based.  The VM heap address is a
            // stable identity for the lifetime of the emulated object.
            vm.current_state.return_reg = Register::Literal(*address as i32);
            Ok(())
        }
        pub fn toString(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let Some(Register::Reference(_, address)) = args.first() else {
                return Err(VMException::InvalidRegisterType);
            };
            let Some(Value::Object(instance)) = vm.heap.get(address) else {
                return Err(VMException::InvalidRegisterType);
            };
            let value = format!("{}@{:x}", instance.class.class_name, address);
            return_string(vm, value)
        }
        pub fn equals(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() != 2 {
                return Err(VMException::WrongNumberOfArguments);
            }
            let equal = match (&args[0], &args[1]) {
                (Register::Reference(_, this), Register::Reference(_, other)) => this == other,
                (Register::Literal(this), Register::Literal(other)) => this == other,
                (Register::Null, Register::Null) => true,
                _ => false,
            };
            vm.current_state.return_reg = Register::Literal(i32::from(equal));
            Ok(())
        }
    }
}

runtime_impl! {
    package "java::lang";
    impl Math {
        pub fn max(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() >= 2 {
                if let (Register::Literal(a), Register::Literal(b)) = (&args[0], &args[1]) {
                    vm.current_state.return_reg = if a >= b {args[0].clone()} else { args[1].clone()};
                    return Ok(())
                }
            }
            Err(VMException::InvalidRegisterType)
        }
         pub fn min(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() >= 2 {
                if let (Register::Literal(a), Register::Literal(b)) = (&args[0], &args[1]) {
                    vm.current_state.return_reg = if a <= b {args[0].clone()} else { args[1].clone()};
                    return Ok(())
                }
            }
            Err(VMException::InvalidRegisterType)
        }

    }
}

runtime_impl! {
    package "android::os";
    impl Debug {
        pub fn isDebuggerConnected(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::Literal(1);
            Ok(())
        }
         pub fn waitingForDebugger(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }

    }
}

runtime_impl! {
    class "[B";
    package "";
    impl JavaArray {
        pub fn clone(vm: &mut VM, args: &[Register])-> Result<(), VMException> {
            if let Register::Reference(_, array) = &args[0] {
                let array = if let Some(Value::Array(array)) =  vm.heap.get(&array) {array.clone()} else {vec![]};
                let reg = vm.new_instance("[B".to_string(), Value::Array(array))?;
                vm.current_state.return_reg = reg;
                return Ok(());
            }
            Err(VMException::InvalidRegisterType)
        }
    }
}

runtime_impl! {
    package "javax::crypto";
    impl Cipher {
        pub fn getInstance(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            let class = Cipher::new();
            let reg = vm.new_instance(Cipher::class_name(), Value::Object(class))?;
            vm.current_state.return_reg = reg;
            Ok(())
        }
    }
}

impl Cipher {
    pub fn new() -> ClassInstance {
        let ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci
    }
}

runtime_impl! {
    package "android::app";
    impl Application {

    }
}

runtime_impl! {
    package "java::security";
    impl SecureRandom {
        pub fn getInstance(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            let class = SecureRandom::new();
            let reg = vm.new_instance(SecureRandom::class_name(), Value::Object(class))?;
            vm.current_state.return_reg = reg;
            Ok(())
        }
        pub fn setSeed(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }
    }
}

impl SecureRandom {
    pub fn new() -> ClassInstance {
        let ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci
    }
}

runtime_impl! {
    package "javax::crypto";
    impl KeyGenerator {
        pub fn getInstance(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            let class = KeyGenerator::new();
            let reg = vm.new_instance(KeyGenerator::class_name(), Value::Object(class))?;
            vm.current_state.return_reg = reg;
            Ok(())
        }
    }
}

impl KeyGenerator {
    pub fn new() -> ClassInstance {
        let ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci
    }
}

runtime_impl! {
    package "java::lang";
    impl System {
        pub fn currentTimeMillis(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            #[cfg(not(target_arch = "wasm32"))]
            {
                use std::time::{SystemTime, UNIX_EPOCH};
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                vm.current_state.return_reg = Register::LiteralWide(since_the_epoch.as_millis() as i64);
            }
            #[cfg(target_arch = "wasm32")]
            {
                 vm.current_state.return_reg = Register::LiteralWide(instant::now() as i64);
            }
            Ok(())
        }
        pub fn nanoTime(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            vm.current_state.return_reg = Register::LiteralWide(now_millis().saturating_mul(1_000_000));
            Ok(())
        }
        pub fn getProperty(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            return_string(vm, string_argument(vm, args, 0).unwrap_or_default())
        }
        pub fn arraycopy(vm : &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() != 5 {
                return Err(VMException::IndexOutOfBounds);
            }
            let from = if let Register::Literal(from_index) = &args[1] {
                *from_index as usize
            } else {
                return Err(VMException::LinkerError);
            };
            let dst_start =  if let Register::Literal(from_index) = &args[3] {
                *from_index as usize
            } else {
                return Err(VMException::LinkerError);
            };
            let length =  if let Register::Literal(from_index) = &args[4] {
                *from_index as usize
            } else {
                return Err(VMException::LinkerError);
            };
            if let (Register::Reference(_name, address),Register::Reference(_n, address2) ) = (&args[0], &args[2]) {
                log::debug!("Executing built in System->arraycopy");
                let from_array = if let Some(Value::Array(array)) = vm.heap.get_mut(address) {
                    array.to_vec()
                } else {
                    return Err(VMException::LinkerError);
                };
                let to_array =  if let Some(Value::Array(array)) = vm.heap.get_mut(address2) {
                    array
                } else {
                    return Err(VMException::LinkerError);
                };
                to_array[dst_start..dst_start+length].copy_from_slice(&from_array[from..from+length]);
            } else {
                return Err(VMException::LinkerError);
            }
            Ok(())
        }
    }
}

runtime_impl! {
    package "java::lang";
    impl Integer {
        pub fn valueOf(vm: &mut VM, args: &[Register])-> Result<(), VMException> {
            if let Register::Reference(_, string_ref) = &args[0] {
                let string = if let Some(Value::Object(string)) =  vm.heap.get(&string_ref) {string} else {return Err(VMException::InvalidRegisterType)};
                let string = format!("{}", string);
                if let Ok(parsed) = string.parse() {
                    let integer = Integer::new(parsed);
                    let reg = vm.new_instance(Integer::class_name(), Value::Object(integer))?;
                    vm.current_state.return_reg = reg;
                    return Ok(());
                }

            }
            Err(VMException::InvalidRegisterType)
        }
    }
}

impl Integer {
    pub fn new(integer: i32) -> ClassInstance {
        let mut ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci.internal_state
            .insert("tmp_int".to_string(), InternalObject::I32(integer));
        ci
    }
}

runtime_impl! {
    package "java::lang";
    impl Long {
        pub fn valueOf(vm: &mut VM, args: &[Register])-> Result<(), VMException> {
            if let Register::Reference(_, string_ref) = &args[0] {
                let string = if let Some(Value::Object(string)) =  vm.heap.get(&string_ref) {string} else {return Err(VMException::InvalidRegisterType)};
                let string = format!("{}", string);
                if let Ok(parsed) = string.parse() {
                    let integer = Long::new(parsed);
                    let reg = vm.new_instance(Long::class_name(), Value::Object(integer))?;
                    vm.current_state.return_reg = reg;
                    return Ok(());
                }

            }
            Err(VMException::InvalidRegisterType)
        }
    }
}
impl Long {
    pub fn new(integer: i64) -> ClassInstance {
        let mut ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci.internal_state
            .insert("tmp_long".to_string(), InternalObject::I64(integer));
        ci
    }
}

runtime_impl! {
    package "java::lang";
    impl ClassLoader {
    }
}

impl ClassLoader {
    pub fn new() -> ClassInstance {
        let ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci
    }
}

runtime_impl! {
    class "Class";
    package "java::lang";
    impl ClassObject {
        pub fn getName(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let Register::Reference(name, _) = &args[0] {
                let string = StringClass::new(name.to_owned());
                if let Ok(reg) = vm.new_instance(StringClass::class_name().to_string(), Value::Object(string)){
                    vm.current_state.return_reg = reg;
                    return Ok(());
                }
            }
            Err(VMException::InvalidRegisterType)
        }
        pub fn getClassLoader(vm: &mut VM, _args: &[Register]) -> Result<(), VMException>  {
            let class =ClassLoader::new();
            let reg = vm.new_instance(ClassLoader::class_name(), Value::Object(class))?;
            vm.current_state.return_reg = reg;
            Ok(())
        }
    }
}
impl ClassObject {
    pub fn new(class: Arc<Class>) -> ClassInstance {
        let mut ci = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        ci.internal_state
            .insert("class".to_string(), InternalObject::Class(class));
        ci
    }
}

// TODO: provide implementation for IV
runtime_impl! {
    package "javax::crypto::spec";
    impl IvParameterSpec {
        pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let (Register::Reference(_name, address),Register::Reference(_, iv_array)) = (&args[0], &args[1]) {
                log::debug!("Executing built in StringBuilder->init");
                let array = if let Some(Value::Array(array)) =  vm.heap.get(&iv_array) {array.clone()} else {vec![]};
                if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                    builder_instance.internal_state.insert(
                        "iv_array".to_string(),
                        InternalObject::Vec(array),
                    );
                }
            }
            Ok(())
        }
    }
}

runtime_impl! {
    package "javax::crypto::spec";
    impl SecretKeySpec {
        pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let Register::Reference(_name, address) = &args[0] {
                log::debug!("Executing built in StringBuilder->init");
                if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                    builder_instance.internal_state.insert(
                        "tmp_string".to_string(),
                        InternalObject::String(String::from("")),
                    );
                }
            }
            Ok(())
        }
    }
}

//TODO: provide impl
runtime_impl! {
    package "java::util";
    impl Arrays {
        pub fn copyOf(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let (Register::Reference(_name, address), Register::Literal(new_size)) = (&args[0], &args[1]) {
                //let new_vec = Vec::<
                let array = if let Some(Value::Array(arr)) = vm.heap.get(address) {
                    arr.clone()
                } else {
                    return Err(VMException::LinkerError)
                };
                if *new_size as usize > array.len() {
                    return Err(VMException::IndexOutOfBounds);
                }
                if let Ok(register) = vm.new_instance(
                    "[B".to_string(),
                    Value::Array((&array[..(*new_size as usize)]).to_vec()),
                ) {
                    vm.current_state.return_reg = register;
                    return Ok(());
                }

            }

            Err(VMException::LinkerError)
        }
    }
}

runtime_impl! {
    package "java::util";
    impl Objects {
        pub fn requireNonNull(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() > 0 {
                vm.current_state.return_reg = args[0].clone();
                return Ok(());
            }

            Err(VMException::LinkerError)
        }
        pub fn hashCode(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let hash = match args.first() {
                Some(Register::Reference(_, address)) => *address as i32,
                Some(Register::Literal(value)) => *value,
                _ => 0,
            };
            vm.current_state.return_reg = Register::Literal(hash);
            Ok(())
        }
        pub fn equals(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            let equal = match (args.first(), args.get(1)) {
                (Some(Register::Reference(_, left)), Some(Register::Reference(_, right))) => left == right,
                (Some(Register::Literal(left)), Some(Register::Literal(right))) => left == right,
                (Some(Register::Null), Some(Register::Null)) => true,
                _ => false,
            };
            vm.current_state.return_reg = Register::Literal(i32::from(equal));
            Ok(())
        }
    }
}

runtime_impl! {
    package "java::io";
    impl PrintWriter {
        pub fn print(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
            Ok(())
        }
    }
}

runtime_impl! {
    package "java::security";
    impl MessageDigest {
        pub fn getInstance(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if let Register::Reference(_name, address) = &args[0] {
                if let Some(Value::Object(string_object)) = vm.heap.get(address) {
                    if string_object.class.class_name.as_str() == StringClass::class_name() {
                        if let Some(InternalObject::String(algo)) =
                            string_object.internal_state.get("tmp_string")
                        {
                            let algo = algo.clone();
                            let mut ci = ClassInstance::new(VM_BUILTINS[&MessageDigest::class_name()].clone());
                            ci.internal_state.insert(
                                "digest_algo".to_string(),
                                InternalObject::String(algo.clone()),
                            );
                            let instance =
                                vm.new_instance(Self::class_name(), Value::Object(ci))?;
                            vm.current_state.return_reg = instance;
                            log::debug!("get MessageDigest instance {}", algo);
                        }
                    }
                }
            }
            Ok(())
        }
        pub fn digest(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
            if args.len() <2 {
                return Err(VMException::WrongNumberOfArguments);
            }
            if let (Register::Reference(_, instance), Register::Reference(_, byte_array)) =
                (&args[0], &args[1])
            {
                if let (Some(Value::Object(md)), Some(Value::Array(bytes))) =
                    (vm.heap.get(instance), vm.heap.get(byte_array))
                {
                    if let InternalObject::String(algo) = md.internal_state.get("digest_algo").expect("Digest was not created by Runtime Implementation")
                    {
                        match algo.as_str() {
                            "SHA-256" => {
                                use sha2::{Digest, Sha256};
                                let mut hasher = Sha256::new();
                                hasher.update(bytes);
                                let result = hasher.finalize();
                                let instance =
                                    vm.new_instance("[B".to_string(), Value::Array(result.to_vec()))?;
                                vm.current_state.return_reg = instance;
                            }
                            "SHA-1" => {
                                use sha1::{Digest, Sha1};
                                let mut hasher = Sha1::new();
                                hasher.update(bytes);
                                let result = hasher.finalize();
                                let instance =
                                    vm.new_instance("[B".to_string(), Value::Array(result.to_vec()))?;
                                vm.current_state.return_reg = instance;
                            }
                            "MD5" => {
                                use md5::{Digest, Md5};
                                let mut hasher = Md5::new();
                                hasher.update(bytes);
                                let result = hasher.finalize();
                                let instance =
                                    vm.new_instance("[B".to_string(), Value::Array(result.to_vec()))?;
                                vm.current_state.return_reg = instance;
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

/// Builtin for AndroidBase64
struct AndroidBase64(&'static str);
impl AndroidBase64 {
    pub fn decode(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        //for now we ignore the decoding flags
        if let Register::Reference(_name, address) = &args[0] {
            log::debug!("Executing built in Base64->decode");
            if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                log::debug!("internal state {:?}", builder_instance.internal_state);
                if let Some(InternalObject::String(content)) =
                    builder_instance.internal_state.get("tmp_string")
                {
                    log::debug!("Executing built in Base64->decode");
                    let base64bytes = general_purpose::STANDARD
                        .decode(content)
                        .expect("Could not decode");
                    let reg = vm.new_instance("[B".to_string(), Value::Array(base64bytes))?;
                    vm.current_state.return_reg = reg;
                }
            }
        }
        Ok(())
    }

    pub fn encode_to_string(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let Register::Reference(_name, address) = &args[0] {
            log::debug!("Executing built in Base64->decode");
            if let Some(Value::Array(array)) = vm.heap.get_mut(&address) {
                log::debug!("Executing built in Base64->decode");
                let base64_string = general_purpose::STANDARD.encode(&array);
                let mut the_state = HashMap::new();
                the_state.insert(
                    "tmp_string".to_string(),
                    InternalObject::String(base64_string),
                );
                let string_class = ClassInstance::with_internal_state(
                    VM_BUILTINS[StringClass::class_name()].clone(),
                    the_state,
                );
                vm.current_state.return_reg = vm.new_instance(
                    StringClass::class_name().to_string(),
                    Value::Object(string_class),
                )?;
            }
        }
        Ok(())
    }

    pub fn call(fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        match fn_name {
            "decode" => AndroidBase64::decode(vm, args),
            "encodeToString" => AndroidBase64::encode_to_string(vm, args),
            _ => {
                log::error!("AndroidBase64: {} not found", fn_name);
                Err(VMException::LinkerError)
            }
        }
    }

    pub fn class_name() -> &'static str {
        "Landroid/util/Base64;"
    }
}

struct StringBuilder(&'static str);
impl StringBuilder {
    pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let Register::Reference(_name, address) = &args[0] {
            log::debug!("Executing built in StringBuilder->init");
            if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                builder_instance.internal_state.insert(
                    "tmp_string".to_string(),
                    InternalObject::String(String::from("")),
                );
            }
        }
        Ok(())
    }
    pub fn append(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let (Register::Reference(_, this_address), Register::Reference(_, arg1_address)) =
            (&args[0], &args[1])
        {
            log::debug!("Executing built in StringBuilder->init");
            let argument = if let Some(Value::Object(string_instance)) = vm.heap.get(arg1_address) {
                if let Some(InternalObject::String(string)) =
                    string_instance.internal_state.get("tmp_string")
                {
                    string.clone()
                } else {
                    return Err(VMException::InvalidRegisterType);
                }
            } else {
                return Err(VMException::InvalidRegisterType);
            };
            if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&this_address) {
                builder_instance
                    .internal_state
                    .entry("tmp_string".to_string())
                    .and_modify(|e| match e {
                        InternalObject::String(string) => {
                            *string += argument.as_str();
                        }
                        _ => {}
                    });
            }
        }
        Ok(())
    }
    pub fn to_string(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let Register::Reference(_, address) = &args[0] {
            if let Some(Value::Object(builder_instance)) = vm.heap.get(&address) {
                match builder_instance.internal_state.get("tmp_string") {
                    Some(InternalObject::String(string)) => {
                        let string = string.to_owned();
                        let mut the_state = HashMap::new();
                        the_state.insert("tmp_string".to_string(), InternalObject::String(string));
                        let string_class = ClassInstance::with_internal_state(
                            VM_BUILTINS[StringClass::class_name()].clone(),
                            the_state,
                        );
                        vm.current_state.return_reg = vm.new_instance(
                            StringClass::class_name().to_string(),
                            Value::Object(string_class),
                        )?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn call(fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        match fn_name {
            "<init>" => StringBuilder::init(vm, args),
            "append" => StringBuilder::append(vm, args),
            "toString" => StringBuilder::to_string(vm, args),
            _ => Err(VMException::LinkerError),
        }
    }

    pub fn class_name() -> &'static str {
        "Ljava/lang/StringBuilder;"
    }
}

// pub struct ObjectClass;
// impl ObjectClass {
//     pub fn call(fn_name: &str, _vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
//         match fn_name {
//             "<init>" => Ok(()),
//             _ => Err(VMException::LinkerError),
//         }
//     }

//     pub fn class_name() -> &'static str {
//         "Ljava/lang/Object;"
//     }
// }

impl ObjectClass {
    pub fn new() -> ClassInstance {
        ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone())
    }
}

pub struct StringClass;
impl StringClass {
    pub fn new(string: String) -> ClassInstance {
        let mut ci = ClassInstance::new(VM_BUILTINS[Self::class_name()].clone());
        ci.internal_state
            .insert("tmp_string".to_string(), InternalObject::String(string));
        ci
    }
    pub fn init(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if args.len() == 1 {
            if let Register::Reference(_name, address) = &args[0] {
                log::debug!("Executing built in String->init");
                if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                    log::debug!("update internal state");
                    builder_instance.internal_state.insert(
                        "tmp_string".to_string(),
                        InternalObject::String(String::from("")),
                    );
                }
            }
        } else if args.len() == 2 {
            if let (Register::Reference(_, address), Register::Reference(_, array_address)) =
                (&args[0], &args[1])
            {
                log::debug!("Executing built in String->init with Array");
                let array = if let Some(Value::Array(array)) = vm.heap.get(array_address) {
                    array.clone()
                } else {
                    return Err(VMException::InvalidRegisterType);
                };
                if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                    builder_instance.internal_state.insert(
                        "tmp_string".to_string(),
                        InternalObject::String(
                            String::from_utf8(array).unwrap_or_else(|_| "".to_string()),
                        ),
                    );
                }
            }
        } else if args.len() == 5 {
            //init from byte array offset, len and charset
            // we ignore the charset and interpret it as utf-8
            if let (
                Register::Reference(_, string_ptr),
                Register::Reference(_, arr_ptr),
                Register::Literal(offset),
                Register::Literal(len),
            ) = (&args[0], &args[1], &args[2], &args[3])
            {
                let array = if let Some(Value::Array(array)) = vm.heap.get(arr_ptr) {
                    array.clone()
                } else {
                    return Err(VMException::InvalidRegisterType);
                };
                if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&string_ptr) {
                    let start = *offset as usize;
                    let end = start + *len as usize;
                    builder_instance.internal_state.insert(
                        "tmp_string".to_string(),
                        InternalObject::String(
                            String::from_utf8((&array[start..end]).to_vec())
                                .unwrap_or_else(|_| "".to_string()),
                        ),
                    );
                }
            }
        }
        Ok(())
    }
    pub fn sub_sequence(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let (Register::Reference(_, address), Register::Literal(start), Register::Literal(end)) =
            (&args[0], &args[1], &args[2])
        {
            if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                match builder_instance.internal_state.get("tmp_string") {
                    Some(InternalObject::String(string)) => {
                        let string = string[(*start as usize)..(*end as usize)].to_owned();
                        let mut the_state = HashMap::new();
                        the_state.insert("tmp_string".to_string(), InternalObject::String(string));
                        let string_class = ClassInstance::with_internal_state(
                            VM_BUILTINS[Self::class_name()].clone(),
                            the_state,
                        );
                        vm.current_state.return_reg = vm.new_instance(
                            StringClass::class_name().to_string(),
                            Value::Object(string_class),
                        )?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
    pub fn length(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let Some(Register::Reference(_name, address)) = args.get(0).as_ref() {
            log::debug!("Executing built in String->length");
            if let Some(Value::Object(builder_instance)) = vm.heap.get_mut(&address) {
                match builder_instance.internal_state.get("tmp_string") {
                    Some(InternalObject::String(string)) => {
                        vm.current_state.return_reg = Register::Literal(string.len() as i32);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn get_string_from_instance(address: &u32, vm: &mut VM, _: &[Register]) -> String {
        if let Some(Value::Object(builder_instance)) = vm.heap.get(&address) {
            match builder_instance.internal_state.get("tmp_string") {
                Some(InternalObject::String(string)) => string.to_string(),
                _ => String::from(""),
            }
        } else {
            String::from("")
        }
    }
    pub fn get_bytes(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let Register::Reference(_name, address) = &args[0] {
            log::debug!("Executing built in String->getBytes");
            let internal_string = Self::get_string_from_instance(address, vm, args);
            if let Ok(register) = vm.new_instance(
                "[B".to_string(),
                Value::Array(internal_string.as_bytes().to_vec()),
            ) {
                vm.current_state.return_reg = register;
                return Ok(());
            }
        }
        Err(VMException::InvalidRegisterType)
    }
    pub fn to_char_array(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let Register::Reference(_name, address) = &args[0] {
            log::debug!("Executing built in String->getBytes");
            let internal_string = Self::get_string_from_instance(address, vm, args);
            if let Ok(register) = vm.new_instance(
                "[C".to_string(),
                Value::Array(internal_string.as_bytes().to_vec()),
            ) {
                vm.current_state.return_reg = register;
                return Ok(());
            }
        }
        Err(VMException::InvalidRegisterType)
    }
    pub fn value_of(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if let Some(value) = string_argument(vm, args, 0) {
            return_string(vm, value)?;
            return Ok(());
        }
        let char_array = if let Register::Reference(_name, address) = &args[0] {
            if let Some(Value::Array(builder_instance)) = vm.heap.get(&address) {
                builder_instance.clone()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let the_string = if args.len() == 3 {
            if let (&Register::Literal(offset), &Register::Literal(count)) = (&args[1], &args[2]) {
                let offset = offset as usize;
                let count = count as usize;
                String::from_utf8_lossy(&char_array[offset..offset + count]).to_string()
            } else {
                String::from("")
            }
        } else if args.len() == 1 {
            String::from_utf8_lossy(&char_array).to_string()
        } else {
            String::from("")
        };
        let instance = Self::new(the_string);
        if let Ok(register) =
            vm.new_instance(Self::class_name().to_string(), Value::Object(instance))
        {
            vm.current_state.return_reg = register;
            return Ok(());
        }
        Err(VMException::InvalidRegisterType)
    }

    pub fn is_empty(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        vm.current_state.return_reg =
            Register::Literal(i32::from(string_argument(vm, args, 0).unwrap_or_default().is_empty()));
        Ok(())
    }

    pub fn starts_with(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let value = string_argument(vm, args, 0).unwrap_or_default();
        let prefix = string_argument(vm, args, 1).unwrap_or_default();
        vm.current_state.return_reg = Register::Literal(i32::from(value.starts_with(&prefix)));
        Ok(())
    }

    pub fn ends_with(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let value = string_argument(vm, args, 0).unwrap_or_default();
        let suffix = string_argument(vm, args, 1).unwrap_or_default();
        vm.current_state.return_reg = Register::Literal(i32::from(value.ends_with(&suffix)));
        Ok(())
    }

    pub fn contains(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let value = string_argument(vm, args, 0).unwrap_or_default();
        let needle = string_argument(vm, args, 1).unwrap_or_default();
        vm.current_state.return_reg = Register::Literal(i32::from(value.contains(&needle)));
        Ok(())
    }

    pub fn substring(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let value = string_argument(vm, args, 0).unwrap_or_default();
        let chars = value.chars().collect::<Vec<_>>();
        let start = match args.get(1) {
            Some(Register::Literal(value)) => (*value).max(0) as usize,
            _ => 0,
        };
        let end = match args.get(2) {
            Some(Register::Literal(value)) => (*value).max(0) as usize,
            _ => chars.len(),
        };
        let start = start.min(chars.len());
        let end = end.min(chars.len()).max(start);
        return_string(vm, chars[start..end].iter().collect::<String>())
    }

    pub fn concat(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let value = string_argument(vm, args, 0).unwrap_or_default();
        let suffix = string_argument(vm, args, 1).unwrap_or_default();
        return_string(vm, format!("{}{}", value, suffix))
    }

    pub fn trim(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let value = string_argument(vm, args, 0).unwrap_or_default();
        return_string(vm, value.trim().to_string())
    }

    pub fn to_lower_case(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        return_string(vm, string_argument(vm, args, 0).unwrap_or_default().to_lowercase())
    }

    pub fn to_upper_case(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        return_string(vm, string_argument(vm, args, 0).unwrap_or_default().to_uppercase())
    }

    pub fn index_of(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        let value = string_argument(vm, args, 0).unwrap_or_default();
        let needle = string_argument(vm, args, 1).unwrap_or_default();
        vm.current_state.return_reg = Register::Literal(
            value.find(&needle).map(|index| index as i32).unwrap_or(-1),
        );
        Ok(())
    }

    pub fn intern(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        vm.current_state.return_reg = args[0].clone();
        Ok(())
    }
    pub fn hash_code(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if args.len() != 1 {
            return Err(VMException::WrongNumberOfArguments);
        }
        let value = if let Value::Object(ci) = vm.get_instance(args[0].clone()) {
            if &ci.class.class_name == StringClass::class_name() {
                format!("{}", ci)
            } else {
                return Err(VMException::InvalidRegisterType);
            }
        } else {
            return Err(VMException::InvalidRegisterType);
        };
        vm.current_state.return_reg = Register::Literal(java_string_hash(&value));
        Ok(())
    }

    pub fn equals(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if args.len() != 2 {
            return Err(VMException::WrongNumberOfArguments);
        }
        let value = if let (Value::Object(a), Value::Object(b)) = (
            vm.get_instance(args[0].clone()),
            vm.get_instance(args[1].clone()),
        ) {
            if &a.class.class_name == StringClass::class_name()
                && &b.class.class_name == StringClass::class_name()
            {
                format!("{}", a) == format!("{}", b)
            } else {
                return Err(VMException::InvalidRegisterType);
            }
        } else {
            return Err(VMException::InvalidRegisterType);
        };
        vm.current_state.return_reg = Register::Literal(if value { 1 } else { 0 });
        Ok(())
    }

    pub fn call(fn_name: &str, vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        match fn_name {
            "<init>" => StringClass::init(vm, args),
            "subSequence" => StringClass::sub_sequence(vm, args),
            "length" => StringClass::length(vm, args),
            "getBytes" => Self::get_bytes(vm, args),
            "toCharArray" => Self::to_char_array(vm, args),
            "valueOf" => Self::value_of(vm, args),
            "isEmpty" => Self::is_empty(vm, args),
            "startsWith" => Self::starts_with(vm, args),
            "endsWith" => Self::ends_with(vm, args),
            "contains" => Self::contains(vm, args),
            "substring" => Self::substring(vm, args),
            "concat" => Self::concat(vm, args),
            "trim" => Self::trim(vm, args),
            "toLowerCase" => Self::to_lower_case(vm, args),
            "toUpperCase" => Self::to_upper_case(vm, args),
            "indexOf" => Self::index_of(vm, args),
            "intern" => Self::intern(vm, args),
            "hashCode" => Self::hash_code(vm, args),
            "equals" => Self::equals(vm, args),
            _ => Err(VMException::LinkerError),
        }
    }

    pub fn class_name() -> &'static str {
        "Ljava/lang/String;"
    }
}

pub fn invoke_runtime_with_method(
    vm: &mut VM,
    class_name: &str,
    method: Arc<Method>,
    arguments: Vec<Register>,
) -> Result<(), VMException> {
    let method_name = method.method_name.as_str();
    log::debug!("Invoke: {} {}", class_name, method_name);
    match class_name {
        x if x == StringBuilder::class_name() => {
            StringBuilder::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == URL::class_name() => {
            URL::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == URI::class_name() => {
            URI::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == URLConnection::class_name() => {
            URLConnection::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == HttpURLConnection::class_name() => {
            HttpURLConnection::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == StringClass::class_name() => {
            StringClass::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == AndroidBase64::class_name() => {
            AndroidBase64::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == ObjectClass::class_name() => {
            ObjectClass::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == ClassObject::class_name() => {
            ClassObject::call(method_name, vm, arguments.as_slice())?
        }
        x if x == ClassLoader::class_name() => {
            ClassLoader::call(method_name, vm, arguments.as_slice())?
        }
        x if x == MessageDigest::class_name() => {
            MessageDigest::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == IvParameterSpec::class_name() => {
            IvParameterSpec::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Arrays::class_name() => {
            Arrays::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == SecretKeySpec::class_name() => {
            SecretKeySpec::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Integer::class_name() => {
            Integer::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Long::class_name() => {
            Long::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == JavaArray::class_name() => {
            JavaArray::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == System::class_name() => {
            System::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Cipher::class_name() => {
            Cipher::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == SecureRandom::class_name() => {
            SecureRandom::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == KeyGenerator::class_name() => {
            KeyGenerator::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == PrintWriter::class_name() => {
            PrintWriter::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Context::class_name() => {
            Context::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == SharedPreferences::class_name() => {
            SharedPreferences::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Application::class_name() => {
            Application::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == AssetManager::class_name() => {
            AssetManager::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == InputStream::class_name() => {
            InputStream::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Charset::class_name() => {
            Charset::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Objects::class_name() => {
            Objects::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Math::class_name() => {
            Math::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Debug::class_name() => {
            Debug::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == URLUtil::class_name() => {
            URLUtil::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == TextUtils::class_name() => {
            TextUtils::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Log::class_name() => {
            Log::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == SystemClock::class_name() => {
            SystemClock::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Bundle::class_name() => {
            Bundle::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Intent::class_name() => {
            Intent::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Resources::class_name() => {
            Resources::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == PackageManager::class_name() => {
            PackageManager::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Activity::class_name() => {
            Activity::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Uri::class_name() => {
            Uri::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == ConnectivityManager::class_name() => {
            ConnectivityManager::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == NetworkInfo::class_name() => {
            NetworkInfo::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Pair::class_name() => {
            Pair::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == SharedPreferencesEditor::class_name() => {
            SharedPreferencesEditor::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == SettingsSecure::class_name() => {
            SettingsSecure::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Process::class_name() => {
            Process::call(method_name, vm, arguments.as_slice())?;
        }
        x if x == Looper::class_name() => {
            Looper::call(method_name, vm, arguments.as_slice())?;
        }
        _ => {
            log::debug!("{}->{} not provided", class_name, method_name);
            //if we have a unknown init function, just try to ignore it, as it does not modify the stack
            if method_name == "<init>" {
                return Ok(());
            }
            // Most Android framework and Kotlin serialization classes are
            // supplied by the device runtime rather than the APK.  Returning
            // a type-correct default keeps unrelated framework calls from
            // aborting an emulation while the concrete implementations above
            // cover the high-value behavior.
            if is_framework_class(class_name)
                || (method_name == "u" && method.proto_name == "()Ljava/lang/String;")
            {
                if method_name == "u" && method.proto_name == "()Ljava/lang/String;" {
                    return_string(vm, "https://example.invalid/")?;
                } else {
                    return_default_for_method(vm, &method, &arguments)?;
                }
                return Ok(());
            }
            if method_name == "setSeed" {
                log::error!("{:?}", arguments);
            }
            return Err(VMException::MethodNotFound(format!(
                "[RUNTIME LINKER ERROR] {}->{}",
                class_name, method_name
            )));
        }
    }
    Ok(())
}

pub fn invoke_runtime(
    vm: &mut VM,
    dex_file: Arc<DexFile>,
    method_idx: u32,
    arguments: Vec<Register>,
) -> Result<(), VMException> {
    let method = dex_file
        .methods
        .get(method_idx as usize)
        .ok_or_else(|| VMException::MethodNotFound(method_idx.to_string()))?;
    let type_str = *dex_file
        .types
        .get(method.class_idx as usize)
        .ok_or_else(|| VMException::StaticDataNotFound(method.class_idx as u32))?;
    let class_name = dex_file
        .get_string(type_str as usize)
        .ok_or_else(|| VMException::StaticDataNotFound(type_str))?;
    invoke_runtime_with_method(vm, class_name, method.clone(), arguments)
}
