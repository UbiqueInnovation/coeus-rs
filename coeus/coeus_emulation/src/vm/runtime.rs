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
    fn init(vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
        let instance = ClassInstance::new(VM_BUILTINS[&Self::class_name()].clone());
        let register = vm.new_instance(Self::class_name(), Value::Object(instance))?;
        vm.current_state.return_reg = register;
        Ok(())
    }
    fn cinit(_vm: &mut VM, _args: &[Register]) -> Result<(), VMException> {
        Ok(())
    }
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
                            }
                        },
                        _ => {}
                    }
                }
            }
            Err(VMException::InvalidRegisterType)
        }
        pub fn equals(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
           if args.len() == 2 {
                 match (&args[1], &args[0]) {
                    (Register::Literal(this), Register::Literal(other)) => {
                          if this == other {
                                 vm.current_state.return_reg = Register::Literal(1);
                            } else {
                                 vm.current_state.return_reg = Register::Literal(0);
                            }
                    }
                     (Register::Reference(_,this), Register::Reference(_,other)) => {
                         if let (Some(Value::Object(this)), Some(Value::Object(other)) ) = (vm.heap.get(this), vm.heap.get(other)) {
                            if format!("{}", this) == format!("{}", other) {
                                 vm.current_state.return_reg = Register::Literal(1);
                            } else {
                                 vm.current_state.return_reg = Register::Literal(0);
                            }
                         }
                     }
                     _ => {
                         vm.current_state.return_reg = Register::Literal(0);
                     }

                 }
            } else {
             vm.current_state.return_reg = Register::Literal(1);
            }
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

    pub fn intern(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        vm.current_state.return_reg = args[0].clone();
        Ok(())
    }
    pub fn hash_code(vm: &mut VM, args: &[Register]) -> Result<(), VMException> {
        if args.len() != 1 {
            return Err(VMException::WrongNumberOfArguments);
        }
        let mut h = 0;
        let value = if let Value::Object(ci) = vm.get_instance(args[0].clone()) {
            if &ci.class.class_name == StringClass::class_name() {
                format!("{}", ci)
            } else {
                return Err(VMException::InvalidRegisterType);
            }
        } else {
            return Err(VMException::InvalidRegisterType);
        };
        if h == 0 && value.len() > 0 {
            let val: Vec<char> = value.chars().collect();

            for i in 0..value.len() {
                h = 31 * h + val[i] as i32;
            }
        }

        vm.current_state.return_reg = Register::Literal(h);
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
        _ => {
            log::debug!("{}->{} not provided", class_name, method_name);
            //if we have a unknown init function, just try to ignore it, as it does not modify the stack
            if method_name == "<init>" {
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
