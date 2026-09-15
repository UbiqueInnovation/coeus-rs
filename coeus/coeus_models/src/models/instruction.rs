// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::{Decode, DexFile, Switch, TestFunction};
use std::{
    collections::HashMap,
    fmt::Debug,
    io::{Read, Seek},
    sync::Arc,
};
use ux::{i4, u4};

#[derive(Clone, Hash, Eq, PartialEq)]
pub enum Instruction {
    Nop,
    MoveException(u8),

    Move(u4, u4),
    MoveFrom16(u8, u16),
    Move16(u16, u16),
    MoveWide(u4, u4),
    MoveWideFrom16(u8, u16),
    MoveWide16(u16, u16),
    MoveObject(u4, u4),
    MoveObjectFrom16(u8, u16),
    MoveObject16(u16, u16),

    MonitorEnter(u8),
    MonitorExit(u8),

    XorInt(u4, u4),
    XorLong(u4, u4),
    XorIntDst(u8, u8, u8),
    XorLongDst(u8, u8, u8),
    XorIntDstLit8(u8, u8, u8),
    XorIntDstLit16(u4, u4, u16),

    RemIntDst(u8, u8, u8),
    RemLongDst(u8, u8, u8),
    RemInt(u4, u4),
    RemLong(u4, u4),
    RemIntLit16(u4, u4, u16),
    RemIntLit8(u8, u8, u8),

    AddInt(u4, u4),
    AddIntDst(u8, u8, u8),
    AddIntLit8(u8, u8, u8),
    AddIntLit16(u4, u4, u16),
    AddLong(u4, u4),
    AddLongDst(u8, u8, u8),

    SubInt(u4, u4),
    SubIntDst(u8, u8, u8),
    SubIntLit8(u8, u8, u8),
    SubIntLit16(u4, u4, u16),
    SubLong(u4, u4),
    SubLongDst(u8, u8, u8),

    MulInt(u4, u4),
    MulIntDst(u8, u8, u8),
    MulIntLit8(u8, u8, u8),
    MulIntLit16(u4, u4, u16),
    MulLong(u4, u4),
    MulLongDst(u8, u8, u8),

    DivInt(u4, u4),
    DivIntDst(u8, u8, u8),
    DivIntLit8(u8, u8, u8),
    DivIntLit16(u4, u4, u16),
    DivLong(u4, u4),
    DivLongDst(u8, u8, u8),

    AndInt(u4, u4),
    AndIntDst(u8, u8, u8),
    AndIntLit8(u8, u8, u8),
    AndIntLit16(u4, u4, u16),
    AndLong(u4, u4),
    AndLongDst(u8, u8, u8),

    OrInt(u4, u4),
    OrIntDst(u8, u8, u8),
    OrIntLit8(u8, u8, u8),
    OrIntLit16(u4, u4, u16),
    OrLong(u4, u4),
    OrLongDst(u8, u8, u8),

    Test(TestFunction, u4, u4, i16),
    TestZero(TestFunction, u8, i16),

    Goto8(i8),
    Goto16(i16),
    Goto32(i32),

    ArrayGetWide(u8, u8, u8),
    ArrayGetObject(u8, u8, u8),
    ArrayGetBoolean(u8, u8, u8),
    ArrayGetByte(u8, u8, u8),
    ArrayGetChar(u8, u8, u8),
    ArrayGetShort(u8, u8, u8),
    ArrayPutWide(u8, u8, u8),
    ArrayPutObject(u8, u8, u8),
    ArrayPutBoolean(u8, u8, u8),
    ArrayPutByte(u8, u8, u8),
    ArrayPutChar(u8, u8, u8),
    ArrayPutShort(u8, u8, u8),

    CmplFloat(u8, u8, u8),
    CmpgFloat(u8, u8, u8),
    CmplDouble(u8, u8, u8),
    CmpgDouble(u8, u8, u8),
    CmpLong(u8, u8, u8),

    Invoke(u16),

    InvokeVirtual(u4, u16, Vec<u8>),
    InvokeSuper(u4, u16, Vec<u8>),
    InvokeDirect(u4, u16, Vec<u8>),
    InvokeStatic(u4, u16, Vec<u8>),
    InvokeInterface(u4, u16, Vec<u8>),

    InvokeVirtualRange(u8, u16, u16),
    InvokeSuperRange(u8, u16, u16),
    InvokeDirectRange(u8, u16, u16),
    InvokeStaticRange(u8, u16, u16),
    InvokeInterfaceRange(u8, u16, u16),

    InvokeCustom(u4, u16, Vec<u8>),
    InvokeType(String),

    MoveResult(u8),
    MoveResultWide(u8),
    MoveResultObject(u8),

    ReturnVoid,

    Return(u8),

    ConstLit4(u4, i4),
    Const,
    ConstLit16(u8, i16),
    ConstLit32(u8, i32),
    ConstHigh16(u8, i16),
    ConstWide(u8, i64),
    ConstWideLit16(u8, i16),
    ConstWideLit32(u8, i32),
    ConstWideHigh16(u8, i16),
    ConstString(u8, u16),
    ConstStringJumbo(u8, u32),
    ConstClass(u8, u16),
    CheckCast(u8, u16),
    InstanceOf(u4, u4, u16),

    IntToByte(u4, u4),
    IntToChar(u4, u4),
    IntToLong(u4, u4),
    IntToFloat(u4, u4),
    IntToDouble(u4, u4),
    LongToInt(u4, u4),
    LongToFloat(u4, u4),
    LongToDouble(u4, u4),
    FloatToInt(u4, u4),
    FloatToLong(u4, u4),
    FloatToDouble(u4, u4),
    DoubleToInt(u4, u4),
    DoubleToLong(u4, u4),
    DoubleToFloat(u4, u4),
    IntToShort(u4, u4),

    NegInt(u4, u4),
    NegLong(u4, u4),
    NegFloat(u4, u4),
    NegDouble(u4, u4),
    NotInt(u4, u4),

    ArrayLength(u4, u4),
    NewInstance(u8, u16),
    NewInstanceType(String),

    NewArray(u4, u4, u16),
    FilledNewArray(u4, u16, Vec<u8>),
    FilledNewArrayRange(u8, u16, u16),
    FillArrayData(u8, u32),

    StaticGet(u8, u16),
    StaticGetWide(u8, u16),
    StaticGetObject(u8, u16),
    StaticGetBoolean(u8, u16),
    StaticGetByte(u8, u16),
    StaticGetChar(u8, u16),
    StaticGetShort(u8, u16),
    StaticPut(u8, u16),
    StaticPutWide(u8, u16),
    StaticPutObject(u8, u16),
    StaticPutBoolean(u8, u16),
    StaticPutByte(u8, u16),
    StaticPutChar(u8, u16),
    StaticPutShort(u8, u16),

    PackedSwitch(u8, i32),
    SparseSwitch(u8, i32),
    Switch(Switch),
    InstanceGet(u4, u4, u16),
    InstanceGetWide(u4, u4, u16),
    InstanceGetObject(u4, u4, u16),
    InstanceGetBoolean(u4, u4, u16),
    InstanceGetByte(u4, u4, u16),
    InstanceGetChar(u4, u4, u16),
    InstanceGetShort(u4, u4, u16),
    InstancePut(u4, u4, u16),
    InstancePutWide(u4, u4, u16),
    InstancePutObject(u4, u4, u16),
    InstancePutBoolean(u4, u4, u16),
    InstancePutByte(u4, u4, u16),
    InstancePutChar(u4, u4, u16),
    InstancePutShort(u4, u4, u16),
    Throw(u8),

    AddFloat(u4, u4),
    AddFloatDst(u8, u8, u8),
    SubFloat(u4, u4),
    SubFloatDst(u8, u8, u8),
    MulFloat(u4, u4),
    MulFloatDst(u8, u8, u8),
    DivFloat(u4, u4),
    DivFloatDst(u8, u8, u8),
    RemFloat(u4, u4),
    RemFloatDst(u8, u8, u8),

    AddDouble(u4, u4),
    AddDoubleDst(u8, u8, u8),
    SubDouble(u4, u4),
    SubDoubleDst(u8, u8, u8),
    MulDouble(u4, u4),
    MulDoubleDst(u8, u8, u8),
    DivDouble(u4, u4),
    DivDoubleDst(u8, u8, u8),
    RemDouble(u4, u4),
    RemDoubleDst(u8, u8, u8),

    ShlInt(u4, u4),
    ShrInt(u4, u4),
    UShrInt(u4, u4),
    ShlIntDst(u8, u8, u8),
    ShrIntDst(u8, u8, u8),
    UShrIntDst(u8, u8, u8),
    ShlIntLit8(u8, u8, u8),
    ShrIntLit8(u8, u8, u8),
    UShrIntLit8(u8, u8, u8),

    ShlLong(u4, u4),
    ShrLong(u4, u4),
    UShrLong(u4, u4),
    ShlLongDst(u8, u8, u8),
    ShrLongDst(u8, u8, u8),
    UShrLongDst(u8, u8, u8),

    ConstMethodHandle(u8, u16),
    ConstMethodType(u8, u16),
    ConstDynamic(u8, u16, u32),

    NotImpl(u8, u8),
    ArrayData(u16, Vec<u8>),
    PackedSwitchData(Switch),
    SparseSwitchData(Switch),
    SwitchData(Switch),
    ArbitraryData(String),
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nop => write!(f, "Nop"),
            Self::ReturnVoid => write!(f, "ReturnVoid"),
            Self::ArbitraryData(arg0) => f.write_str(&arg0),
            Self::ArrayData(arg0, arg1) => {
                f.debug_tuple("ArrayData").field(arg0).field(arg1).finish()
            }
            Self::PackedSwitchData(arg0) => f.debug_tuple("PackedSwitchData").field(arg0).finish(),
            Self::SparseSwitchData(arg0) => f.debug_tuple("SparseSwitchData").field(arg0).finish(),
            Self::NotImpl(arg0, arg1) => f.debug_tuple("NotImpl").field(arg0).field(arg1).finish(),
            _ => f.debug_tuple("Instruction").field(&self.mnemonic_from_opcode()).finish(),
        }
    }
}

static MNEMONICS: [&str; 82] = [
    "nop",
    "const-string",
    "const-string/jumbo",
    "new-array",
    "filled-new-array",
    "fill-array-data",
    "array-data",
    "goto",
    "goto/16",
    "goto/32",
    "aget-byte",
    "aput-byte",
    "sput-object",
    "sget-object",
    "xor-int",
    "rem-int",
    "and-int",
    "or-int",
    "xor-int/2addr",
    "rem-int/2addr",
    "and-int/2addr",
    "or-int/2addr",
    "xor-int/lit16",
    "rem-int/lit16",
    "and-int/lit16",
    "or-int/lit16",
    "xor-int/lit8",
    "rem-int/lit8",
    "and-int/lit8",
    "or-int/lit8",
    "return-void",
    "return-object",
    "aget-char",
    "aput-char",
    "invoke-static",
    "invoke-direct",
    "invoke-virtual",
    "invoke-super",
    "new-instance",
    "iput-object",
    "iget-object",
    "sput-object",
    "sget-object",
    "move-object",
    "const/4",
    "const/16",
    "const",
    "move-result-object",
    "array-length",
    "invoke-interface",
    "if-eq",
    "if-ne",
    "if-lt",
    "if-le",
    "if-gt",
    "if-ge",
    "if-eqz",
    "if-nez",
    "if-ltz",
    "if-lez",
    "if-gtz",
    "if-gez",
    "iput",
    "iget",
    "sget",
    "sput",
    "add-int/lit8",
    "add-int/lit16",
    "sub-int/lit8",
    "sub-int/lit16",
    "add-int/2addr",
    "add-int",
    "sub-int/2addr",
    "sub-int",
    "int-to-byte",
    "move-result",
    "check-cast",
    "throw",
    "move",
    "const-class",
    "shr-int/lit8",
    "ushr-int/lit8",
];

fn test_function_code(function: &TestFunction) -> u8 {
    match function {
        TestFunction::Equal => 0,
        TestFunction::NotEqual => 1,
        TestFunction::LessThan => 2,
        TestFunction::GreaterEqual => 3,
        TestFunction::GreaterThan => 4,
        TestFunction::LessEqual => 5,
    }
}

impl Instruction {
    /// Encode this decoded instruction as DEX code units.
    ///
    /// The parser intentionally exposes a compact instruction model.  This
    /// encoder covers every concrete instruction currently produced by the
    /// decoder and rejects the few context-dependent display placeholders
    /// rather than emitting invalid DEX.
    pub fn to_code_units(&self) -> Result<Vec<u16>, String> {
        use Instruction::*;
        let u4 = |value: &u4| u8::from(*value);
        let i4 = |value: &i4| i8::from(*value);
        let one = |opcode: u8, high: u8| vec![u16::from_le_bytes([opcode, high])];
        let fmt12 = |opcode: u8, dst: &u4, src: &u4| one(opcode, u4(src) << 4 | u4(dst));
        let fmt22 = |opcode: u8, dst: u8, idx: u16| vec![u16::from_le_bytes([opcode, dst]), idx];
        let fmt22s = |opcode: u8, dst: u8, src: u8, value: i16| {
            vec![
                u16::from_le_bytes([opcode, dst]),
                value as u16 | ((src as u16) << 8),
            ]
        };
        let fmt22s4 = |opcode: u8, dst: &u4, src: &u4, value: i16| {
            vec![
                u16::from_le_bytes([opcode, u4(src) << 4 | u4(dst)]),
                value as u16,
            ]
        };
        let fmt23 = |opcode: u8, dst: u8, a: u8, b: u8| {
            vec![
                u16::from_le_bytes([opcode, dst]),
                a as u16 | ((b as u16) << 8),
            ]
        };
        let fmt22c = |opcode: u8, dst: &u4, object: &u4, field: u16| {
            vec![
                u16::from_le_bytes([opcode, u4(object) << 4 | u4(dst)]),
                field,
            ]
        };
        let fmt31 = |opcode: u8, dst: u8, value: i32| {
            vec![
                u16::from_le_bytes([opcode, dst]),
                value as u32 as u16,
                (value as u32 >> 16) as u16,
            ]
        };
        let fmt35 =
            |opcode: u8, count: &u4, method: u16, regs: &[u8]| -> Result<Vec<u16>, String> {
                if regs.len() > 5 || regs.len() != u4(count) as usize {
                    return Err("invoke register count does not match the instruction".to_string());
                }
                let mut register_words = [0u8; 5];
                for (index, register) in regs.iter().enumerate() {
                    if *register > 0x0f {
                        return Err("35c invoke registers must fit in four bits".to_string());
                    }
                    register_words[index] = *register;
                }
                Ok(vec![
                    u16::from_le_bytes([opcode, u4(count) << 4 | register_words[4]]),
                    method,
                    register_words[0] as u16
                        | ((register_words[1] as u16) << 4)
                        | ((register_words[2] as u16) << 8)
                        | ((register_words[3] as u16) << 12),
                ])
            };

        let result = match self {
            Nop => one(0x00, 0),
            MoveException(reg) => one(0x0d, *reg),
            MonitorEnter(reg) => one(0x1d, *reg),
            MonitorExit(reg) => one(0x1e, *reg),

            Move(dst, src) => fmt12(0x01, dst, src),
            MoveFrom16(dst, src) => fmt22(0x02, *dst, *src),
            Move16(dst, src) => vec![0x0003, *dst, *src],
            MoveWide(dst, src) => fmt12(0x04, dst, src),
            MoveWideFrom16(dst, src) => fmt22(0x05, *dst, *src),
            MoveWide16(dst, src) => vec![0x0006, *dst, *src],
            MoveObject(dst, src) => fmt12(0x07, dst, src),
            MoveObjectFrom16(dst, src) => fmt22(0x08, *dst, *src),
            MoveObject16(dst, src) => vec![0x0009, *dst, *src],

            MoveResult(dst) => one(0x0a, *dst),
            MoveResultWide(dst) => one(0x0b, *dst),
            MoveResultObject(dst) => one(0x0c, *dst),
            ReturnVoid => one(0x0e, 0),
            Return(dst) => one(0x0f, *dst),
            Throw(dst) => one(0x27, *dst),

            ConstLit4(dst, value) => {
                let literal = (i4(value) as u8) & 0x0f;
                one(0x12, u4(dst) | (literal << 4))
            }
            ConstLit16(dst, value) => fmt22s(0x13, *dst, 0, *value),
            ConstLit32(dst, value) => fmt31(0x14, *dst, *value),
            ConstHigh16(dst, value) => vec![u16::from_le_bytes([0x15, *dst]), *value as u16],
            ConstWide(dst, value) => {
                let literal = *value as u64;
                vec![
                    u16::from_le_bytes([0x18, *dst]),
                    literal as u16,
                    (literal >> 16) as u16,
                    (literal >> 32) as u16,
                    (literal >> 48) as u16,
                ]
            }
            ConstWideLit16(dst, value) => vec![
                u16::from_le_bytes([0x16, *dst]),
                *value as u16,
            ],
            ConstWideLit32(dst, value) => vec![
                u16::from_le_bytes([0x17, *dst]),
                *value as u32 as u16,
                (*value as u32 >> 16) as u16,
            ],
            ConstWideHigh16(dst, value) => vec![
                u16::from_le_bytes([0x19, *dst]),
                *value as u16,
            ],
            ConstString(dst, string_idx) => fmt22(0x1a, *dst, *string_idx),
            ConstStringJumbo(dst, string_idx) => {
                vec![
                    u16::from_le_bytes([0x1b, *dst]),
                    *string_idx as u16,
                    (*string_idx >> 16) as u16,
                ]
            }
            ConstClass(dst, type_idx) => fmt22(0x1c, *dst, *type_idx),
            CheckCast(dst, type_idx) => fmt22(0x1f, *dst, *type_idx),
            InstanceOf(dst, object, type_idx) => fmt22c(0x20, dst, object, *type_idx),

            Goto8(offset) => one(0x28, *offset as u8),
            Goto16(offset) => vec![0x0029, *offset as u16],
            Goto32(offset) => vec![0x002a, *offset as u32 as u16, (*offset as u32 >> 16) as u16],
            Test(function, a, b, offset) => {
                one(0x32 + test_function_code(function), u4(a) | (u4(b) << 4))
                    .into_iter()
                    .chain(std::iter::once(*offset as u16))
                    .collect()
            }
            TestZero(function, a, offset) => vec![
                u16::from_le_bytes([0x38 + test_function_code(function), *a]),
                *offset as u16,
            ],

            CmplFloat(dst, a, b) => fmt23(0x2d, *dst, *a, *b),
            CmpgFloat(dst, a, b) => fmt23(0x2e, *dst, *a, *b),
            CmplDouble(dst, a, b) => fmt23(0x2f, *dst, *a, *b),
            CmpgDouble(dst, a, b) => fmt23(0x30, *dst, *a, *b),
            CmpLong(dst, a, b) => fmt23(0x31, *dst, *a, *b),

            ArrayGetWide(dst, array, index) => fmt23(0x44, *dst, *array, *index),
            ArrayGetObject(dst, array, index) => fmt23(0x45, *dst, *array, *index),
            ArrayGetBoolean(dst, array, index) => fmt23(0x46, *dst, *array, *index),
            ArrayGetByte(dst, array, index) => fmt23(0x47, *dst, *array, *index),
            ArrayGetChar(dst, array, index) => fmt23(0x48, *dst, *array, *index),
            ArrayGetShort(dst, array, index) => fmt23(0x49, *dst, *array, *index),
            ArrayPutWide(src, array, index) => fmt23(0x4a, *src, *array, *index),
            ArrayPutObject(src, array, index) => fmt23(0x4b, *src, *array, *index),
            ArrayPutBoolean(src, array, index) => fmt23(0x4c, *src, *array, *index),
            ArrayPutByte(src, array, index) => fmt23(0x4d, *src, *array, *index),
            ArrayPutChar(src, array, index) => fmt23(0x4e, *src, *array, *index),
            ArrayPutShort(src, array, index) => fmt23(0x4f, *src, *array, *index),
            ArrayLength(dst, array) => fmt12(0x21, dst, array),

            XorInt(dst, src) => fmt12(0xb7, dst, src),
            XorLong(dst, src) => fmt12(0xc2, dst, src),
            XorIntDst(dst, a, b) => fmt23(0x97, *dst, *a, *b),
            XorLongDst(dst, a, b) => fmt23(0xa2, *dst, *a, *b),
            XorIntDstLit8(dst, src, value) => fmt22s(0xdf, *dst, *src, *value as i16),
            XorIntDstLit16(dst, src, value) => fmt22s4(0xd7, dst, src, *value as i16),
            RemInt(dst, src) => fmt12(0xb4, dst, src),
            RemLong(dst, src) => fmt12(0xbf, dst, src),
            RemIntDst(dst, a, b) => fmt23(0x94, *dst, *a, *b),
            RemLongDst(dst, a, b) => fmt23(0x9f, *dst, *a, *b),
            RemIntLit8(dst, src, value) => fmt22s(0xdc, *dst, *src, *value as i16),
            RemIntLit16(dst, src, value) => fmt22s4(0xd4, dst, src, *value as i16),
            AddInt(dst, src) => fmt12(0xb0, dst, src),
            AddIntDst(dst, a, b) => fmt23(0x90, *dst, *a, *b),
            AddIntLit8(dst, src, value) => fmt22s(0xd8, *dst, *src, *value as i16),
            AddIntLit16(dst, src, value) => fmt22s4(0xd0, dst, src, *value as i16),
            SubInt(dst, src) => fmt12(0xb1, dst, src),
            SubIntDst(dst, a, b) => fmt23(0x91, *dst, *a, *b),
            SubIntLit8(dst, src, value) => fmt22s(0xd9, *dst, *src, *value as i16),
            SubIntLit16(dst, src, value) => fmt22s4(0xd1, dst, src, *value as i16),
            MulInt(dst, src) => fmt12(0xb2, dst, src),
            MulIntDst(dst, a, b) => fmt23(0x92, *dst, *a, *b),
            MulIntLit8(dst, src, value) => fmt22s(0xda, *dst, *src, *value as i16),
            MulIntLit16(dst, src, value) => fmt22s4(0xd2, dst, src, *value as i16),
            DivInt(dst, src) => fmt12(0xb3, dst, src),
            DivIntDst(dst, a, b) => fmt23(0x93, *dst, *a, *b),
            DivIntLit8(dst, src, value) => fmt22s(0xdb, *dst, *src, *value as i16),
            DivIntLit16(dst, src, value) => fmt22s4(0xd3, dst, src, *value as i16),
            AndInt(dst, src) => fmt12(0xb5, dst, src),
            AndLong(dst, src) => fmt12(0xc0, dst, src),
            AndIntDst(dst, a, b) => fmt23(0x95, *dst, *a, *b),
            AndLongDst(dst, a, b) => fmt23(0xa0, *dst, *a, *b),
            AndIntLit8(dst, src, value) => fmt22s(0xdd, *dst, *src, *value as i16),
            AndIntLit16(dst, src, value) => fmt22s4(0xd5, dst, src, *value as i16),
            OrInt(dst, src) => fmt12(0xb6, dst, src),
            OrLong(dst, src) => fmt12(0xc1, dst, src),
            OrIntDst(dst, a, b) => fmt23(0x96, *dst, *a, *b),
            OrLongDst(dst, a, b) => fmt23(0xa1, *dst, *a, *b),
            OrIntLit8(dst, src, value) => fmt22s(0xde, *dst, *src, *value as i16),
            OrIntLit16(dst, src, value) => fmt22s4(0xd6, dst, src, *value as i16),

ShlInt(dst, src) => fmt12(0xb8, dst, src),
            ShrInt(dst, src) => fmt12(0xb9, dst, src),
            UShrInt(dst, src) => fmt12(0xba, dst, src),
            ShlIntDst(dst, a, b) => fmt23(0x98, *dst, *a, *b),
            ShrIntDst(dst, a, b) => fmt23(0x99, *dst, *a, *b),
            UShrIntDst(dst, a, b) => fmt23(0x9a, *dst, *a, *b),
            ShlIntLit8(dst, src, value) => fmt22s(0xe0, *dst, *src, *value as i16),
            ShrIntLit8(dst, src, value) => fmt22s(0xe1, *dst, *src, *value as i16),
            UShrIntLit8(dst, src, value) => fmt22s(0xe2, *dst, *src, *value as i16),

            ShlLong(dst, src) => fmt12(0xc3, dst, src),
            ShrLong(dst, src) => fmt12(0xc4, dst, src),
            UShrLong(dst, src) => fmt12(0xc5, dst, src),
            ShlLongDst(dst, a, b) => fmt23(0xa3, *dst, *a, *b),
            ShrLongDst(dst, a, b) => fmt23(0xa4, *dst, *a, *b),
            UShrLongDst(dst, a, b) => fmt23(0xa5, *dst, *a, *b),

            NegInt(dst, src) => fmt12(0x7b, dst, src),
            NotInt(dst, src) => fmt12(0x7c, dst, src),
            NegLong(dst, src) => fmt12(0x7d, dst, src),
            NegFloat(dst, src) => fmt12(0x7f, dst, src),
            NegDouble(dst, src) => fmt12(0x80, dst, src),

            IntToLong(dst, src) => fmt12(0x81, dst, src),
            IntToFloat(dst, src) => fmt12(0x82, dst, src),
            IntToDouble(dst, src) => fmt12(0x83, dst, src),
            IntToByte(dst, src) => fmt12(0x84, dst, src),
            IntToChar(dst, src) => fmt12(0x85, dst, src),
            IntToShort(dst, src) => fmt12(0x86, dst, src),
            LongToInt(dst, src) => fmt12(0x87, dst, src),
            LongToFloat(dst, src) => fmt12(0x88, dst, src),
            LongToDouble(dst, src) => fmt12(0x89, dst, src),
            FloatToInt(dst, src) => fmt12(0x8a, dst, src),
            FloatToLong(dst, src) => fmt12(0x8b, dst, src),
            FloatToDouble(dst, src) => fmt12(0x8c, dst, src),
            DoubleToInt(dst, src) => fmt12(0x8d, dst, src),
            DoubleToLong(dst, src) => fmt12(0x8e, dst, src),
            DoubleToFloat(dst, src) => fmt12(0x8f, dst, src),

            AddFloat(dst, src) => fmt12(0xc6, dst, src),
            AddFloatDst(dst, a, b) => fmt23(0xa6, *dst, *a, *b),
            SubFloat(dst, src) => fmt12(0xc7, dst, src),
            SubFloatDst(dst, a, b) => fmt23(0xa7, *dst, *a, *b),
            MulFloat(dst, src) => fmt12(0xc8, dst, src),
            MulFloatDst(dst, a, b) => fmt23(0xa8, *dst, *a, *b),
            DivFloat(dst, src) => fmt12(0xc9, dst, src),
            DivFloatDst(dst, a, b) => fmt23(0xa9, *dst, *a, *b),
            RemFloat(dst, src) => fmt12(0xca, dst, src),
            RemFloatDst(dst, a, b) => fmt23(0xaa, *dst, *a, *b),

            AddDouble(dst, src) => fmt12(0xcb, dst, src),
            AddDoubleDst(dst, a, b) => fmt23(0xab, *dst, *a, *b),
            SubDouble(dst, src) => fmt12(0xcc, dst, src),
            SubDoubleDst(dst, a, b) => fmt23(0xac, *dst, *a, *b),
            MulDouble(dst, src) => fmt12(0xcd, dst, src),
            MulDoubleDst(dst, a, b) => fmt23(0xad, *dst, *a, *b),
            DivDouble(dst, src) => fmt12(0xce, dst, src),
            DivDoubleDst(dst, a, b) => fmt23(0xae, *dst, *a, *b),
            RemDouble(dst, src) => fmt12(0xcf, dst, src),
            RemDoubleDst(dst, a, b) => fmt23(0xaf, *dst, *a, *b),

            AddLong(dst, src) => fmt12(0xbb, dst, src),
            AddLongDst(dst, a, b) => fmt23(0x9b, *dst, *a, *b),
            SubLong(dst, src) => fmt12(0xbc, dst, src),
            SubLongDst(dst, a, b) => fmt23(0x9c, *dst, *a, *b),
            MulLong(dst, src) => fmt12(0xbd, dst, src),
            MulLongDst(dst, a, b) => fmt23(0x9d, *dst, *a, *b),
            DivLong(dst, src) => fmt12(0xbe, dst, src),
            DivLongDst(dst, a, b) => fmt23(0x9e, *dst, *a, *b),

            NewInstance(dst, type_idx) => fmt22(0x22, *dst, *type_idx),
            NewArray(dst, size, type_idx) => one(0x23, u4(dst) | (u4(size) << 4))
                .into_iter()
                .chain(std::iter::once(*type_idx))
                .collect(),
            FilledNewArray(count, type_idx, regs) => fmt35(0x24, count, *type_idx, regs)?,
            FilledNewArrayRange(first, type_idx, count) => {
                vec![u16::from_le_bytes([0x25, *first]), *type_idx, *count]
            }
            FillArrayData(array, offset) => vec![
                u16::from_le_bytes([0x26, *array]),
                *offset as u16,
                (*offset >> 16) as u16,
            ],

            InvokeVirtual(count, method, regs) => fmt35(0x6e, count, *method, regs)?,
            InvokeSuper(count, method, regs) => fmt35(0x6f, count, *method, regs)?,
            InvokeDirect(count, method, regs) => fmt35(0x70, count, *method, regs)?,
            InvokeStatic(count, method, regs) => fmt35(0x71, count, *method, regs)?,
            InvokeInterface(count, method, regs) => fmt35(0x72, count, *method, regs)?,
            InvokeVirtualRange(count, method, first) => {
                vec![u16::from_le_bytes([0x74, *count]), *method, *first]
            }
            InvokeSuperRange(count, method, first) => {
                vec![u16::from_le_bytes([0x75, *count]), *method, *first]
            }
            InvokeDirectRange(count, method, first) => {
                vec![u16::from_le_bytes([0x76, *count]), *method, *first]
            }
            InvokeStaticRange(count, method, first) => {
                vec![u16::from_le_bytes([0x77, *count]), *method, *first]
            }
            InvokeInterfaceRange(count, method, first) => {
                vec![u16::from_le_bytes([0x78, *count]), *method, *first]
            }
            Invoke(method) => vec![u16::from_le_bytes([0xfa, 0]), *method],
            InvokeCustom(count, method, regs) => fmt35(0xf9, count, *method, regs)?,

            InstanceGet(dst, object, field) => fmt22c(0x52, dst, object, *field),
            InstanceGetWide(dst, object, field) => fmt22c(0x53, dst, object, *field),
            InstanceGetObject(dst, object, field) => fmt22c(0x54, dst, object, *field),
            InstanceGetBoolean(dst, object, field) => fmt22c(0x55, dst, object, *field),
            InstanceGetByte(dst, object, field) => fmt22c(0x56, dst, object, *field),
            InstanceGetChar(dst, object, field) => fmt22c(0x57, dst, object, *field),
            InstanceGetShort(dst, object, field) => fmt22c(0x58, dst, object, *field),
            InstancePut(src, object, field) => fmt22c(0x59, src, object, *field),
            InstancePutWide(src, object, field) => fmt22c(0x5a, src, object, *field),
            InstancePutObject(src, object, field) => fmt22c(0x5b, src, object, *field),
            InstancePutBoolean(src, object, field) => fmt22c(0x5c, src, object, *field),
            InstancePutByte(src, object, field) => fmt22c(0x5d, src, object, *field),
            InstancePutChar(src, object, field) => fmt22c(0x5e, src, object, *field),
            InstancePutShort(src, object, field) => fmt22c(0x5f, src, object, *field),
            StaticGet(dst, field) => fmt22(0x60, *dst, *field),
            StaticGetWide(dst, field) => fmt22(0x61, *dst, *field),
            StaticGetObject(dst, field) => fmt22(0x62, *dst, *field),
            StaticGetBoolean(dst, field) => fmt22(0x63, *dst, *field),
            StaticGetByte(dst, field) => fmt22(0x64, *dst, *field),
            StaticGetChar(dst, field) => fmt22(0x65, *dst, *field),
            StaticGetShort(dst, field) => fmt22(0x66, *dst, *field),
            StaticPut(src, field) => fmt22(0x67, *src, *field),
            StaticPutWide(src, field) => fmt22(0x68, *src, *field),
            StaticPutObject(src, field) => fmt22(0x69, *src, *field),
            StaticPutBoolean(src, field) => fmt22(0x6a, *src, *field),
            StaticPutByte(src, field) => fmt22(0x6b, *src, *field),
            StaticPutChar(src, field) => fmt22(0x6c, *src, *field),
            StaticPutShort(src, field) => fmt22(0x6d, *src, *field),

            PackedSwitch(register, offset) => vec![
                u16::from_le_bytes([0x2b, *register]),
                *offset as u32 as u16,
                (*offset as u32 >> 16) as u16,
            ],
            SparseSwitch(register, offset) => vec![
                u16::from_le_bytes([0x2c, *register]),
                *offset as u32 as u16,
                (*offset as u32 >> 16) as u16,
            ],
            ConstMethodHandle(dst, idx) => fmt22(0xfc, *dst, *idx),
            ConstMethodType(dst, idx) => fmt22(0xfd, *dst, *idx),
            ConstDynamic(dst, idx, extra) => vec![
                u16::from_le_bytes([0xfe, *dst]),
                *idx,
                *extra as u16,
            ],

            NotImpl(opcode, high) => one(*opcode, *high),
            ArrayData(width, data) => {
                if *width == 0 || data.len() % *width as usize != 0 {
                    return Err(
                        "array-data requires a non-zero width and complete elements".to_string()
                    );
                }
                let element_count = data.len() / *width as usize;
                let mut result = vec![
                    u16::from_le_bytes([0x00, 0x03]),
                    *width,
                    element_count as u16,
                    (element_count >> 16) as u16,
                ];
                for bytes in data.chunks(2) {
                    result.push(u16::from_le_bytes([bytes[0], *bytes.get(1).unwrap_or(&0)]));
                }
                result
            }
            PackedSwitchData(switch) => {
                let entries = switch.targets.len() as u32;
                let first_key = switch
                    .targets
                    .keys()
                    .min()
                    .copied()
                    .unwrap_or(0);
                let mut result = vec![
                    u16::from_le_bytes([0x00, 0x01]),
                    entries as u16,
                    (entries >> 16) as u16,
                    first_key as u32 as u16,
                    (first_key as u32 >> 16) as u16,
                ];
                for i in 0..entries {
                    let key = first_key + i as i32;
                    let target = switch.targets.get(&key).copied().unwrap_or(0);
                    result.push(target as u32 as u16);
                    result.push((target as u32 >> 16) as u16);
                }
                result
            }
            SparseSwitchData(switch) => {
                let entries = switch.targets.len() as u32;
                let mut sorted: Vec<(i32, i32)> = switch
                    .targets
                    .iter()
                    .map(|(&k, &v)| (k, v))
                    .collect();
                sorted.sort_by_key(|&(k, _)| k);
                let mut result = vec![
                    u16::from_le_bytes([0x00, 0x02]),
                    entries as u16,
                    (entries >> 16) as u16,
                ];
                for &(key, _) in &sorted {
                    result.push(key as u32 as u16);
                    result.push((key as u32 >> 16) as u16);
                }
                for &(_, target) in &sorted {
                    result.push(target as u32 as u16);
                    result.push((target as u32 >> 16) as u16);
                }
                result
            }
            InvokeType(_)
            | Const
            | NewInstanceType(_)
            | Switch(_)
            | SwitchData(_)
            | ArbitraryData(_) => {
                return Err("instruction is a decoder placeholder and cannot be encoded".to_string())
            }
        };
        Ok(result)
    }

    pub fn mnemonic_from_opcode(&self) -> &'static str {
        match self {
            Instruction::ConstString(..) => MNEMONICS[1],
            Instruction::ConstStringJumbo(..) => MNEMONICS[2],

            Instruction::NewArray(..) => MNEMONICS[3],
            Instruction::FilledNewArray(..) => MNEMONICS[4],
            Instruction::FillArrayData(..) => MNEMONICS[5],
            Instruction::ArrayData(..) => MNEMONICS[6],

            Instruction::Goto8(_) => MNEMONICS[7],
            Instruction::Goto16(_) => MNEMONICS[8],
            Instruction::Goto32(_) => MNEMONICS[9],

            Instruction::ArrayGetByte(..) => MNEMONICS[10],
            Instruction::ArrayPutByte(..) => MNEMONICS[11],
            Instruction::ArrayGetChar(..) => MNEMONICS[32],
            Instruction::ArrayPutChar(..) => MNEMONICS[33],
            Instruction::StaticPutObject(..) => MNEMONICS[12],
            Instruction::StaticGetObject(..) => MNEMONICS[13],

            Instruction::XorIntDst(..) => MNEMONICS[14],
            Instruction::RemIntDst(..) => MNEMONICS[15],
            Instruction::AndIntDst(..) => MNEMONICS[16],
            Instruction::OrIntDst(..) => MNEMONICS[17],

            Instruction::XorInt(..) => MNEMONICS[18],
            Instruction::RemInt(..) => MNEMONICS[19],
            Instruction::AndInt(..) => MNEMONICS[20],
            Instruction::OrInt(..) => MNEMONICS[21],

            Instruction::XorIntDstLit16(..) => MNEMONICS[22],
            Instruction::RemIntLit16(..) => MNEMONICS[23],
            Instruction::AndIntLit16(..) => MNEMONICS[24],
            Instruction::OrIntLit16(..) => MNEMONICS[25],

            Instruction::XorIntDstLit8(..) => MNEMONICS[26],
            Instruction::RemIntLit8(..) => MNEMONICS[27],
            Instruction::AndIntLit8(..) => MNEMONICS[28],
            Instruction::OrIntLit8(..) => MNEMONICS[29],

            Instruction::ReturnVoid => MNEMONICS[30],
            Instruction::Return(..) => MNEMONICS[31],
            Instruction::AddIntLit8(..) => MNEMONICS[66],
            Instruction::AddIntLit16(..) => MNEMONICS[67],
            Instruction::SubIntLit8(..) => MNEMONICS[68],
            Instruction::SubIntLit16(..) => MNEMONICS[69],
            Instruction::AddInt(..) => MNEMONICS[70],
            Instruction::AddIntDst(..) => MNEMONICS[71],
            Instruction::SubInt(..) => MNEMONICS[72],
            Instruction::SubIntDst(..) => MNEMONICS[73],
            Instruction::IntToByte(..) => MNEMONICS[74],
            Instruction::MoveResult(..) => MNEMONICS[75],
            Instruction::CheckCast(..) => MNEMONICS[76],
            Instruction::Throw(..) => MNEMONICS[77],
            Instruction::ShrIntLit8(..) => MNEMONICS[80],
            Instruction::UShrIntLit8(..) => MNEMONICS[81],
            Instruction::ConstWide(..) => "const-wide",
            Instruction::ConstHigh16(..) => "const/high16",
            _ => MNEMONICS[0],
        }
    }

    pub fn disassembly_from_opcode(
        &self,
        current_pos: i32,
        addr_label: &mut HashMap<i32, String>,
        file: Arc<DexFile>,
    ) -> String {
        match self {
            &Instruction::Throw(reg) => format!("{} v{}", MNEMONICS[77], reg),
            &Instruction::ConstString(reg, string_idx) => format!(
                "{} v{}, \"{}\"",
                MNEMONICS[1],
                reg,
                file.get_string(string_idx)
                    .unwrap_or("INVALID")
                    .replace("\n", "\\n")
                    .replace("\"", "\\\"")
            ),
            &Instruction::ConstStringJumbo(reg, string_idx) => format!(
                "{} v{}, \"{}\"",
                MNEMONICS[2],
                reg,
                file.get_string(string_idx as usize)
                    .unwrap_or("INVALID")
                    .replace("\n", "\\n")
            ),
            &Instruction::CheckCast(reg, type_idx) => format!(
                "{} v{}, {}",
                MNEMONICS[76],
                reg,
                file.get_type_name(type_idx).unwrap_or("INVALID")
            ),

            &Instruction::NewArray(dst, size, type_idx) => format!(
                "{} v{}, v{}, {}",
                MNEMONICS[3],
                dst,
                size,
                file.get_type_name(type_idx).unwrap_or("INVALID")
            ),
            Instruction::FilledNewArray(..) => MNEMONICS[4].to_string(),
            Instruction::FillArrayData(..) => MNEMONICS[5].to_string(),
            Instruction::ArrayData(.., data) => format!("{} {:?}", MNEMONICS[6].to_string(), data),

            &Instruction::Goto8(dst) => {
                let jmp_addr: i32 = current_pos + dst as i32;
                let number_of_labels = addr_label.len();
                let label = addr_label
                    .entry(jmp_addr)
                    .or_insert(format!("label_{}", number_of_labels));
                format!("{} :{}", MNEMONICS[7], label)
            }
            &Instruction::Goto16(dst) => {
                let jmp_addr: i32 = current_pos + dst as i32;
                let number_of_labels = addr_label.len();
                let label = addr_label
                    .entry(jmp_addr)
                    .or_insert(format!("label_{}", number_of_labels));
                format!("{} :{}", MNEMONICS[8], label)
            }
            &Instruction::Goto32(dst) => {
                let jmp_addr: i32 = current_pos + dst as i32;
                let number_of_labels = addr_label.len();
                let label = addr_label
                    .entry(jmp_addr)
                    .or_insert(format!("label_{}", number_of_labels));
                format!("{} :{}", MNEMONICS[9], label)
            }
            Instruction::Test(test_function, a, b, offset) => {
                let jmp_addr: i32 = current_pos + *offset as i32;
                let number_of_labels = addr_label.len();
                let label = addr_label
                    .entry(jmp_addr)
                    .or_insert(format!("cond_{}", number_of_labels));
                match test_function {
                    TestFunction::Equal => format!("{} v{}, v{}, :{}", MNEMONICS[50], a, b, label),
                    TestFunction::NotEqual => {
                        format!("{} v{}, v{}, :{}", MNEMONICS[51], a, b, label)
                    }
                    TestFunction::LessThan => {
                        format!("{} v{}, v{}, :{}", MNEMONICS[52], a, b, label)
                    }
                    TestFunction::LessEqual => {
                        format!("{} v{}, v{}, :{}", MNEMONICS[53], a, b, label)
                    }
                    TestFunction::GreaterThan => {
                        format!("{} v{}, v{}, :{}", MNEMONICS[54], a, b, label)
                    }
                    TestFunction::GreaterEqual => {
                        format!("{} v{}, v{}, :{}", MNEMONICS[55], a, b, label)
                    }
                }
            }
            Instruction::TestZero(test_function, a, offset) => {
                let jmp_addr: i32 = current_pos + *offset as i32;
                let number_of_labels = addr_label.len();
                let label = addr_label
                    .entry(jmp_addr)
                    .or_insert(format!("cond_{}", number_of_labels));
                match test_function {
                    TestFunction::Equal => format!("{} v{}, :{}", MNEMONICS[56], a, label),
                    TestFunction::NotEqual => format!("{} v{}, :{}", MNEMONICS[57], a, label),
                    TestFunction::LessThan => format!("{} v{}, :{}", MNEMONICS[58], a, label),
                    TestFunction::LessEqual => format!("{} v{}, :{}", MNEMONICS[59], a, label),
                    TestFunction::GreaterThan => format!("{} v{}, :{}", MNEMONICS[60], a, label),
                    TestFunction::GreaterEqual => format!("{} v{}, :{}", MNEMONICS[61], a, label),
                }
            }

            Instruction::ArrayGetByte(src, arr, index) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[10], src, arr, index)
            }
            Instruction::ArrayPutByte(src, arr, index) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[11], src, arr, index)
            }
            Instruction::ArrayGetChar(src, arr, index) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[32], src, arr, index)
            }
            Instruction::ArrayPutChar(src, arr, index) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[33], src, arr, index)
            }

            Instruction::XorIntDst(dst, a, b) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[14], dst, a, b)
            }
            Instruction::RemIntDst(dst, a, b) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[15], dst, a, b)
            }
            Instruction::AndIntDst(dst, a, b) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[16], dst, a, b)
            }
            Instruction::OrIntDst(dst, a, b) => {
                format!("{} v{}, v{}, v{}", MNEMONICS[17], dst, a, b)
            }

            Instruction::XorInt(a, b) => format!("{} v{}, v{}", MNEMONICS[18], a, b),
            Instruction::RemInt(a, b) => format!("{} v{}, v{}", MNEMONICS[19], a, b),
            Instruction::AndInt(a, b) => format!("{} v{}, v{}", MNEMONICS[20], a, b),
            Instruction::OrInt(a, b) => format!("{} v{}, v{}", MNEMONICS[21], a, b),

            Instruction::XorIntDstLit16(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[22], dst, src, constant)
            }
            Instruction::RemIntLit16(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[23], dst, src, constant)
            }
            Instruction::AndIntLit16(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[24], dst, src, constant)
            }
            Instruction::OrIntLit16(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[25], dst, src, constant)
            }

            Instruction::XorIntDstLit8(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[26], dst, src, constant)
            }
            Instruction::RemIntLit8(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[27], dst, src, constant)
            }
            Instruction::AndIntLit8(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[28], dst, src, constant)
            }
            Instruction::OrIntLit8(dst, src, constant) => {
                format!("{} v{}, v{}, {:#x}", MNEMONICS[29], dst, src, constant)
            }

            Instruction::ReturnVoid => MNEMONICS[30].to_string(),
            Instruction::Return(obj) => format!("{} v{}", MNEMONICS[31], obj),

            Instruction::InvokeStatic(_, method_idx, arg_regs) => {
                if let Some(method) = file.methods.get(*method_idx as usize) {
                    if let Some(proto) = file.protos.get(method.proto_idx as usize) {
                        let return_type = file
                            .get_type_name(proto.return_type_idx as usize)
                            // .and_then(|t| t.split("/").last())
                            // .and_then(|t| Some(t.replace(";", "")))
                            .unwrap_or("INVALID")
                            .to_string();
                        let args = proto
                            .arguments
                            .iter()
                            .map(|&arg| {
                                file.get_type_name(arg)
                                    // .and_then(|t| t.split("/").last())
                                    // .and_then(|t| Some(t.replace(";", "")))
                                    .unwrap_or("INVALID")
                                    .to_string()
                            })
                            .collect::<Vec<_>>()
                            .join("");
                        format!(
                            "{} {{{}}}, {}->{}({}){}",
                            MNEMONICS[34],
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", "),
                            file.get_type_name(method.class_idx).unwrap_or("INVALID"),
                            method.method_name,
                            args,
                            return_type,
                        )
                    } else {
                        format!(
                            "{} {{{}}} @{}",
                            MNEMONICS[34],
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", "),
                            method_idx,
                        )
                    }
                } else {
                    format!(
                        "{} {{{}}} @{}",
                        MNEMONICS[32],
                        arg_regs
                            .iter()
                            .map(|a| format!("v{}", a))
                            .collect::<Vec<_>>()
                            .join(", "),
                        method_idx,
                    )
                }
            }
            Instruction::InvokeDirect(_, method_idx, arg_regs) => {
                if let Some(method) = file.methods.get(*method_idx as usize) {
                    if let Some(proto) = file.protos.get(method.proto_idx as usize) {
                        let return_type = file
                            .get_type_name(proto.return_type_idx as usize)
                            // .and_then(|t| t.split("/").last())
                            // .and_then(|t| Some(t.replace(";", "")))
                            .unwrap_or("INVALID")
                            .to_string();
                        let args = proto
                            .arguments
                            .iter()
                            .map(|&arg| {
                                file.get_type_name(arg)
                                    // .and_then(|t| t.split("/").last())
                                    // .and_then(|t| Some(t.replace(";", "")))
                                    .unwrap_or("INVALID")
                                    .to_string()
                            })
                            .collect::<Vec<_>>()
                            .join("");
                        format!(
                            "{} {{{}}}, {}->{}({}){}",
                            MNEMONICS[35],
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(","),
                            file.get_type_name(method.class_idx).unwrap_or("INVALID"),
                            method.method_name,
                            args,
                            return_type,
                        )
                    } else {
                        format!(
                            "{} @{}, {}",
                            MNEMONICS[35],
                            method_idx,
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                } else {
                    format!(
                        "{} @{}, {}",
                        MNEMONICS[35],
                        method_idx,
                        arg_regs
                            .iter()
                            .map(|a| format!("v{}", a))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            Instruction::InvokeInterface(_, method_idx, arg_regs) => {
                if let Some(method) = file.methods.get(*method_idx as usize) {
                    if let Some(proto) = file.protos.get(method.proto_idx as usize) {
                        let return_type = file
                            .get_type_name(proto.return_type_idx as usize)
                            // .and_then(|t| t.split("/").last())
                            // .and_then(|t| Some(t.replace(";", "")))
                            .unwrap_or("INVALID")
                            .to_string();
                        let args = proto
                            .arguments
                            .iter()
                            .map(|&arg| {
                                file.get_type_name(arg)
                                    // .and_then(|t| t.split("/").last())
                                    // .and_then(|t| Some(t.replace(";", "")))
                                    .unwrap_or("INVALID")
                                    .to_string()
                            })
                            .collect::<Vec<_>>()
                            .join("");
                        format!(
                            "{} {{{}}}, {}->{}({}){}",
                            MNEMONICS[49],
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(","),
                            file.get_type_name(method.class_idx).unwrap_or("INVALID"),
                            method.method_name,
                            args,
                            return_type,
                        )
                    } else {
                        format!(
                            "{} @{}, {}",
                            MNEMONICS[49],
                            method_idx,
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                } else {
                    format!(
                        "{} @{}, {}",
                        MNEMONICS[49],
                        method_idx,
                        arg_regs
                            .iter()
                            .map(|a| format!("v{}", a))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            Instruction::InvokeVirtual(_, method_idx, arg_regs) => {
                if let Some(method) = file.methods.get(*method_idx as usize) {
                    if let Some(proto) = file.protos.get(method.proto_idx as usize) {
                        let return_type = file
                            .get_type_name(proto.return_type_idx as usize)
                            // .and_then(|t| t.split("/").last())
                            // .and_then(|t| Some(t.replace(";", "")))
                            .unwrap_or("INVALID")
                            .to_string();
                        let args = proto
                            .arguments
                            .iter()
                            .map(|&arg| {
                                file.get_type_name(arg)
                                    // .and_then(|t| t.split("/").last())
                                    // .and_then(|t| Some(t.replace(";", "")))
                                    .unwrap_or("INVALID")
                                    .to_string()
                            })
                            .collect::<Vec<_>>()
                            .join("");
                        format!(
                            "{} {{{}}}, {}->{}({}){}",
                            MNEMONICS[36],
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", "),
                            file.get_type_name(method.class_idx).unwrap_or("INVALID"),
                            method.method_name,
                            args,
                            return_type,
                        )
                    } else {
                        format!(
                            "{} @{}, {}",
                            MNEMONICS[36],
                            method_idx,
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                } else {
                    format!(
                        "{} @{}, {}",
                        MNEMONICS[36],
                        method_idx,
                        arg_regs
                            .iter()
                            .map(|a| format!("v{}", a))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            Instruction::InvokeSuper(_, method_idx, arg_regs) => {
                if let Some(method) = file.methods.get(*method_idx as usize) {
                    if let Some(proto) = file.protos.get(method.proto_idx as usize) {
                        let return_type = file
                            .get_type_name(proto.return_type_idx as usize)
                            // .and_then(|t| t.split("/").last())
                            // .and_then(|t| Some(t.replace(";", "")))
                            .unwrap_or("INVALID")
                            .to_string();
                        let args = proto
                            .arguments
                            .iter()
                            .map(|&arg| {
                                file.get_type_name(arg)
                                    // .and_then(|t| t.split("/").last())
                                    // .and_then(|t| Some(t.replace(";", "")))
                                    .unwrap_or("INVALID")
                                    .to_string()
                            })
                            .collect::<Vec<_>>()
                            .join("");
                        format!(
                            "{} {{{}}}, {}->{}({}){}",
                            MNEMONICS[37],
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", "),
                            file.get_type_name(method.class_idx).unwrap_or("INVALID"),
                            method.method_name,
                            args,
                            return_type,
                        )
                    } else {
                        format!(
                            "{} @{}, {}",
                            MNEMONICS[37],
                            method_idx,
                            arg_regs
                                .iter()
                                .map(|a| format!("v{}", a))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                } else {
                    format!(
                        "{} @{}, {}",
                        MNEMONICS[37],
                        method_idx,
                        arg_regs
                            .iter()
                            .map(|a| format!("v{}", a))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            &Instruction::NewInstance(dst, type_idx) => format!(
                "{} v{}, {}",
                MNEMONICS[38],
                dst,
                file.get_type_name(type_idx).unwrap_or("INVALID")
            ),
            &Instruction::InstancePutObject(src, obj, field) => {
                format!(
                    "{} v{}, v{}, {}",
                    MNEMONICS[39],
                    src,
                    obj,
                    file.fields
                        .get(field as usize)
                        .and_then(|f| Some(format!(
                            "{}->{}:{}",
                            file.get_type_name(f.class_idx as usize).unwrap_or(""),
                            f.name,
                            file.get_type_name(f.type_idx as usize).unwrap_or("")
                        )))
                        .unwrap_or("".to_string())
                )
            }
            &Instruction::ConstClass(dst, obj) => {
                format!(
                    "{} v{}, {}",
                    MNEMONICS[79],
                    dst,
                    file.get_type_name(obj).unwrap_or("INVALID")
                )
            }
            &Instruction::InstancePut(src, obj, field)
            | &Instruction::InstancePutBoolean(src, obj, field)
            | &Instruction::InstancePutByte(src, obj, field) => {
                let instruction_type = file
                    .fields
                    .get(field as usize)
                    .and_then(|f| match file.get_type_name(f.type_idx as usize) {
                        Some("I") => Some(""),
                        Some("J") => Some("-wide"),
                        Some("Z") => Some("-boolean"),
                        Some("B") => Some("-byte"),
                        Some("C") => Some("-char"),
                        Some("S") => Some("-short"),
                        _ => None,
                    })
                    .unwrap_or("INVALID");
                format!(
                    "{}{} v{}, v{}, {}",
                    MNEMONICS[62],
                    instruction_type,
                    src,
                    obj,
                    file.fields
                        .get(field as usize)
                        .and_then(|f| Some(format!(
                            "{}->{}:{}",
                            file.get_type_name(f.class_idx as usize).unwrap_or(""),
                            f.name,
                            file.get_type_name(f.type_idx as usize).unwrap_or("")
                        )))
                        .unwrap_or("".to_string())
                )
            }
            &Instruction::InstanceGetObject(src, obj, field) => format!(
                "{} v{}, v{}, {}",
                MNEMONICS[40],
                src,
                obj,
                file.fields
                    .get(field as usize)
                    .and_then(|f| Some(format!(
                        "{}->{}:{}",
                        file.get_type_name(f.class_idx as usize).unwrap_or(""),
                        f.name,
                        file.get_type_name(f.type_idx as usize).unwrap_or("")
                    )))
                    .unwrap_or("".to_string())
            ),
            &Instruction::InstanceGet(src, obj, field)
            | &Instruction::InstanceGetBoolean(src, obj, field) => {
                let instruction_type = file
                    .fields
                    .get(field as usize)
                    .and_then(|f| match file.get_type_name(f.type_idx as usize) {
                        Some("I") => Some(""),
                        Some("J") => Some("-wide"),
                        Some("Z") => Some("-boolean"),
                        Some("B") => Some("-byte"),
                        Some("C") => Some("-char"),
                        Some("S") => Some("-short"),
                        _ => None,
                    })
                    .unwrap_or("INVALID");
                format!(
                    "{}{} v{}, v{}, {}",
                    MNEMONICS[63],
                    instruction_type,
                    src,
                    obj,
                    file.fields
                        .get(field as usize)
                        .and_then(|f| Some(format!(
                            "{}->{}:{}",
                            file.get_type_name(f.class_idx as usize).unwrap_or(""),
                            f.name,
                            file.get_type_name(f.type_idx as usize).unwrap_or("")
                        )))
                        .unwrap_or("".to_string())
                )
            }
            &Instruction::StaticGetObject(src, field) => format!(
                "{} v{}, {}",
                MNEMONICS[13],
                src,
                file.fields
                    .get(field as usize)
                    .and_then(|f| Some(format!(
                        "{}->{}:{}",
                        file.get_type_name(f.class_idx as usize).unwrap_or(""),
                        f.name,
                        file.get_type_name(f.type_idx as usize).unwrap_or("")
                    )))
                    .unwrap_or("".to_string())
            ),
            &Instruction::StaticGet(src, field) => {
                let instruction_type = file
                    .fields
                    .get(field as usize)
                    .and_then(|f| match file.get_type_name(f.type_idx as usize) {
                        Some("I") => Some(""),
                        Some("J") => Some("-wide"),
                        Some("Z") => Some("-boolean"),
                        Some("B") => Some("-byte"),
                        Some("C") => Some("-char"),
                        Some("S") => Some("-short"),
                        _ => None,
                    })
                    .unwrap_or("INVALID");
                format!(
                    "{}{} v{}, {}",
                    MNEMONICS[64],
                    instruction_type,
                    src,
                    file.fields
                        .get(field as usize)
                        .and_then(|f| Some(format!(
                            "{}->{}:{}",
                            file.get_type_name(f.class_idx as usize).unwrap_or(""),
                            f.name,
                            file.get_type_name(f.type_idx as usize).unwrap_or("")
                        )))
                        .unwrap_or("".to_string())
                )
            }
            &Instruction::StaticPutObject(src, field) => format!(
                "{} v{}, {}",
                MNEMONICS[12],
                src,
                file.fields
                    .get(field as usize)
                    .and_then(|f| Some(format!(
                        "{}->{}:{}",
                        file.get_type_name(f.class_idx as usize).unwrap_or(""),
                        f.name,
                        file.get_type_name(f.type_idx as usize).unwrap_or("")
                    )))
                    .unwrap_or("".to_string())
            ),
            &Instruction::StaticPut(src, field) => {
                let instruction_type = file
                    .fields
                    .get(field as usize)
                    .and_then(|f| match file.get_type_name(f.type_idx as usize) {
                        Some("I") => Some(""),
                        Some("J") => Some("-wide"),
                        Some("Z") => Some("-boolean"),
                        Some("B") => Some("-byte"),
                        Some("C") => Some("-char"),
                        Some("S") => Some("-short"),
                        _ => None,
                    })
                    .unwrap_or("INVALID");
                format!(
                    "{}{} v{}, {}",
                    MNEMONICS[65],
                    instruction_type,
                    src,
                    file.fields
                        .get(field as usize)
                        .and_then(|f| Some(format!(
                            "{}->{}:{}",
                            file.get_type_name(f.class_idx as usize).unwrap_or(""),
                            f.name,
                            file.get_type_name(f.type_idx as usize).unwrap_or("")
                        )))
                        .unwrap_or("".to_string())
                )
            }
            Instruction::MoveObject(dst, src) => format!("{} v{}, v{}", MNEMONICS[43], dst, src),
            Instruction::Move(dst, src) => format!("{} v{}, v{}", MNEMONICS[78], dst, src),
            Instruction::ConstLit4(dst, lit) => format!("{} v{}, {:#x}", MNEMONICS[44], dst, lit),
            Instruction::ConstLit16(dst, lit) => format!("{} v{}, {:#x}", MNEMONICS[45], dst, lit),
            Instruction::ConstLit32(dst, lit) => format!("{} v{}, {:#x}", MNEMONICS[46], dst, lit),
            Instruction::ConstHigh16(dst, lit) => format!("{} v{}, {:#x}", "const/high16", dst, (i32::from(*lit) << 16)),
            Instruction::ConstWide(dst, lit) => format!("{} v{}, {:#x}", "const-wide", dst, lit),
            Instruction::MoveResultObject(dst) => format!("{} v{}", MNEMONICS[47], dst),
            Instruction::ArrayLength(dst, array) => {
                format!("{} v{}, v{}", MNEMONICS[48], dst, array)
            }
            Instruction::AddIntLit8(dst, src, lit)
            | Instruction::SubIntLit8(dst, src, lit)
            | Instruction::ShrIntLit8(dst, src, lit)
            | Instruction::UShrIntLit8(dst, src, lit) => {
                format!(
                    "{} v{}, v{}, {:#x}",
                    self.mnemonic_from_opcode(),
                    dst,
                    src,
                    lit
                )
            }
            Instruction::SubIntLit16(dst, src, lit) | Instruction::AddIntLit16(dst, src, lit) => {
                format!(
                    "{} v{}, v{}, {:#x}",
                    self.mnemonic_from_opcode(),
                    dst,
                    src,
                    lit
                )
            }
            Instruction::AddInt(dst_src_a, src_b) | Instruction::SubInt(dst_src_a, src_b) => {
                format!("{} v{}, v{}", self.mnemonic_from_opcode(), dst_src_a, src_b)
            }
            Instruction::AddIntDst(dst, src_a, src_b)
            | Instruction::SubIntDst(dst, src_a, src_b) => format!(
                "{} v{}, v{}, v{}",
                self.mnemonic_from_opcode(),
                dst,
                src_a,
                src_b
            ),

            Instruction::IntToByte(dst, src) => {
                format!("{} v{}, v{}", self.mnemonic_from_opcode(), dst, src)
            }
            Instruction::MoveResult(dst) => format!("{} v{}", self.mnemonic_from_opcode(), dst),
            _ => format!("#[RAW] {:?}", self),
        }
    }
    pub fn get_opcode(op: u16, data: &[u16]) -> Instruction {
        let low = op.to_be_bytes();
        let high = low[0];
        match low[1] {
            0 => Instruction::Nop,
            1 => Instruction::Move(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x2 => Instruction::MoveFrom16(high, data[0]),
            0x3 => Instruction::Move16(data[0], data[1]),
            0x4 => Instruction::MoveWide(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x5 => Instruction::MoveWideFrom16(high, data[0]),
            0x6 => Instruction::MoveWide16(data[0], data[1]),
            0x7 => Instruction::MoveObject(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x8 => Instruction::MoveObjectFrom16(high, data[0]),
            0x9 => Instruction::MoveObject16(data[0], data[1]),

            0x0a => Instruction::MoveResult(high),
            0x0b => Instruction::MoveResultWide(high),
            0xc => Instruction::MoveResultObject(high),
            0xd => Instruction::MoveException(high),

            0x1d => Instruction::MonitorEnter(high),
            0x1e => Instruction::MonitorExit(high),

            0x2b => Instruction::PackedSwitch(
                high,
                i32::from_be_bytes([
                    (data[1] >> 8) as u8,
                    (data[1] & 0xff) as u8,
                    (data[0] >> 8) as u8,
                    (data[0] & 0xff) as u8,
                ]),
            ),
            0x2c => Instruction::SparseSwitch(
                high,
                i32::from_be_bytes([
                    (data[1] >> 8) as u8,
                    (data[1] & 0xff) as u8,
                    (data[0] >> 8) as u8,
                    (data[0] & 0xff) as u8,
                ]),
            ),
            0x27 => Instruction::Throw(high),

            0x2d => Instruction::CmplFloat(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x2e => Instruction::CmpgFloat(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x2f => Instruction::CmplDouble(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x30 => Instruction::CmpgDouble(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x31 => Instruction::CmpLong(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0xb7 => Instruction::XorInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc2 => Instruction::XorLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x97 => Instruction::XorIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa2 => Instruction::XorLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xdf => Instruction::XorIntDstLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xd7 => {
                Instruction::XorIntDstLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x94 => Instruction::RemIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9f => Instruction::RemLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb4 => Instruction::RemInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbf => Instruction::RemLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd4 => Instruction::RemIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xdc => Instruction::RemIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x90 => Instruction::AddIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9b => Instruction::AddLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xab => Instruction::AddDoubleDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb0 => Instruction::AddInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbb => Instruction::AddLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xcb => Instruction::AddDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd0 => Instruction::AddIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xd8 => Instruction::AddIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x92 => Instruction::MulIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9d => Instruction::MulLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xad => Instruction::MulDoubleDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb2 => Instruction::MulInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbd => Instruction::MulLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xcd => Instruction::MulDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd2 => Instruction::MulIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xda => Instruction::MulIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x93 => Instruction::DivIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9e => Instruction::DivLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xae => Instruction::DivDoubleDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb3 => Instruction::DivInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbe => Instruction::DivLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xce => Instruction::DivDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd3 => Instruction::DivIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xdb => Instruction::DivIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x91 => Instruction::SubIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9c => Instruction::SubLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xac => Instruction::SubDoubleDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb1 => Instruction::SubInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbc => Instruction::SubLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xcc => Instruction::SubDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd1 => Instruction::SubIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xd9 => Instruction::SubIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x95 => Instruction::AndIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa0 => Instruction::AndLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb5 => Instruction::AndInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc0 => Instruction::AndLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd5 => Instruction::AndIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xdd => Instruction::AndIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x96 => Instruction::OrIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa1 => Instruction::OrLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb6 => Instruction::OrInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc1 => Instruction::OrLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd6 => Instruction::OrIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xde => Instruction::OrIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x98 => Instruction::ShlIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x99 => Instruction::ShrIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9a => Instruction::UShrIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa3 => Instruction::ShlLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa4 => Instruction::ShrLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa5 => Instruction::UShrLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb8 => Instruction::ShlInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xb9 => Instruction::ShrInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xba => Instruction::UShrInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc3 => Instruction::ShlLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc4 => Instruction::ShrLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc5 => Instruction::UShrLong(u4::new(high & 0b1111), u4::new(high >> 4)),

            0xe0 => Instruction::ShlIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xe1 => Instruction::ShrIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xe2 => Instruction::UShrIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x32..=0x37 => Instruction::Test(
                (low[1] - 0x32).into(),
                u4::new(high & 0b1111),
                u4::new(high >> 4),
                data[0] as i16,
            ),
            0x38..=0x3d => Instruction::TestZero((low[1] - 0x38).into(), high, data[0] as i16),
            0x28 => Instruction::Goto8(high as i8),
            0x29 => Instruction::Goto16(data[0] as i16),
            0x2a => Instruction::Goto32(((data[1] as i32) << 16) | data[0] as i32),

            0x44 => Instruction::ArrayGetWide(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x45 => Instruction::ArrayGetObject(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x46 => Instruction::ArrayGetBoolean(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x47 => Instruction::ArrayGetByte(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x48 => Instruction::ArrayGetChar(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x49 => Instruction::ArrayGetShort(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x4a => Instruction::ArrayPutWide(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x4b => Instruction::ArrayPutObject(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x4c => Instruction::ArrayPutBoolean(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x4d => Instruction::ArrayPutByte(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x4e => Instruction::ArrayPutChar(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x4f => Instruction::ArrayPutShort(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x7b => Instruction::NegInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x7c => Instruction::NotInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x7d => Instruction::NegLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x7e => Instruction::NegFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x7f => Instruction::NegDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x80 => Instruction::IntToLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x81 => Instruction::IntToFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x82 => Instruction::IntToDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x83 => Instruction::IntToByte(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x84 => Instruction::IntToChar(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x85 => Instruction::IntToShort(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x86 => Instruction::LongToInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x87 => Instruction::LongToFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x88 => Instruction::LongToDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x89 => Instruction::FloatToInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x8a => Instruction::FloatToLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x8b => Instruction::FloatToDouble(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x8c => Instruction::DoubleToInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x8d => Instruction::DoubleToLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x8e => Instruction::DoubleToFloat(u4::new(high & 0b1111), u4::new(high >> 4)),

            0xa6 => Instruction::AddFloatDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa7 => Instruction::SubFloatDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa8 => Instruction::MulFloatDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xa9 => Instruction::DivFloatDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xaa => Instruction::RemFloatDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xaf => Instruction::RemDoubleDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xc6 => Instruction::AddFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc7 => Instruction::SubFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc8 => Instruction::MulFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xc9 => Instruction::DivFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xca => Instruction::RemFloat(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xcf => Instruction::RemDouble(u4::new(high & 0b1111), u4::new(high >> 4)),

            0x6e => {
                let arg_num = u4::new((high & 0b11110000) >> 4);
                let content: Vec<u8> = match (high & 0b11110000) >> 4 {
                    0 => vec![],
                    1 => vec![(data[1] & 0x000f) as u8],
                    2 => vec![(data[1] & 0x000f) as u8, ((data[1] & 0x00f0) >> 4) as u8],
                    3 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                    ],
                    4 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                    ],
                    5 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                        high & 0b1111,
                    ],
                    _ => vec![],
                };
                Instruction::InvokeVirtual(arg_num, data[0], content)
            }
            0x6f => {
                let arg_num = u4::new((high & 0b11110000) >> 4);
                let content: Vec<u8> = match (high & 0b11110000) >> 4 {
                    0 => vec![],
                    1 => vec![(data[1] & 0x000f) as u8],
                    2 => vec![(data[1] & 0x000f) as u8, ((data[1] & 0x00f0) >> 4) as u8],
                    3 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                    ],
                    4 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                    ],
                    5 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                        high & 0b1111,
                    ],
                    _ => vec![],
                };
                Instruction::InvokeSuper(arg_num, data[0], content)
            }
            0x70 => {
                let arg_num = u4::new((high & 0b11110000) >> 4);
                let content: Vec<u8> = match (high & 0b11110000) >> 4 {
                    0 => vec![],
                    1 => vec![(data[1] & 0x000f) as u8],
                    2 => vec![(data[1] & 0x000f) as u8, ((data[1] & 0x00f0) >> 4) as u8],
                    3 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                    ],
                    4 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                    ],
                    5 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                        high & 0b1111,
                    ],
                    _ => vec![],
                };
                Instruction::InvokeDirect(arg_num, data[0], content)
            }
            0x71 => {
                let arg_num = u4::new((high & 0b11110000) >> 4);
                let content: Vec<u8> = match (high & 0b11110000) >> 4 {
                    0 => vec![],
                    1 => vec![(data[1] & 0x000f) as u8],
                    2 => vec![(data[1] & 0x000f) as u8, ((data[1] & 0x00f0) >> 4) as u8],
                    3 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                    ],
                    4 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                    ],
                    5 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                        high & 0b1111,
                    ],
                    _ => vec![],
                };
                Instruction::InvokeStatic(arg_num, data[0], content)
            }
            0x72 => {
                let arg_num = u4::new((high & 0b11110000) >> 4);
                let content: Vec<u8> = match (high & 0b11110000) >> 4 {
                    0 => vec![],
                    1 => vec![(data[1] & 0x000f) as u8],
                    2 => vec![(data[1] & 0x000f) as u8, ((data[1] & 0x00f0) >> 4) as u8],
                    3 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                    ],
                    4 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                    ],
                    5 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                        high & 0b1111,
                    ],
                    _ => vec![],
                };
                Instruction::InvokeInterface(arg_num, data[0], content)
            }
            0x74 => Instruction::InvokeVirtualRange(high, data[0], data[1]),
            0x75 => Instruction::InvokeSuperRange(high, data[0], data[1]),
            0x76 => Instruction::InvokeDirectRange(high, data[0], data[1]),
            0x77 => Instruction::InvokeStaticRange(high, data[0], data[1]),
            0x78 => Instruction::InvokeInterfaceRange(high, data[0], data[1]),

            0xfa..=0xfb => Instruction::Invoke(data[0]),

            0x0e => Instruction::ReturnVoid,
            0x0f..=0x11 => Instruction::Return(high),
            0x12 => Instruction::ConstLit4(
                u4::new(high & 0b1111),
                if (high >> 4) & 0b1000 == 0b1000 {
                    i4::new(0) - i4::new(((high >> 4) & 0b0111) as i8)
                } else {
                    i4::new(((high >> 4) & 0b0111) as i8)
                },
            ),
            0x13 => Instruction::ConstLit16(high, data[0] as i16),
            0x14 => Instruction::ConstLit32(
                high,
                (data[0] as u32 | ((data[1] as u32) << 16)) as i32,
            ),
            0x15 => Instruction::ConstHigh16(high, data[0] as i16),
            0x16 => Instruction::ConstWideLit16(high, data[0] as i16),
            0x17 => Instruction::ConstWideLit32(
                high,
                (data[0] as u32 | ((data[1] as u32) << 16)) as i32,
            ),
            0x18 => Instruction::ConstWide(
                high,
                (data[0] as u64
                    | ((data[1] as u64) << 16)
                    | ((data[2] as u64) << 32)
                    | ((data[3] as u64) << 48)) as i64,
            ),
            0x19 => Instruction::ConstWideHigh16(high, data[0] as i16),
            0x1a => Instruction::ConstString(high, data[0]),
            0x1b => Instruction::ConstStringJumbo(
                high,
                data[0] as u32 | ((data[1] as u32) << 16),
            ),
            0x1c => Instruction::ConstClass(high, data[0]),
            0x1f => Instruction::CheckCast(high, data[0]),
            0x20 => Instruction::InstanceOf(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0x21 => Instruction::ArrayLength(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x22 => Instruction::NewInstance(high, data[0]),
            0x23 => Instruction::NewArray(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0x24 => {
                let arg_num = u4::new((high & 0b11110000) >> 4);
                let content: Vec<u8> = match (high & 0b11110000) >> 4 {
                    0 => vec![],
                    1 => vec![(data[1] & 0x000f) as u8],
                    2 => vec![(data[1] & 0x000f) as u8, ((data[1] & 0x00f0) >> 4) as u8],
                    3 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                    ],
                    4 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                    ],
                    5 => vec![
                        (data[1] & 0x000f) as u8,
                        ((data[1] & 0x00f0) >> 4) as u8,
                        ((data[1] & 0x0f00) >> 8) as u8,
                        ((data[1] & 0xf000) >> 12) as u8,
                        high & 0b1111,
                    ],
                    _ => vec![],
                };
                Instruction::FilledNewArray(arg_num, data[0], content)
            }
            0x25 => Instruction::FilledNewArrayRange(high, data[0], data[1]),
            0x26 => Instruction::FillArrayData(high, (data[1] as u32) << 16 | (data[0] as u32)),

            0x52 => Instruction::InstanceGet(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0x53 => {
                Instruction::InstanceGetWide(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x54 => {
                Instruction::InstanceGetObject(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x55 => {
                Instruction::InstanceGetBoolean(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x56 => {
                Instruction::InstanceGetByte(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x57 => {
                Instruction::InstanceGetChar(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x58 => {
                Instruction::InstanceGetShort(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }

            0x59 => Instruction::InstancePut(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0x5a => {
                Instruction::InstancePutWide(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x5b => {
                Instruction::InstancePutObject(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x5c => {
                Instruction::InstancePutBoolean(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x5d => {
                Instruction::InstancePutByte(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x5e => {
                Instruction::InstancePutChar(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }
            0x5f => {
                Instruction::InstancePutShort(u4::new(high & 0b1111), u4::new(high >> 4), data[0])
            }

            0x60 => Instruction::StaticGet(high, data[0]),
            0x61 => Instruction::StaticGetWide(high, data[0]),
            0x62 => Instruction::StaticGetObject(high, data[0]),
            0x63 => Instruction::StaticGetBoolean(high, data[0]),
            0x64 => Instruction::StaticGetByte(high, data[0]),
            0x65 => Instruction::StaticGetChar(high, data[0]),
            0x66 => Instruction::StaticGetShort(high, data[0]),
            0x67 => Instruction::StaticPut(high, data[0]),
            0x68 => Instruction::StaticPutWide(high, data[0]),
            0x69 => Instruction::StaticPutObject(high, data[0]),
            0x6a => Instruction::StaticPutBoolean(high, data[0]),
            0x6b => Instruction::StaticPutByte(high, data[0]),
            0x6c => Instruction::StaticPutChar(high, data[0]),
            0x6d => Instruction::StaticPutShort(high, data[0]),

            0xfc => Instruction::ConstMethodHandle(high, data[0]),
            0xfd => Instruction::ConstMethodType(high, data[0]),

            _ => Instruction::NotImpl(low[1], high),
        }
    }
    pub fn get_op_len<R: Read + Seek>(op: u16, data: &mut R) -> (u32, bool, u32) {
        let low = op.to_be_bytes();
        match low[1] {
            0 => {
                if low[0] == 0x03 {
                    let element_width = u16::from_bytes(data) as u32;
                    let number_of_elements = u32::from_bytes(data);
                    (element_width * number_of_elements, true, element_width)
                } else if low[0] == 0x01 || low[0] == 0x02 {
                    //packedswitch
                    let num_of_entries = u16::from_bytes(data) as u32;

                    (num_of_entries * 4, true, 0)
                } else {
                    (2, false, 0)
                }
            }

            1
            | 4
            | 7
            | 0xa..=0x12
            | 0x1d..=0x1e
            | 0x21
            | 0x27..=0x28
            | 0x73
            | 0x79..=0x8f
            | 0xb0..=0xcf
            | 0xe3..=0xf9 => (2, false, 0),

            0x02
            | 0x05
            | 0x08
            | 0x13
            | 0x15..=0x16
            | 0x19
            | 0x1a
            | 0x1c
            | 0x1f..=0x20
            | 0x22..=0x23
            | 0x29
            | 0x2d..=0x3d
            | 0x44..=0x6d
            | 0x90..=0xaf
            | 0xd0..=0xe2
            | 0xfe..=0xff => (4, false, 0),

            0x03
            | 0x6
            | 0x9
            | 0x14
            | 0x17
            | 0x1b
            | 0x24..=0x26
            | 0x2a..=0x2c
            | 0x6e..=0x72
            | 0x74..=0x78
            | 0xfc..=0xfd => (6, false, 0),

            0xfa..=0xfb => (8, false, 0),

            0x18 => (10, false, 0),

            _ => (2, false, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(op: u16, data: &[u16]) -> (Instruction, Vec<u16>) {
        let instruction = Instruction::get_opcode(op, data);
        let units = instruction.to_code_units().expect("encodes");
        (instruction, units)
    }

    #[test]
    fn const_uses_little_endian_low_word_first() {
        let (instruction, units) = roundtrip(0x0014, &[0x68b3, 0x1234]);
        assert_eq!(instruction, Instruction::ConstLit32(0, 0x123468b3));
        assert_eq!(units, vec![0x0014, 0x68b3, 0x1234]);
    }

    #[test]
    fn const_high16_roundtrips() {
        let (instruction, units) = roundtrip(0x0015, &[0x4040]);
        assert_eq!(instruction, Instruction::ConstHigh16(0, 0x4040));
        assert_eq!(units, vec![0x0015, 0x4040]);
    }

    #[test]
    fn const_wide_uses_little_endian_low_word_first() {
        let (instruction, units) = roundtrip(0x0018, &[0x193c, 0x0506, 0x1538, 0x0102]);
        assert_eq!(instruction, Instruction::ConstWide(0, 0x010215380506193c));
        assert_eq!(units, vec![0x0018, 0x193c, 0x0506, 0x1538, 0x0102]);
    }

    #[test]
    fn const_wide_lit32_uses_little_endian_low_word_first() {
        let (instruction, units) = roundtrip(0x0017, &[0x5678, 0x1234]);
        assert_eq!(instruction, Instruction::ConstWideLit32(0, 0x12345678));
        assert_eq!(units, vec![0x0017, 0x5678, 0x1234]);
    }

    #[test]
    fn const_string_jumbo_uses_little_endian_low_word_first() {
        let (instruction, units) = roundtrip(0x001b, &[0x5678, 0x1234]);
        assert_eq!(instruction, Instruction::ConstStringJumbo(0, 0x12345678));
        assert_eq!(units, vec![0x001b, 0x5678, 0x1234]);
    }

    #[test]
    fn cmp_long_roundtrips() {
        let (instruction, units) = roundtrip(0x0031, &[0x0201]);
        assert_eq!(instruction, Instruction::CmpLong(0, 1, 2));
        assert_eq!(units, vec![0x0031, 0x0201]);
    }

    #[test]
    fn array_get_23x_roundtrips() {
        let (instruction, units) = roundtrip(0x0044, &[0x0100]);
        assert_eq!(instruction, Instruction::ArrayGetWide(0, 0, 1));
        assert_eq!(units, vec![0x0044, 0x0100]);
    }

    #[test]
    fn const_high16_has_correct_mnemonic() {
        let instruction = Instruction::ConstHigh16(0, 0x4040);
        assert_eq!(instruction.mnemonic_from_opcode(), "const/high16");
    }

    #[test]
    fn const_wide_has_correct_mnemonic() {
        let instruction = Instruction::ConstWide(0, 42);
        assert_eq!(instruction.mnemonic_from_opcode(), "const-wide");
    }
}
