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

    Move(u4, u4),
    MoveFrom16(u8, u16),
    Move16(u16, u16),
    MoveWide(u4, u4),
    MoveWideFrom16(u8, u16),
    MoveWide16(u16, u16),
    MoveObject(u4, u4),
    MoveObjectFrom16(u8, u16),
    MoveObject16(u16, u16),

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

    ArrayGetByte(u8, u8, u8),
    ArrayPutByte(u8, u8, u8),
    ArrayGetChar(u8, u8, u8),
    ArrayPutChar(u8, u8, u8),

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

    InvokeType(String),

    MoveResult(u8),
    MoveResultWide(u8),
    MoveResultObject(u8),

    ReturnVoid,

    Return(u8),

    Const,
    ConstLit4(u4, i4),
    ConstLit16(u8, i16),
    ConstLit32(u8, i32),
    ConstWide,
    ConstString(u8, u16),
    ConstStringJumbo(u8, u32),
    ConstClass(u8, u16),
    CheckCast(u8, u16),

    IntToByte(u4, u4),
    IntToChar(u4, u4),
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

    Switch(u8, i32),
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

    ShrIntLit8(u8, u8, u8),
    UShrIntLit8(u8, u8, u8),

    NotImpl(u8, u8),
    ArrayData(u16, Vec<u8>),
    SwitchData(Switch),
    ArbitraryData(String),
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nop => write!(f, "Nop"),
            Self::Move(arg0, arg1) => f.debug_tuple("Move").field(arg0).field(arg1).finish(),
            Self::MoveFrom16(arg0, arg1) => {
                f.debug_tuple("MoveFrom16").field(arg0).field(arg1).finish()
            }
            Self::Move16(arg0, arg1) => f.debug_tuple("Move16").field(arg0).field(arg1).finish(),
            Self::MoveWide(arg0, arg1) => {
                f.debug_tuple("MoveWide").field(arg0).field(arg1).finish()
            }
            Self::MoveWideFrom16(arg0, arg1) => f
                .debug_tuple("MoveWideFrom16")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::MoveWide16(arg0, arg1) => {
                f.debug_tuple("MoveWide16").field(arg0).field(arg1).finish()
            }
            Self::MoveObject(arg0, arg1) => {
                f.debug_tuple("MoveObject").field(arg0).field(arg1).finish()
            }
            Self::MoveObjectFrom16(arg0, arg1) => f
                .debug_tuple("MoveObjectFrom16")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::MoveObject16(arg0, arg1) => f
                .debug_tuple("MoveObject16")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::XorInt(arg0, arg1) => f.debug_tuple("XorInt").field(arg0).field(arg1).finish(),
            Self::XorLong(arg0, arg1) => f.debug_tuple("XorLong").field(arg0).field(arg1).finish(),
            Self::XorIntDst(arg0, arg1, arg2) => f
                .debug_tuple("XorIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::XorLongDst(arg0, arg1, arg2) => f
                .debug_tuple("XorLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::XorIntDstLit8(arg0, arg1, arg2) => f
                .debug_tuple("XorIntDstLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::XorIntDstLit16(arg0, arg1, arg2) => f
                .debug_tuple("XorIntDstLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::RemIntDst(arg0, arg1, arg2) => f
                .debug_tuple("RemIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::RemLongDst(arg0, arg1, arg2) => f
                .debug_tuple("RemLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::RemInt(arg0, arg1) => f.debug_tuple("RemInt").field(arg0).field(arg1).finish(),
            Self::RemLong(arg0, arg1) => f.debug_tuple("RemLong").field(arg0).field(arg1).finish(),
            Self::RemIntLit16(arg0, arg1, arg2) => f
                .debug_tuple("RemIntLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::RemIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("RemIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::AddInt(arg0, arg1) => f.debug_tuple("AddInt").field(arg0).field(arg1).finish(),
            Self::AddIntDst(arg0, arg1, arg2) => f
                .debug_tuple("AddIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::AddIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("AddIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::AddIntLit16(arg0, arg1, arg2) => f
                .debug_tuple("AddIntLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::AddLong(arg0, arg1) => f.debug_tuple("AddLong").field(arg0).field(arg1).finish(),
            Self::AddLongDst(arg0, arg1, arg2) => f
                .debug_tuple("AddLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::SubInt(arg0, arg1) => f.debug_tuple("SubInt").field(arg0).field(arg1).finish(),
            Self::SubIntDst(arg0, arg1, arg2) => f
                .debug_tuple("SubIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::SubIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("SubIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::SubIntLit16(arg0, arg1, arg2) => f
                .debug_tuple("SubIntLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::SubLong(arg0, arg1) => f.debug_tuple("SubLong").field(arg0).field(arg1).finish(),
            Self::SubLongDst(arg0, arg1, arg2) => f
                .debug_tuple("SubLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::MulInt(arg0, arg1) => f.debug_tuple("MulInt").field(arg0).field(arg1).finish(),
            Self::MulIntDst(arg0, arg1, arg2) => f
                .debug_tuple("MulIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::MulIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("MulIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::MulIntLit16(arg0, arg1, arg2) => f
                .debug_tuple("MulIntLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::MulLong(arg0, arg1) => f.debug_tuple("MulLong").field(arg0).field(arg1).finish(),
            Self::MulLongDst(arg0, arg1, arg2) => f
                .debug_tuple("MulLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),

            Self::DivInt(arg0, arg1) => f.debug_tuple("DivInt").field(arg0).field(arg1).finish(),
            Self::DivIntDst(arg0, arg1, arg2) => f
                .debug_tuple("DivIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::DivIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("DivIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::DivIntLit16(arg0, arg1, arg2) => f
                .debug_tuple("DivIntLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::DivLong(arg0, arg1) => f.debug_tuple("DivLong").field(arg0).field(arg1).finish(),
            Self::DivLongDst(arg0, arg1, arg2) => f
                .debug_tuple("DivLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),

            Self::AndInt(arg0, arg1) => f.debug_tuple("AndInt").field(arg0).field(arg1).finish(),
            Self::AndIntDst(arg0, arg1, arg2) => f
                .debug_tuple("AndIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::AndIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("AndIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::AndIntLit16(arg0, arg1, arg2) => f
                .debug_tuple("AndIntLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::AndLong(arg0, arg1) => f.debug_tuple("AndLong").field(arg0).field(arg1).finish(),
            Self::AndLongDst(arg0, arg1, arg2) => f
                .debug_tuple("AndLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::OrInt(arg0, arg1) => f.debug_tuple("OrInt").field(arg0).field(arg1).finish(),
            Self::OrIntDst(arg0, arg1, arg2) => f
                .debug_tuple("OrIntDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::OrIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("OrIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::OrIntLit16(arg0, arg1, arg2) => f
                .debug_tuple("OrIntLit16")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::OrLong(arg0, arg1) => f.debug_tuple("OrLong").field(arg0).field(arg1).finish(),
            Self::OrLongDst(arg0, arg1, arg2) => f
                .debug_tuple("OrLongDst")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::Test(arg0, arg1, arg2, arg3) => f
                .debug_tuple("Test")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .field(arg3)
                .finish(),
            Self::TestZero(arg0, arg1, arg2) => f
                .debug_tuple("TestZero")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::Goto8(arg0) => f.debug_tuple("Goto8").field(arg0).finish(),
            Self::Goto16(arg0) => f.debug_tuple("Goto16").field(arg0).finish(),
            Self::Goto32(arg0) => f.debug_tuple("Goto32").field(arg0).finish(),
            Self::ArrayGetByte(arg0, arg1, arg2) => f
                .debug_tuple("ArrayGetByte")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::ArrayPutByte(arg0, arg1, arg2) => f
                .debug_tuple("ArrayPutByte")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::ArrayGetChar(arg0, arg1, arg2) => f
                .debug_tuple("ArrayGetChar")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::ArrayPutChar(arg0, arg1, arg2) => f
                .debug_tuple("ArrayPutChar")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::Invoke(arg0) => f.debug_tuple("Invoke").field(arg0).finish(),
            Self::InvokeVirtual(arg0, arg1, arg2) => f
                .debug_tuple("InvokeVirtual")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeSuper(arg0, arg1, arg2) => f
                .debug_tuple("InvokeSuper")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeDirect(arg0, arg1, arg2) => f
                .debug_tuple("InvokeDirect")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeStatic(arg0, arg1, arg2) => f
                .debug_tuple("InvokeStatic")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeInterface(arg0, arg1, arg2) => f
                .debug_tuple("InvokeInterface")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeVirtualRange(arg0, arg1, arg2) => f
                .debug_tuple("InvokeVirtualRange")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeSuperRange(arg0, arg1, arg2) => f
                .debug_tuple("InvokeSuperRange")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeDirectRange(arg0, arg1, arg2) => f
                .debug_tuple("InvokeDirectRange")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeStaticRange(arg0, arg1, arg2) => f
                .debug_tuple("InvokeStaticRange")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeInterfaceRange(arg0, arg1, arg2) => f
                .debug_tuple("InvokeInterfaceRange")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InvokeType(arg0) => f.debug_tuple("InvokeType").field(arg0).finish(),
            Self::MoveResult(arg0) => f.debug_tuple("MoveResult").field(arg0).finish(),
            Self::MoveResultWide(arg0) => f.debug_tuple("MoveResultWide").field(arg0).finish(),
            Self::MoveResultObject(arg0) => f.debug_tuple("MoveResultObject").field(arg0).finish(),
            Self::ReturnVoid => write!(f, "ReturnVoid"),
            Self::Return(arg0) => f.debug_tuple("Return").field(arg0).finish(),
            Self::Const => write!(f, "Const"),
            Self::ConstLit4(arg0, arg1) => {
                f.debug_tuple("ConstLit4").field(arg0).field(arg1).finish()
            }
            Self::ConstLit16(arg0, arg1) => {
                f.debug_tuple("ConstLit16").field(arg0).field(arg1).finish()
            }
            Self::ConstLit32(arg0, arg1) => {
                f.debug_tuple("ConstLit32").field(arg0).field(arg1).finish()
            }
            Self::ConstWide => write!(f, "ConstWide"),
            Self::ConstString(arg0, arg1) => f
                .debug_tuple("ConstString")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::ConstStringJumbo(arg0, arg1) => f
                .debug_tuple("ConstStringJumbo")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::ConstClass(arg0, arg1) => {
                f.debug_tuple("ConstClass").field(arg0).field(arg1).finish()
            }
            Self::CheckCast(arg0, arg1) => {
                f.debug_tuple("CheckCast").field(arg0).field(arg1).finish()
            }
            Self::IntToByte(arg0, arg1) => {
                f.debug_tuple("IntToByte").field(arg0).field(arg1).finish()
            }
            Self::IntToChar(arg0, arg1) => {
                f.debug_tuple("IntToChar").field(arg0).field(arg1).finish()
            }
            Self::ArrayLength(arg0, arg1) => f
                .debug_tuple("ArrayLength")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::NewInstance(arg0, arg1) => f
                .debug_tuple("NewInstance")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::NewInstanceType(arg0) => f.debug_tuple("NewInstanceType").field(arg0).finish(),
            Self::NewArray(arg0, arg1, arg2) => f
                .debug_tuple("NewArray")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::FilledNewArray(arg0, arg1, arg2) => f
                .debug_tuple("FilledNewArray")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::FilledNewArrayRange(arg0, arg1, arg2) => f
                .debug_tuple("FilledNewArrayRange")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::FillArrayData(arg0, arg1) => f
                .debug_tuple("FillArrayData")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticGet(arg0, arg1) => {
                f.debug_tuple("StaticGet").field(arg0).field(arg1).finish()
            }
            Self::StaticGetWide(arg0, arg1) => f
                .debug_tuple("StaticGetWide")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticGetObject(arg0, arg1) => f
                .debug_tuple("StaticGetObject")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticGetBoolean(arg0, arg1) => f
                .debug_tuple("StaticGetBoolean")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticGetByte(arg0, arg1) => f
                .debug_tuple("StaticGetByte")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticGetChar(arg0, arg1) => f
                .debug_tuple("StaticGetChar")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticGetShort(arg0, arg1) => f
                .debug_tuple("StaticGetShort")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticPut(arg0, arg1) => {
                f.debug_tuple("StaticPut").field(arg0).field(arg1).finish()
            }
            Self::StaticPutWide(arg0, arg1) => f
                .debug_tuple("StaticPutWide")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticPutObject(arg0, arg1) => f
                .debug_tuple("StaticPutObject")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticPutBoolean(arg0, arg1) => f
                .debug_tuple("StaticPutBoolean")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticPutByte(arg0, arg1) => f
                .debug_tuple("StaticPutByte")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticPutChar(arg0, arg1) => f
                .debug_tuple("StaticPutChar")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::StaticPutShort(arg0, arg1) => f
                .debug_tuple("StaticPutShort")
                .field(arg0)
                .field(arg1)
                .finish(),
            Self::Switch(arg0, arg1) => f.debug_tuple("Switch").field(arg0).field(arg1).finish(),
            Self::InstanceGet(arg0, arg1, arg2) => f
                .debug_tuple("InstanceGet")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstanceGetWide(arg0, arg1, arg2) => f
                .debug_tuple("InstanceGetWide")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstanceGetObject(arg0, arg1, arg2) => f
                .debug_tuple("InstanceGetObject")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstanceGetBoolean(arg0, arg1, arg2) => f
                .debug_tuple("InstanceGetBoolean")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstanceGetByte(arg0, arg1, arg2) => f
                .debug_tuple("InstanceGetByte")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstanceGetChar(arg0, arg1, arg2) => f
                .debug_tuple("InstanceGetChar")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstanceGetShort(arg0, arg1, arg2) => f
                .debug_tuple("InstanceGetShort")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstancePut(arg0, arg1, arg2) => f
                .debug_tuple("InstancePut")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstancePutWide(arg0, arg1, arg2) => f
                .debug_tuple("InstancePutWide")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstancePutObject(arg0, arg1, arg2) => f
                .debug_tuple("InstancePutObject")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstancePutBoolean(arg0, arg1, arg2) => f
                .debug_tuple("InstancePutBoolean")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstancePutByte(arg0, arg1, arg2) => f
                .debug_tuple("InstancePutByte")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstancePutChar(arg0, arg1, arg2) => f
                .debug_tuple("InstancePutChar")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::InstancePutShort(arg0, arg1, arg2) => f
                .debug_tuple("InstancePutShort")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::Throw(arg0) => f.debug_tuple("Throw").field(arg0).finish(),
            Self::NotImpl(arg0, arg1) => f.debug_tuple("NotImpl").field(arg0).field(arg1).finish(),
            Self::ArrayData(arg0, arg1) => {
                f.debug_tuple("ArrayData").field(arg0).field(arg1).finish()
            }
            Self::SwitchData(arg0) => f.debug_tuple("SwitchData").field(arg0).finish(),
            Self::ArbitraryData(arg0) => f.write_str(&arg0),
            Self::ShrIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("ShrIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
            Self::UShrIntLit8(arg0, arg1, arg2) => f
                .debug_tuple("ShrIntLit8")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .finish(),
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
        TestFunction::LessEqual => 3,
        TestFunction::GreaterThan => 4,
        TestFunction::GreaterEqual => 5,
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

            ArrayGetByte(dst, array, index) => fmt23(0x48, *dst, *array, *index),
            ArrayGetChar(dst, array, index) => fmt23(0x49, *dst, *array, *index),
            ArrayPutByte(src, array, index) => fmt23(0x4f, *src, *array, *index),
            ArrayPutChar(src, array, index) => fmt23(0x50, *src, *array, *index),
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
            AddLong(dst, src) => fmt12(0xbb, dst, src),
            AddIntDst(dst, a, b) => fmt23(0x90, *dst, *a, *b),
            AddLongDst(dst, a, b) => fmt23(0x9b, *dst, *a, *b),
            AddIntLit8(dst, src, value) => fmt22s(0xd8, *dst, *src, *value as i16),
            AddIntLit16(dst, src, value) => fmt22s4(0xd0, dst, src, *value as i16),
            SubInt(dst, src) => fmt12(0xb1, dst, src),
            SubLong(dst, src) => fmt12(0xbc, dst, src),
            SubIntDst(dst, a, b) => fmt23(0x91, *dst, *a, *b),
            SubLongDst(dst, a, b) => fmt23(0x9c, *dst, *a, *b),
            SubIntLit8(dst, src, value) => fmt22s(0xd9, *dst, *src, *value as i16),
            SubIntLit16(dst, src, value) => fmt22s4(0xd1, dst, src, *value as i16),
            MulInt(dst, src) => fmt12(0xb2, dst, src),
            MulLong(dst, src) => fmt12(0xbd, dst, src),
            MulIntDst(dst, a, b) => fmt23(0x92, *dst, *a, *b),
            MulLongDst(dst, a, b) => fmt23(0x9d, *dst, *a, *b),
            MulIntLit8(dst, src, value) => fmt22s(0xda, *dst, *src, *value as i16),
            MulIntLit16(dst, src, value) => fmt22s4(0xd2, dst, src, *value as i16),
            DivInt(dst, src) => fmt12(0xb3, dst, src),
            DivLong(dst, src) => fmt12(0xbe, dst, src),
            DivIntDst(dst, a, b) => fmt23(0x93, *dst, *a, *b),
            DivLongDst(dst, a, b) => fmt23(0x9e, *dst, *a, *b),
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
            ShrIntLit8(dst, src, value) => fmt22s(0xe1, *dst, *src, *value as i16),
            UShrIntLit8(dst, src, value) => fmt22s(0xe2, *dst, *src, *value as i16),

            IntToByte(dst, src) => fmt12(0x8d, dst, src),
            IntToChar(dst, src) => fmt12(0x82, dst, src),
            NewInstance(dst, type_idx) => fmt22(0x22, *dst, *type_idx),
            NewArray(dst, size, type_idx) => one(0x23, u4(dst) | (u4(size) << 4))
                .into_iter()
                .chain(std::iter::once(*type_idx))
                .collect(),
            FilledNewArray(count, type_idx, regs) => fmt35(0x24, count, *type_idx, regs)?,
            FilledNewArrayRange(count, first, type_idx) => {
                vec![u16::from_le_bytes([0x25, *count]), *type_idx, *first]
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

            Switch(register, offset) => vec![
                u16::from_le_bytes([0x2b, *register]),
                *offset as u32 as u16,
                (*offset as u32 >> 16) as u16,
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
            Const | ConstWide | InvokeType(_) | NewInstanceType(_) | SwitchData(_)
            | ArbitraryData(_) => {
                return Err(format!(
                    "instruction is a display placeholder and cannot be encoded: {:?}",
                    self
                ));
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
            0x2b => Instruction::Switch(
                high,
                i32::from_be_bytes([
                    (data[1] >> 8) as u8,
                    (data[1] & 0xff) as u8,
                    (data[0] >> 8) as u8,
                    (data[0] & 0xff) as u8,
                ]),
            ),
            0x2c => Instruction::Switch(
                high,
                i32::from_be_bytes([
                    (data[1] >> 8) as u8,
                    (data[1] & 0xff) as u8,
                    (data[0] >> 8) as u8,
                    (data[0] & 0xff) as u8,
                ]),
            ),
            0x27 => Instruction::Throw(high),

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
            0xb0 => Instruction::AddInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbb => Instruction::AddLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd0 => Instruction::AddIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xd8 => Instruction::AddIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x92 => Instruction::MulIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9d => Instruction::MulLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb2 => Instruction::MulInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbd => Instruction::MulLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd2 => Instruction::MulIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xda => Instruction::MulIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x93 => Instruction::DivIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9e => Instruction::DivLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb3 => Instruction::DivInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbe => Instruction::DivLong(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xd3 => Instruction::DivIntLit16(u4::new(high & 0b1111), u4::new(high >> 4), data[0]),
            0xdb => Instruction::DivIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

            0x91 => Instruction::SubIntDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x9c => Instruction::SubLongDst(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xb1 => Instruction::SubInt(u4::new(high & 0b1111), u4::new(high >> 4)),
            0xbc => Instruction::SubLong(u4::new(high & 0b1111), u4::new(high >> 4)),
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
            0x48 => Instruction::ArrayGetByte(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x49 => Instruction::ArrayGetChar(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x4f => Instruction::ArrayPutByte(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0x50 => Instruction::ArrayPutChar(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
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
                i32::from_be_bytes([
                    ((data[0] >> 8) as u8),
                    ((data[0] & 0xff) as u8),
                    ((data[1] >> 8) as u8),
                    ((data[1] & 0xff) as u8),
                ]),
            ),
            0x15 => Instruction::ConstLit32(high, (data[0] as i32) << 16),
            0x16..=0x19 => Instruction::ConstWide,
            0x1a => Instruction::ConstString(high, data[0]),
            0x1b => Instruction::ConstStringJumbo(
                high,
                u32::from_be_bytes([
                    ((data[0] >> 8) as u8),
                    ((data[0] & 0xff) as u8),
                    ((data[1] >> 8) as u8),
                    ((data[1] & 0xff) as u8),
                ]),
            ),
            0x1c => Instruction::ConstClass(high, data[0]),
            0x1f => Instruction::CheckCast(high, data[0]),
            0x8d => Instruction::IntToByte(u4::new(high & 0b1111), u4::new(high >> 4)),
            0x82 => Instruction::IntToChar(u4::new(high & 0b1111), u4::new(high >> 4)),
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

            0xe1 => Instruction::ShrIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),
            0xe2 => Instruction::UShrIntLit8(high, (data[0] & 0xff) as u8, (data[0] >> 8) as u8),

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
