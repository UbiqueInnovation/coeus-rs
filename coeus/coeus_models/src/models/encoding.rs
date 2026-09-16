// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::{Read, Seek, Write};

pub trait Encode {
    type EncodableUnit;
    fn to_bytes<W: Write>(writer: &mut W) -> Self;
    fn write<W: Write>(
        obj: &mut Self::EncodableUnit,
        writer: &mut W,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let obj_ptr = unsafe {
            std::slice::from_raw_parts_mut(
                obj as *mut _ as *mut u8,
                std::mem::size_of::<Self::EncodableUnit>(),
            )
        };
        writer.write_all(obj_ptr)?;
        Ok(obj_ptr.len())
    }
    fn write_leb128<W: Write>(
        writer: &mut W,
        value: u64,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        Ok(leb128::write::unsigned(writer, value)?)
    }
}

pub trait Decode {
    type DecodableUnit;
    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self;
    fn read<R: Read + Seek>(obj: &mut Self::DecodableUnit, data: &mut R) {
        unsafe {
            let obj_ptr = std::slice::from_raw_parts_mut(
                obj as *mut _ as *mut u8,
                std::mem::size_of::<Self::DecodableUnit>(),
            );
            data.read_exact(obj_ptr)
                .expect("Could not read/write object");
        }
    }
    fn read_leb128<R: Read + Seek>(
        mut byte_view: &mut R,
    ) -> Result<(usize, u64), Box<dyn std::error::Error>> {
        let value = leb128::read::unsigned(&mut byte_view).expect("Could not parse leb128");
        let mut tmp = vec![0; 10];
        let lebbytes = leb128::write::unsigned(&mut tmp, value).unwrap();
        Ok((lebbytes, value))
    }
}

impl Decode for u8 {
    type DecodableUnit = u8;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        u8::from_le_bytes(bytes)
    }
}

impl Decode for u16 {
    type DecodableUnit = u16;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        u16::from_le_bytes(bytes)
    }
}

impl Decode for u32 {
    type DecodableUnit = u32;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        u32::from_le_bytes(bytes)
    }
}

impl Decode for u64 {
    type DecodableUnit = u64;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        u64::from_le_bytes(bytes)
    }
}

impl Decode for i8 {
    type DecodableUnit = i8;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        i8::from_le_bytes(bytes)
    }
}

impl Decode for i16 {
    type DecodableUnit = i16;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        i16::from_le_bytes(bytes)
    }
}

impl Decode for i32 {
    type DecodableUnit = i32;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        Self::DecodableUnit::from_le_bytes(bytes)
    }
}

impl Decode for i64 {
    type DecodableUnit = i64;

    fn from_bytes<R: Read + Seek>(byte_view: &mut R) -> Self {
        let mut bytes: [u8; std::mem::size_of::<Self::DecodableUnit>()] =
            [0; std::mem::size_of::<Self::DecodableUnit>()];
        byte_view.read_exact(&mut bytes).unwrap();
        Self::DecodableUnit::from_le_bytes(bytes)
    }
}
