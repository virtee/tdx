// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Seek, SeekFrom};
use uuid::Uuid;

const EXPECTED_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const EXPECTED_METADATA_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";

#[repr(C, packed)]
#[derive(Default, Debug)]
struct TdvfDescriptor {
    /// Signature should equal "TDVF" in bytes
    signature: [u8; 4],

    /// Size of the structure
    length: u32,

    /// Version of the structure. It must be 1
    version: u32,

    /// Number of section entries
    number_of_section_entry: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TdvfSection {
    /// The offset to the raw section in the binary image
    pub data_offset: u32,

    /// The size of the raw section in the image. If it is zero, the VMM shall allocate zero memory
    /// from MemoryAddress to (MemoryAddress + MemoryDataSize). If it is zero, then the DataOffset
    /// shall also be zero
    pub raw_data_size: u32,

    /// The guest physical address of the section loaded. It must be 4k aligned. Zero means no
    /// action for the VMM.
    pub memory_address: u64,

    /// The size of the section to be loaded. It must be 4k aligned. It must be at least
    /// RawDataSize if non-zero. If MemoryDataSize is greater than RawDataSize, the VMM shall fill
    /// zero up to the MemoryDataSize. Zero means no action for the VMM.
    pub memory_data_size: u64,

    /// The type of the TDVF section
    pub section_type: TdvfSectionType,

    /// The attribute of the section
    pub attributes: u32,
}

#[repr(u32)]
#[derive(Debug, Default, Copy, Clone)]
pub enum TdvfSectionType {
    /// Boot Firmware Volume
    Bfv,

    /// Configuration Firmware Volume
    Cfv,

    /// Trust Domain Hand Off Block
    TdHob,

    /// Temporary Memory
    TempMem,

    /// Reserved
    #[default]
    Reserved = 0xFFFFFFFF,
}

#[derive(Debug)]
pub enum Error {
    TableSeek(std::io::Error),
    TableRead(std::io::Error),
    UuidCreate(uuid::Error),
    InvalidDescriptorSignature,
    InvalidDescriptorSize,
    InvalidDescriptorVersion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::TableSeek(ref err) => write!(
                f,
                "Error attempting to seek to a byte offset in a stream: {}",
                err
            ),
            Self::TableRead(ref err) => write!(
                f,
                "Error attempting to read exact number of bytes to completely fill a buffer: {}",
                err
            ),
            Self::UuidCreate(ref err) => write!(f, "Error attempting to create a UUID: {}", err),
            Self::InvalidDescriptorSignature => {
                write!(f, "TDX Metadata Descriptor signature is invalid")
            }
            Self::InvalidDescriptorVersion => {
                write!(f, "TDX Metadata Descriptor version is invalid")
            }
            Self::InvalidDescriptorSize => write!(f, "TDX Metadata Descriptor size is invalid"),
        }
    }
}

/// Locate the GUID at the footer of the OVMF flash file
fn locate_table_footer_guid(fd: &mut std::fs::File) -> Result<Uuid, Error> {
    // there are 32 bytes between the footer GUID and the bottom of the flash file, so we need to
    // move -48 bytes from the bottom of the file to read the 16 byte GUID
    fd.seek(SeekFrom::End(-0x30)).map_err(Error::TableSeek)?;

    let mut table_footer_guid: [u8; 16] = [0; 16];
    fd.read_exact(&mut table_footer_guid)
        .map_err(Error::TableRead)?;

    Uuid::from_slice_le(table_footer_guid.as_slice()).map_err(Error::UuidCreate)
}

/// Locate the size of the entry table in the OVMF flash file
fn locate_table_size(fd: &mut std::fs::File) -> Result<u16, Error> {
    // from the bottom of the file, there is 32 bytes between the footer GUID, 16 bytes for the
    // GUID, and there are 2 bytes for the size of the entry table. We need to move -50 bytes from
    // the bottom of the file to read those 2 bytes.
    fd.seek(SeekFrom::End(-0x32)).map_err(Error::TableSeek)?;

    let mut table_size: [u8; 2] = [0; 2];
    fd.read_exact(&mut table_size).map_err(Error::TableRead)?;

    Ok(u16::from_le_bytes(table_size))
}

/// Reads the entry table into the provided table vector
fn read_table_contents(
    fd: &mut std::fs::File,
    table: &mut Vec<u8>,
    table_size: u16,
) -> Result<(), Error> {
    // table_size + the 32 bytes between the footer GUID and the EOF
    let table_start = -(table_size as i64 + 0x20);
    fd.seek(SeekFrom::End(table_start))
        .map_err(Error::TableSeek)?;
    fd.read_exact(table.as_mut_slice())
        .map_err(Error::TableRead)?;
    Ok(())
}

/// Try to calculate the offset from the bottom of the flash file for the TDX Metadata GUID offset
fn calculate_tdx_metadata_guid_offset(
    table: &mut [u8],
    table_size: usize,
) -> Result<Option<u32>, Error> {
    // starting from the end of the table and after the footer guid and table size bytes (16 + 2)
    let mut offset = table_size - 18;
    while offset >= 18 {
        // entries are laid out as follows:
        //
        // - data (arbitrary bytes identified by the guid)
        // - length from start of data to end of guid (2 bytes)
        // - guid (16 bytes)

        // move backwards through the table to locate the entry guid
        let entry_uuid =
            Uuid::from_slice_le(&table[offset - 16..offset]).map_err(Error::UuidCreate)?;
        // move backwards through the table to locate the entry size
        let entry_size =
            u16::from_le_bytes(table[offset - 18..offset - 16].try_into().unwrap()) as usize;

        // Avoid going through an infinite loop if the entry size is 0
        if entry_size == 0 {
            break;
        }

        offset -= entry_size;

        let expected_uuid = Uuid::parse_str(EXPECTED_METADATA_GUID).map_err(Error::UuidCreate)?;
        if entry_uuid == expected_uuid && entry_size == 22 {
            return Ok(Some(u32::from_le_bytes(
                table[offset..offset + 4].try_into().unwrap(),
            )));
        }
    }

    Ok(None)
}

/// Calculate the offset from the bottom of the file where the TDX Metadata offset block is
/// located
pub fn calculate_tdvf_descriptor_offset(fd: &mut std::fs::File) -> Result<u32, Error> {
    let located = locate_table_footer_guid(fd)?;
    let expected = Uuid::parse_str(EXPECTED_TABLE_FOOTER_GUID).map_err(Error::UuidCreate)?;

    // we found the table footer guid
    if located == expected {
        // find the table size
        let table_size = locate_table_size(fd)?;

        let mut table: Vec<u8> = vec![0; table_size as usize];
        read_table_contents(fd, &mut table, table_size)?;

        // starting from the top and go backwards down the table.
        // starting after the footer GUID and the table length
        if let Ok(Some(offset)) =
            calculate_tdx_metadata_guid_offset(&mut table, table_size as usize)
        {
            return Ok(offset);
        }
    }

    // if we get here then the firmware doesn't support exposing the offset through the GUID table
    fd.seek(SeekFrom::End(-0x20)).map_err(Error::TableSeek)?;

    let mut descriptor_offset: [u8; 4] = [0; 4];
    fd.read_exact(&mut descriptor_offset)
        .map_err(Error::TableRead)?;

    Ok(u32::from_le_bytes(descriptor_offset))
}

/// Parse the entries table and return the TDVF sections
pub fn parse_sections(fd: &mut std::fs::File) -> Result<Vec<TdvfSection>, Error> {
    let offset = calculate_tdvf_descriptor_offset(fd)?;
    fd.seek(SeekFrom::End(-(offset as i64)))
        .map_err(Error::TableSeek)?;
    let mut descriptor: TdvfDescriptor = Default::default();
    fd.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            &mut descriptor as *mut _ as *mut u8,
            std::mem::size_of::<TdvfDescriptor>(),
        )
    })
    .map_err(Error::TableRead)?;

    if &descriptor.signature != b"TDVF" {
        return Err(Error::InvalidDescriptorSignature);
    }

    let metadata_size = std::mem::size_of::<TdvfDescriptor>()
        + std::mem::size_of::<TdvfSection>() * descriptor.number_of_section_entry as usize;
    if descriptor.length as usize != metadata_size {
        return Err(Error::InvalidDescriptorSize);
    }

    if descriptor.version != 1 {
        return Err(Error::InvalidDescriptorVersion);
    }

    let mut sections = Vec::new();
    sections.resize_with(
        descriptor.number_of_section_entry as usize,
        TdvfSection::default,
    );

    fd.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            sections.as_mut_ptr() as *mut u8,
            descriptor.number_of_section_entry as usize * std::mem::size_of::<TdvfSection>(),
        )
    })
    .map_err(Error::TableRead)?;

    Ok(sections)
}

/// Given the sections in the TDVF table, return the HOB (Hand-off Block) section
pub fn get_hob_section(sections: &Vec<TdvfSection>) -> Option<&TdvfSection> {
    for section in sections {
        match section.section_type {
            TdvfSectionType::TdHob => {
                return Some(section);
            }
            _ => continue,
        }
    }
    None
}
