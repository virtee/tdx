// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Seek, SeekFrom};
use uuid::Uuid;

const EXPECTED_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const EXPECTED_METADATA_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";

#[repr(packed)]
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

#[repr(packed)]
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
