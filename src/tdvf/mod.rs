// SPDX-License-Identifier: Apache-2.0

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
