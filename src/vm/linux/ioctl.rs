// SPDX-License-Identifier: Apache-2.0

use crate::linux::{Cmd, CmdId};
use crate::vm::linux::types::{Capabilities, InitVm};

impl From<&Capabilities> for Cmd {
    fn from(caps: &Capabilities) -> Self {
        Self {
            id: CmdId::GetCapabilities as u32,
            flags: 0,
            data: caps as *const Capabilities as _,
            error: 0,
            _unused: 0,
        }
    }
}

impl From<&InitVm> for Cmd {
    fn from(init_vm: &InitVm) -> Self {
        Self {
            id: CmdId::InitVm as u32,
            flags: 0,
            data: init_vm as *const InitVm as _,
            error: 0,
            _unused: 0,
        }
    }
}
