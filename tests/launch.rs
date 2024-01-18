// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;

// Defined in linux/arch/x86/include/uapi/asm/kvm.h
const KVM_X86_TDX_VM: u64 = 2;

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();
    let vm_fd = kvm_fd.create_vm_with_type(KVM_X86_TDX_VM).unwrap();
}
