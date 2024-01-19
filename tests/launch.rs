// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;

use tdx::vm::TdxVm;

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();
    let tdx_vm = TdxVm::new(kvm_fd).unwrap();
    let _caps = tdx_vm.get_capabilities().unwrap();
}
