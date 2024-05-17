// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;

use tdx::launch::TdxVm;

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();
    let tdx_vm = TdxVm::new(&kvm_fd, 100).unwrap();
    let caps = tdx_vm.get_capabilities().unwrap();
    let _ = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();
    let _vcpufd = tdx_vm.fd.create_vcpu(0).unwrap();
}
