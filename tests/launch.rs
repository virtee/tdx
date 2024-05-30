// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;

use tdx::launch::TdxVm;
use tdx::tdvf;

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();

    // create vm
    let tdx_vm = TdxVm::new(&kvm_fd, 100).unwrap();
    let caps = tdx_vm.get_capabilities().unwrap();
    let _ = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();

    // create vcpu
    let _vcpufd = tdx_vm.fd.create_vcpu(10).unwrap();
    let mut firmware = std::fs::File::open("./tests/data/OVMF.inteltdx.fd").unwrap();
    let sections = tdvf::parse_sections(&mut firmware).unwrap();
    let _hob_section = tdvf::get_hob_section(&sections).unwrap();
}
