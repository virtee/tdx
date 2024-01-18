[![Workflow Status](https://github.com/virtee/tdx/workflows/test/badge.svg)](https://github.com/virtee/tdx/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/virtee/tdx.svg)](https://isitmaintained.com/project/virtee/tdx "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/virtee/tdx.svg)](https://isitmaintained.com/project/virtee/tdx "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# tdx

The `tdx` crate provides an implementation of APIs for [Intel Trusted Domain eXtensions (TDX)](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html).

### TDX APIs

The Linux kernel exposes APIs for managing TDX-enabled KVM virtual machines

This crate implements those APIs and offers them to Rust client code through a
flexible and type-safe high-level interface.

### TDX KVM VM APIs

Refer to the [`vm`] module for more information.

### TDX KVM vCPU APIs

Refer to the [`vcpu`] module for more information.

### Remarks

Note that the Linux kernel provides access to these APIs through a set
of `ioctl`s that are meant to be called on the `/dev/kvm` device node.
As a result, these `ioctl`s form the substrate of the `tdx` crate.
Binaries that result from consumers of this crate are expected to run as
a process with the necessary privileges to interact with the device nodes.

[`vm`]: ./src/vm/
[`vcpu`]: ./src/vcpu/

License: Apache-2.0
