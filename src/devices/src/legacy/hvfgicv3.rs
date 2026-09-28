// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::LazyLock;

use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

use hvf::bindings::{
    hv_gic_config_t, hv_gic_msi_reg_t_HV_GIC_REG_GICM_SET_SPI_NSR, hv_ipa_t, hv_return_t,
    HV_SUCCESS,
};
use hvf::Error;
use utils::eventfd::EventFd;

// Device trees specific constants
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

pub struct HvfGicBindings {
    hv_gic_create:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t) -> hv_return_t>,
    hv_gic_config_create: libloading::Symbol<'static, unsafe extern "C" fn() -> hv_gic_config_t>,
    hv_gic_config_set_distributor_base:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t>,
    hv_gic_config_set_redistributor_base:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t>,
    hv_gic_config_set_msi_region_base:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t>,
    hv_gic_config_set_msi_interrupt_range:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, u32, u32) -> hv_return_t>,
    hv_gic_get_distributor_size:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_get_redistributor_size:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_get_msi_region_size:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_get_msi_region_base_alignment:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_get_spi_interrupt_range:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut u32, *mut u32) -> hv_return_t>,
    hv_gic_set_spi: libloading::Symbol<'static, unsafe extern "C" fn(u32, bool) -> hv_return_t>,
    hv_gic_send_msi: libloading::Symbol<'static, unsafe extern "C" fn(hv_ipa_t, u32) -> hv_return_t>,
}

pub struct HvfGicV3 {
    bindings: HvfGicBindings,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,

    /// Address of the Hypervisor.framework GIC MSI SET_SPI_NSR register.
    msi_addr: hv_ipa_t,
}

static HVF: LazyLock<libloading::Library> = LazyLock::new(|| unsafe {
    libloading::Library::new(
        "/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor",
    )
    .unwrap()
});

impl HvfGicV3 {
    pub fn new(vcpu_count: u64) -> Result<Self, Error> {
        let bindings = unsafe {
            HvfGicBindings {
                hv_gic_create: HVF.get(b"hv_gic_create").map_err(Error::FindSymbol)?,
                hv_gic_config_create: HVF
                    .get(b"hv_gic_config_create")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_distributor_base: HVF
                    .get(b"hv_gic_config_set_distributor_base")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_redistributor_base: HVF
                    .get(b"hv_gic_config_set_redistributor_base")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_msi_region_base: HVF
                    .get(b"hv_gic_config_set_msi_region_base")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_msi_interrupt_range: HVF
                    .get(b"hv_gic_config_set_msi_interrupt_range")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_distributor_size: HVF
                    .get(b"hv_gic_get_distributor_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_redistributor_size: HVF
                    .get(b"hv_gic_get_redistributor_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_msi_region_size: HVF
                    .get(b"hv_gic_get_msi_region_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_msi_region_base_alignment: HVF
                    .get(b"hv_gic_get_msi_region_base_alignment")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_spi_interrupt_range: HVF
                    .get(b"hv_gic_get_spi_interrupt_range")
                    .map_err(Error::FindSymbol)?,
                hv_gic_set_spi: HVF.get(b"hv_gic_set_spi").map_err(Error::FindSymbol)?,
                hv_gic_send_msi: HVF.get(b"hv_gic_send_msi").map_err(Error::FindSymbol)?,
            }
        };

        let mut dist_size: usize = 0;
        let ret = unsafe { (bindings.hv_gic_get_distributor_size)(&mut dist_size) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }
        let dist_size = dist_size as u64;

        let mut redist_size: usize = 0;
        let ret = unsafe { (bindings.hv_gic_get_redistributor_size)(&mut redist_size) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let redists_size = redist_size as u64 * vcpu_count;
        let dist_addr = arch::MMIO_MEM_START - dist_size - redists_size;
        let redists_addr = arch::MMIO_MEM_START - redists_size;

        let gic_config = unsafe { (bindings.hv_gic_config_create)() };
        let ret = unsafe { (bindings.hv_gic_config_set_distributor_base)(gic_config, dist_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let ret = unsafe {
            (bindings.hv_gic_config_set_redistributor_base)(
                gic_config,
                arch::MMIO_MEM_START - redists_size,
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let mut msi_region_size: usize = 0;
        let ret = unsafe { (bindings.hv_gic_get_msi_region_size)(&mut msi_region_size) };
        if ret != HV_SUCCESS || msi_region_size == 0 {
            return Err(Error::VmCreate);
        }

        let mut msi_region_alignment: usize = 0;
        let ret = unsafe {
            (bindings.hv_gic_get_msi_region_base_alignment)(&mut msi_region_alignment)
        };
        if ret != HV_SUCCESS
            || msi_region_alignment == 0
            || !msi_region_alignment.is_power_of_two()
        {
            return Err(Error::VmCreate);
        }

        let msi_region_size = msi_region_size as u64;
        let msi_region_alignment = msi_region_alignment as u64;
        let msi_addr = dist_addr
            .checked_sub(msi_region_size)
            .map(|addr| addr & !(msi_region_alignment - 1))
            .ok_or(Error::VmCreate)?;

        let ret = unsafe {
            (bindings.hv_gic_config_set_msi_region_base)(gic_config, msi_addr)
        };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let mut spi_base = 0u32;
        let mut spi_count = 0u32;
        let ret = unsafe {
            (bindings.hv_gic_get_spi_interrupt_range)(&mut spi_base, &mut spi_count)
        };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        // Keep ordinary MMIO devices on the low end of libkrun's SPI range and
        // reserve the upper 32 IDs for MSI-delivered virtio-net interrupts.
        const MSI_IRQ_COUNT: u32 = 32;
        let msi_irq_base = arch::IRQ_MAX + 1 - MSI_IRQ_COUNT;
        let spi_end = spi_base.checked_add(spi_count).ok_or(Error::VmCreate)?;
        if msi_irq_base < spi_base || arch::IRQ_MAX >= spi_end {
            return Err(Error::VmCreate);
        }

        let ret = unsafe {
            (bindings.hv_gic_config_set_msi_interrupt_range)(
                gic_config,
                msi_irq_base,
                MSI_IRQ_COUNT,
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let ret = unsafe { (bindings.hv_gic_create)(gic_config) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        Ok(Self {
            bindings,
            properties: [dist_addr, dist_size, redists_addr, redists_size],
            vcpu_count,
            msi_addr: msi_addr + hv_gic_msi_reg_t_HV_GIC_REG_GICM_SET_SPI_NSR as u64,
        })
    }
}

impl IrqChipT for HvfGicV3 {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(irq_line) = irq_line {
            let ret = unsafe { (self.bindings.hv_gic_set_spi)(irq_line, true) };
            if ret != HV_SUCCESS {
                Err(DeviceError::FailedSignalingUsedQueue(
                    std::io::Error::other("HVF returned error when setting SPI"),
                ))
            } else {
                Ok(())
            }
        } else {
            Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "IRQ not line configured",
            )))
        }
    }

    fn send_msi(&self, irq_line: Option<u32>) -> Result<(), DeviceError> {
        if let Some(irq_line) = irq_line {
            let ret = unsafe { (self.bindings.hv_gic_send_msi)(self.msi_addr, irq_line) };
            if ret != HV_SUCCESS {
                Err(DeviceError::FailedSignalingUsedQueue(
                    std::io::Error::other("HVF returned error when sending MSI"),
                ))
            } else {
                Ok(())
            }
        } else {
            Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "MSI IRQ not configured",
            )))
        }
    }
}

impl BusDevice for HvfGicV3 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for HvfGicV3 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-v3".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        7
    }
}
