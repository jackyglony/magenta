// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <dev/iommu/intel.h>

#include "hw.h"

#include <err.h>
#include <kernel/auto_lock.h>
#include <kernel/vm.h>
#include <kernel/vm/vm_aspace.h>
#include <kernel/vm/vm_object_paged.h>
#include <mxalloc/new.h>
#include <mxtl/algorithm.h>
#include <mxtl/ref_ptr.h>
#include <platform.h>
#include <trace.h>

#define LOCAL_TRACE 1

IntelIommu::IntelIommu(uint64_t id, volatile void* register_base,
                       mxtl::RefPtr<VmObject> backing_vmo)
    : Iommu(id), mmio_(register_base), backing_vmo_(mxtl::move(backing_vmo)) {
}

mxtl::RefPtr<Iommu> IntelIommu::Create(uint64_t id, paddr_t register_base) {
    const uint64_t vmo_size = needed_backing_vmo_size();
    mxtl::RefPtr<VmObject> vmo(VmObjectPaged::Create(0, vmo_size));
    if (!vmo) {
        return nullptr;
    }

    auto kernel_aspace = VmAspace::kernel_aspace();
    void *vaddr;
    status_t status = kernel_aspace->AllocPhysical(
            "iommu",
            PAGE_SIZE,
            &vaddr,
            PAGE_SIZE_SHIFT,
            register_base,
            0,
            ARCH_MMU_FLAG_PERM_READ | ARCH_MMU_FLAG_PERM_WRITE);
    if (status != NO_ERROR) {
        TRACEF("Failed to create wakeup bootstrap aspace\n");
        return nullptr;
    }

    AllocChecker ac;
    auto instance = mxtl::AdoptRef<IntelIommu>(new (&ac) IntelIommu(id, vaddr, mxtl::move(vmo)));
    if (!ac.check()) {
        kernel_aspace->FreeRegion(reinterpret_cast<vaddr_t>(vaddr));
        return nullptr;
    }

    status = instance->Initialize();
    if (status != NO_ERROR) {
        return nullptr;
    }

    RegisterIommu(instance);
    return instance;
}

IntelIommu::~IntelIommu() {
    AutoLock guard(&lock_);

    // We cannot unpin memory until translation is disabled
    status_t status = SetTranslationEnableLocked(false, INFINITE_TIME);
    ASSERT(status == NO_ERROR);

    backing_vmo_->Unpin(0, allocated_pages_ * PAGE_SIZE);
    VmAspace::kernel_aspace()->FreeRegion(mmio_.base());
}

bool IntelIommu::IsValidBusTxnId(uint64_t bus_txn_id) const {
    // TODO(teisenbe): Decode the txn id and check against configuration.
    if (bus_txn_id > UINT16_MAX) {
        return false;
    }
    return true;
}

status_t IntelIommu::Map(uint64_t bus_txn_id, paddr_t paddr, size_t size, uint32_t perms,
                         dev_vaddr_t* vaddr) {
    DEBUG_ASSERT(vaddr);
    if (!IS_PAGE_ALIGNED(paddr) || !IS_PAGE_ALIGNED(size)) {
        return ERR_INVALID_ARGS;
    }
    if (perms & ~(IOMMU_FLAG_PERM_READ | IOMMU_FLAG_PERM_WRITE | IOMMU_FLAG_PERM_EXECUTE)) {
        return ERR_INVALID_ARGS;
    }
    if (perms == 0) {
        return ERR_INVALID_ARGS;
    }
    return NO_ERROR;
}

status_t IntelIommu::Unmap(uint64_t bus_txn_id, dev_vaddr_t vaddr, size_t size) {
    if (!IS_PAGE_ALIGNED(vaddr) || !IS_PAGE_ALIGNED(size)) {
        return ERR_INVALID_ARGS;
    }
    return NO_ERROR;
}

status_t IntelIommu::ClearMappingsForBusTxnId(uint64_t bus_txn_id) {
    return NO_ERROR;
}


status_t IntelIommu::Initialize() {
    namespace reg = intel_iommu::reg;

    AutoLock guard(&lock_);

    // Ensure we support this device version
    auto version = reg::Version::Get().ReadFrom(&mmio_);
    if (version.major() != 1 && version.minor() != 0) {
        LTRACEF("Unsupported IOMMU version: %u.%u\n", version.major(), version.minor());
        return ERR_NOT_SUPPORTED;
    }

    // Cache useful capability info
    auto caps = reg::Capability::Get().ReadFrom(&mmio_);
    auto ext_caps = reg::ExtendedCapability::Get().ReadFrom(&mmio_);
    requires_write_buf_flushing_ = caps.required_write_buf_flushing();
    supports_read_draining_ = caps.supports_read_draining();
    supports_write_draining_ = caps.supports_write_draining();
    max_guest_addr_mask_ = (1ULL << (caps.max_guest_addr_width() + 1)) - 1;
    iotlb_reg_offset_ = static_cast<uint32_t>(ext_caps.iotlb_register_offset() * 16);
    if (iotlb_reg_offset_ > PAGE_SIZE - 16) {
        LTRACEF("Unsupported IOMMU: IOTLB offset runs past the register page\n");
        return ERR_NOT_SUPPORTED;
    }
    supports_extended_context_ = ext_caps.supports_extended_context();
    supports_pasid_ = ext_caps.supports_pasid();
    if (supports_pasid_) {
        valid_pasid_mask_ = static_cast<uint32_t>((1ULL << (ext_caps.pasid_size() + 1)) - 1);
    }

    const uint64_t num_domains  = caps.num_domains();
    if (num_domains > 0x6) {
        LTRACEF("Unknown num_domains value\n");
        return ERR_NOT_SUPPORTED;
    }
    num_supported_domains_ = static_cast<uint32_t>(4 + 2 * num_domains);

    auto global_ctl = reg::GlobalControl::Get().ReadFrom(&mmio_);
    if (global_ctl.translation_enable()) {
        LTRACEF("DMA remapping already enabled?!\n");
        return ERR_BAD_STATE;
    }

    uint64_t root_table_offset;
    status_t status = AllocatePagesLocked(1, &root_table_offset);
    if (status != NO_ERROR) {
        LTRACEF("Alloc failed\n");
        return status;
    }
    paddr_t root_table_paddr;
    auto lookup_fn = [](void* context, size_t offset, size_t index, paddr_t pa) -> status_t {
        *static_cast<paddr_t*>(context) = pa;
        return NO_ERROR;
    };
    status = backing_vmo_->Lookup(root_table_offset, PAGE_SIZE, 0, lookup_fn, &root_table_paddr);
    ASSERT(status == NO_ERROR);

    status = SetRootTablePointerLocked(root_table_paddr);
    if (status != NO_ERROR) {
        LTRACEF("set root table failed\n");
        return status;
    }

    status = SetTranslationEnableLocked(true, current_time() + LK_SEC(1));
    if (status != NO_ERROR) {
        LTRACEF("set translation enable failed\n");
        return status;
    }

    return NO_ERROR;
}

// Sets the root table pointer and invalidates the context-cache and IOTLB.
status_t IntelIommu::SetRootTablePointerLocked(paddr_t pa) {
    namespace reg = intel_iommu::reg;

    DEBUG_ASSERT(IS_PAGE_ALIGNED(pa));

    auto root_table_addr = reg::RootTableAddress::Get().FromValue(0);
    // TODO: Make enum for this, and handle more gracefully if not supported.
    DEBUG_ASSERT(supports_extended_context_);
    root_table_addr.set_root_table_type(1);
    root_table_addr.set_root_table_address(pa >> PAGE_SIZE_SHIFT);
    root_table_addr.WriteTo(&mmio_);

    auto global_ctl = reg::GlobalControl::Get().ReadFrom(&mmio_);
    DEBUG_ASSERT(!global_ctl.translation_enable());
    global_ctl.set_root_table_ptr(1);
    global_ctl.WriteTo(&mmio_);
    status_t status = WaitForValueLocked(&global_ctl, &decltype(global_ctl)::root_table_ptr,
                                         1, current_time() + LK_SEC(1));
    if (status != NO_ERROR) {
        LTRACEF("Timed out waiting for root_table_ptr bit to take\n");
        return status;
    }

    status = InvalidateContextCacheGlobalLocked();
    if (status != NO_ERROR) {
        return status;
    }

    status = InvalidateIotlbGlobalLocked();
    if (status != NO_ERROR) {
        return status;
    }

    return NO_ERROR;
}

status_t IntelIommu::SetTranslationEnableLocked(bool enabled, lk_time_t deadline) {
    auto global_ctl = intel_iommu::reg::GlobalControl::Get().ReadFrom(&mmio_);
    global_ctl.set_translation_enable(enabled);
    global_ctl.WriteTo(&mmio_);

    return WaitForValueLocked(&global_ctl, &decltype(global_ctl)::translation_enable,
                              enabled, deadline);
}

status_t IntelIommu::InvalidateContextCacheGlobalLocked() {
    DEBUG_ASSERT(lock_.IsHeld());

    auto context_cmd = intel_iommu::reg::ContextCommand::Get().FromValue(0);
    context_cmd.set_invld_context_cache(1);
    // TODO: make this an enum
    context_cmd.set_invld_request_granularity(1);
    context_cmd.WriteTo(&mmio_);

    return WaitForValueLocked(&context_cmd, &decltype(context_cmd)::invld_context_cache, 0,
                              INFINITE_TIME);
}

status_t IntelIommu::InvalidateIotlbGlobalLocked() {
    DEBUG_ASSERT(lock_.IsHeld());

    auto iotlb_invld = intel_iommu::reg::IotlbInvalidate::Get(iotlb_reg_offset_).ReadFrom(&mmio_);
    iotlb_invld.set_invld_iotlb(1);
    // TODO: make this an enum
    iotlb_invld.set_invld_request_granularity(1);
    iotlb_invld.WriteTo(&mmio_);

    return WaitForValueLocked(&iotlb_invld, &decltype(iotlb_invld)::invld_iotlb, 0,
                              INFINITE_TIME);
}

status_t IntelIommu::AllocatePagesLocked(size_t count, uint64_t* base_offset) {
    DEBUG_ASSERT(lock_.IsHeld());

    const size_t base = allocated_pages_ * PAGE_SIZE;
    status_t status = backing_vmo_->CommitRange(base, count * PAGE_SIZE, nullptr);
    if (status != NO_ERROR) {
        return status;
    }
    status = backing_vmo_->Pin(base, count * PAGE_SIZE);
    if (status != NO_ERROR) {
        return status;
    }
    *base_offset = allocated_pages_ * PAGE_SIZE;
    allocated_pages_ += count;
    return NO_ERROR;
}

uint64_t IntelIommu::needed_backing_vmo_size() {
    namespace ds = intel_iommu::ds;
    return sizeof(ds::RootTable) +
            2 * ds::RootTable::kNumEntries * sizeof(ds::ExtendedContextTable);
}

template <class RegType>
status_t IntelIommu::WaitForValueLocked(RegType* reg,
                                        typename RegType::ValueType (RegType::*getter)(),
                                        typename RegType::ValueType value,
                                        lk_time_t deadline) {
    DEBUG_ASSERT(lock_.IsHeld());

    const lk_time_t kMaxSleepDuration = LK_USEC(10);

    while (true) {
        reg->ReadFrom(&mmio_);
        if ((reg->*getter)() == value) {
            return NO_ERROR;
        }

        const lk_time_t now = current_time();
        if (now > deadline) {
            break;
        }

        lk_time_t sleep_deadline = mxtl::min(now + kMaxSleepDuration, deadline);
        thread_sleep(sleep_deadline);
    }
    return ERR_TIMED_OUT;
}
