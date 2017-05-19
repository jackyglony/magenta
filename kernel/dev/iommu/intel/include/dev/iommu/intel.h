// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <dev/iommu.h>
#include <hwreg/mmio.h>
#include <kernel/mutex.h>
#include <mxtl/ref_ptr.h>

class VmObject;

class IntelIommu final : public Iommu {
public:
    static mxtl::RefPtr<Iommu> Create(uint64_t id, paddr_t register_base);

    bool IsValidBusTxnId(uint64_t bus_txn_id) const final;

    status_t Map(uint64_t bus_txn_id, paddr_t paddr, size_t size, uint32_t perms,
                 dev_vaddr_t* vaddr) final;
    status_t Unmap(uint64_t bus_txn_id, dev_vaddr_t vaddr, size_t size) final;

    status_t ClearMappingsForBusTxnId(uint64_t bus_txn_id) final;

    ~IntelIommu() final;

private:
    IntelIommu(uint64_t id, volatile void* register_base, mxtl::RefPtr<VmObject> backing_vmo);

    // Compute the minimum size for the backing VMO (pages will be
    // committed/pinned as used.
    static uint64_t needed_backing_vmo_size();

    // Set up initial structures
    status_t Initialize();

    // Allocate and pin N pages
    status_t AllocatePagesLocked(size_t count, uint64_t* base_offset) TA_REQ(lock_);

    status_t InvalidateContextCacheGlobalLocked() TA_REQ(lock_);
    status_t InvalidateIotlbGlobalLocked() TA_REQ(lock_);
    status_t SetRootTablePointerLocked(paddr_t pa) TA_REQ(lock_);
    status_t SetTranslationEnableLocked(bool enabled, lk_time_t deadline) TA_REQ(lock_);

    // Utility for waiting until a register field changes to a value, timing out
    // if the deadline elapses.  If deadline is INFINITE_TIME, then will never time
    // out.  Can only return NO_ERROR and ERR_TIMED_OUT.
    template <class RegType>
    status_t WaitForValueLocked(RegType* reg,
                                typename RegType::ValueType (RegType::*getter)(),
                                typename RegType::ValueType value,
                                lk_time_t deadline) TA_REQ(lock_);

    Mutex lock_;

    // Location of the memory-mapped hardware register bank.
    hwreg::RegisterIo mmio_ TA_GUARDED(lock_);
    // VMO backing the memory for all of the IOMMU memory-mapped datastructures.
    const mxtl::RefPtr<VmObject> backing_vmo_ TA_GUARDED(lock_);
    size_t allocated_pages_ TA_GUARDED(lock_) = 0;

    // A mask with bits set for each usable bit in an addres with the largest allowed
    // address width.  E.g., if the largest allowed width is 48-bit,
    // max_guest_addr_mask will be 0xffff_ffff_ffff.
    uint64_t max_guest_addr_mask_ TA_GUARDED(lock_) = 0;
    uint32_t num_supported_domains_ TA_GUARDED(lock_) = 0;
    uint32_t valid_pasid_mask_ TA_GUARDED(lock_) = 0;
    uint32_t iotlb_reg_offset_ TA_GUARDED(lock_) = 0;
    bool requires_write_buf_flushing_ TA_GUARDED(lock_) = false;
    bool supports_read_draining_ TA_GUARDED(lock_) = false;
    bool supports_write_draining_ TA_GUARDED(lock_) = false;
    bool supports_pasid_ TA_GUARDED(lock_) = false;
    bool supports_extended_context_ TA_GUARDED(lock_) = false;
};
