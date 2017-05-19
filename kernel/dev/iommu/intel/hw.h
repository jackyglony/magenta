// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <err.h>
#include <magenta/compiler.h>
#include <hwreg/bitfields.h>
#include <stdint.h>

namespace intel_iommu {

namespace reg {

class Version : public hwreg::RegisterBase<uint32_t> {
 public:
    static constexpr uint32_t kAddr = 0x0;
    static auto Get() { return hwreg::RegisterAddr<Version>(kAddr); }

    DEF_FIELD(3, 0, minor);
    DEF_FIELD(7, 4, major);
    DEF_RSVDZ_FIELD(31, 8);
};

class Capability : public hwreg::RegisterBase<uint64_t> {
 public:
    static constexpr uint32_t kAddr = 0x8;
    static auto Get() { return hwreg::RegisterAddr<Capability>(kAddr); }

    DEF_FIELD(2, 0, num_domains);
    DEF_BIT(3, adv_fault_logging);
    DEF_BIT(4, required_write_buf_flushing);
    DEF_BIT(5, supports_protected_low_mem);
    DEF_BIT(6, supports_protected_high_mem);
    DEF_BIT(7, caching_mode);
    DEF_RSVDZ_BIT(8);
    DEF_BIT(9, supports_39_bit_agaw);
    DEF_BIT(10, supports_48_bit_agaw);
    DEF_RSVDZ_BIT(11);
    DEF_RSVDZ_BIT(12);
    DEF_RSVDZ_FIELD(15, 13);
    DEF_FIELD(21, 16, max_guest_addr_width);
    DEF_BIT(22, supports_zero_length_read);
    DEF_RSVDZ_BIT(23);
    DEF_FIELD(33, 24, fault_recording_reg_offset);
    DEF_BIT(34, supports_second_level_2mb_page);
    DEF_BIT(35, supports_second_level_1gb_page);
    DEF_RSVDZ_FIELD(37, 36);
    DEF_RSVDZ_BIT(38);
    DEF_BIT(39, supports_page_selective_invld);
    DEF_FIELD(47, 40, num_fault_recording_reg);
    DEF_FIELD(53, 48, max_addr_mask_value);
    DEF_BIT(54, supports_write_draining);
    DEF_BIT(55, supports_read_draining);
    DEF_BIT(56, supports_first_level_1gb_page);
    DEF_RSVDZ_FIELD(58, 57);
    DEF_BIT(59, supports_posted_interrupts);
    DEF_RSVDZ_FIELD(63, 60);
};

class ExtendedCapability : public hwreg::RegisterBase<uint64_t> {
 public:
    static constexpr uint32_t kAddr = 0x10;
    static auto Get() { return hwreg::RegisterAddr<ExtendedCapability>(kAddr); }

    DEF_BIT(0, page_walk_coherency);
    DEF_BIT(1, supports_queued_invld);
    DEF_BIT(2, supports_device_tlb);
    DEF_BIT(3, supports_interrupt_remapping);
    DEF_BIT(4, supports_extended_interrupt_mode);
    DEF_BIT(6, supports_pass_through);
    DEF_BIT(7, supports_snoop_control);
    DEF_FIELD(17, 8, iotlb_register_offset);
    DEF_RSVDZ_FIELD(19, 18);
    DEF_FIELD(23, 20, max_handle_mask_value);
    DEF_BIT(24, supports_extended_context);
    DEF_BIT(25, supports_memory_type);
    DEF_BIT(26, supports_nested_translation);
    DEF_BIT(27, supports_deferred_invld);
    DEF_BIT(28, supports_pasid);
    DEF_BIT(29, supports_page_requests);
    DEF_BIT(30, supports_execute_requests);
    DEF_BIT(31, supports_supervisor_requests);
    DEF_RSVDZ_BIT(32);
    DEF_BIT(33, supports_no_write_flag);
    DEF_BIT(34, supports_extended_accessed_flag);
    DEF_FIELD(39, 35, pasid_size);
    DEF_RSVDZ_FIELD(63, 40);
};

// This is a merger of the Global Command and Global Status registers.
class GlobalControl : public hwreg::RegisterBase<uint32_t> {
 public:
    static constexpr uint32_t kWriteAddr = 0x18;
    static constexpr uint32_t kReadAddr = 0x1c;
    static auto Get() { return hwreg::RegisterAddr<GlobalControl>(kReadAddr); }

    DEF_RSVDZ_FIELD(22, 0);
    DEF_BIT(23, compat_format_interrupt);
    DEF_BIT(24, interrupt_remap_table_ptr);
    DEF_BIT(25, interrupt_remap_enable);
    DEF_BIT(26, queued_invld_enable);
    DEF_BIT(27, write_buffer_flush);
    DEF_BIT(28, adv_fault_logging_enable);
    DEF_BIT(29, fault_log);
    DEF_BIT(30, root_table_ptr);
    DEF_BIT(31, translation_enable);

    // This redefines functions from RegisterBase which are not virtual.
    // This is safe, since no callers operate on this type as its base class.
    void ReadFrom(hwreg::RegisterIo* reg_io) {
        hwreg::RegisterBase<uint32_t>::set_reg_addr(kReadAddr);
        return hwreg::RegisterBase<uint32_t>::ReadFrom(reg_io);
    }
    void WriteTo(hwreg::RegisterIo* reg_io) {
        hwreg::RegisterBase<uint32_t>::set_reg_addr(kWriteAddr);
        return hwreg::RegisterBase<uint32_t>::WriteTo(reg_io);
    }
};

class RootTableAddress : public hwreg::RegisterBase<uint64_t> {
 public:
    static constexpr uint32_t kAddr = 0x20;
    static auto Get() { return hwreg::RegisterAddr<RootTableAddress>(kAddr); }

    DEF_RSVDZ_FIELD(10, 0);
    DEF_BIT(11, root_table_type);
    DEF_FIELD(63, 12, root_table_address);
};

class ContextCommand : public hwreg::RegisterBase<uint64_t> {
public:
    static constexpr uint32_t kAddr = 0x28;
    static auto Get() { return hwreg::RegisterAddr<ContextCommand>(kAddr); }

    DEF_FIELD(15, 0, domain_id);
    DEF_FIELD(31, 16, source_id);
    DEF_FIELD(33, 32, function_mask);
    DEF_RSVDZ_FIELD(58, 34);
    DEF_FIELD(60, 59, actual_invld_granularity);
    DEF_FIELD(62, 61, invld_request_granularity);
    DEF_BIT(63, invld_context_cache);
};

class InvalidateAddress : public hwreg::RegisterBase<uint64_t> {
 public:
    static constexpr uint32_t kInstanceOffset = 0x0;
    static auto Get(uint32_t iotlb_base) {
        return hwreg::RegisterAddr<InvalidateAddress>(iotlb_base + kInstanceOffset);
    }

    DEF_FIELD(5, 0, address_mask);
    DEF_BIT(6, invld_hint);
    DEF_RSVDZ_FIELD(11, 7);
    DEF_FIELD(63, 12, address);
};

class IotlbInvalidate : public hwreg::RegisterBase<uint64_t> {
 public:
    static constexpr uint32_t kInstanceOffset = 0x08;
    static auto Get(uint32_t iotlb_base) {
        return hwreg::RegisterAddr<IotlbInvalidate>(iotlb_base + kInstanceOffset);
    }

    DEF_FIELD(47, 32, domain_id);
    DEF_BIT(48, drain_writes);
    DEF_BIT(49, drain_reads);
    DEF_RSVDZ_FIELD(56, 50);
    DEF_FIELD(58, 57, actual_invld_granularity);
    DEF_RSVDZ_BIT(59);
    DEF_FIELD(61, 60, invld_request_granularity);
    DEF_RSVDZ_BIT(62);
    DEF_BIT(63, invld_iotlb);
};

} // namespace reg

namespace ds {

struct RootEntry {
    uint64_t raw[2];

    DEF_SUBBIT(raw[0], 0, lower_present);
    DEF_SUBFIELD(raw[0], 63, 12, lower_context_table);
    DEF_SUBBIT(raw[1], 0, upper_present);
    DEF_SUBFIELD(raw[1], 63, 12, upper_context_table);
};
static_assert(mxtl::is_pod<RootEntry>::value, "not POD");
static_assert(sizeof(RootEntry) == 16, "wrong size");

struct RootTable {
    static constexpr size_t kNumEntries = 256;
    RootEntry entry[kNumEntries];
};
static_assert(mxtl::is_pod<RootTable>::value, "not POD");
static_assert(sizeof(RootTable) == 4096, "wrong size");

struct ContextEntry {
    uint64_t raw[2];

    DEF_SUBBIT(raw[0], 0, present);
    DEF_SUBBIT(raw[0], 1, fault_processing_disable);
    DEF_SUBFIELD(raw[0], 3, 2, translation_type);
    DEF_SUBFIELD(raw[0], 63, 12, second_level_pt_ptr);
    DEF_SUBFIELD(raw[1], 2, 0, address_width);
    DEF_SUBFIELD(raw[1], 6, 3, hw_ignored);
    DEF_SUBFIELD(raw[1], 23, 8, domain_id);
};
static_assert(mxtl::is_pod<ContextEntry>::value, "not POD");
static_assert(sizeof(ContextEntry) == 16, "wrong size");

struct ContextTable {
    static constexpr size_t kNumEntries = 256;
    ContextEntry entry[kNumEntries];
};
static_assert(mxtl::is_pod<ContextTable>::value, "not POD");
static_assert(sizeof(ContextTable) == 4096, "wrong size");

struct ExtendedContextEntry {
    uint64_t raw[4];

    DEF_SUBBIT(raw[0], 0, present);
    DEF_SUBBIT(raw[0], 1, fault_processing_disable);
    DEF_SUBFIELD(raw[0], 4, 2, translation_type);
    DEF_SUBFIELD(raw[0], 7, 5, extended_mem_type);
    DEF_SUBBIT(raw[0], 8, deferred_invld_enable);
    DEF_SUBBIT(raw[0], 9, page_request_enable);
    DEF_SUBBIT(raw[0], 10, nested_translation_enable);
    DEF_SUBBIT(raw[0], 11, pasid_enable);
    DEF_SUBFIELD(raw[0], 63, 12, second_level_pt_ptr);

    DEF_SUBFIELD(raw[1], 2, 0, address_width);
    DEF_SUBBIT(raw[1], 3, global_page_enable);
    DEF_SUBBIT(raw[1], 4, no_exec_enable);
    DEF_SUBBIT(raw[1], 5, write_protect_enable);
    DEF_SUBBIT(raw[1], 6, cache_disable);
    DEF_SUBBIT(raw[1], 7, extended_mem_type_enable);
    DEF_SUBFIELD(raw[1], 23, 8, domain_id);
    DEF_SUBBIT(raw[1], 24, smep_enable);
    DEF_SUBBIT(raw[1], 25, extended_accessed_flag_enable);
    DEF_SUBBIT(raw[1], 26, extended_requests_enable);
    DEF_SUBBIT(raw[1], 27, second_level_execute_bit_enable);
    DEF_SUBFIELD(raw[1], 63, 32, page_attribute_table);

    DEF_SUBFIELD(raw[2], 3, 0, pasid_table_size);
    DEF_SUBFIELD(raw[2], 63, 12, pasid_table_ptr);

    DEF_SUBFIELD(raw[3], 63, 12, pasid_state_table_ptr);
};
static_assert(mxtl::is_pod<ExtendedContextEntry>::value, "not POD");
static_assert(sizeof(ExtendedContextEntry) == 32, "wrong size");

struct ExtendedContextTable {
    static constexpr size_t kNumEntries = 128;
    ExtendedContextEntry entry[kNumEntries];
};
static_assert(mxtl::is_pod<ExtendedContextTable>::value, "not POD");
static_assert(sizeof(ExtendedContextTable) == 4096, "wrong size");

struct PasidEntry {
    uint64_t raw;

    DEF_SUBBIT(raw, 0, present);
    DEF_SUBBIT(raw, 3, page_level_write_through);
    DEF_SUBBIT(raw, 4, page_level_cache_disable);
    DEF_SUBBIT(raw, 11, supervisor_requests_enable);
    DEF_SUBFIELD(raw, 63, 12, first_level_pt_ptr);
};
static_assert(mxtl::is_pod<PasidEntry>::value, "not POD");
static_assert(sizeof(PasidEntry) == 8, "wrong size");

struct PasidState {
    uint64_t raw;

    DEF_SUBFIELD(raw, 47, 32, active_ref_count);
    DEF_SUBBIT(raw, 63, deferred_invld);
};
static_assert(mxtl::is_pod<PasidState>::value, "not POD");
static_assert(sizeof(PasidState) == 8, "wrong size");

} // namespace ds

} // namespace intel_iommu
