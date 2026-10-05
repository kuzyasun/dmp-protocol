/* Compile-only layout probe for a 32-bit freestanding ABI.
 * Each object's size is the symbol size of ram_mcu_size_<name>.
 * Each alignment is the symbol size of ram_mcu_align_<name>.
 * This file is not linked and is not a runtime heap or stack measurement.
 * dmp_hs and dmp_provider are incomplete here; their sizes come from
 * dmp_hs_size and dmp_provider_size in the cross-compiled library objects.
 */
#include "dmp/endpoint.h"
#include "dmp/identity.h"
#include "dmp/reassembly.h"
#include "dmp/reliability.h"
#include "dmp/stream.h"

#include "replay_window.h"

_Static_assert(sizeof(void *) == 4, "MCU layout probe is for a 32-bit ABI");

#define RAM_MCU_REC(name, type)                                                \
    char ram_mcu_size_##name[sizeof(type)];                                   \
    char ram_mcu_align_##name[_Alignof(type)]

RAM_MCU_REC(endpoint, dmp_endpoint);
RAM_MCU_REC(endpoint_storage, dmp_endpoint_storage);
RAM_MCU_REC(endpoint_grant, dmp_endpoint_grant);
RAM_MCU_REC(endpoint_tx, dmp_endpoint_tx);
RAM_MCU_REC(freshness_slot, dmp_endpoint_freshness_slot);
RAM_MCU_REC(reliability, dmp_reliability);
RAM_MCU_REC(sender_slot, dmp_reliability_sender_slot);
RAM_MCU_REC(result_slot, dmp_reliability_result_slot);
RAM_MCU_REC(history_slot, dmp_reliability_history_slot);
RAM_MCU_REC(correlation_slot, dmp_reliability_correlation_slot);
RAM_MCU_REC(adapter_slot, dmp_reliability_adapter_slot);
RAM_MCU_REC(reassembly, dmp_reassembly);
RAM_MCU_REC(reassembly_slot, dmp_reassembly_slot);
RAM_MCU_REC(reassembly_tombstone, dmp_reassembly_tombstone);
RAM_MCU_REC(identity_slot, dmp_identity_slot);
RAM_MCU_REC(identity_table, dmp_identity_table);
RAM_MCU_REC(identity_context, dmp_identity_context_config);
RAM_MCU_REC(identity_handle, dmp_identity_handle);
RAM_MCU_REC(stream_decoder, dmp_stream_decoder);
RAM_MCU_REC(config, dmp_config);
RAM_MCU_REC(replay_window, dmp_replay_window);
RAM_MCU_REC(transport, dmp_transport);

const char ram_mcu_abi_note[] =
    "compile-only sizeof/alignof; not a host or MCU heap/stack peak";
