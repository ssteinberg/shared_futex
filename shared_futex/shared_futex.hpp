// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_impl.hpp"

namespace ste {

/*
 *	@brief	Shared, upgradeable futex.
 */
using shared_futex = shared_futex_t<shared_futex_default_policy, shared_futex_default_latch>;

/*
 *	@brief	Shared, upgradeable futex.
 *			Compact version, consumes 8-bit of storage, at the expense of performance under contention.
 */
using shared_futex_pico = shared_futex_t<shared_futex_pico_policy, shared_futex_default_latch>;

/*
 *	@brief	Shared, upgradeable futex.
 *			Multi-slot version. Provides much greater shared scalability, at the expense of storage space. Intended for heavy
 *			shared-workloads with very high shared-to-exclusive ratios.
 */
using shared_futex_concurrent = shared_futex_t<shared_futex_multi_slot_policy, shared_futex_default_latch>;

/*
 *	@brief	Shared, upgradeable futex.
 *			Enables lock elision via transactional memory. Might greatly accelerate heavy exclusive workloads, however correctness 
 *			under mixed workloads depends on usage.
 *			Requires x86 Transactional Synchronization Extensions. It is the consumer responsibility to ensure TSX is supported.
 */
using shared_futex_tsx_rtm = shared_futex_t<shared_futex_tsx_rtm_policy, shared_futex_default_latch>;

}
