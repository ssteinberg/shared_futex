// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include <cstdint>
#include <cstddef>

namespace ste::shared_futex_detail {

// Enables per-thread statistics collection
#define STE_SHARED_FUTEX_COLLECT_STATISTICS
// Enables additional asserts
static constexpr bool debug_shared_futex = true;


struct statistics {
	std::size_t iterations{};

	std::size_t lock_rmw_instructions{};
	std::size_t lock_atomic_loads{};

	std::size_t lock_parks{};
	std::size_t unparks{};

	// Counts TSX statistics, when enabled.
	std::size_t transactional_lock_elision_attempts{};
	std::size_t transactional_lock_elision_success{};
	std::size_t transactional_lock_elision_aborts_sys{};
	std::size_t transactional_lock_elision_aborts_explicit{};
	std::size_t transactional_lock_elision_aborts_too_many_retries{};
	std::size_t transactional_lock_elision_aborts_conflict{};
	std::size_t transactional_lock_elision_aborts_capacity{};
	std::size_t transactional_lock_elision_aborts_debug{};
	std::size_t transactional_lock_elision_aborts_nested{};
	std::size_t transactional_lock_elision_aborts_other{};

	statistics& operator+=(const statistics& rhs) noexcept {
		iterations += rhs.iterations;
		lock_rmw_instructions += rhs.lock_rmw_instructions;
		lock_atomic_loads += rhs.lock_atomic_loads;
		lock_parks += rhs.lock_parks;
		unparks += rhs.unparks;
		transactional_lock_elision_attempts += rhs.transactional_lock_elision_attempts;
		transactional_lock_elision_success += rhs.transactional_lock_elision_success;
		transactional_lock_elision_aborts_sys += rhs.transactional_lock_elision_aborts_sys;
		transactional_lock_elision_aborts_explicit += rhs.transactional_lock_elision_aborts_explicit;
		transactional_lock_elision_aborts_too_many_retries += rhs.transactional_lock_elision_aborts_too_many_retries;
		transactional_lock_elision_aborts_conflict += rhs.transactional_lock_elision_aborts_conflict;
		transactional_lock_elision_aborts_capacity += rhs.transactional_lock_elision_aborts_capacity;
		transactional_lock_elision_aborts_debug += rhs.transactional_lock_elision_aborts_debug;
		transactional_lock_elision_aborts_nested += rhs.transactional_lock_elision_aborts_nested;
		transactional_lock_elision_aborts_other += rhs.transactional_lock_elision_aborts_other;

		return *this;
	}
};

#ifdef STE_SHARED_FUTEX_COLLECT_STATISTICS
static thread_local statistics debug_statistics;
static constexpr bool collect_statistics = true;
#else
static statistics debug_statistics;
static constexpr bool collect_statistics = false;
#endif


enum class modus_operandi : std::uint8_t {
	shared_lock,
	upgradeable_lock,
	exclusive_lock,
	upgrade_to_exclusive_lock,
};

enum class backoff_operation : std::uint8_t {
	spin,
	yield,
	timeout,
	park,
};

enum class backoff_result : std::uint8_t {
	unparked,
	unparked_and_unregistered,
	park_predicate_triggered,
	timeout,
	spin,
};

enum class backoff_aggressiveness : std::uint8_t {
	aggressive,
	normal,
	relaxed,
	very_relaxed,
};

enum class acquisition_primality : std::uint8_t {
	initial, 
	waiter,
};

enum class unpark_tactic : std::uint8_t {
	one,
	all,
};

}

enum class shared_futex_parking_policy {
	// Disallow parking
	none,
	// Use system shared parking lot
	parking_lot,
	// Use a local parking slot for shared and a system shared parking lot
	// Trades latch memory for better performance during mixed contention workloads
	shared_local
};
