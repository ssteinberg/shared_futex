// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include <cstdint>
#include <cstddef>

namespace strt {

enum class shared_futex_lock_class {
	shared,
	upgradeable,
	exclusive
};

namespace shared_futex_detail {

// Enables per-thread statistics collection
// #define STE_SHARED_FUTEX_COLLECT_STATISTICS
// Enables additional asserts
static constexpr bool debug_shared_futex = false;


struct statistics {
	std::size_t shared_locks{};
	std::size_t upgradeable_locks{};
	std::size_t exclusive_locks{};

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
		shared_locks += rhs.shared_locks;
		upgradeable_locks += rhs.upgradeable_locks;
		exclusive_locks += rhs.exclusive_locks;
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


// Latch operation
enum class operation : std::uint8_t {
	lock_shared,
	lock_upgradeable,
	lock_exclusive,
	upgrade,
};

constexpr operation op_for_class(shared_futex_lock_class lock_class) noexcept {
	return
		lock_class == shared_futex_lock_class::shared ? operation::lock_shared :
		lock_class == shared_futex_lock_class::upgradeable ? operation::lock_upgradeable :
		operation::lock_exclusive;
}


// Backoff iteration type
enum class backoff_operation : std::uint8_t {
	spin,
	yield,
	timeout,
	park,
};

// Result of a backoff iteration
enum class backoff_result : std::uint8_t {
	unparked,
	park_predicate_triggered,
	timeout,
	unparked_and_unregistered,
	spin,
};

// Hint for the backoff protocol
enum class backoff_aggressiveness : std::uint8_t {
	aggressive,
	normal,
	relaxed,
	very_relaxed,
};

// Acquisition type
enum class acquisition_primality : std::uint8_t {
	initial,
	waiter,
};

// Hint given by latch release operation in regards to latch state
enum class latch_availability_hint : std::uint8_t {
	// Latch is free
	free,
	// Held in exclusive mode
	exclusive,
	// Held in shared mode
	shared
};

// Unpark operation
enum class unpark_tactic : std::uint8_t {
	one,
	all,
};

enum class shared_futex_parking_policy {
	// Disallow parking
	none,
	// Use system shared parking lot
	parking_lot,
	// Use a local parking slot for shared and a system shared parking lot
	// Trades latch memory for better performance during mixed contention workloads
	shared_local
};

}
}
