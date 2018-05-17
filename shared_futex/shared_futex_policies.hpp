// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"

#include <cstddef>
#include <chrono>
#include <new>
#include <tuple>
#include <algorithm>
#include <intrin.h>

namespace ste {

/*
 *	Feature flags affecting shared_futex's global behaviour
 */
namespace shared_futex_features {

// Allows the futex to employ x64 TSX hardware-lock-elision, if supported, for exclusive locks only.
struct use_transactional_hle_exclusive {};
// Allows the futex to employ x64 TSX restricted-transactional-memory. Exception will be raised if TSX is unsupported by hardware.
// Consumers can abort a transaction manually by calling xabort.
struct use_transactional_rtm {};

// Splits latch into slots. Slots are placed on distinct cache lines, greatly increasing potential for concurrency. Slots are allocated
// statically, however actual count of slots in use varies based on usage.
struct use_slots {};

}

namespace shared_futex_policies {

/*
 *	@brief	Policy of shared_futex's data storage
 */
struct shared_futex_default_policy {
	/*
	 *	Locking variable storage policies
	 */

	 // Futex alignment
	static constexpr std::size_t alignment = std::hardware_destructive_interference_size;
	// Latch data type
	using latch_data_type = std::uint32_t;

	// Bit depth for shared waiters counter
	static constexpr std::size_t shared_bits = 10;
	// Bit depth for upgradeable waiters counter
	static constexpr std::size_t upgradeable_bits = 10;
	// Bit depth for exclusive waiters counter
	static constexpr std::size_t exclusive_bits = 10;

	/*
	 *	Futex behaviour policies
	 */

	 // Specifies thread parking policy
	static constexpr shared_futex_detail::shared_futex_parking_policy parking_policy = shared_futex_detail::shared_futex_parking_policy::shared_local;
	// Disables/enables waiters counting. Counting waiters increases performance during heavier contention, at the cost of a small overhead.
	static constexpr bool count_waiters = true;
	// List of requested featrues, see namespace shared_futex_features.
	using features = std::tuple<>;
};

/*
 *	@brief	Policy without parking or waiters counters, used to fit a futex into 32-bits.
 */
struct shared_futex_micro_policy {
	static constexpr std::size_t alignment = 1;
	using latch_data_type = std::uint32_t;

	static constexpr std::size_t shared_bits = 15;
	static constexpr std::size_t upgradeable_bits = 1;
	static constexpr std::size_t exclusive_bits = 1;

	static constexpr shared_futex_detail::shared_futex_parking_policy parking_policy = shared_futex_detail::shared_futex_parking_policy::none;
	static constexpr bool count_waiters = false;
	using features = std::tuple<>;
};

/*
 *	@brief	Policy without parking or waiters counters and TSX HLE, used to fit a futex into 32-bits.
 */
struct shared_futex_micro_tsx_hle_policy {
	static constexpr std::size_t alignment = 1;
	using latch_data_type = std::uint32_t;

	static constexpr std::size_t shared_bits = 15;
	static constexpr std::size_t upgradeable_bits = 1;
	static constexpr std::size_t exclusive_bits = 1;

	static constexpr shared_futex_detail::shared_futex_parking_policy parking_policy = shared_futex_detail::shared_futex_parking_policy::none;
	static constexpr bool count_waiters = false;
	using features = std::tuple<shared_futex_features::use_transactional_hle_exclusive>;
};

/*
 *	@brief	Policy with TSX RTM feature
 */
struct shared_futex_tsx_rtm_policy {
	static constexpr std::size_t alignment = std::hardware_destructive_interference_size;
	using latch_data_type = std::uint32_t;

	static constexpr std::size_t shared_bits = 10;
	static constexpr std::size_t upgradeable_bits = 10;
	static constexpr std::size_t exclusive_bits = 10;

	static constexpr shared_futex_detail::shared_futex_parking_policy parking_policy = shared_futex_detail::shared_futex_parking_policy::shared_local;
	static constexpr bool count_waiters = true;
	using features = std::tuple<shared_futex_features::use_transactional_rtm>;
};

/*
 *	@brief	Policy with multi-slot feature
 */
struct shared_futex_multi_slot_policy {
	static constexpr std::size_t alignment = std::hardware_destructive_interference_size;
	using latch_data_type = std::uint32_t;

	static constexpr std::size_t shared_bits = 10;
	static constexpr std::size_t upgradeable_bits = 10;
	static constexpr std::size_t exclusive_bits = 10;

	static constexpr shared_futex_detail::shared_futex_parking_policy parking_policy = shared_futex_detail::shared_futex_parking_policy::shared_local;
	static constexpr bool count_waiters = true;
	using features = std::tuple<shared_futex_features::use_slots>;
};


/*
 *	@brief	Simple spin-lock backoff policy.
 *			Employs cross-thread symmetry-breaking spinning logic.
 */
struct spinlock_backoff_policy {
	using backoff_operation = shared_futex_detail::backoff_operation;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;

	static constexpr std::size_t max_spin_count = 10;

	template <shared_futex_detail::modus_operandi, typename Clock, typename Duration>
	static constexpr backoff_operation select_operation(std::size_t iteration, backoff_aggressiveness, float,
														const std::chrono::time_point<Clock, Duration> &until) noexcept {
		if ((iteration % 100) == 0 &&
			until != std::chrono::time_point<Clock, Duration>::max() && Clock::now() >= until)
			return backoff_operation::timeout;
		return backoff_operation::spin;
	}
	template <shared_futex_detail::modus_operandi>
	static constexpr std::size_t spin_count(std::size_t, float, backoff_aggressiveness) noexcept {
		const auto rdtsc = __rdtsc();
		return (rdtsc % 48) + 32;
	}
};

/*
 *	@brief	Spins, yields and then parks.
 *			A spin cycle will take ~4 ns, a context-switch ~1000ns and a park will cost multiple thousands ns and more in case
 *			of contention on the parking slot. Therefore this implementation is essentially an exponential backoff policy, which is a
 *			well studied approach to find an acceptable balance between contending processes and reduce number of collisions.
 *			Employs cross-thread symmetry-breaking spinning logic.
 */
struct exponential_backoff_policy {
	using backoff_operation = shared_futex_detail::backoff_operation;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;

	template <shared_futex_detail::modus_operandi, typename Clock, typename Duration>
	static constexpr backoff_operation select_operation(std::size_t iteration, float,
														backoff_aggressiveness aggressiveness,
														const std::chrono::time_point<Clock, Duration> &until) noexcept {
		const auto s = spin_iterations(aggressiveness);
		const auto y = yield_iterations(aggressiveness);
		const bool do_not_park = disallow_parking(aggressiveness);

		// Spin
		if (iteration <= s)
			return backoff_operation::spin;

		// Check timeout
		if (until != std::chrono::time_point<Clock, Duration>::max() && Clock::now() >= until)
			return backoff_operation::timeout;

		// Yield
		if (iteration <= s + y || do_not_park)
			return backoff_operation::yield;

		// Park
		return backoff_operation::park;
	}
	template <shared_futex_detail::modus_operandi>
	static std::size_t spin_count(std::size_t iteration, float, backoff_aggressiveness aggressiveness) noexcept {
		// Calculate spin count
		const auto x = static_cast<float>(iteration - 1);
		const auto norm = sqrt_spins_on_last_iteration(aggressiveness) / static_cast<float>(spin_iterations(aggressiveness));
		const auto sqrt_spins = x * norm;

		// Inject some randomness to break cross-thread symmetry
		const auto symmetry_breaker = spin_symmetry_breaker(aggressiveness);

		return spin_base_count(aggressiveness) + static_cast<std::size_t>(sqrt_spins*sqrt_spins) + symmetry_breaker;
	}

private:
	static constexpr float sqrt_spins_on_last_iteration(backoff_aggressiveness aggressiveness) noexcept {
		return aggressiveness == backoff_aggressiveness::aggressive ?
			16.f :   // ~900 pause instructions, on the scale of ~3 microseconds
			32.f;    // ~500 pause instructions, on the scale of ~2 microseconds
	}
	static constexpr std::size_t spin_iterations(backoff_aggressiveness aggressiveness) noexcept {
		return
			aggressiveness == backoff_aggressiveness::aggressive ? 128 :
			aggressiveness == backoff_aggressiveness::normal ? 96 :
			aggressiveness == backoff_aggressiveness::relaxed ? 32 :
			0;
	}
	static constexpr std::size_t spin_base_count(backoff_aggressiveness aggressiveness) noexcept {
		return aggressiveness == backoff_aggressiveness::relaxed ? 64ull : 32ull;
	}
	static std::size_t spin_symmetry_breaker(backoff_aggressiveness aggressiveness) noexcept {
		const auto rdtsc = __rdtsc();
		return static_cast<std::size_t>(rdtsc % 64);
	}
	static constexpr std::size_t yield_iterations(backoff_aggressiveness aggressiveness) noexcept {
		return 0;
	}
	static constexpr bool disallow_parking(backoff_aggressiveness aggressiveness) noexcept {
		return aggressiveness == backoff_aggressiveness::aggressive;
	}
};

/*
 *	@brief	Does not spin, yields and then parks.
 */
struct relaxed_backoff_policy {
	using backoff_operation = shared_futex_detail::backoff_operation;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;

	static constexpr int yield_iterations = 5;

	template <shared_futex_detail::modus_operandi, typename Clock, typename Duration>
	static constexpr backoff_operation select_operation(std::size_t iteration, float, backoff_aggressiveness aggressiveness,
														const std::chrono::time_point<Clock, Duration> &until) noexcept {
		if (until != std::chrono::time_point<Clock, Duration>::max() && Clock::now() >= until)
			return backoff_operation::timeout;

		// Yield
		if (iteration <= yield_iterations && aggressiveness != backoff_aggressiveness::very_relaxed)
			return backoff_operation::yield;
		// Otherwise park
		return backoff_operation::park;
	}
	template <shared_futex_detail::modus_operandi>
	static constexpr std::size_t spin_count(std::size_t, float, backoff_aggressiveness) noexcept { return 0; }
};


/*
 *	@brief	Policy that fine-tunes shared_futex protcol's behaviour, fairness and performance.
 */
struct shared_futex_protocol_policy {
	// The desired count of waiters using an aggressive backoff protocol, on average.
	static constexpr auto desired_aggressive_waiters_count = 1;
	// The desired count of waiters using a normal backoff protocol, on average.
	static constexpr auto desired_normal_waiters_count = 3;
	// The desired count of waiters using a relaxed backoff protocol, on average.
	static constexpr auto desired_relaxed_waiters_count = 0;

	// Each count of those iterations we re-choose the backoff protocol
	static constexpr auto refresh_backoff_protocol_every_iterations = 0;
	// If set to true, iteration counter will be reset after an unpark, causing the waiter to restart its backoff policy.
	static constexpr bool reset_iterations_count_after_unpark = false;

	// When looking for candidates to unpark, we unpark a waiter if count of active waiters, that might block said waiter, is lower than 
	// this threshold.
	static constexpr auto active_waiters_count_thershold_for_unpark = 0;
};

}

}
