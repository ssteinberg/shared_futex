// StE
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "parking_lot.hpp"

#include <cstdint>
#include <cmath>
#include <chrono>

namespace ste {

/*
 *	Flags affecting shared_futex's global behaviour
 */
namespace shared_futex_features {

// Allows the futex to employ x64 TSX hardware-lock-elision, if supported.
struct use_transactional_hle {};

}

/*
 *	@brief	Policy of shared_futex's data storage
 */
struct shared_futex_default_storage_policy {
	// Futex alignment
	static constexpr std::size_t alignment = std::hardware_destructive_interference_size;

	/*
	 *	Locking variable bit allocation
	 */
	// Bit depth for simultaneous shared lockers
	static constexpr std::size_t shared_bits = 10;
	// Bit depth for simultaneous upgradeable lockers
	static constexpr std::size_t upgradeable_bits = 10;
	// Bit depth for simultaneous exclusive lockers
	static constexpr std::size_t exclusive_bits = 10;
};


/*
 *	@brief	Simple spin-lock backoff policy
 */
struct spinlock_backoff_policy {
	using backoff_operation = shared_futex_detail::backoff_operation;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;

	static constexpr std::size_t max_spin_count = 10;

	template <shared_futex_detail::modus_operandi, typename Clock, typename Duration>
	static constexpr backoff_operation select_operation(std::size_t iteration, backoff_aggressiveness,
														const std::chrono::time_point<Clock, Duration> &until) noexcept {
		if ((iteration % 100) == 0 &&
			until != std::chrono::time_point<Clock, Duration>::max() && Clock::now() >= until)
			return backoff_operation::timeout;
		return backoff_operation::spin;
	}
	template <shared_futex_detail::modus_operandi>
	static constexpr std::size_t spin_count(std::size_t iteration, backoff_aggressiveness) noexcept {
		return std::min(iteration, max_spin_count);
	}
};

/*
 *	@brief	Spins, yields and then parks.
 *			A spin cycle will take 3-5 ns, a context-switch ~1000ns and a park will cost thousands ns and more in case 
 *			of contention on the parking slot. Therefore this implementation is essentially an exponential backoff policy, which is a 
 *			well studied approach to find an acceptable balance between contending processes and reduce number of collisions.
 */
struct exponential_backoff_policy {
	using backoff_operation = shared_futex_detail::backoff_operation;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;

	template <shared_futex_detail::modus_operandi, typename Clock, typename Duration>
	static constexpr backoff_operation select_operation(std::size_t iteration, backoff_aggressiveness aggressiveness,
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
	static constexpr std::size_t spin_count(std::size_t iteration, backoff_aggressiveness aggressiveness) noexcept {
		// Calculate spin count
		const auto x = static_cast<float>(iteration);
		const auto norm = sqrt_spins_on_last_iteration(aggressiveness) / static_cast<float>(spin_iterations(aggressiveness));
		const auto sqrt_spins = x * norm;
		return static_cast<std::size_t>(sqrt_spins*sqrt_spins);
	}

private:
	static constexpr float sqrt_spins_on_last_iteration(backoff_aggressiveness aggressiveness) noexcept {
		return aggressiveness == backoff_aggressiveness::aggressive ? 
			64.f :   // 4k pause instructions ~ on the scale of 10 microseconds
			32.f;    // 1k pause instructions ~ on the scale of  3 microseconds
	}
	static constexpr std::size_t spin_iterations(backoff_aggressiveness aggressiveness) noexcept {
		return 
			aggressiveness == backoff_aggressiveness::aggressive ? 64 : 
			aggressiveness == backoff_aggressiveness::normal     ? 32 :
			aggressiveness == backoff_aggressiveness::relaxed    ? 6 : 
			0;
	}
	static constexpr std::size_t yield_iterations(backoff_aggressiveness aggressiveness) noexcept {
		return 0;
	}
	static constexpr bool disallow_parking(backoff_aggressiveness aggressiveness) noexcept {
		return aggressiveness == backoff_aggressiveness::aggressive;
	}
};

/*
 *	@brief	Does not spin, yields and then parks
 */
struct relaxed_backoff_policy {
	using backoff_operation = shared_futex_detail::backoff_operation;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;
	
	static constexpr int yield_iterations = 5;

	template <shared_futex_detail::modus_operandi, typename Clock, typename Duration>
	static constexpr backoff_operation select_operation(std::size_t iteration, backoff_aggressiveness aggressiveness,
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
	static constexpr std::size_t spin_count(std::size_t, backoff_aggressiveness) noexcept { return 0;}
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
	static constexpr auto refresh_backoff_protocol_every_iterations = 1;

	// When unparking shared waiters, use a reserve-and-unpark tactic if shared parked count is greater or equal to this threshold
	static constexpr auto shared_parked_count_threshold_for_reserve_and_unpark = 2;
	
	// When looking for candidates to unpark, we unpark a waiter if count of active waiters, that might block said waiter, is lower than 
	// this threshold.
	static constexpr auto active_waiters_count_thershold_for_unpark = 1;
};

}
