// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "../parking_lot/parking_lot.hpp"
#include "../shared_futex/shared_futex_impl.hpp"
#include "../shared_futex/shared_futex_type_traits.hpp"

#include <chrono>
#include <type_traits>
#include <limits>

namespace ste {

// Tag for condition_variable::wait methods
struct cv_predicate_thread_safe {};

template <typename Data = void>
class condition_variable {
private:
	using park_slot_key_t = std::size_t;
	using parking_lot_t = parking_lot<park_slot_key_t, Data>;

public:
	using wait_return_t = typename parking_lot_t::park_return_t;

private:
	parking_lot_t parking_lot;

private:
	static constexpr auto park_key(shared_futex_lock_class sf_class) noexcept {
		// Segregate into shared, upgragradeable and non-shared groups.
		return static_cast<park_slot_key_t>(sf_class);
	}
	
	template <shared_futex_lock_class sf_class, typename Clock, typename Duration>
	wait_return_t wait_until_impl(const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Park in our local parking lot
		return parking_lot.park_until(park_key(sf_class),
									  until);
	}
	template <shared_futex_lock_class sf_class, typename OnPark, typename Clock, typename Duration>
	wait_return_t wait_until_impl(OnPark&& on_park,
								  const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Park in our local parking lot
		return parking_lot.park_until(on_park,
									  park_key(sf_class),
									  until);
	}
	template <shared_futex_lock_class sf_class, typename Predicate, typename OnPark, typename Clock, typename Duration>
	wait_return_t wait_until_impl(Predicate&& predicate,
								  OnPark&& on_park,
								  const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Park in our local parking lot
		return parking_lot.park_until(predicate,
									  on_park,
									  park_key(sf_class),
									  until);
	}

public:
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied. Upon successful return lock is acquired.
	 *			
	 *	@return	A pair of wait state and an optional Data supplied by the signaler. See parking_lot_wait_state.
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename Predicate, typename Clock, typename Duration
	>
	wait_return_t wait(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
					   Predicate &&predicate,
					   const std::chrono::time_point<Clock, Duration> &until) noexcept {
		static constexpr auto lg_class = lock_class_v<lock_guard<SharedFutex, SharedFutexLockingProtocol>>;

		// Acquire inital lock
		if (!lg && !lg.try_lock_until(until))
			return { parking_lot_wait_state::timeout, std::nullopt };

		// Check predicate under lock
		if (predicate())
			return { parking_lot_wait_state::predicate, std::nullopt };

		const auto on_park = [&]() {
			// On park, release the lock.
			// This is done under parking_lot node lock culminating an atomic release and park.
			lg.unlock();
		};
		for (;;) {
			// Park
			auto wait_result = wait_until_impl<lg_class>(on_park,
														 until);

			// Acquire lock
			if (wait_result.first == parking_lot_wait_state::timeout ||
				!lg.try_lock_until(until))
				return { parking_lot_wait_state::timeout, std::move(wait_result.second) };

			// Check predicate under lock
			if (predicate())
				return { parking_lot_wait_state::signalled, std::move(wait_result.second) };
		}
	}
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied. Upon successful return lock is acquired.
	 *			This is a fast version that assumes the predicate() is thread-safe.
	 *			
	 *	@return	A pair of wait state and an optional Data supplied by the signaler. See parking_lot_wait_state.
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename Predicate, typename Clock, typename Duration
	>
	wait_return_t wait(cv_predicate_thread_safe,
					   lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
					   Predicate &&predicate,
					   const std::chrono::time_point<Clock, Duration> &until) noexcept {
		static constexpr auto lg_class = lock_class_v<lock_guard<SharedFutex, SharedFutexLockingProtocol>>;

		// Check predicate without explicit locking
		if (predicate())
			return { parking_lot_wait_state::predicate, std::nullopt };

		for (;;) {
			// Park with predicate
			auto wait_result = wait_until_impl<lg_class>(predicate,
														 []() {},		// on_park
														 until);

			// Acquire lock
			if (wait_result.first == parking_lot_wait_state::timeout ||
				!lg.try_lock_until(until))
				return { parking_lot_wait_state::timeout, std::move(wait_result.second) };

			// Verify predicate under lock
			if (predicate())
				return { parking_lot_wait_state::signalled, std::move(wait_result.second) };
		}
	}
	
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied. Upon successful return lock is acquired.
	 *			
	 *	@return	A pair of wait state and an optional Data supplied by the signaler. See parking_lot_wait_state.
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename Clock, typename Duration
	>
	wait_return_t wait(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
					   const std::chrono::time_point<Clock, Duration> &until) noexcept {
		static constexpr auto lg_class = lock_class_v<lock_guard<SharedFutex, SharedFutexLockingProtocol>>;

		if (lg)
			lg.unlock();

		// Park
		auto wait_result = wait_until_impl<lg_class>(until);

		// Acquire lock
		if (wait_result.first == parking_lot_wait_state::timeout ||
			!lg.try_lock_until(until))
			return { parking_lot_wait_state::timeout, std::move(wait_result.second) };

		return wait_result;
	}

	/*
	 *	@brief	Signals and wakes-up up to n waiters.
	 *			Args are used to construct Data object that are passed to signalled threads.
	 *			
	 *	@return	Count of threads woken-up
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename... Args
	>
	std::size_t signal_n(std::size_t n,
						 lock_guard<SharedFutex, SharedFutexLockingProtocol>&& lg, 
						 const Args&... args) noexcept {
		if (n == 0)
			return 0;
		
		// lock_guard should be held
		assert(lg);

		// Extract exclusive nodes to signal
		auto extracted_nodes_exc = parking_lot.extract_n(1, park_key(shared_futex_lock_class::exclusive));
		if (extracted_nodes_exc.size()) {
			lg.unlock();
			return extracted_nodes_exc.signal(args...);
		}

		// If no exclusive, extract upgradeable and shared.
		auto extracted_nodes_upg = parking_lot.extract_n(1, park_key(shared_futex_lock_class::upgradeable));
		const auto max_shared_count = n - (extracted_nodes_upg.size() ? 1 : 0);
		auto extracted_nodes_shr = parking_lot.extract_n(max_shared_count, park_key(shared_futex_lock_class::shared));

		lg.unlock();
		return extracted_nodes_upg.signal(args...) + extracted_nodes_shr.signal(args...);
	}
	
	/*
	 *	@brief	Signals and wakes-up all possible waiters.
	 *			Args are used to construct Data object that are passed to signalled threads.
	 *			
	 *	@return	Count of threads woken-up
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename... Args
	>
	std::size_t signal(lock_guard<SharedFutex, SharedFutexLockingProtocol> &&lg,
					   const Args&... args) noexcept {
		return signal_n(std::numeric_limits<std::size_t>::max(),
						std::move(lg),
						args...);
	}
};

}
