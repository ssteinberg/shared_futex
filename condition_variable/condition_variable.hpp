// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include "../parking_lot/parking_lot.hpp"
#include "../shared_futex/shared_futex_impl.hpp"
#include "../shared_futex/shared_futex_policies.hpp"
#include "../shared_futex/shared_futex_type_traits.hpp"

#include <chrono>
#include <type_traits>
#include <limits>

namespace strt {

class condition_variable {
private:
	using park_slot_key_t = std::size_t;
	using parking_lot_t = parking_lot<park_slot_key_t, void>;

public:
	using wait_return_t = parking_lot_wait_state;

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
									  until).first;
	}
	template <shared_futex_lock_class sf_class, typename OnPark, typename Clock, typename Duration>
	wait_return_t wait_until_impl(OnPark&& on_park,
								  const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Park in our local parking lot
		return parking_lot.park_until(std::forward<OnPark>(on_park),
									  park_key(sf_class),
									  until).first;
	}
	template <shared_futex_lock_class sf_class, typename Predicate, typename OnPark, typename Clock, typename Duration>
	wait_return_t wait_until_impl(Predicate&& predicate,
								  OnPark&& on_park,
								  const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Park in our local parking lot
		return parking_lot.park_until(std::forward<Predicate>(predicate),
									  std::forward<OnPark>(on_park),
									  park_key(sf_class),
									  until).first;
	}

public:
	constexpr condition_variable() noexcept = default;
	
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied. Upon successful return lock is acquired.
	 *			
	 *	@return	Wait state. See parking_lot_wait_state.
	 */
	template <typename SharedFutex, typename SharedFutexLockingProtocol, typename Predicate>
	wait_return_t wait(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
					   Predicate &&predicate) noexcept {
		return wait_until(lg,
						  std::forward<Predicate>(predicate),
						  std::chrono::steady_clock::time_point::max());
	}
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied or timeout has occured. Upon successful return lock is acquired.
	 *			
	 *	@return	Wait state. See parking_lot_wait_state.
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename Predicate, class Rep, class Period
	>
	wait_return_t wait_for(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
						   Predicate &&predicate,
						   const std::chrono::duration<Rep, Period> &duration) noexcept {
		return wait_until(lg,
						  std::forward<Predicate>(predicate),
						  std::chrono::steady_clock::now() + duration);
	}
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied or timeout has occured. Upon successful return lock is acquired.
	 *			
	 *	@return	Wait state. See parking_lot_wait_state.
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename Predicate, typename Clock, typename Duration
	>
	wait_return_t wait_until(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
							 Predicate &&predicate,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		static constexpr auto lg_class = lock_class_v<lock_guard<SharedFutex, SharedFutexLockingProtocol>>;
		
		if (!lg.try_lock_until(until))
			return parking_lot_wait_state::timeout;

		// Check predicate
		if (predicate())
			return parking_lot_wait_state::predicate;
		
		const auto on_park = [&]() {
			// On park, release the lock.
			// This is done under parking_lot node lock culminating an atomic release and park.
			lg.unlock(); 
		};
		for (;;) {
			// Park with predicate
			auto wait_result = wait_until_impl<lg_class>(predicate,
														 on_park,
														 until);

			// Acquire lock
			if (wait_result == parking_lot_wait_state::timeout ||
				!lg.try_lock_until(until))
				return parking_lot_wait_state::timeout;

			// Verify predicate under lock
			if (predicate())
				return parking_lot_wait_state::signalled;
		}
	}
	
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied. Upon successful return lock is acquired.
	 *			
	 *	@return	Wait state. See parking_lot_wait_state.
	 */
	template <typename SharedFutex, typename SharedFutexLockingProtocol>
	wait_return_t wait(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg) noexcept {
		return wait_until(lg,
						  std::chrono::steady_clock::time_point::max());
	}
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied or timeout has occured. Upon successful return lock is acquired.
	 *			
	 *	@return	Wait state. See parking_lot_wait_state.
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		class Rep, class Period
	>
	wait_return_t wait_for(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
						   const std::chrono::duration<Rep, Period> &duration) noexcept {
		return wait_until(lg,
						  std::chrono::steady_clock::now() + duration);
	}
	/*
	 *	@brief	Initially checks predicate and if not satisfied parks the calling thread and waits for signal. Returns once signalled and
	 *			predicate is satisfied or timeout has occured. Upon successful return lock is acquired.
	 *			
	 *	@return	Wait state. See parking_lot_wait_state.
	 */
	template <
		typename SharedFutex, typename SharedFutexLockingProtocol,
		typename Clock, typename Duration
	>
	wait_return_t wait_until(lock_guard<SharedFutex, SharedFutexLockingProtocol> &lg,
					   const std::chrono::time_point<Clock, Duration> &until) noexcept {
		static constexpr auto lg_class = lock_class_v<lock_guard<SharedFutex, SharedFutexLockingProtocol>>;

		// Park
		const auto on_park = [&]() {
			// On park, release the lock.
			// This is done under parking_lot node lock culminating an atomic release and park.
			if (lg)
				lg.unlock(); 
		};
		auto wait_result = wait_until_impl<lg_class>(on_park,
													 until);

		// Acquire lock
		if (wait_result == parking_lot_wait_state::timeout ||
			!lg.try_lock_until(until))
			return parking_lot_wait_state::timeout;

		return wait_result.first;
	}

	/*
	 *	@brief	Signals and wakes-up up to n waiters.
	 *			
	 *	@return	Count of threads woken-up
	 */
	template <typename SharedFutex, typename SharedFutexLockingProtocol>
	std::size_t signal_n(std::size_t n,
						 lock_guard<SharedFutex, SharedFutexLockingProtocol>&& lg) noexcept {
		assert(n > 0);
		
		// lock_guard should be held
		assert(lg);

		// Extract exclusive nodes to signal
		auto extracted_nodes_exc = parking_lot.extract_n(1, park_key(shared_futex_lock_class::exclusive));
		if (extracted_nodes_exc.size()) {
			lg.unlock();
			return std::move(extracted_nodes_exc).signal();
		}

		// If no exclusive, extract upgradeable and shared.
		auto extracted_nodes_upg = parking_lot.extract_n(1, park_key(shared_futex_lock_class::upgradeable));
		const auto max_shared_count = n - (extracted_nodes_upg.size() ? 1 : 0);
		auto extracted_nodes_shr = parking_lot.extract_n(max_shared_count, park_key(shared_futex_lock_class::shared));

		lg.unlock();
		return std::move(extracted_nodes_upg).signal() + std::move(extracted_nodes_shr).signal();
	}
	
	/*
	 *	@brief	Signals and wakes-up all possible waiters.
	 *			
	 *	@return	Count of threads woken-up
	 */
	template <typename SharedFutex, typename SharedFutexLockingProtocol>
	std::size_t signal(lock_guard<SharedFutex, SharedFutexLockingProtocol> &&lg) noexcept {
		return signal_n(std::numeric_limits<std::size_t>::max(),
						std::move(lg));
	}
};


/*
 *	@brief	Waits upon a condition variable, locks the futex in mode specified by lock_class and returns a lock_guard.
 *			See condition_variable::wait().
 */
template <
	shared_futex_lock_class lock_class,
	typename BackoffPolicy = shared_futex_policies::exponential_backoff_policy,
	typename SharedFutex, typename Clock, typename Duration
>
auto make_lock_when(SharedFutex &l, condition_variable &cv, const std::chrono::time_point<Clock, Duration> &until) noexcept {
	static constexpr auto op = shared_futex_detail::op_for_class(lock_class);
	lock_guard<
		SharedFutex,
		shared_futex_detail::shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_policies::shared_futex_protocol_policy, op>
	> lg(l, std::defer_lock);

	cv.wait_until(lg, until);
	return lg;
}

/*
 *	@brief	Waits upon a condition variable, locks the futex in mode specified by lock_class and returns a lock_guard.
 *			See condition_variable::wait().
 */
template <
	shared_futex_lock_class lock_class,
	typename BackoffPolicy = shared_futex_policies::exponential_backoff_policy,
	typename SharedFutex
>
auto make_lock_when(SharedFutex &l, condition_variable &cv) noexcept {
	return make_lock_when<lock_class, BackoffPolicy>(l, cv, std::chrono::steady_clock::time_point::max());
}

/*
 *	@brief	Waits upon a condition variable, locks the futex in mode specified by lock_class and returns a lock_guard.
 *			See condition_variable::wait().
 */
template <
	shared_futex_lock_class lock_class,
	typename BackoffPolicy = shared_futex_policies::exponential_backoff_policy,
	typename SharedFutex, typename Rep, typename Period
>
auto make_lock_when(SharedFutex &l, condition_variable &cv, const std::chrono::duration<Rep, Period> &duration) noexcept {
	const auto until = std::chrono::steady_clock::now() + duration;
	return make_lock_when<lock_class, BackoffPolicy>(l, cv, until);
}

/*
 *	@brief	Waits upon a condition variable, locks the futex in mode specified by lock_class and returns a lock_guard.
 *			See condition_variable::wait().
 */
template <
	shared_futex_lock_class lock_class,
	typename BackoffPolicy = shared_futex_policies::exponential_backoff_policy,
	typename SharedFutex, typename Predicate,
	typename Clock, typename Duration
>
auto make_lock_when(SharedFutex &l, condition_variable &cv,
					Predicate &&predicate,
					const std::chrono::time_point<Clock, Duration> &until) noexcept {
	static constexpr auto op = shared_futex_detail::op_for_class(lock_class);
	lock_guard<
		SharedFutex,
		shared_futex_detail::shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_policies::shared_futex_protocol_policy, op>
	> lg(l, std::defer_lock);

	cv.wait_until(lg, std::forward<Predicate>(predicate), until);
	return lg;
}

/*
 *	@brief	Waits upon a condition variable, locks the futex in mode specified by lock_class and returns a lock_guard.
 *			See condition_variable::wait().
 */
template <
	shared_futex_lock_class lock_class,
	typename BackoffPolicy = shared_futex_policies::exponential_backoff_policy,
	typename SharedFutex, typename Predicate
>
auto make_lock_when(SharedFutex &l, condition_variable &cv,
					Predicate &&predicate) noexcept {
	return make_lock_when<lock_class, BackoffPolicy>(l, cv, std::forward<Predicate>(predicate), std::chrono::steady_clock::time_point::max());
}

/*
 *	@brief	Waits upon a condition variable, locks the futex in mode specified by lock_class and returns a lock_guard.
 *			See condition_variable::wait().
 */
template <
	shared_futex_lock_class lock_class,
	typename BackoffPolicy = shared_futex_policies::exponential_backoff_policy,
	typename SharedFutex, typename Predicate,
	typename Rep, typename Period
>
auto make_lock_when(SharedFutex &l, condition_variable &cv,
					Predicate &&predicate,
					const std::chrono::duration<Rep, Period> &duration) noexcept {
	const auto until = std::chrono::steady_clock::now() + duration;
	return make_lock_when<lock_class, BackoffPolicy>(l, cv, std::forward<Predicate>(predicate), until);
}

}
