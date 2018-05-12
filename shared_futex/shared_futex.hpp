// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "shared_futex_policies.hpp"
#include "shared_futex_latch.hpp"

#include <chrono>
#include <mutex>
#include <utility>
#include <type_traits>
#include <functional>
#include <random>
#include <cassert>
#include <immintrin.h>

namespace ste {

template <typename FutexPolicy, template <typename> class Latch>
class shared_futex_t {
public:
	using futex_policy = FutexPolicy;
	using latch_type = Latch<futex_policy>;

private:
	latch_type latch;

public:
	shared_futex_t() = default;
	~shared_futex_t() noexcept = default;

	shared_futex_t(shared_futex_t &&) = delete;
	shared_futex_t(const shared_futex_t &) = delete;
	shared_futex_t &operator=(shared_futex_t &&) = delete;
	shared_futex_t &operator=(const shared_futex_t &) = delete;

	auto &data() noexcept { return latch; }
	const auto &data() const noexcept { return latch; }

};

template <typename SharedFutex, typename LockingProtocol>
class lock_guard {
	SharedFutex *l{ nullptr };
	LockingProtocol locker;

public:
	using mutex_type = SharedFutex;
	using locker_type = LockingProtocol;

public:
	lock_guard() = default;
	explicit lock_guard(SharedFutex &futex) noexcept : l(&futex) {
		lock();
	}
	lock_guard(SharedFutex &futex, std::defer_lock_t) noexcept : l(&futex) {}
	lock_guard(SharedFutex &futex, typename locker_type::latch_lock_t&& lock) noexcept : l(&futex), locker(std::move(lock)) {}
	lock_guard(SharedFutex &futex, std::try_to_lock_t) noexcept : l(&futex) {
		try_lock();
	}
	template <class Rep, class Period>
	lock_guard(SharedFutex &futex, const std::chrono::duration<Rep,Period> &duration) noexcept : l(&futex) {
		try_lock_for(duration);
	}
	template <class Clock, class Duration>
	lock_guard(SharedFutex &futex, const std::chrono::time_point<Clock,Duration> &time_point) noexcept : l(&futex) {
		try_lock_until(time_point);
	}

	~lock_guard() noexcept {
		if (owns_lock())
			unlock();
	}

	lock_guard(const lock_guard &) = delete;
	lock_guard &operator=(const lock_guard &) = delete;

	lock_guard(lock_guard &&o) noexcept : l(std::exchange(o.l, nullptr)), locker(std::move(o.locker)) {}

	lock_guard &operator=(lock_guard &&o) noexcept {
		SharedFutex{ std::move(*this) };
		l = std::exchange(o.l, nullptr);
		locker = std::move(o.locker);

		return *this;
	}

	friend void swap(lock_guard<SharedFutex, LockingProtocol> &a, lock_guard<SharedFutex, LockingProtocol> &b) noexcept {
		std::swap(a.l, b.l);
		std::swap(a.locker, b.locker);
	}
	void swap(lock_guard &o) noexcept { swap(*this, o); }
	
	/*
	 *	@brief	Acquires lock. Blocks until lock acquisition is successful.
	 */
	void lock() noexcept {
		try_lock_until(std::chrono::steady_clock::time_point::max());
	}
	
	/*
	 *	@brief	Attempts a lock acquisition.
	 *	@return	True on success, false on failure.
	 */
	bool try_lock() noexcept {
		assert(l && !owns_lock());
		return locker.try_lock(l->data());
	}
	
	/*
	 *	@brief	Attempts lock acquisition and blocks until lock is acquired or until timeout duration (optional) has elapsed.
	 *			Will always succeed if duration is std::chrono::duration::max().
	 *			
	 *	@param	duration	Timeout duration. Ignored if equals std::chrono::duration::max().
	 *	
	 *	@return	True on success, false on timeout.
	 */
	template <typename Rep, typename Period>
	bool try_lock_for(const std::chrono::duration<Rep, Period> &duration) noexcept {
		const auto until = std::chrono::steady_clock::now() + duration;
		return try_lock_until(until);
	}
	
	/*
	 *	@brief	Attempts lock acquisition and blocks until lock is acquired or a specified timeout time (optional) has been reached.
	 *			Will always succeed if time_point is std::chrono::time_point::max().
	 *			
	 *	@param	time_point	Timeout time point. Ignored if equals std::chrono::time_point::max().
	 *	
	 *	@return	True on success, false on timeout.
	 */
	template <typename Clock, typename Duration>
	bool try_lock_until(const std::chrono::time_point<Clock, Duration> &time_point) noexcept {
		assert(l && !owns_lock());
		return locker.try_lock_until(l->data(), time_point);
	}
	
	/*
	 *	@brief	Releases the lock.
	 */
	void unlock() noexcept {
		assert(l && owns_lock());
		locker.unlock(l->data());
	}
	
	SharedFutex &mutex() noexcept { return *l; }
	const SharedFutex &mutex() const noexcept { return *l; }
	
	/*
	 *	@brief	Releases ownership of the lock.
	 *	@return	Lock object
	 */
	[[nodiscard]] auto&& drop() && noexcept {
		l = nullptr;

		return std::move(locker).drop();
	}
	
	/*
	 *	@brief	Checks if lock_guard has successfully acquired the lock.
	 */
	bool owns_lock() const noexcept { return l && locker.owns_lock(); }
	/*
	 *	@brief	True if lock_guard has successfully acquired the lock.
	 */
	operator bool() const noexcept { return owns_lock(); }
};


namespace shared_futex_detail {

// Seeded random engine
struct random_generator {
private:
	struct seeded_mt19937 {
		std::mt19937 rand_engine;
		seeded_mt19937() noexcept;
	} gen;

public:
	auto operator()() noexcept { return std::uniform_real_distribution<float>(.0f, 1.f)(gen.rand_engine); }
};

}

/*
 *	@brief	Back-off protocol
 */
template <typename Latch, typename BackoffPolicy, shared_futex_parking_policy parking_mode>
struct shared_futex_backoff_protocol {
	using backoff_result = shared_futex_detail::backoff_result;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;
	using backoff_operation = shared_futex_detail::backoff_operation;
	
	static constexpr bool parking_allowed = parking_mode != shared_futex_parking_policy::none;
	
	/*
	 *	@brief	If returns true than it is the unparker duty to unregister from park counters, otherwise the unparked waiter does the
	 *			unregistaration.
	 */
	template <shared_futex_detail::modus_operandi mo>
	static constexpr bool is_unparker_responsible_for_unregistration() noexcept {
		return Latch::parking_lot_t::template provides_accurate_unpark_count<mo>();
	}

	/*
	 *	@brief	Implements backoff protocol.
	 */
	template <shared_futex_detail::modus_operandi mo, typename ParkPredicate, typename OnPark, typename Clock, typename Duration>
	static backoff_result pause(Latch &l,
								backoff_aggressiveness aggressiveness,
								ParkPredicate &&park_predicate,
								OnPark &&on_park,
								std::size_t iteration,
								const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Query the policy for backoff operation
		const backoff_operation op = BackoffPolicy::template select_operation<mo>(iteration, aggressiveness, until);

		// Spin
		if (op == backoff_operation::spin) {
			// Choose spin count
			const auto spins = BackoffPolicy::template spin_count<mo>(iteration, aggressiveness);
			spin(spins);

			return backoff_result::spin;
		}

		if constexpr (parking_allowed) {
			// Yield
			if (op == backoff_operation::yield) {
				std::this_thread::yield();

				return backoff_result::spin;
			}

			// Park
			if (op == backoff_operation::park) {
				const auto wait_state = l.template park<mo>(std::forward<ParkPredicate>(park_predicate),
															std::forward<OnPark>(on_park),
															until);
		
				if (wait_state == parking_lot_wait_state::signaled) {
					// Signalled. If unparker is responsible for unregistration, then we know that unregistration was already handled.
					if constexpr (is_unparker_responsible_for_unregistration<mo>())
						return backoff_result::unparked_and_unregistered;
					else
						return backoff_result::unparked;
				}
				if (wait_state == parking_lot_wait_state::park_validation_failed) {
					// Predicate was triggered before parking could take place.
					return backoff_result::park_predicate_triggered;
				}
				if (wait_state == parking_lot_wait_state::timeout) {
					// Wait timed-out
					return backoff_result::timeout;
				}

				// Unreachable
				assert(false);
			}
		}
		else {
			// Yield instead of parking if paking is disallowed
			std::this_thread::yield();
			return backoff_result::spin;
		}

		// Timeout
		return backoff_result::timeout;
	}

private:
	static void spin(std::size_t spins = 1) noexcept {
		for (std::size_t i=0;i<spins;++i)
			::_mm_pause();
	}
};

/*
 *	@brief	Locking protocol
 */
template <typename Latch, typename BackoffPolicy, typename ProtocolPolicy, shared_futex_detail::modus_operandi mo>
class shared_futex_locking_protocol {
	using futex_policy = typename Latch::futex_policy;
	using latch_descriptor = typename Latch::latch_descriptor;
	using waiters_descriptor = typename Latch::waiters_descriptor;

public:
	using latch_lock_t = typename Latch::latch_lock;

private:
	// Pre-thread random generator
	static thread_local shared_futex_detail::random_generator rand;
	
	static constexpr shared_futex_parking_policy parking_mode = futex_policy::parking_policy;

	// Helper values
	enum class release_reason { failure, lock_release };
	using unpark_tactic = shared_futex_detail::unpark_tactic;
	using modus_operandi = shared_futex_detail::modus_operandi;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;
	using acquisition_primality = shared_futex_detail::acquisition_primality;
	using backoff_result = shared_futex_detail::backoff_result;
	using backoff_protocol = shared_futex_backoff_protocol<Latch, BackoffPolicy, parking_mode>;

	struct park_slot_t {
		typename Latch::parking_key_t key;
	};
	
private:
	latch_lock_t lock;

protected:
	// Checks if a latch value is valid for lock acquisition
	template <acquisition_primality primality, modus_operandi mo_to_check = mo>
	static bool can_acquire_lock(const latch_descriptor &latch_value) noexcept {
		const auto exclusive_holders = latch_value.template consumers<modus_operandi::exclusive_lock>();
		const auto upgradeable_holders = latch_value.template consumers<modus_operandi::upgradeable_lock>();
		const auto shared_holders = latch_value.template consumers<modus_operandi::shared_lock>();

		if constexpr (mo_to_check == modus_operandi::shared_lock) {
			// Shared waiters are permitted iff there are no exclusive holders,
			// while new shared lockers need to also wait for upgradeable and upgrading holders.
			if constexpr (primality == acquisition_primality::waiter)
				return exclusive_holders == 0;
			else /*(primality == acquisition_primality::acquirer)*/
				return exclusive_holders == 0 && upgradeable_holders == 0;
		}
		else if constexpr (mo_to_check == modus_operandi::upgradeable_lock) {
			// Upgradeable lockers are permitted iff there are no exclusive holders nor upgradeable holders
			return exclusive_holders == 0 && upgradeable_holders == 0;
		}
		else if constexpr (mo_to_check == modus_operandi::exclusive_lock) {
			// Exclusive lockers are mutually exclusive with all lock kinds
			return exclusive_holders == 0 && upgradeable_holders == 0 && shared_holders == 0;
		}
		else /*(mo_to_check == modus_operandi::upgrade_to_exclusive_lock)*/ {
			// We already hold an upgradeable lock, therefore we only need to wait for the shared holders to clear out.
			return shared_holders == 0;
		}
	}

	// Unparks thread(s) using given unpark tactic
	template <unpark_tactic tactic, modus_operandi mo_to_unpark>
	static std::size_t unpark(Latch &l) noexcept {
		// Unpark
		const auto unparked = l.template unpark<tactic, mo_to_unpark>();

		if constexpr (backoff_protocol::template is_unparker_responsible_for_unregistration<mo_to_unpark>()) {
			// Unregister unparked threads from parked counters
			if (unparked)
				l.template register_unpark<mo_to_unpark>(unparked);
		}

		if constexpr (shared_futex_detail::collect_statistics)
			++shared_futex_detail::debug_statistics.unparks;

		return unparked;
	}
	
	// Handles unparking of shared and upgradeable parked waiters.
	static std::size_t unpark_shared_if_needed(Latch &l, const latch_descriptor &latch_value, const waiters_descriptor &waiters_value) noexcept {
		// Check if shared can even be unparked
		if (!can_acquire_lock<acquisition_primality::waiter, modus_operandi::shared_lock>(latch_value))
			return 0;

		std::size_t unparked = 0;
		const auto shared_parked = waiters_value.template parked<modus_operandi::shared_lock>();

		// Unpark all shared
		if (shared_parked > 0)
			unparked += unpark<unpark_tactic::all, modus_operandi::shared_lock>(l);

		// Unpark an upgradeable, if available.
		const auto upgradeable_waiters = waiters_value.template waiters<modus_operandi::upgradeable_lock>();
		const auto upgradeable_parked = waiters_value.template parked<modus_operandi::upgradeable_lock>();
		if (upgradeable_waiters == 0 &&
			upgradeable_parked > 0)
			unparked += unpark<unpark_tactic::one, modus_operandi::upgradeable_lock>(l);

		return unparked;
	}

	/*
	 *	@brief	Handles unparking of parked threads.
	 *	
	 *			Priority: 
	 *			Upgrade-to-exclusive first as they block all other lockers, exclusive are secondary and shared and upgradeable waiters are last.
	 */
	template <modus_operandi unparker_mo = mo>
	static std::size_t unpark_if_needed(Latch &l, const latch_descriptor &latch_value) noexcept {
		const auto waiters_value = l.load_waiters_counters(memory_order::relaxed);

		// Try to unpark an upgrade-to-exclusive waiter (there can only be one at most)
		if constexpr (unparker_mo == modus_operandi::shared_lock) {
			if (can_acquire_lock<acquisition_primality::waiter, modus_operandi::upgrade_to_exclusive_lock>(latch_value)) {
				const auto upgrading_to_exclusive_parked = waiters_value.template parked<modus_operandi::upgrade_to_exclusive_lock>();

				if (upgrading_to_exclusive_parked > 0) {
					const auto unparked = unpark<unpark_tactic::one, modus_operandi::upgrade_to_exclusive_lock>(l);
					if (unparked)
						return unparked;
				}
			}
		}
		
		if constexpr (unparker_mo != modus_operandi::shared_lock) {
			// Avoid unparking exclusive or upgradeable waiters if there are enough exclusive/upgradeable waiters.
			const auto x = waiters_value.template waiters<modus_operandi::exclusive_lock>();
			const auto u = waiters_value.template waiters<modus_operandi::upgradeable_lock>();
			if (x + u > ProtocolPolicy::active_waiters_count_thershold_for_unpark)
				return 0;
		}

		// ... and all shared waiters
		if constexpr (unparker_mo != modus_operandi::shared_lock) {
			const auto unparked = unpark_shared_if_needed(l, latch_value, waiters_value);
			if (unparked)
				return unparked;
		}
		
		// ... an exclusive waiter	
		if (can_acquire_lock<acquisition_primality::waiter, modus_operandi::exclusive_lock>(latch_value)) {
			const auto exclusive_parked = waiters_value.template parked<modus_operandi::exclusive_lock>();

			if (exclusive_parked > 0) {
				const auto unparked = unpark<unpark_tactic::one, modus_operandi::exclusive_lock>(l);
				if (unparked)
					return unparked;
			}
		}

		return 0;
	}

	// Chooses a backoff protocol
	backoff_aggressiveness select_backoff_protocol(Latch &l) const noexcept {
		if constexpr (mo == modus_operandi::shared_lock)
			return backoff_aggressiveness::relaxed;

		// Calculate relevant waiters count
		const auto waiters_value = l.load_waiters_counters(memory_order::relaxed);
		const auto x = waiters_value.template waiters<modus_operandi::exclusive_lock>();
		const auto u = waiters_value.template waiters<modus_operandi::upgradeable_lock>();
		const std::size_t waiters = x + u;

		// Calculate probabilities (normalized to waiters count)
		const auto probability_aggressive = static_cast<float>(ProtocolPolicy::desired_aggressive_waiters_count);
		const auto probability_normal = static_cast<float>(ProtocolPolicy::desired_normal_waiters_count);
		const auto probability_relaxed = static_cast<float>(ProtocolPolicy::desired_relaxed_waiters_count);

		// Generate a random number and choose protocol
		const auto r = rand() * static_cast<float>(waiters);
		if (ProtocolPolicy::desired_aggressive_waiters_count > 0 &&
			r < probability_aggressive)
			return backoff_aggressiveness::aggressive;
		if (ProtocolPolicy::desired_normal_waiters_count > 0 &&
			r < probability_aggressive + probability_normal)
			return backoff_aggressiveness::normal;
		if (ProtocolPolicy::desired_relaxed_waiters_count > 0 &&
			r < probability_aggressive + probability_normal + probability_relaxed)
			return backoff_aggressiveness::relaxed;
		return backoff_aggressiveness::very_relaxed;
	}

	// Attempts lock acquisition
	// For upgrades (modus_operandi::upgrade_to_exclusive_lock), lock_to_consume must be provided.
	template <acquisition_primality primality>
	bool acquire(Latch &l, latch_lock_t &&lock_to_upgrade = {}) noexcept {
		const auto validator = [](auto &&latch_value) {
			return can_acquire_lock<primality, mo>(latch_value);
		};

		// Acquire/Upgrade lock
		if constexpr (mo == modus_operandi::upgrade_to_exclusive_lock)
			lock = l.template upgrade<primality>(std::move(lock_to_upgrade), validator);
		else
			lock = l.template acquire<primality, mo>(validator);

		return !!lock;
	}

	// Releases the lock.
	template <release_reason reason>
	void release(Latch &l) noexcept {
		// Release
		l.template release<mo>(std::move(lock), memory_order::acq_rel);

		// Unpark waiters
		const auto latch_value = l.load(memory_order::relaxed);
		unpark_if_needed<mo>(l, latch_value);
	}

	/*
	 *	@brief	Periodically reattempts to acquire lock and exceutes backoff policy. Protocol waiting logic is implemented here.
	 *	
	 *			For upgrades (modus_operandi::upgrade_to_exclusive_lock), lock_to_upgrade must be provided.
	 */
	template <typename Clock, typename Duration>
	bool wait_and_try_lock_until(Latch &l, const std::chrono::time_point<Clock, Duration> &until,
								 latch_lock_t &&lock_to_upgrade = {}) noexcept {
		// Wait and Choose backoff agressiveness protocol
		l.template register_wait<mo>();
		auto aggressiveness = select_backoff_protocol(l);

		for (std::size_t iteration = 1;; ++iteration) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.iterations;

			// Once backoff policy decides to park us, register us as parked.
			bool parked = false;
			const auto park_predicate = [&]() {
				return can_acquire_lock<acquisition_primality::waiter>(l.load(memory_order::relaxed));
			};
			const auto on_park = [&]() {
				l.template register_unwait_and_park<mo>();
				parked = true;
				
				if constexpr (shared_futex_detail::collect_statistics)
					++shared_futex_detail::debug_statistics.lock_parks;
			};
			// Execute back-off policy
			const auto pause_result = backoff_protocol::template pause<mo>(l,
																		   aggressiveness,
																		   park_predicate,
																		   on_park,
																		   iteration,
																		   until);
			/*		Possible backoff results:
			 *	Timed-out - If we can't take lock we revert state and return failure result.
			 *	Park predicate triggered - Parking failed due to park predicate.
			 *	Unpark - Unparked by another thread. Need to reset iteration counter.
			 *	Spin - A spin or yield iteration was performed.
			 *	After backoff we always pessimistically check if we can lock, and if so try to acquire, otherwise continue waiting or timeout.
			 *	
			 *		There are two possible unpark operations:
			 *	Unpark - Simple unpark. 
			 *	Unpark and unregister - In addition to unparking the unparker has also unregistered us from park counters.
			 */

			const bool is_registered_as_parked = pause_result != backoff_result::unparked_and_unregistered && parked;
			const bool is_waiting = !parked;

			// On successful backoff we check, conservatively without ping-ponging cache lines, if we should reattempt to acquire lock.
			const auto latch_value = l.load();
			if (can_acquire_lock<acquisition_primality::waiter>(latch_value)) {
				// Otherwise we need to actively reattempt lock acquisition
				acquire<acquisition_primality::waiter>(l, std::move(lock_to_upgrade));
			}

			// Are we done here?
			if (owns_lock() || pause_result == backoff_result::timeout) {
				// Unwait/unpark.
				if (is_registered_as_parked)
					l.template register_unpark<mo>();
				else if (is_waiting)
					l.template register_unwait<mo>();

				// Have we acquired lock?
				if (owns_lock())
					return true;

				// Timeout
				return false;
			}

			// Otherwise go back to waiting
			if (is_registered_as_parked)
				l.template register_unpark_and_wait<mo>();
			else if (!is_waiting)
				l.template register_wait<mo>();

			if constexpr (ProtocolPolicy::reset_iterations_count_after_unpark) {
				// If we have been unparked, reset iterations counter to restart backoff process.
				if (parked)
					iteration = 0;
			}
			
			// Choose a new backoff aggressiveness protocol every few iterations.
			if (ProtocolPolicy::refresh_backoff_protocol_every_iterations > 0 &&
				iteration % ProtocolPolicy::refresh_backoff_protocol_every_iterations == 0)
				aggressiveness = select_backoff_protocol(l);
		}
	}

public:
	/*
	 *	@brief	Attempts a lock acquisition.
	 *	@return	True on success, false on failure.
	 */
	template <modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo != modus_operandi::upgrade_to_exclusive_lock>>
	bool try_lock(Latch &l) noexcept {
		// Attempt lock/upgrade
		return acquire<acquisition_primality::initial>(l);
	}
	/*
	 *	@brief	Attempts a lock upgrade. In case of success lock_to_consume is consumed and an upgraded (exclusive) lock is acquired, 
	 *			otherwise lock_to_consume is untouched.
	 *	@param	lock_to_consume		Must be a valid upgradeable lock
	 *	
	 *	@return	True on success, false on failure.
	 */
	template <modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo == modus_operandi::upgrade_to_exclusive_lock>>
	bool try_lock(Latch &l, latch_lock_t &&lock_to_consume) noexcept {
		// Attempt lock/upgrade
		return acquire<acquisition_primality::initial>(l, std::move(lock_to_consume));
	}
	
	/*
	 *	@brief	Attempts lock acquisition and blocks until lock is acquired or a specified timeout time (optional) has been reached.
	 *			Will always succeed if until is std::chrono::time_point::max().
	 *	
	 *	@return	True on success, false on timeout.
	 */
	template <
		typename Clock, typename Duration,
		modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo != modus_operandi::upgrade_to_exclusive_lock>
	>
	bool try_lock_until(Latch &l, const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Attempt lock/upgrade
		if (acquire<acquisition_primality::initial>(l))
			return true;

		return wait_and_try_lock_until(l, until);
	}
	/*
	 *	@brief	Attempts lock upgrade and blocks until lock is acquired or a specified timeout time (optional) has been reached. In case 
	 *			of success lock_to_consume is consumed and an upgraded (exclusive) lock is acquired, otherwise lock_to_consume is untouched.
	 *			Will always succeed if until is std::chrono::time_point::max().
	 *	@param	lock_to_consume		Must be a valid upgradeable lock
	 *	
	 *	@return	True on success, false on timeout.
	 */
	template <
		typename Clock, typename Duration,
		modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo == modus_operandi::upgrade_to_exclusive_lock>
	>
	bool try_lock_until(Latch &l, latch_lock_t &&lock_to_consume, const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Attempt lock/upgrade
		const auto acquire_result = acquire<acquisition_primality::initial>(l, std::move(lock_to_consume));
		if (acquire_result)
			return true;

		return wait_and_try_lock_until(l, until, std::move(lock_to_consume));
	}

	/*
	 *	@brief	Releases the lock.
	 */
	void unlock(Latch &l) noexcept {
		assert(owns_lock());
		release<release_reason::lock_release>(l);
	}
	
	/*
	 *	@brief	Checks if we hold lock.
	 */
	bool owns_lock() const noexcept { return !!lock; }

public:
	shared_futex_locking_protocol() noexcept = default;
	shared_futex_locking_protocol(latch_lock_t&& lock) noexcept : lock(std::move(lock)) {}
	~shared_futex_locking_protocol() noexcept = default;

	shared_futex_locking_protocol(shared_futex_locking_protocol &&o) noexcept : lock(std::move(o.lock)) {}
	shared_futex_locking_protocol &operator=(shared_futex_locking_protocol &&o) noexcept { 
		lock = std::move(o.lock);
		return *this;
	}
	shared_futex_locking_protocol(const shared_futex_locking_protocol&) = delete;
	shared_futex_locking_protocol &operator=(const shared_futex_locking_protocol&) = delete;

	[[nodiscard]] auto&& drop() && noexcept { return std::move(lock); }
};

template <typename Latch, typename BackoffPolicy, typename ProtocolPolicy, shared_futex_detail::modus_operandi mo>
thread_local shared_futex_detail::random_generator shared_futex_locking_protocol<Latch, BackoffPolicy, ProtocolPolicy, mo>::rand;


// shared_futex helpers

/*
 *	@brief	Shared, upgradeable futex.
 */
using shared_futex = shared_futex_t<shared_futex_default_policy, shared_futex_default_latch>;

/*
 *	@brief	Locks the futex in shared mode and returns a lock_guard.
 */
template <typename BackoffPolicy, typename SharedFutex, typename... Args>
lock_guard<
	SharedFutex, 
	shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_protocol_policy, shared_futex_detail::modus_operandi::shared_lock>
> 
make_shared_lock(SharedFutex &l, Args &&... args) noexcept {
	return lock_guard<
		SharedFutex, 
		shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_protocol_policy, shared_futex_detail::modus_operandi::shared_lock>
	>(l, std::forward<Args>(args)...);
}

/*
 *	@brief	Locks the futex in upgradeable mode and returns a lock_guard.
 */
template <typename BackoffPolicy, typename SharedFutex, typename... Args>
lock_guard<
	SharedFutex, 
	shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_protocol_policy, shared_futex_detail::modus_operandi::upgradeable_lock>
> 
make_upgradeable_lock(SharedFutex &l, Args &&... args) noexcept {
	return lock_guard<
		SharedFutex, 
		shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_protocol_policy, shared_futex_detail::modus_operandi::upgradeable_lock>
	>(l, std::forward<Args>(args)...);
}

/*
 *	@brief	Locks the futex in exclusive mode and returns a lock_guard.
 */
template <typename BackoffPolicy, typename SharedFutex, typename... Args>
lock_guard<
	SharedFutex, 
	shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_protocol_policy, shared_futex_detail::modus_operandi::exclusive_lock>
> 
make_exclusive_lock(SharedFutex &l, Args &&... args) noexcept {
	return lock_guard<
		SharedFutex, 
		shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, shared_futex_protocol_policy, shared_futex_detail::modus_operandi::exclusive_lock>
	>(l, std::forward<Args>(args)...);
}

/*
*	@brief	Upgrades the lock owned by an upgradeable lock_guard to an exclusive lock, consuming the guard and returning an exclusive one.
*			Lock must have been successfully acquired via an upgrade lock.
*			
*	@param	upgradeable_guard	Must be a lock_guard of an upgradeable_lock modus operandi and owning the lock
*	
*	@return	An exclusive guard that owns the lock
*/
template <typename BackoffPolicy, typename SharedFutex, typename P, typename B>
auto upgrade_lock(lock_guard<SharedFutex, shared_futex_locking_protocol<typename SharedFutex::latch_type, B, P, shared_futex_detail::modus_operandi::upgradeable_lock>> &&upgradeable_guard) noexcept {
	// Upgradeable guard owns lock?
	assert(upgradeable_guard.owns_lock());

	auto& l = upgradeable_guard.mutex();
	auto latch_lock = std::move(upgradeable_guard).drop();

	// Upgrade by consuming the upgradeable lock
	shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, P, shared_futex_detail::modus_operandi::upgrade_to_exclusive_lock> upgrader;
	upgrader.try_lock_until(l.data(), std::move(latch_lock), std::chrono::steady_clock::time_point::max());
	
	// Adopt the lock with a new exclusive guard
	return make_exclusive_lock<BackoffPolicy>(l, std::move(std::move(upgrader).drop()));
}

/*
*	@brief	Attempts to upgrade the lock owned by an upgradeable lock_guard to an exclusive lock, on success consumes the guard and
*			creates an exclusive one, otherwise leaves the upgradeable guard untouched.
*			Lock must have been successfully acquired via an upgrade lock.
*			
*	@param	upgradeable_guard	Must be a lock_guard of an upgradeable_lock modus operandi and owning the lock
*
*	@return	Returns a pair of a success flag and the new exclusive guard, if successful.
*/
template <typename BackoffPolicy, typename SharedFutex, typename P, typename B, typename Clock, typename Duration>
auto try_upgrade_lock_until(lock_guard<SharedFutex, shared_futex_locking_protocol<typename SharedFutex::latch_type, B, P, shared_futex_detail::modus_operandi::upgradeable_lock>> &&upgradeable_guard, const std::chrono::time_point<Clock, Duration> &until) noexcept {
	using exclusive_lock_guard = lock_guard<SharedFutex, shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, P, shared_futex_detail::modus_operandi::exclusive_lock>>;

	// Upgradeable guard owns lock?
	assert(upgradeable_guard.owns_lock());

	auto& l = upgradeable_guard.mutex();
	auto latch_lock = std::move(upgradeable_guard).drop();

	// Upgrade
	shared_futex_locking_protocol<typename SharedFutex::latch_type, BackoffPolicy, P, shared_futex_detail::modus_operandi::upgrade_to_exclusive_lock> upgrader;
	if (!upgrader.try_lock_until(l.data(), std::move(latch_lock), until))
		return std::make_pair(false, exclusive_lock_guard{});
	
	// Adopt the lock with a new exclusive guard
	return std::make_pair(true, make_exclusive_lock(l, std::move(std::move(upgrader).drop())));
}

/*
*	@brief	Attempts to upgrade the lock owned by an upgradeable lock_guard to an exclusive lock, on success consumes the guard and
*			creates an exclusive one, otherwise leaves the upgradeable guard untouched.
*			Lock must have been successfully acquired via an upgrade lock.
*			
*	@param	upgradeable_guard	Must be a lock_guard of an upgradeable_lock modus operandi and owning the lock
*
*	@return	Returns a pair of a success flag and the new exclusive guard, if successful.
*/
template <typename BackoffPolicy, typename SharedFutex, typename P, typename B, typename Rep, typename Period>
auto try_upgrade_lock_for(lock_guard<SharedFutex, shared_futex_locking_protocol<typename SharedFutex::latch_type, B, P, shared_futex_detail::modus_operandi::upgradeable_lock>> &&upgradeable_guard, const std::chrono::duration<Rep, Period> &duration) noexcept {
	const auto until = std::chrono::steady_clock::now() + duration;
	return try_upgrade_lock_until<BackoffPolicy>(std::move(upgradeable_guard), until);
}

}
