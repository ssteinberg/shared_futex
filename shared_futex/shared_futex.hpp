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

	void lock() noexcept {
		try_lock_until(std::chrono::steady_clock::time_point::max());
	}

	bool try_lock() noexcept {
		assert(l);
		return locker.try_lock(l->data());
	}

	template <typename Rep, typename Period>
	bool try_lock_for(const std::chrono::duration<Rep, Period> &duration) noexcept {
		const auto until = std::chrono::steady_clock::now() + duration;
		return try_lock_until(until);
	}

	template <typename Clock, typename Duration>
	bool try_lock_until(const std::chrono::time_point<Clock, Duration> &time_point) noexcept {
		assert(l);
		return locker.try_lock_until(l->data(), time_point);
	}

	void unlock() noexcept {
		assert(l);
		locker.unlock(l->data());
	}

	SharedFutex &mutex() noexcept { return *l; }
	const SharedFutex &mutex() const noexcept { return *l; }

	[[nodiscard]] auto&& drop() && noexcept {
		l = nullptr;

		return std::move(locker).drop();
	}

	bool owns_lock() const noexcept { return l && locker.owns_lock(); }
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
template <typename BackoffPolicy, typename LatchLock, shared_futex_parking_policy parking_mode>
struct shared_futex_backoff_protocol {
	using backoff_result = shared_futex_detail::backoff_result;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;
	using backoff_operation = shared_futex_detail::backoff_operation;
	using backoff_return_t = shared_futex_detail::backoff_return_t<LatchLock>;
	
	static constexpr bool parking_allowed = parking_mode != shared_futex_parking_policy::none;

	template <shared_futex_detail::modus_operandi mo, typename Latch, typename ParkPredicate, typename OnPark, typename ParkKey, typename Clock, typename Duration>
	static backoff_return_t backoff(Latch &l,
									backoff_aggressiveness aggressiveness,
									ParkPredicate &&park_predicate,
									OnPark &&on_park,
									std::size_t iteration,
									ParkKey &&park_key,
									const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Query the policy for backoff operation
		const backoff_operation op = BackoffPolicy::template select_operation<mo>(iteration, aggressiveness, until);

		// Spin
		if (op == backoff_operation::spin) {
			// Choose spin count
			const auto spins = BackoffPolicy::template spin_count<mo>(iteration, aggressiveness);
			spin(spins);

			return { backoff_result::spin };
		}

		if constexpr (parking_allowed) {
			// Yield
			if (op == backoff_operation::yield) {
				std::this_thread::yield();

				return { backoff_result::spin };
			}

			// Park
			if (op == backoff_operation::park) {
				return wait_until(l,
								  std::forward<ParkPredicate>(park_predicate),
								  std::forward<OnPark>(on_park),
								  std::forward<ParkKey>(park_key),
								  until);
			}
		}
		else {
			// Yield instead of parking if paking is disallowed
			std::this_thread::yield();
			return { backoff_result::spin };
		}

		// Timeout
		return { backoff_result::timeout };
	}

private:
	template <typename Latch, typename ParkPredicate, typename OnPark, typename ParkKey, typename Clock, typename Duration>
	static backoff_return_t wait_until(Latch &l,
									   ParkPredicate &&park_predicate,
									   OnPark &&on_park,
									   ParkKey &&park_key,
									   const std::chrono::time_point<Clock, Duration> &until) {
		static_assert(parking_mode == shared_futex_parking_policy::parking_lot, "Unsupported parking mode");

		// Park
		auto park_result = l.parking.park_until(std::forward<ParkPredicate>(park_predicate),
												std::forward<OnPark>(on_park),
												std::forward<ParkKey>(park_key),
												until);

		const auto wait_state = park_result.first;
		if (wait_state == parking_lot_wait_state::signaled) {
			// Communicate data stored by the unparker
			return {
				backoff_result::unparked,
				std::move(park_result.second).value()
			};
		}
		if (wait_state == parking_lot_wait_state::park_validation_failed) {
			return { backoff_result::park_predicate_triggered };
		}
		if (wait_state == parking_lot_wait_state::timeout) {
			return { backoff_result::timeout };
		}

		// Unreachable
		assert(false);
		return {};
	}

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
	using counter_t = typename Latch::counter_t;

public:
	using latch_lock_t = typename Latch::latch_lock;

private:
	// Pre-thread random generator
	static thread_local shared_futex_detail::random_generator rand;
	
	static constexpr shared_futex_parking_policy parking_mode = futex_policy::parking_policy;

	// Helper values
	enum class unpark_tactic { one, all, all_reserve };
	enum class release_reason { failure, lock_release, reservation_release };

	using modus_operandi = shared_futex_detail::modus_operandi;
	using backoff_aggressiveness = shared_futex_detail::backoff_aggressiveness;
	using acquisition_primality = shared_futex_detail::acquisition_primality;
	using backoff_protocol = shared_futex_backoff_protocol<BackoffPolicy, latch_lock_t, parking_mode>;

	struct park_slot_t {
		typename Latch::parking_key_t key;
	};
	
protected:
	latch_lock_t lock;

private:
	/*
	 *	@brief	Unparks threads of a specified modus operandi and specified unparking key.
	 *			On successful unpark it the unparker's duty to unregister from parked counters
	 *			
	 *	@return	Count of threads successfully unparked
	 */
	template <unpark_tactic tactic, modus_operandi mo_to_unpark>
	static std::size_t unpark(Latch &l, const waiters_descriptor &waiters_value) noexcept {
		// Generate parking key
		const auto unpark_key = Latch::template parking_key<mo_to_unpark>();
		using unpark_key_t = std::decay_t<decltype(unpark_key)>;

		std::size_t unparked;
		
		// When unparking shared holders we first might try to reserve the lock for shared usage and we unpark only if successful.
		// This avoids a thundering herd of unparked shared waiters, which then stomp on an (possibly) exclusively held lock.
		if constexpr (tactic == unpark_tactic::all_reserve) {
			// Try to acquire a reservation
			auto acquired_lock = acquire<acquisition_primality::initial, mo_to_unpark>(l);
			if (!acquired_lock)
				return 0;

			// We have acquired lock, unpark and pass the lock to the first waiter.
			unparked = l.parking.unpark_all_closure(unpark_key, [&](const std::size_t count) -> latch_lock_t {
				return count == 0 ? std::move(acquired_lock) : latch_lock_t{};
			});

			// Release our reservation if we failed to unpark anyone.
			if (acquired_lock)
				release<release_reason::failure, mo_to_unpark>(std::move(acquired_lock), l);
		}
		else {
			// Choose function for given unpark tactic
			using parking_lot_t = decltype(l.parking);
			const auto unparking_function = tactic == unpark_tactic::all ?
				&parking_lot_t::template unpark_all<unpark_key_t> :
				&parking_lot_t::template unpark_one<unpark_key_t>;

			// Attempt unpark
			unparked = std::invoke(unparking_function, l.parking, unpark_key);
		}

		// Unregister unparked threads from parked counters
		if (unparked) {
			l.template unpark<mo_to_unpark>(static_cast<counter_t>(unparked));

			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.unparks;
		}

		return unparked;
	}

protected:
	/*
	*	@brief	Checks if a latch value is valid for lock acquisition
	*/
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
	
	/*
	 *	@brief	Handles unparking of shared and upgradeable parked waiters.
	 */
	template <modus_operandi unparker_mo = mo>
	static std::size_t unpark_shared_if_needed(Latch &l, const latch_descriptor &latch_value, const waiters_descriptor &waiters_value) noexcept {
		// Check if shared can even be unparked
		const auto exclusive_waiters = waiters_value.template waiters<modus_operandi::exclusive_lock>();
		if (exclusive_waiters > 0 ||
			!can_acquire_lock<acquisition_primality::waiter, modus_operandi::shared_lock>(latch_value))
			return 0;

		std::size_t unparked = 0;
		const auto shared_parked = waiters_value.template parked<modus_operandi::shared_lock>();

		// Attempt a reserve-and-unpark-all tactic
		// Applicable iff there are more shared parked waiters than a protocol-defined threshold.
		if (shared_parked >= ProtocolPolicy::shared_parked_count_threshold_for_reserve_and_unpark)
			unparked += unpark<unpark_tactic::all_reserve, modus_operandi::shared_lock>(l, waiters_value);
		// ... else unpark all shared
		else if (shared_parked > 0)
			unparked += unpark<unpark_tactic::all, modus_operandi::shared_lock>(l, waiters_value);

		// Unpark an upgradeable, if available.
		const auto upgradeable_waiters = waiters_value.template waiters<modus_operandi::upgradeable_lock>();
		const auto upgradeable_parked = waiters_value.template parked<modus_operandi::upgradeable_lock>();
		if (upgradeable_waiters == 0 &&
			upgradeable_parked > 0)
			unparked += unpark<unpark_tactic::one, modus_operandi::upgradeable_lock>(l, waiters_value);

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
					const auto unparked = unpark<unpark_tactic::one, modus_operandi::upgrade_to_exclusive_lock>(l, waiters_value);
					if (unparked)
						return unparked;
				}
			}
		}

		// ... an exclusive waiter
		const auto exclusive_waiters = waiters_value.template waiters<modus_operandi::exclusive_lock>();
		if (exclusive_waiters < ProtocolPolicy::active_waiters_count_thershold_for_unpark) {
			if (can_acquire_lock<acquisition_primality::waiter, modus_operandi::exclusive_lock>(latch_value)) {
				const auto exclusive_parked = waiters_value.template parked<modus_operandi::exclusive_lock>();

				if (exclusive_parked > 0) {
					const auto unparked = unpark<unpark_tactic::one, modus_operandi::exclusive_lock>(l, waiters_value);
					if (unparked)
						return unparked;
				}
			}
		}

		// ... and all shared waiters
		return unpark_shared_if_needed<unparker_mo>(l, latch_value, waiters_value);
	}

	// Chooses a backoff protocol
	backoff_aggressiveness select_backoff_protocol(Latch &l) const noexcept {
		// Calculate relevant waiters count
		std::size_t waiters;
		{
			const auto waiters_value = l.load_waiters_counters(memory_order::relaxed);
			const auto x = waiters_value.template waiters<modus_operandi::exclusive_lock>();
			const auto u = waiters_value.template waiters<modus_operandi::upgradeable_lock>();

			// For shared lockers, we do not care about upgradeable waiters, they do not block us.
			if constexpr (mo == modus_operandi::shared_lock)
				waiters = x;
			else
				waiters = x + u;

			if constexpr (mo == modus_operandi::exclusive_lock)
				waiters += l.load(memory_order::relaxed).template consumers<modus_operandi::shared_lock>();
		}

		// Calculate probabilities (normalized to waiters count)
		const auto probability_aggressive = static_cast<float>(ProtocolPolicy::desired_aggressive_waiters_count);
		const auto probability_normal = static_cast<float>(ProtocolPolicy::desired_normal_waiters_count);
		const auto probability_relaxed = static_cast<float>(ProtocolPolicy::desired_relaxed_waiters_count);

		// Generate a random number and choose protocol
		const auto x = rand() * static_cast<float>(waiters);
		if (ProtocolPolicy::desired_aggressive_waiters_count > 0 &&
			x < probability_aggressive)
			return backoff_aggressiveness::aggressive;
		if (ProtocolPolicy::desired_normal_waiters_count > 0 &&
			x < probability_aggressive + probability_normal)
			return backoff_aggressiveness::normal;
		if (ProtocolPolicy::desired_relaxed_waiters_count > 0 &&
			x < probability_aggressive + probability_normal + probability_relaxed)
			return backoff_aggressiveness::relaxed;
		return backoff_aggressiveness::very_relaxed;
	}

	// Generates a key for parking
	static park_slot_t backoff_parking_slot() noexcept {
		return { Latch::template parking_key<mo>() };
	}

	// Attempts lock acquisition
	// For upgrades (modus_operandi::upgrade_to_exclusive_lock), lock_to_consume must be provided.
	template <acquisition_primality primality, modus_operandi mo_to_acquire = mo>
	static auto acquire(Latch &l, latch_lock_t &&lock_to_upgrade = {}) noexcept {
		const auto validator = [](auto &&latch_value) {
			return can_acquire_lock<primality, mo_to_acquire>(latch_value);
		};

		// Acquire/Upgrade lock
		if constexpr (mo_to_acquire == modus_operandi::upgrade_to_exclusive_lock)
			return l.template upgrade<primality>(std::move(lock_to_upgrade), validator);
		else
			return l.template acquire<primality, mo_to_acquire>(validator);
	}

	// Releases the lock.
	template <release_reason reason, modus_operandi mo_to_release = mo>
	static void release(latch_lock_t&& lock, Latch &l) noexcept {
		// Release and unpark waiters.
		static constexpr auto memory_order = reason != release_reason::reservation_release ? memory_order::acq_rel : memory_order::release;
		l.template release<mo_to_release>(std::move(lock), memory_order);

		if constexpr (reason != release_reason::reservation_release) {
			// Latch release will serve as a fence
			const auto latch_value = l.load(memory_order::relaxed);
			unpark_if_needed<mo_to_release>(l, latch_value);
		}
	}

	// Protocol waiting logic
	// For upgrades (modus_operandi::upgrade_to_exclusive_lock), lock_to_consume must be provided.
	template <typename Clock, typename Duration>
	bool wait_and_try_lock_until(Latch &l, const std::chrono::time_point<Clock, Duration> &until,
								 latch_lock_t &&lock_to_upgrade = {}) noexcept {
		// Wait and Choose backoff agressiveness protocol
		l.template wait<mo>();
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
				l.template unwait_and_park<mo>();
				parked = true;
				
				if constexpr (shared_futex_detail::collect_statistics)
					++shared_futex_detail::debug_statistics.lock_parks;
			};
			// Execute back-off policy
			auto backoff_result = backoff_protocol::template backoff<mo>(l,
																		 aggressiveness,
																		 park_predicate,
																		 on_park,
																		 iteration,
																		 backoff_parking_slot().key,
																		 until);
			/*		Possible backoff results:
			 *	Timed-out - If we can't take lock we revert state and return failure result.
			 *	Park predicate triggered - Parking failed due to park predicate.
			 *	Unpark - Unparked by another thread. Need to reset iteration counter.
			 *	Spin - A spin or yield iteration was performed.
			 *	After backoff we always pessimistically check if we can lock, and if so try to acquire, otherwise continue waiting or timeout.
			 *	
			 *		There are two possible unpark operations:
			 *	Unpark - Simple unpark. The unparker has unregistered us from park counters.
			 *	Reserve and unpark - In addition to unregistering us from park counters, the unparker has also reserved the lock for us. In this
			 *						 case the reserved_lock field will be populated with a valid lock.
			 */

			const auto result = backoff_result.result;
			auto& reserved_lock = backoff_result.reserved_lock;

			const bool is_registered_as_parked = result != shared_futex_detail::backoff_result::unparked && parked;
			const bool is_waiting = !parked;

			if (!reserved_lock) {
				// On successful backoff we check, conservatively without ping-ponging cache lines, if we should reattempt to acquire lock.
				const auto latch_value = l.load();
				if (can_acquire_lock<acquisition_primality::waiter>(latch_value)) {
					// Otherwise we need to actively reattempt lock acquisition
					lock = acquire<acquisition_primality::waiter>(l, std::move(lock_to_upgrade));
				}
			}
			else {
				// Lock was reserved for us
				if constexpr (shared_futex_detail::debug_shared_futex)
					assert(reserved_lock);

				lock = std::move(reserved_lock);
			}

			// Are we done here?
			if (lock || result == shared_futex_detail::backoff_result::timeout) {
				// Unwait/unpark.
				if (is_registered_as_parked)
					l.template unpark<mo>();
				else if (is_waiting)
					l.template unwait<mo>();

				// Have we acquired lock?
				if (lock)
					return true;

				// Timeout
				return false;
			}

			// Otherwise go back to waiting
			if (is_registered_as_parked)
				l.template unpark_and_wait<mo>();
			else if (!is_waiting)
				l.template wait<mo>();

			// If we have been unparked, reset iterations counter to restart backoff policy.
			if (parked)
				iteration = 0;
			
			// Choose a new backoff aggressiveness protocol every few iterations.
			if (iteration % ProtocolPolicy::refresh_backoff_protocol_every_iterations == 0)
				aggressiveness = select_backoff_protocol(l);
		}
	}

public:
	// Attempts a single lock acquisition, returns true on success, false on failure.
	template <modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo != modus_operandi::upgrade_to_exclusive_lock>>
	bool try_lock(Latch &l) noexcept {
		// Attempt lock/upgrade
		lock = acquire<acquisition_primality::initial>(l);
		return owns_lock();
	}
	// Attempts a single lock acquisition, returns true on success, false on failure.
	template <modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo == modus_operandi::upgrade_to_exclusive_lock>>
	bool try_lock(Latch &l, latch_lock_t &&lock_to_consume) noexcept {
		// Attempt lock/upgrade
		lock = acquire<acquisition_primality::initial>(l, std::move(lock_to_consume));
		return owns_lock();
	}
	
	// Attempts lock acquisition with an optional timeout.
	template <
		typename Clock, typename Duration,
		modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo != modus_operandi::upgrade_to_exclusive_lock>
	>
	bool try_lock_until(Latch &l, const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Attempt lock/upgrade
		lock = acquire<acquisition_primality::initial>(l);
		if (owns_lock())
			return true;

		return wait_and_try_lock_until(l, until);
	}
	// Attempts lock acquisition with an optional timeout.
	template <
		typename Clock, typename Duration,
		modus_operandi lock_mo = mo, typename = std::enable_if_t<lock_mo == modus_operandi::upgrade_to_exclusive_lock>
	>
	bool try_lock_until(Latch &l, latch_lock_t &&lock_to_consume, const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Attempt lock/upgrade
		lock = acquire<acquisition_primality::initial>(l, std::move(lock_to_consume));
		if (owns_lock())
			return true;

		return wait_and_try_lock_until(l, until, std::move(lock_to_consume));
	}

	// Releases the lock
	void unlock(Latch &l) noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(owns_lock());
		release<release_reason::lock_release>(std::move(lock), l);
	}

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
