// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "shared_futex_parking.hpp"
#include "shared_futex_latch_descriptors.hpp"
#include "../atomic/atomic_tsx.hpp"
#include "../utils/tuple_has_type.hpp"

#include <cassert>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ste {

namespace shared_futex_detail {

struct features_helper {
	template <typename SupportedFeaturesTuple, typename... RequestedFeatures>
	static constexpr bool check_supports_all(const std::tuple<RequestedFeatures...> &requested_features) noexcept {
		return std::conjunction_v<utils::tuple_has_type<RequestedFeatures, SupportedFeaturesTuple>...>;
	}
	template <typename Feature, typename... RequestedFeatures>
	static constexpr bool requires_feature(const std::tuple<RequestedFeatures...> &requested_features) noexcept {
		return (std::is_same_v<Feature, RequestedFeatures> || ...);
	}
};

template <bool has_waiters_counter, typename waiters_type, typename latch_type, std::size_t alignment>
struct latch_storage {
	// Parking/waiters counters
	waiters_type waiters{};
	// Latch
	latch_type latch{};
};
template <typename waiters_type, typename latch_type, std::size_t alignment>
struct latch_storage<false, waiters_type, latch_type, alignment> {
	// Latch
	latch_type latch{};
};

}

/*
 *	@brief	shared_futex's latch
 */
template <typename FutexPolicy>
class shared_futex_default_latch {
public:
	using futex_policy = FutexPolicy;
	// Our list of supported features
	using supported_features = std::tuple<
		shared_futex_features::use_transactional_hle_exclusive,
		shared_futex_features::use_transactional_rtm
	>;
	
private:
	static_assert(shared_futex_detail::features_helper::check_supports_all<supported_features>(futex_policy::features{}), 
				  "futex_policy::features contains unsupported features, see supported_features.");

	// Checks if the futex's Features list contains Feature
	template <typename Feature>
	static constexpr bool requires_feature() noexcept {
		return shared_futex_detail::features_helper::requires_feature<Feature>(futex_policy::features{});
	}

public:
	// Requested features
	static constexpr bool tsx_hle_exclusive = requires_feature<shared_futex_features::use_transactional_hle_exclusive>();	// Using transactional HLE
	static constexpr bool tsx_rtm = requires_feature<shared_futex_features::use_transactional_rtm>();	// Using transactional RTM

	static_assert(!tsx_hle_exclusive || !tsx_rtm, "TSX HLE and RTM cannot be used simultaneously");

private:
	using modus_operandi = shared_futex_detail::modus_operandi;
	using unpark_tactic = shared_futex_detail::unpark_tactic;
	enum class latch_acquisition_method : std::uint8_t {
		set_flag, 
		cxhg, 
		counter,
	};
	enum class lock_status : std::uint8_t {
		not_acquired,
		acquired,
		transaction,
	};

	enum class internal_acquisition_flags {
		none = 0, 
		skip_transactional = 1 << 0
	};
	friend constexpr internal_acquisition_flags operator|(const internal_acquisition_flags &lhs, const internal_acquisition_flags &rhs) noexcept {
		using T = std::underlying_type_t<internal_acquisition_flags>;
		return static_cast<internal_acquisition_flags>(static_cast<T>(lhs) | static_cast<T>(rhs));
	}
	friend constexpr internal_acquisition_flags operator&(const internal_acquisition_flags &lhs, const internal_acquisition_flags &rhs) noexcept {
		using T = std::underlying_type_t<internal_acquisition_flags>;
		return static_cast<internal_acquisition_flags>(static_cast<T>(lhs) & static_cast<T>(rhs));
	}

	static constexpr bool count_waiters = futex_policy::count_waiters;
	static constexpr bool parking_allowed = futex_policy::parking_policy != shared_futex_parking_policy::none;
	// If we neither allow parking nor count waiter we can dispense with the waiters counter.
	static constexpr bool has_waiters_counter = count_waiters || parking_allowed;

	static constexpr bool count_shared_parked = true;// futex_policy::parking_policy != shared_futex_parking_policy::shared_local;

public:
	// Represents a latch lock. A valid object holds a lock and should be released by consuming the object with a call to latch's release().
	class latch_lock {
		friend class shared_futex_default_latch;

		lock_status mode{ lock_status::not_acquired };
		
		latch_lock(lock_status mode) noexcept : mode(mode) {}
		void reset() && noexcept { mode = lock_status::not_acquired; }

	public:
		latch_lock() noexcept = default;
		latch_lock(latch_lock &&o) noexcept : mode(std::exchange(o.mode, lock_status::not_acquired)) {}
		latch_lock(const latch_lock&) = delete;
		latch_lock &operator=(latch_lock &&o) noexcept {
			assert(mode == lock_status::not_acquired);

			mode = std::exchange(o.mode, lock_status::not_acquired);
			return *this;
		}
		latch_lock &operator=(const latch_lock&) = delete;
		~latch_lock() noexcept { assert(mode == lock_status::not_acquired); }

		explicit operator bool() const noexcept { return mode != lock_status::not_acquired; }
	};

	using latch_data_type = std::make_signed_t<typename futex_policy::latch_data_type>;
	using waiters_counter_type = std::int64_t;
	using parking_key_t = std::uint64_t;
	
	using latch_descriptor = shared_futex_detail::latch_descriptor<latch_data_type, futex_policy::parking_policy>;
	using waiters_descriptor = shared_futex_detail::waiters_descriptor<
		waiters_counter_type,
		futex_policy::shared_bits, futex_policy::upgradeable_bits, futex_policy::exclusive_bits,
		count_shared_parked, count_waiters
	>;
	using parking_lot_t = shared_futex_detail::shared_futex_parking<futex_policy::parking_policy>;
	
	static constexpr auto alignment = std::max(futex_policy::alignment, alignof(std::max_align_t));

private:
	using latch_atomic_t = atomic_tsx<latch_data_type>;
	using waiters_atomic_t = atomic_tsx<waiters_counter_type>;

	static_assert(sizeof(latch_descriptor) <= sizeof(latch_data_type), "latch_data_type too small to contain latch_descriptor");
	static_assert(sizeof(waiters_descriptor) <= sizeof(waiters_counter_type), "waiters_counter_type too small to contain waiters_descriptor");
	static_assert(latch_descriptor::shared_consumers_bits >= futex_policy::shared_bits, "Shared consumers bit count can not satisfy requested shared_bits bit count.");
	
	static_assert(latch_atomic_t::is_always_lock_free, "Latch is not lock-free!");
	static_assert(waiters_atomic_t::is_always_lock_free, "Latch waiter counter is not lock-free!");

	using latch_storage_t = shared_futex_detail::latch_storage<
		has_waiters_counter,
		waiters_atomic_t,
		latch_atomic_t,
		alignment
	>;

private:
	// Latch storage
	alignas(alignment) latch_storage_t storage{};

public:
	// Parking lot for smart wakeup
	parking_lot_t parking_lot;

private:
	// Specifies the initial state the latch is assumed to be at.
	template <modus_operandi mo>
	static constexpr latch_descriptor singular_latch_state_for_mo() noexcept {
		if constexpr (mo == modus_operandi::upgrade_to_exclusive_lock) {
			// The locker already holds an upgradeable lock
			return latch_descriptor::template make_locked<modus_operandi::upgradeable_lock>();
		}

		// Clean latch otherwise
		return {};
	}
	// Chooses an acquisition method for a given mo
	template <modus_operandi mo>
	static constexpr latch_acquisition_method acquisition_method_for_mo() noexcept {
		switch (mo) {
		case modus_operandi::shared_lock:
			// Shared holders use a counter
			return latch_acquisition_method::counter;
		case modus_operandi::exclusive_lock:
			// Fastest acquisition method, set the bit.
			return latch_acquisition_method::set_flag;
		default:
		case modus_operandi::upgradeable_lock:
		case modus_operandi::upgrade_to_exclusive_lock:
			// compare-exchange to acquire a slot
			return latch_acquisition_method::cxhg;
		}
	}
	// Returns true if latch should count active waiters for a given mo
	template <modus_operandi mo>
	static constexpr bool should_count_waiters() noexcept {
		if constexpr (count_waiters)
			return mo == modus_operandi::exclusive_lock || mo == modus_operandi::upgradeable_lock;
		else
			return false;
	}
	// Returns true if latch should count parked waiters for a given mo
	template <modus_operandi mo>
	static constexpr bool should_count_parked() noexcept {
		if constexpr (!parking_allowed)
			return false;
		return true;
	}

	// Generates a unique parking key for parking_lot parkings
	template <modus_operandi mo>
	static parking_key_t parking_lot_parking_key() noexcept {
		return static_cast<uint64_t>(mo);
	}

	// Acquires lock in transactional mode
	[[nodiscard]] latch_lock acquire_internal_transactional() noexcept {
		static constexpr auto max_tsx_retries = 3;
		
		if constexpr (shared_futex_detail::collect_statistics)
			++shared_futex_detail::debug_statistics.transactional_lock_elision_attempts;

		transactional_memory::status tsx_start;
		const auto tsx_start_has_flag = [&](const transactional_memory::status f) {
			return (tsx_start & f) != static_cast<transactional_memory::status>(0);
		};
		
		// Attempt a transactions, and retry up to a fixed number of tries depending on returned abort code.
		for (auto i=0;; ++i) {
			tsx_start = transactional_memory::transaction_begin().first;

			const auto should_retry = tsx_start_has_flag(transactional_memory::status::abort_retry);
			if (should_retry && i < max_tsx_retries)
				continue;
			break;
		}
		if (tsx_start == transactional_memory::status::started)
			return { lock_status::transaction };
					  
		// Transaction failed.

		if constexpr (shared_futex_detail::collect_statistics) {
			// Log transaction failure
			if (tsx_start_has_flag(transactional_memory::status::abort_system))
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_sys;
			if (tsx_start_has_flag(transactional_memory::status::abort_capacity))
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_capacity;
			if (tsx_start_has_flag(transactional_memory::status::abort_conflict))
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_conflict;
			if (tsx_start_has_flag(transactional_memory::status::abort_debug))
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_debug;
			if (tsx_start_has_flag(transactional_memory::status::abort_explicit))
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_explicit;
			if (tsx_start_has_flag(transactional_memory::status::abort_nested))
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_nested;
			if (tsx_start == transactional_memory::status::abort_retry)
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_too_many_retries;
			if (tsx_start == transactional_memory::status::abort_unknown)
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_other;
		}

		return {};
	}
	// Attempts lock acquisition
	template <
		shared_futex_detail::acquisition_primality primality, modus_operandi mo, 
		internal_acquisition_flags flags = internal_acquisition_flags::none, typename Validator
	>
	[[nodiscard]] latch_lock acquire_internal(Validator &&validator, memory_order order) noexcept {
		// If transactional is enabled we attempt a lock-elision only if this is an initial acquisition attempt and skip_transactional flag is 
		// unset.
		if constexpr (tsx_rtm && primality == shared_futex_detail::acquisition_primality::initial &&
					  (flags & internal_acquisition_flags::skip_transactional) == internal_acquisition_flags::none) {
			auto lock = acquire_internal_transactional();
			if (lock)
				return lock;
		}

		static constexpr auto method = acquisition_method_for_mo<mo>();
		if constexpr (method == latch_acquisition_method::counter ||
					  method == latch_acquisition_method::cxhg) {
			auto expected = static_cast<latch_data_type>(singular_latch_state_for_mo<mo>());
			auto desired_latch = latch_descriptor::template make_locked<mo>();
						  
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			// If we successfully exchange singular value with desired latch value, we are done.
			if (storage.latch.compare_exchange_strong(expected, static_cast<latch_data_type>(desired_latch), order))
				return { lock_status::acquired };

			// Otherwise keep trying to write desired/increase counter while previous latch value is valid for acquisition
			while (validator(latch_descriptor{ expected })) {
				desired_latch = latch_descriptor{ expected };
				desired_latch.set_lock_held_flag();
				desired_latch.template inc_consumers<mo>(1);
				
				if constexpr (shared_futex_detail::collect_statistics)
					++shared_futex_detail::debug_statistics.lock_rmw_instructions;

				if (storage.latch.compare_exchange_weak(expected, static_cast<latch_data_type>(desired_latch), order))
					return { lock_status::acquired };
			}
		}
		else /*(method == latch_acquisition_method::set_flag)*/ {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			// Bit-test-and-set
			const auto bit = latch_descriptor::lock_held_bit_index;
			if constexpr (tsx_hle_exclusive && primality == shared_futex_detail::acquisition_primality::initial) {
				// xacquire for transactional hardware-lock-elision
				if (!storage.latch.bit_test_and_set(bit, memory_order::xacquire))
					return { lock_status::transaction };
			}
			else {
				if (!storage.latch.bit_test_and_set(bit, order))
					return { lock_status::acquired };
			}
		}

		// Failed
		return {};
	}

	// Releases the latch in transactional mode
	// Returns true on successful transaction commit, false otherwise.
	bool release_internal_transactional(lock_status mode) noexcept {
		if (mode == lock_status::transaction) {
			// Finalize the transaction.
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.transactional_lock_elision_success;

			_xend();
			return true;
		}

		// Not in transactional mode
		return false;
	}
	// Releases the latch
	template <modus_operandi mo>
	void release_internal(lock_status mode, memory_order order) noexcept {
		if constexpr (tsx_rtm) {
			// If we can release the latch in transactional mode, then we return an empty latch
			if (release_internal_transactional(mode))
				return;
		}

		static constexpr auto method = acquisition_method_for_mo<mo>();
		const auto store_mo = order == memory_order::relaxed || order == memory_order::acquire ? 
			memory_order::relaxed : 
			memory_order::release;

		// Calculate some latch bits
		latch_descriptor desired_latch = {};
		const auto single_consumer_bits = static_cast<latch_data_type>(latch_descriptor::template make_single_consumer<mo>());
		
		if constexpr (method == latch_acquisition_method::cxhg ||
					  method == latch_acquisition_method::counter) {
			// Attempt to free the latch
			latch_data_type expected = storage.latch.load(memory_order::acquire);
								 
			// Optimization for counter method: If we have enough holders, atomically decrement counter, last one turns off the lights.
			if constexpr (method == latch_acquisition_method::counter) {
				static constexpr auto shared_holders_for_atomic_add = 3;

				if (latch_descriptor{ expected }.template consumers<mo>() >= shared_holders_for_atomic_add) {
					if constexpr (shared_futex_detail::collect_statistics)
						++shared_futex_detail::debug_statistics.lock_rmw_instructions;

					const auto new_val = storage.latch.fetch_add(-single_consumer_bits, memory_order::acq_rel) - single_consumer_bits;
					if (latch_descriptor{ new_val } == latch_descriptor::make_exclusive_locked())
						storage.latch.store(static_cast<latch_data_type>(desired_latch), store_mo);

					return;
				}
			}

			do {
				if constexpr (shared_futex_detail::collect_statistics)
					++shared_futex_detail::debug_statistics.lock_rmw_instructions;

				// Calculate new desired value
				desired_latch = latch_descriptor{ expected - single_consumer_bits };
				// Clear lock held flag, if needed.
				if (desired_latch == latch_descriptor::make_exclusive_locked())
					desired_latch = {};
			} while (!storage.latch.compare_exchange_weak(expected, static_cast<latch_data_type>(desired_latch), order));
		}
		else /*(method == latch_acquisition_method::set_flag)*/ {
			if constexpr (tsx_hle_exclusive) {
				// xrelease
				if (mode == lock_status::transaction) {
					storage.latch.store(static_cast<latch_data_type>(desired_latch), memory_order::xrelease);
					return;
				}
			}
			// Atomic store
			storage.latch.store(static_cast<latch_data_type>(desired_latch), store_mo);
		}
	}

public:
	shared_futex_default_latch() = default;
	shared_futex_default_latch(shared_futex_default_latch&&) = delete;
	shared_futex_default_latch(const shared_futex_default_latch&) = delete;
	shared_futex_default_latch &operator=(shared_futex_default_latch&&) = delete;
	shared_futex_default_latch &operator=(const shared_futex_default_latch&) = delete;
	~shared_futex_default_latch() noexcept {
		// Latch dtored while lock is held or pending?
		assert(storage.latch.load() == latch_data_type{});
	}

	latch_descriptor load(memory_order order = memory_order::acquire) const noexcept {
		if constexpr (shared_futex_detail::collect_statistics) {
			if (order != memory_order::relaxed)
				++shared_futex_detail::debug_statistics.lock_atomic_loads;
		}

		return latch_descriptor{ storage.latch.load(order) };
	}
	waiters_descriptor load_waiters_counters(memory_order order = memory_order::acquire) const noexcept {
		if constexpr (has_waiters_counter) {
			if constexpr (shared_futex_detail::collect_statistics) {
				if (order != memory_order::relaxed)
					++shared_futex_detail::debug_statistics.lock_atomic_loads;
			}

			return waiters_descriptor{ storage.waiters.load(order) };
		}

		// Return empty waiters descriptor if we are not counting waiters
		return waiters_descriptor{};
	}
	
	/*
	 *	@brief	Attempts to acquire lock.
	 *	
	 *	@param	validator	A closure that takes a latch_descriptor and returns true iff the latch at that state is valid for lock acquisition.
	 *	
	 *	@return	Returns a pair of a boolean indicating whether the acquisition was successful and, on successful acquisitions, a lock object
	 *			that should be consumed when unlocking by a call to release().
	 */
	template <
		shared_futex_detail::acquisition_primality primality, modus_operandi mo, typename Validator,
		typename = std::enable_if_t<mo != modus_operandi::upgrade_to_exclusive_lock>
	>
	[[nodiscard]] latch_lock acquire(Validator &&validator, memory_order order = memory_order::acq_rel) noexcept {
		return acquire_internal<primality, mo>(std::move(validator), order);
	}
	
	/*
	 *	@brief	Attempts to upgrade the lock from upgradeable to exclusive.
	 *	
	 *	@param	lock		Upgradeable lock to upgrade. If acquisition is successful the lock is consumed and an exclusive lock is returned,
	 *						otherwise the lock is untouched.
	 *	@param	validator	A closure that takes a latch_descriptor and returns true iff the latch at that state is valid for lock upgrade.
	 *	
	 *	@return	Returns a pair of a boolean indicating whether the acquisition was successful and, on successful acquisitions, a lock object
	 *			that should be consumed when unlocking by a call to release().
	 */
	template <shared_futex_detail::acquisition_primality primality, typename Validator>
	[[nodiscard]] latch_lock upgrade(latch_lock &&lock, Validator &&validator, memory_order order = memory_order::acq_rel) noexcept {
		static constexpr modus_operandi mo = modus_operandi::upgrade_to_exclusive_lock;

		if constexpr (tsx_rtm) {
			// If we are in a pending transaction treat the upgrade as part of the transaction, so that and in case of an abort, we will be 
			// reverted all the way back to upgradeable acquisition.
			if (lock.mode == lock_status::transaction) {
				std::move(lock).reset();
				return { lock_status::transaction };
			}
		}

		// Otherwise upgrade normally but disallow transactions.
		auto upgraded_lock = acquire_internal<primality, mo, internal_acquisition_flags::skip_transactional>(std::move(validator), order);
		if (upgraded_lock)
			std::move(lock).reset();

		return upgraded_lock;
	}

	/*
	 *	@brief	Attempts unparking of threads of a specified mo using a given unpark tactic.
	 *			Return value might be inaccurate for unpark_all tactic, depending on parking policy used.
	 *	@return	Count of threads successfully unparked
	 */
	template <modus_operandi mo, typename ParkPredicate, typename OnPark, typename Clock, typename Duration>
	parking_lot_wait_state park(ParkPredicate &&park_predicate,
								OnPark &&on_park,
								const std::chrono::time_point<Clock, Duration> &until) noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");

		if constexpr (mo == modus_operandi::shared_lock &&
					  futex_policy::parking_policy == shared_futex_parking_policy::shared_local) {
			// Park shared in local slot
			return parking_lot.template park_until<mo>(std::forward<ParkPredicate>(park_predicate),
													   std::forward<OnPark>(on_park),
													   until);
		}
		else {
			// Wait
			auto key = parking_lot_parking_key<mo>();
			return parking_lot.template park_until<mo>(std::forward<ParkPredicate>(park_predicate),
													   std::forward<OnPark>(on_park),
													   std::move(key),
													   until);
		}
	}
	
	/*
	 *	@brief	Attempts unparking of threads of a specified mo using a given unpark tactic.
	 *			Return value might be inaccurate for unpark_all tactic, depending on parking policy used.
	 *	@return	Count of threads successfully unparked
	 */
	template <unpark_tactic tactic, modus_operandi mo>
	std::size_t unpark() noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");

		if constexpr (mo == modus_operandi::shared_lock &&
					  futex_policy::parking_policy == shared_futex_parking_policy::shared_local) {
			return parking_lot.template unpark<tactic, mo>();
		}
		else {
			// Generate parking key and attempt unpark
			auto unpark_key = parking_lot_parking_key<mo>();
			return parking_lot.template unpark<tactic, mo>(std::move(unpark_key));
		}
	}

	/*
	 *	@brief	Releases the latch, consuming a lock in the process.
	 *	
	 *	@param	lock	lock, acquired via a call to acquire() or upgrade(), to consume.
	 */
	template <modus_operandi mo>
	void release(latch_lock &&lock, memory_order order = memory_order::release) noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(lock);

		// Release and consume the lock
		release_internal<mo>(lock.mode, order);
		std::move(lock).reset();
	}
	
	// Registers as active waiter
	template <modus_operandi mo>
	void register_wait(memory_order order = memory_order::release) noexcept {
		if constexpr (has_waiters_counter && should_count_waiters<mo>()) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_waiters<mo>(1);
			const auto bits = static_cast<waiters_counter_type>(d);
			storage.waiters.fetch_add(bits, order);
		}
	}
	// Unregisters as active waiter
	template <modus_operandi mo>
	void register_unwait(memory_order order = memory_order::release) noexcept {
		if constexpr (has_waiters_counter && should_count_waiters<mo>()) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_waiters<mo>(1);
			const auto bits = -static_cast<waiters_counter_type>(d);
			storage.waiters.fetch_add(bits, order);
		}
	}
	// Registers parked thread
	template <modus_operandi mo>
	void register_unwait_and_park(memory_order order = memory_order::release) noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");
		
		if constexpr (should_count_waiters<mo>() || should_count_parked<mo>()) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			waiters_counter_type bits = 0;
			if constexpr (should_count_parked<mo>()) {
				waiters_descriptor dp = {};
				dp.template inc_parked<mo>(1);
				bits += static_cast<waiters_counter_type>(dp);
			}
			if constexpr (should_count_waiters<mo>()) {
				// Remove wait bit
				waiters_descriptor dw = {};
				dw.template inc_waiters<mo>(1);
				bits -= static_cast<waiters_counter_type>(dw);
			}

			storage.waiters.fetch_add(bits, order);
		}
	}
	// Unregister parked and register as waiter
	template <modus_operandi mo>
	void register_unpark_and_wait(memory_order order = memory_order::release) noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");
		
		if constexpr (should_count_waiters<mo>() || should_count_parked<mo>()) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			waiters_counter_type bits = 0;
			if constexpr (should_count_parked<mo>()) {
				waiters_descriptor dp = {};
				dp.template inc_parked<mo>(1);
				bits -= static_cast<waiters_counter_type>(dp);
			}
			if constexpr (should_count_waiters<mo>()) {
				// Add wait bit
				waiters_descriptor dw = {};
				dw.template inc_waiters<mo>(1);
				bits += static_cast<waiters_counter_type>(dw);
			}

			storage.waiters.fetch_add(bits);
		}
	}
	// Unregister parked thread(s)
	template <modus_operandi mo>
	void register_unpark(std::size_t count = 1, memory_order order = memory_order::release) noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex) {
			assert(parking_allowed && "Parking not allowed");
			assert(count && "Count must be positive");
		}
		
		if constexpr (should_count_parked<mo>()) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_parked<mo>(count);
			const auto bits = -static_cast<waiters_counter_type>(d);
			
			storage.waiters.fetch_add(bits);
		}
	}
};

}
