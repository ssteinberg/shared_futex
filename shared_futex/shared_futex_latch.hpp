// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "shared_futex_parking.hpp"
#include "shared_futex_latch_storage.hpp"
#include "../atomic/atomic_tsx.hpp"
#include "../utils/tuple_has_type.hpp"

#include <cassert>
#include <tuple>
#include <type_traits>
#include <utility>
#include <intrin.h>

namespace ste::shared_futex_detail {

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

template <typename LatchType, typename ParkingType = void, bool has_parking = false>
struct latch_data {
	LatchType latch;
	ParkingType parking_lot;
};
template <typename LatchType, typename ParkingType>
struct latch_data<LatchType, ParkingType, false> {
	LatchType latch;
};

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
		shared_futex_features::use_transactional_rtm,
		shared_futex_features::use_slots
	>;
	
private:
	static_assert(features_helper::check_supports_all<supported_features>(futex_policy::features{}), 
				  "futex_policy::features contains unsupported features, see supported_features.");

	// Checks if the futex's Features list contains Feature
	template <typename Feature>
	static constexpr bool requires_feature() noexcept {
		return features_helper::requires_feature<Feature>(futex_policy::features{});
	}

public:
	// Requested features
	static constexpr bool tsx_hle_exclusive = requires_feature<shared_futex_features::use_transactional_hle_exclusive>();	// Using transactional HLE
	static constexpr bool tsx_rtm = requires_feature<shared_futex_features::use_transactional_rtm>();	// Using transactional RTM

	static_assert(!tsx_hle_exclusive || !tsx_rtm, "TSX HLE and RTM cannot be used simultaneously");

	static constexpr bool use_slots = requires_feature<shared_futex_features::use_slots>();

private:
	using modus_operandi = modus_operandi;
	using unpark_tactic = unpark_tactic;
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
	enum class lock_contention { none, contended };

	enum class internal_acquisition_flags {
		none = 0,
		// Disables transactional features
		skip_transactional = 1 << 0,
		// Upgrading an already upgraded latch returns successfully without modifying the latch
		allow_upgrading_upgraded_latch = 1 << 1,
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
	static constexpr bool count_shared_parked = true;

	using slot_type = std::uint32_t;
	static constexpr std::size_t slot_count = use_slots ? 8 : 1;
	static constexpr slot_type primary_slot = 0;

public:
	// Represents a latch lock. A valid object holds a lock and should be released by consuming the object with a call to latch's release().
	class latch_lock {
		friend class shared_futex_default_latch;

		lock_status mode{ lock_status::not_acquired };
		std::uint8_t slot_used{ 0 };
		
		latch_lock(lock_status mode) noexcept : mode(mode) {}
		void reset() && noexcept { mode = lock_status::not_acquired; }

	public:
		latch_lock() noexcept = default;
		latch_lock(latch_lock &&o) noexcept : mode(std::exchange(o.mode, lock_status::not_acquired)), slot_used(o.slot_used) {}
		latch_lock(const latch_lock&) = delete;
		latch_lock &operator=(latch_lock &&o) noexcept {
			assert(mode == lock_status::not_acquired);

			mode = std::exchange(o.mode, lock_status::not_acquired);
			slot_used = o.slot_used;
			return *this;
		}
		latch_lock &operator=(const latch_lock&) = delete;
		~latch_lock() noexcept { assert(mode == lock_status::not_acquired); }

		explicit operator bool() const noexcept { return mode != lock_status::not_acquired; }
	};

	using latch_data_type = std::make_signed_t<typename futex_policy::latch_data_type>;
	using waiters_counter_type = std::int64_t;
	using parking_key_t = std::uint64_t;
	
	using latch_descriptor = latch_descriptor<latch_data_type, futex_policy::parking_policy>;
	using waiters_descriptor = waiters_descriptor<
		waiters_counter_type,
		futex_policy::shared_bits, futex_policy::upgradeable_bits, futex_policy::exclusive_bits,
		count_shared_parked, count_waiters
	>;
	using parking_lot_t = shared_futex_parking<futex_policy::parking_policy>;

private:
	using latch_atomic_t = atomic_tsx<latch_data_type>;
	using waiters_atomic_t = atomic_tsx<waiters_counter_type>;

	static_assert(sizeof(latch_descriptor) <= sizeof(latch_data_type), "latch_data_type too small to contain latch_descriptor");
	static_assert(sizeof(waiters_descriptor) <= sizeof(waiters_counter_type), "waiters_counter_type too small to contain waiters_descriptor");
	static_assert(latch_descriptor::shared_consumers_bits >= futex_policy::shared_bits, "Shared consumers bit count can not satisfy requested shared_bits bit count.");
	
	static_assert(latch_atomic_t::is_always_lock_free, "Latch is not lock-free!");
	static_assert(waiters_atomic_t::is_always_lock_free, "Latch waiter counter is not lock-free!");
	
	using latch_storage_t = latch_storage<
		has_waiters_counter,
		waiters_atomic_t,
		latch_atomic_t,
		slot_count
	>;
	
	using latch_data_t = latch_data<latch_storage_t, parking_lot_t, parking_allowed>;
	static constexpr auto alignment = std::max(futex_policy::alignment, sizeof(latch_data_t));

private:
	// Latch storage
	alignas(alignment) latch_data_t data{};

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
		return parking_allowed;
	}

	// Generates a unique parking key for parking_lot parkings
	template <modus_operandi mo>
	static parking_key_t parking_lot_parking_key() noexcept {
		return static_cast<uint64_t>(mo);
	}

	// Acquires lock in transactional mode
	[[nodiscard]] latch_lock acquire_internal_transactional() noexcept {
		static constexpr auto max_tsx_retries = 3;
		
		if constexpr (collect_statistics)
			++debug_statistics.transactional_lock_elision_attempts;

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

		if constexpr (collect_statistics) {
			// Log transaction failure
			if (tsx_start_has_flag(transactional_memory::status::abort_system))
				++debug_statistics.transactional_lock_elision_aborts_sys;
			if (tsx_start_has_flag(transactional_memory::status::abort_capacity))
				++debug_statistics.transactional_lock_elision_aborts_capacity;
			if (tsx_start_has_flag(transactional_memory::status::abort_conflict))
				++debug_statistics.transactional_lock_elision_aborts_conflict;
			if (tsx_start_has_flag(transactional_memory::status::abort_debug))
				++debug_statistics.transactional_lock_elision_aborts_debug;
			if (tsx_start_has_flag(transactional_memory::status::abort_explicit))
				++debug_statistics.transactional_lock_elision_aborts_explicit;
			if (tsx_start_has_flag(transactional_memory::status::abort_nested))
				++debug_statistics.transactional_lock_elision_aborts_nested;
			if (tsx_start == transactional_memory::status::abort_retry)
				++debug_statistics.transactional_lock_elision_aborts_too_many_retries;
			if (tsx_start == transactional_memory::status::abort_unknown)
				++debug_statistics.transactional_lock_elision_aborts_other;
		}

		return {};
	}
	// Attempts latch slot acquisition
	// Returns result and lock contention hint
	template <
		acquisition_primality primality, modus_operandi mo, 
		internal_acquisition_flags flags = internal_acquisition_flags::none, typename Validator
	>
	[[nodiscard]] std::pair<lock_status, lock_contention> acquire_internal_slot(slot_type slot, Validator &&validator, memory_order order) noexcept {
		static constexpr auto method = acquisition_method_for_mo<mo>();
		if constexpr (method == latch_acquisition_method::counter ||
					  method == latch_acquisition_method::cxhg) {
			auto expected = static_cast<latch_data_type>(singular_latch_state_for_mo<mo>());
			auto desired_latch = latch_descriptor::template make_locked<mo>();
						  
			if constexpr (collect_statistics)
				++debug_statistics.lock_rmw_instructions;

			// If we successfully exchange singular value with desired latch value, we are done.
			if (data.latch[slot]->compare_exchange_strong(expected, static_cast<latch_data_type>(desired_latch), order))
				return { lock_status::acquired, lock_contention::none };
			
			// If we are upgrading the latch and the allow-upgrading-upgraded flag is set then upgrading a latch that has already been upgraded is
			// allowed.
			if constexpr (mo == modus_operandi::upgrade_to_exclusive_lock &&
				(flags & internal_acquisition_flags::allow_upgrading_upgraded_latch) != internal_acquisition_flags::none) {
				if (expected == static_cast<latch_data_type>(desired_latch))
					return { lock_status::acquired, lock_contention::none };
			}

			// Otherwise keep trying to write desired/increase counter while previous latch value is valid for acquisition
			while (validator(latch_descriptor{ expected })) {
				desired_latch = latch_descriptor{ expected };
				desired_latch.set_lock_held_flag();
				desired_latch.template inc_consumers<mo>(1);
				
				if constexpr (collect_statistics)
					++debug_statistics.lock_rmw_instructions;

				if (data.latch[slot]->compare_exchange_weak(expected, static_cast<latch_data_type>(desired_latch), order))
					return { lock_status::acquired, lock_contention::contended };
			}
		}
		else /*(method == latch_acquisition_method::set_flag)*/ {
			if constexpr (collect_statistics)
				++debug_statistics.lock_rmw_instructions;

			// Bit-test-and-set
			const auto bit = latch_descriptor::lock_held_bit_index;
			if constexpr (tsx_hle_exclusive && primality == acquisition_primality::initial) {
				// xacquire for transactional hardware-lock-elision
				if (!data.latch[slot]->bit_test_and_set(bit, memory_order::xacquire))
					return { lock_status::transaction, lock_contention::none };
			}
			else {
				if (!data.latch[slot]->bit_test_and_set(bit, order))
					return { lock_status::acquired, lock_contention::none };
			}
		}

		// Failed
		return { lock_status::not_acquired, lock_contention::contended };
	}
	// Attempts lock acquisition, multi-slot shared logic.
	template <acquisition_primality primality, typename Validator>
	[[nodiscard]] latch_lock acquire_internal_multislot_shared(Validator &&validator, memory_order order) noexcept {
		// Choose a slot at random from active slots.
		const slot_type active_slots = data.latch.active_slots.load();
		const slot_type slot = __rdtsc() % active_slots;
		assert(active_slots <= latch_storage_t::count);

		// Attempt acquire
		const auto [result, contention] = acquire_internal_slot<primality, modus_operandi::shared_lock>(slot, 
																										std::forward<Validator>(validator), 
																										order);
		if (result != lock_status::not_acquired) {
			// Success. Re-check active slot count and make sure we are not out of range
			if (data.latch.active_slots.load() <= slot) {
				// Revert and fail
				release_internal_slot<modus_operandi::shared_lock>(slot, result, order);
				return {};
			}
			
			// In case of contention on the slot, consider increasing active slot count.
			// Compare-exchange to avoid racing with a non-shared acquirer.
			if (contention == lock_contention::contended && active_slots < latch_storage_t::count) {
				auto expected = active_slots;
				data.latch.active_slots.compare_exchange_strong(expected, active_slots + 1, memory_order::release, memory_order::relaxed);
			}

			// Return acquired lock
			auto l = latch_lock{ result };
			l.slot_used = static_cast<std::uint8_t>(slot);
			return l;
		}

		return {};
	}
	// Attempts lock acquisition, multi-slot non-shared logic.
	template <acquisition_primality primality, modus_operandi mo, typename Validator>
	[[nodiscard]] latch_lock acquire_internal_multislot_nonshared(Validator &&validator, memory_order order) noexcept {
		const auto acquire_order = memory_order_load(order);

		// Attempt to acquire primary slot first
		static constexpr auto flags = mo == modus_operandi::upgrade_to_exclusive_lock ? 
			internal_acquisition_flags::allow_upgrading_upgraded_latch :
			internal_acquisition_flags::none;
		const auto primary_status = acquire_internal_slot<primality, mo, flags>(primary_slot,
																				validator,
																				order).first;
		if (primary_status == lock_status::not_acquired)
			return {};
		// If lock is acquired in transactional mode, we are done
		if (primary_status == lock_status::transaction)
			return { primary_status };

		// Upgradeable locks are not mutually exclusive with shared locks, done.
		if constexpr (mo == modus_operandi::upgradeable_lock)
			return { primary_status };

		// We have acquired primary slot, so there're possibly only shared lockers to contend with on non-primary slots.
		// Kill concurrency by setting active slot count to 1.
		const auto active_slots = data.latch.active_slots.exchange(1, order);
		assert(active_slots <= latch_storage_t::count);

		// Check if the rest of the slots are valid
		bool success = true;
		for (slot_type s = 0; s < active_slots; ++s) {
			if (s == primary_slot)
				continue;
			const auto latch_value = data.latch[s]->load(acquire_order);
			if (!validator(latch_descriptor{ latch_value })) {
				success = false;
				break;
			}
		}
		
		// Lock acquired
		if (success)
			return { primary_status };

		// Failure. Revert primary slot.
		if constexpr (mo != modus_operandi::upgrade_to_exclusive_lock) {
			release_internal_slot<mo>(primary_slot, primary_status, order);
		}
		return {};
	}
	// Attempts lock acquisition
	template <
		acquisition_primality primality, modus_operandi mo, 
		internal_acquisition_flags flags = internal_acquisition_flags::none, typename Validator
	>
	[[nodiscard]] latch_lock acquire_internal(const latch_lock &upgrading_lock, Validator &&validator, memory_order order) noexcept {
		// If transactional is enabled we attempt a lock-elision only if this is an initial acquisition attempt and skip_transactional flag is 
		// unset.
		if constexpr (tsx_rtm && primality == acquisition_primality::initial &&
					  (flags & internal_acquisition_flags::skip_transactional) == internal_acquisition_flags::none) {
			auto lock = acquire_internal_transactional();
			if (lock)
				return lock;
		}
		
		// Multi-slot acquisition
		if constexpr (use_slots) {
			if constexpr (mo == modus_operandi::shared_lock)
				return acquire_internal_multislot_shared<primality>(std::forward<Validator>(validator), order);
			else
				return acquire_internal_multislot_nonshared<primality, mo>(std::forward<Validator>(validator), order);
		}

		// Single-slot acquisition
		const auto status = acquire_internal_slot<primality, mo, flags>(primary_slot, std::forward<Validator>(validator), order).first;
		return latch_lock{ status };
	}

	// Releases the latch in transactional mode
	// Returns true on successful transaction commit, false otherwise.
	bool release_internal_transactional(lock_status mode) noexcept {
		if (mode == lock_status::transaction) {
			// Finalize the transaction.
			if constexpr (collect_statistics)
				++debug_statistics.transactional_lock_elision_success;

			_xend();
			return true;
		}

		// Not in transactional mode
		return false;
	}
	// Release a slot
	template <modus_operandi mo>
	void release_internal_slot(slot_type slot, lock_status mode, memory_order order) noexcept {
		static constexpr auto method = acquisition_method_for_mo<mo>();
		const auto store_order = memory_order_store(order);

		// Calculate some latch bits
		latch_descriptor desired_latch = {};
		const auto single_consumer_bits = static_cast<latch_data_type>(latch_descriptor::template make_single_consumer<mo>());
		
		if constexpr (method == latch_acquisition_method::cxhg ||
					  method == latch_acquisition_method::counter) {
			// Attempt to free the latch
			latch_data_type expected = data.latch[slot]->load(memory_order::acquire);
								 
			// Optimization for counter method: If we have enough holders, atomically decrement counter.
			if constexpr (method == latch_acquisition_method::counter) {
				static constexpr auto shared_holders_for_atomic_add = 2;

				 if (latch_descriptor{ expected }.template consumers<mo>() >= shared_holders_for_atomic_add) {
				 	if constexpr (collect_statistics)
				 		++debug_statistics.lock_rmw_instructions;
    
				 	const auto new_val = data.latch[slot]->fetch_add(-single_consumer_bits, memory_order::acq_rel) - single_consumer_bits;
				 	if (latch_descriptor{ new_val } == latch_descriptor::make_exclusive_locked())
				 		data.latch[slot]->store(static_cast<latch_data_type>(desired_latch), store_order);
    
				 	return;
				 }
			}

			do {
				if constexpr (collect_statistics)
					++debug_statistics.lock_rmw_instructions;

				// Calculate new desired value
				desired_latch = latch_descriptor{ expected - single_consumer_bits };
				// Clear lock held flag, if needed.
				if (desired_latch == latch_descriptor::make_exclusive_locked())
					desired_latch = {};
			} while (!data.latch[slot]->compare_exchange_weak(expected, static_cast<latch_data_type>(desired_latch), order));
		}
		else /*(method == latch_acquisition_method::set_flag)*/ {
			if constexpr (tsx_hle_exclusive) {
				// xrelease
				if (mode == lock_status::transaction) {
					data.latch[slot]->store(static_cast<latch_data_type>(desired_latch), memory_order::xrelease);
					return;
				}
			}
			// Atomic store
			data.latch[slot]->store(static_cast<latch_data_type>(desired_latch), store_order);
		}
	}
	// Releases the latch
	template <modus_operandi mo>
	void release_internal(slot_type used_slot, lock_status mode, memory_order order) noexcept {
		// If we can release the latch in transactional mode, we are done.
		if constexpr (tsx_rtm) {
			if (release_internal_transactional(mode))
				return;
		}

		auto slot = primary_slot;
		if constexpr (use_slots) {
			// Multi-slot mode
			slot = used_slot;
		}
		return release_internal_slot<mo>(slot, mode, order);
	}

public:
	shared_futex_default_latch() = default;
	shared_futex_default_latch(shared_futex_default_latch&&) = delete;
	shared_futex_default_latch(const shared_futex_default_latch&) = delete;
	shared_futex_default_latch &operator=(shared_futex_default_latch&&) = delete;
	shared_futex_default_latch &operator=(const shared_futex_default_latch&) = delete;
	~shared_futex_default_latch() noexcept {
		// Latch dtored while lock is held or pending?
		assert(data.latch[primary_slot]->load() == latch_data_type{});
	}

	latch_descriptor load(memory_order order = memory_order::acquire) const noexcept {
		if constexpr (collect_statistics) {
			if (order != memory_order::relaxed)
				++debug_statistics.lock_atomic_loads;
		}

		return latch_descriptor{ data.latch[primary_slot]->load(order) };
	}
	waiters_descriptor load_waiters_counters(memory_order order = memory_order::acquire) const noexcept {
		if constexpr (has_waiters_counter) {
			if constexpr (collect_statistics) {
				if (order != memory_order::relaxed)
					++debug_statistics.lock_atomic_loads;
			}

			return waiters_descriptor{ data.latch.waiters.load(order) };
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
		acquisition_primality primality, modus_operandi mo, typename Validator,
		typename = std::enable_if_t<mo != modus_operandi::upgrade_to_exclusive_lock>
	>
	[[nodiscard]] latch_lock acquire(Validator &&validator, memory_order order = memory_order::acq_rel) noexcept {
		return acquire_internal<primality, mo>({}, std::forward<Validator>(validator), order);
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
	template <acquisition_primality primality, typename Validator>
	[[nodiscard]] latch_lock upgrade(latch_lock &&lock, Validator &&validator, memory_order order = memory_order::acq_rel) noexcept {
		static constexpr modus_operandi mo = modus_operandi::upgrade_to_exclusive_lock;

		if constexpr (tsx_rtm) {
			// If we are in a pending transaction we treat the upgrade as part of the transaction, so that and in case of an abort we will be 
			// reverted all the way back to upgradeable acquisition.
			if (lock.mode == lock_status::transaction) {
				std::move(lock).reset();
				return { lock_status::transaction };
			}
		}

		// Otherwise upgrade normally but disallow transactions.
		auto upgraded_lock = acquire_internal<primality, mo, internal_acquisition_flags::skip_transactional>(lock,
																											 std::forward<Validator>(validator), 
																											 order);
		if (upgraded_lock)
			std::move(lock).reset();

		return upgraded_lock;
	}

	/*
	 *	@brief	Releases the latch, consuming a lock in the process.
	 *	
	 *	@param	lock	lock, acquired via a call to acquire() or upgrade(), to consume.
	 */
	template <modus_operandi mo>
	void release(latch_lock &&lock, memory_order order = memory_order::release) noexcept {
		if constexpr (debug_shared_futex)
			assert(lock);
		
		// Release and consume the lock
		release_internal<mo>(lock.slot_used, lock.mode, order);
		std::move(lock).reset();
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
		if constexpr (debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");

		if constexpr (mo == modus_operandi::shared_lock &&
					  futex_policy::parking_policy == shared_futex_parking_policy::shared_local) {
			// Park shared in local slot
			return data.parking_lot.park_until<mo>(std::forward<ParkPredicate>(park_predicate),
												   std::forward<OnPark>(on_park),
												   until);
		}
		else if constexpr (parking_allowed) {
			// Wait
			auto key = parking_lot_parking_key<mo>();
			return data.parking_lot.park_until<mo>(std::forward<ParkPredicate>(park_predicate),
												   std::forward<OnPark>(on_park),
												   std::move(key),
												   until);
		}

		return parking_lot_wait_state::signaled;
	}
	
	/*
	 *	@brief	Attempts unparking of threads of a specified mo using a given unpark tactic.
	 *			Return value might be inaccurate for unpark_all tactic, depending on parking policy used.
	 *	@return	Count of threads successfully unparked
	 */
	template <unpark_tactic tactic, modus_operandi mo>
	std::size_t unpark() noexcept {
		if constexpr (debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");

		if constexpr (mo == modus_operandi::shared_lock &&
					  futex_policy::parking_policy == shared_futex_parking_policy::shared_local) {
			return data.parking_lot.unpark<tactic, mo>();
		}
		else if constexpr (parking_allowed) {
			// Generate parking key and attempt unpark
			auto unpark_key = parking_lot_parking_key<mo>();
			return data.parking_lot.unpark<tactic, mo>(std::move(unpark_key));
		}

		return {};
	}
	
	// Registers as active waiter
	template <modus_operandi mo>
	void register_wait(memory_order order = memory_order::release) noexcept {
		if constexpr (has_waiters_counter && should_count_waiters<mo>()) {
			if constexpr (collect_statistics)
				++debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_waiters<mo>(1);
			const auto bits = static_cast<waiters_counter_type>(d);
			data.latch.waiters.fetch_add(bits, order);
		}
	}
	// Unregisters as active waiter
	template <modus_operandi mo>
	void register_unwait(memory_order order = memory_order::release) noexcept {
		if constexpr (has_waiters_counter && should_count_waiters<mo>()) {
			if constexpr (collect_statistics)
				++debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_waiters<mo>(1);
			const auto bits = -static_cast<waiters_counter_type>(d);
			data.latch.waiters.fetch_add(bits, order);
		}
	}
	// Registers parked thread
	template <modus_operandi mo>
	void register_unwait_and_park(memory_order order = memory_order::release) noexcept {
		if constexpr (debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");
		
		if constexpr (should_count_waiters<mo>() || should_count_parked<mo>()) {
			if constexpr (collect_statistics)
				++debug_statistics.lock_rmw_instructions;

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

			data.latch.waiters.fetch_add(bits, order);
		}
	}
	// Unregister parked and register as waiter
	template <modus_operandi mo>
	void register_unpark_and_wait(memory_order order = memory_order::release) noexcept {
		if constexpr (debug_shared_futex)
			assert(parking_allowed && "Parking not allowed");
		
		if constexpr (should_count_waiters<mo>() || should_count_parked<mo>()) {
			if constexpr (collect_statistics)
				++debug_statistics.lock_rmw_instructions;

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

			data.latch.waiters.fetch_add(bits);
		}
	}
	// Unregister parked thread(s)
	template <modus_operandi mo>
	void register_unpark(std::size_t count = 1, memory_order order = memory_order::release) noexcept {
		if constexpr (debug_shared_futex) {
			assert(parking_allowed && "Parking not allowed");
			assert(count && "Count must be positive");
		}
		
		if constexpr (should_count_parked<mo>()) {
			if constexpr (collect_statistics)
				++debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_parked<mo>(count);
			const auto bits = -static_cast<waiters_counter_type>(d);
			
			data.latch.waiters.fetch_add(bits);
		}
	}
};

}
