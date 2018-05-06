// StE
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "../parking_lot/parking_lot.hpp"
#include "../atomic/atomic_tsx.hpp"

#include <cassert>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ste {

namespace shared_futex_detail {

template <typename T, typename Tuple>
struct tuple_has_type : std::false_type {};
template <typename T, typename... Ts>
struct tuple_has_type<T, std::tuple<Ts...>> {
	static constexpr bool value = std::disjunction_v<std::is_same<T, Ts>...>;
};
template <typename T, typename... Ts>
static constexpr bool tuple_has_type_v = tuple_has_type<T, std::tuple<Ts...>>::value;

}

/*
 *	@brief	shared_futex's latch
 */
template <typename StoragePolicy, typename... RequestedFeatures>
class shared_futex_default_latch {
public:
	// Our list of supported features
	using supported_features = std::tuple<shared_futex_features::use_transactional_hle>;
	
private:
	static_assert(std::conjunction_v<shared_futex_detail::tuple_has_type<RequestedFeatures, supported_features>...>, 
				  "RequestedFeatures contains unsupported features, see supported_features.");

	// Checks if the futex's Features list contains Feature
	template <typename Feature>
	static constexpr bool requires_feature() noexcept {
		return (std::is_same_v<Feature, RequestedFeatures> || ...);
	}

public:
	// Requested features
	static constexpr bool transactional = requires_feature<shared_futex_features::use_transactional_hle>();	// Using transactional HLE

private:
	using modus_operandi = shared_futex_detail::modus_operandi;
	enum class latch_acquisition_method : std::uint8_t {
		set_flag, 
		cxhg, 
		counter,
	};
	enum class latch_acquisition_mode : std::uint8_t {
		not_acquired,
		normal,
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

public:
	// Represents a latch lock. A valid object holds a lock and should be released by consuming the object with a call to latch's release().
	class latch_lock {
		friend class shared_futex_default_latch;

		latch_acquisition_mode mode{ latch_acquisition_mode::not_acquired };
		
		latch_lock(latch_acquisition_mode mode) noexcept : mode(mode) {}
		void reset() && noexcept { mode = latch_acquisition_mode::not_acquired; }

	public:
		latch_lock() noexcept = default;
		latch_lock(latch_lock &&o) noexcept : mode(std::exchange(o.mode, latch_acquisition_mode::not_acquired)) {}
		latch_lock(const latch_lock&) = delete;
		latch_lock &operator=(latch_lock &&o) noexcept {
			assert(mode == latch_acquisition_mode::not_acquired);

			mode = std::exchange(o.mode, latch_acquisition_mode::not_acquired);
			return *this;
		}
		latch_lock &operator=(const latch_lock&) = delete;
		~latch_lock() noexcept { assert(mode == latch_acquisition_mode::not_acquired); }

		explicit operator bool() const noexcept { return mode != latch_acquisition_mode::not_acquired; }
	};

	using storage_policy = StoragePolicy;
	using latch_data_type = std::int32_t;
	using waiters_counter_type = std::int64_t;
	using counter_t = std::make_unsigned_t<latch_data_type>;

	static constexpr auto alignment = std::max(storage_policy::alignment, alignof(std::max_align_t));
	static constexpr auto shared_consumers_bits = sizeof(latch_data_type) * 8 - 4;

	static_assert(shared_consumers_bits >= storage_policy::shared_bits, "Shared consumers bit count can not satisfy requested shared_bits bit count.");

	class latch_descriptor {
		friend class shared_futex_default_latch;
		
		static constexpr auto lock_held_bit_index = 0;
		
		counter_t lock_held_flag_bit		: 1;
		counter_t upgradeable_consumers		: 1;
		counter_t _unused					: 2;
		counter_t shared_consumers			: shared_consumers_bits;
		
		explicit latch_descriptor(const latch_data_type &l) { *this = *reinterpret_cast<const latch_descriptor*>(&l); }
		explicit operator latch_data_type() const {
			latch_data_type t = {};
			*reinterpret_cast<latch_descriptor*>(&t) = *this;
			return t;
		}

		// Accessors and helpers

		template <modus_operandi mo>
		void inc_consumers(const counter_t &count) noexcept {
			switch (mo) {
			case modus_operandi::shared_lock:
				shared_consumers += count;
				break;
			case modus_operandi::upgradeable_lock:
				upgradeable_consumers += count;
			default:
				if constexpr (shared_futex_detail::debug_shared_futex)
					assert(count <= 1);
			}
		}
		
		void set_lock_held_flag() noexcept { lock_held_flag_bit = true; }

		// Returns a dummy latch value with a single consumer
		template <modus_operandi mo>
		static latch_descriptor make_single_consumer() noexcept {
			latch_descriptor d = {};
			d.inc_consumers<mo>(1);
			return d;
		}
		// Returns a dummy latch value with lock held by a single consumer
		template <modus_operandi mo>
		static latch_descriptor make_locked() noexcept {
			latch_descriptor d = {};
			d.set_lock_held_flag();
			d.inc_consumers<mo>(1);
			return d;
		}
		static latch_descriptor make_exclusive_locked() noexcept {
			latch_descriptor d = {};
			d.set_lock_held_flag();
			return d;
		}

	public:
		latch_descriptor() = default;
		bool operator==(const latch_descriptor &rhs) const noexcept {
			return static_cast<latch_data_type>(*this) == static_cast<latch_data_type>(rhs);
		}
		bool operator!=(const latch_descriptor &rhs) const noexcept { return !(*this == rhs); }

		// Counts number of active consumers
		template <modus_operandi mo>
		auto consumers() const noexcept {
			switch (mo) {
			case modus_operandi::shared_lock:
				return shared_consumers;
			case modus_operandi::upgradeable_lock:
				return upgradeable_consumers;
			case modus_operandi::exclusive_lock:
			case modus_operandi::upgrade_to_exclusive_lock:
				// Exclusively owned iff lock is held and no shared consumers are in flight.
				return lock_held_flag_bit && !upgradeable_consumers && !shared_consumers ? 
					static_cast<counter_t>(1) : 
					static_cast<counter_t>(0);
			default:
				return counter_t{};
			}
		}
	};
	class waiters_descriptor {
		friend class shared_futex_default_latch;
		
		// Parked counters
		counter_t shared_parked					: storage_policy::shared_bits;
		counter_t upgradeable_parked			: storage_policy::upgradeable_bits;
		counter_t exclusive_parked				: storage_policy::exclusive_bits;
		counter_t upgrading_to_exclusive_parked : 1;
		// Waiter counters
		counter_t upgradeable_waiters			: storage_policy::upgradeable_bits;
		counter_t exclusive_waiters				: storage_policy::exclusive_bits;

		explicit waiters_descriptor(const waiters_counter_type &l) { *this = *reinterpret_cast<const waiters_descriptor*>(&l); }
		explicit operator waiters_counter_type() const {
			waiters_counter_type c = {};
			*reinterpret_cast<waiters_descriptor*>(&c) = *this;
			return c;
		}

		// Accessors and helpers

		template <modus_operandi mo>
		void inc_parked(const counter_t &count) noexcept {
			switch (mo) {
			case modus_operandi::shared_lock:
				shared_parked += count;
				break;
			case modus_operandi::upgradeable_lock:
				upgradeable_parked += count;
				break;
			case modus_operandi::exclusive_lock:
				exclusive_parked += count;
				break;
			case modus_operandi::upgrade_to_exclusive_lock:
				upgrading_to_exclusive_parked += count;
				break;
			default:{}
			}
		}
		template <modus_operandi mo>
		void inc_waiters(const counter_t &count) noexcept {
			static_assert(mo == modus_operandi::upgradeable_lock || mo == modus_operandi::exclusive_lock);
			switch (mo) {
			case modus_operandi::upgradeable_lock:
				upgradeable_waiters += count;
				break;
			case modus_operandi::exclusive_lock:
				exclusive_waiters += count;
				break;
			}
		}

	public:
		waiters_descriptor() = default;
		bool operator==(const waiters_descriptor &rhs) const noexcept {
			return static_cast<waiters_counter_type>(*this) == static_cast<waiters_counter_type>(rhs);
		}
		bool operator!=(const waiters_descriptor &rhs) const noexcept { return !(*this == rhs); }

		// Counts number of parked consumers
		template <modus_operandi mo>
		auto parked() const noexcept {
			switch (mo) {
			case modus_operandi::shared_lock:
				return shared_parked;
			case modus_operandi::upgradeable_lock:
				return upgradeable_parked;
			case modus_operandi::exclusive_lock:
				return exclusive_parked;
			case modus_operandi::upgrade_to_exclusive_lock:
			default:
				return upgrading_to_exclusive_parked;
			}
		}
		// Counts number of waiting consumers
		template <modus_operandi mo>
		auto waiters() const noexcept {
			static_assert(mo == modus_operandi::upgradeable_lock || mo == modus_operandi::exclusive_lock);
			switch (mo) {
			case modus_operandi::upgradeable_lock:
				return upgradeable_waiters;
			case modus_operandi::exclusive_lock:
				return exclusive_waiters;
			default:
				return counter_t{};
			}
		}
	};

	using parking_key_t = std::uint64_t;

private:
	using latch_atomic_t = atomic_tsx<latch_data_type>;
	using waiters_atomic_t = atomic_tsx<waiters_counter_type>;

	static_assert(sizeof(latch_descriptor) <= sizeof(latch_data_type), "Total bits count should take no more than the latch size");
	static_assert(sizeof(waiters_descriptor) <= sizeof(waiters_counter_type), "Total bits count should take no more than the waiters counter size");
	static_assert(latch_atomic_t::is_always_lock_free, "Latch is not lock-free!");
	static_assert(waiters_atomic_t::is_always_lock_free, "Latch waiter counter is not lock-free!");

private:
	// Parking/waiters counters
	alignas(alignment) waiters_atomic_t waiters{};
	// Latch
	latch_atomic_t latch{};

public:
	// Parking lot for smart wakeup
	parking_lot<latch_lock> parking;

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
	// Returns true if latch should count waiters for a given mo
	template <modus_operandi mo>
	static constexpr bool should_count_waiters() noexcept {
		return mo == modus_operandi::exclusive_lock || mo == modus_operandi::upgradeable_lock;
	}

	// Acquires lock in transactional mode
	[[nodiscard]] latch_lock acquire_internal_transactional() noexcept {
		static constexpr auto max_tsx_retries_on_capacity_abort = 3;
		static constexpr auto max_tsx_retries_on_retry_abort = 3;
		static constexpr auto max_tsx_retries_on_sys_abort = 2;
		
		if constexpr (shared_futex_detail::collect_statistics)
			++shared_futex_detail::debug_statistics.transactional_lock_elision_attempts;

		// Attempt a transactions, and retry up to a fixed number of tries depending on returned abort code.
		unsigned tsx_start;
		for (auto i=0;; ++i) {
			tsx_start = _xbegin();
			if (tsx_start == _XABORT_CAPACITY && i < max_tsx_retries_on_capacity_abort)
				continue;
			if (tsx_start == _XABORT_RETRY && i < max_tsx_retries_on_retry_abort)
				continue;
			if (tsx_start == 0 && i < max_tsx_retries_on_sys_abort)
				continue;
			break;
		}
		if (tsx_start == _XBEGIN_STARTED)
			return { latch_acquisition_mode::transaction };
					  
		// Transaction failed.

		if constexpr (shared_futex_detail::collect_statistics) {
			// Log transaction failure
			switch (tsx_start) {
			case 0:
				// Return code of 0 indicates an abort due to system call, a serializing instruction, touching unmapped pages or other obscure
				// reasons. See https://software.intel.com/en-us/forums/intel-moderncode-for-parallel-architectures/topic/658265
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_sys;
				break;
			case _XABORT_CAPACITY:
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_capacity;
				break;
			case _XABORT_CONFLICT:
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_conflict;
				break;
			case _XABORT_DEBUG:
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_debug;
				break;
			case _XABORT_EXPLICIT:
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_explicit;
				break;
			case _XABORT_NESTED:
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_nested;
				break;
			case _XABORT_RETRY:
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_too_many_retries;
				break;
			default:
				++shared_futex_detail::debug_statistics.transactional_lock_elision_aborts_other;
				break;
			}
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
		if constexpr (transactional && primality == shared_futex_detail::acquisition_primality::initial &&
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
			if (latch.compare_exchange_strong(expected, static_cast<latch_data_type>(desired_latch), order))
				return { latch_acquisition_mode::normal };

			// Otherwise keep trying to write desired/increase counter while previous latch value is valid for acquisition
			while (validator(latch_descriptor{ expected })) {
				desired_latch = latch_descriptor{ expected };
				desired_latch.set_lock_held_flag();
				desired_latch.template inc_consumers<mo>(1);
				
				if constexpr (shared_futex_detail::collect_statistics)
					++shared_futex_detail::debug_statistics.lock_rmw_instructions;

				if (latch.compare_exchange_weak(expected, static_cast<latch_data_type>(desired_latch), order))
					return { latch_acquisition_mode::normal };
			}

			// Failed
			return {};
		}
		else /*(method == latch_acquisition_method::set_flag)*/ {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			// Bit-test-and-set
			const auto bit = latch_descriptor::lock_held_bit_index;
			if (!latch.bit_test_and_set(bit, order))
				return { latch_acquisition_mode::normal };
			return {};
		}
	}

	// Releases the latch in transactional mode
	// Returns true on successful transaction commit, false otherwise.
	bool release_internal_transactional(latch_acquisition_mode mode) noexcept {
		if (mode == latch_acquisition_mode::transaction) {
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
	void release_internal(latch_acquisition_mode mode, memory_order order) noexcept {
		if constexpr (transactional) {
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
			latch_data_type expected = latch.load(memory_order::acquire);
								 
			// Optimization for counter method: If we have enough holders, atomically decrement counter, last one turns off the lights.
			if constexpr (method == latch_acquisition_method::counter) {
				static constexpr auto shared_holders_for_atomic_add = 3;

				if (latch_descriptor{ expected }.template consumers<mo>() >= shared_holders_for_atomic_add) {
					if constexpr (shared_futex_detail::collect_statistics)
						++shared_futex_detail::debug_statistics.lock_rmw_instructions;

					const auto new_val = latch.fetch_add(-single_consumer_bits, memory_order::acq_rel) - single_consumer_bits;
					if (latch_descriptor{ new_val } == latch_descriptor::make_exclusive_locked())
						latch.store(static_cast<latch_data_type>(desired_latch), store_mo);

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
			} while (!latch.compare_exchange_weak(expected, static_cast<latch_data_type>(desired_latch), order));
		}
		else /*(method == latch_acquisition_method::set_flag)*/ {
			latch.store(static_cast<latch_data_type>(desired_latch), store_mo);
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
		assert(latch.load() == latch_data_type{});
	}

	latch_descriptor load(memory_order order = memory_order::acquire) const noexcept {
		if constexpr (shared_futex_detail::collect_statistics) {
			if (order != memory_order::relaxed)
				++shared_futex_detail::debug_statistics.lock_atomic_loads;
		}

		return latch_descriptor{ latch.load(order) };
	}
	waiters_descriptor load_waiters_counters(memory_order order = memory_order::acquire) const noexcept {
		if constexpr (shared_futex_detail::collect_statistics) {
			if (order != memory_order::relaxed)
				++shared_futex_detail::debug_statistics.lock_atomic_loads;
		}

		return waiters_descriptor{ waiters.load(order) };
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

		if constexpr (transactional) {
			// If we are in a pending transaction treat the upgrade as part of the transaction, so that and in case of an abort, we will be 
			// reverted all the way back to upgradeable acquisition.
			if (lock.mode == latch_acquisition_mode::transaction) {
				std::move(lock).reset();
				return { latch_acquisition_mode::transaction };
			}
		}

		// Otherwise upgrade normally but disallow transactions.
		auto upgraded_lock = acquire_internal<primality, mo, internal_acquisition_flags::skip_transactional>(std::move(validator), order);
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
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(lock);

		// Release and consume the lock
		release_internal<mo>(lock.mode, order);
		std::move(lock).reset();
	}

	// Generates a unique parking key
	template <modus_operandi mo>
	static parking_key_t parking_key() noexcept {
		return static_cast<uint64_t>(mo);
	}
	
	// Registers as active waiter
	template <modus_operandi mo>
	void wait(memory_order order = memory_order::release) noexcept {
		if constexpr (should_count_waiters<mo>()) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_waiters<mo>(1);
			const auto bits = static_cast<waiters_counter_type>(d);
			waiters.fetch_add(bits, order);
		}
	}
	// Unregisters as active waiter
	template <modus_operandi mo>
	void unwait(memory_order order = memory_order::release) noexcept {
		if constexpr (should_count_waiters<mo>()) {
			if constexpr (shared_futex_detail::collect_statistics)
				++shared_futex_detail::debug_statistics.lock_rmw_instructions;

			waiters_descriptor d = {};
			d.template inc_waiters<mo>(1);
			const auto bits = -static_cast<waiters_counter_type>(d);
			waiters.fetch_add(bits, order);
		}
	}
	// Registers parked thread
	template <modus_operandi mo>
	void unwait_and_park(memory_order order = memory_order::release) noexcept {
		if constexpr (shared_futex_detail::collect_statistics)
			++shared_futex_detail::debug_statistics.lock_rmw_instructions;

		waiters_descriptor d = {};
		d.template inc_parked<mo>(1);
		auto bits = static_cast<waiters_counter_type>(d);
		
		if constexpr (should_count_waiters<mo>()) {
			// Remove wait bit
			waiters_descriptor dw = {};
			dw.template inc_waiters<mo>(1);
			bits -= static_cast<waiters_counter_type>(dw);
		}

		waiters.fetch_add(bits, order);
	}
	// Unregister parked and register as waiter
	template <modus_operandi mo>
	void unpark_and_wait(memory_order order = memory_order::release) noexcept {
		if constexpr (shared_futex_detail::collect_statistics)
			++shared_futex_detail::debug_statistics.lock_rmw_instructions;

		waiters_descriptor d = {};
		d.template inc_parked<mo>(1);
		auto bits = -static_cast<waiters_counter_type>(d);
		
		if constexpr (should_count_waiters<mo>()) {
			// Add wait bit
			waiters_descriptor dw = {};
			dw.template inc_waiters<mo>(1);
			bits += static_cast<waiters_counter_type>(dw);
		}

		waiters.fetch_add(bits);
	}
	// Unregister parked thread(s)
	template <modus_operandi mo>
	void unpark(counter_t count = 1, memory_order order = memory_order::release) noexcept {
		if constexpr (shared_futex_detail::debug_shared_futex)
			assert(count);
		
		if constexpr (shared_futex_detail::collect_statistics)
			++shared_futex_detail::debug_statistics.lock_rmw_instructions;

		waiters_descriptor d = {};
		d.template inc_parked<mo>(count);
		const auto bits = -static_cast<waiters_counter_type>(d);
		waiters.fetch_add(bits);
	}
};

}
