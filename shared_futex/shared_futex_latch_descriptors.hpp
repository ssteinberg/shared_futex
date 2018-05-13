// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"

#include <type_traits>

namespace ste::shared_futex_detail {

template <typename T, typename Data, shared_futex_parking_policy parking_policy>
struct latch_descriptor_storage {
	static constexpr auto shared_consumers_bits = sizeof(Data) * 8 - 4;

	T lock_held_flag_bit		: 1;
	T upgradeable_consumers		: 1;
	T _unused					: 2;
	T shared_consumers			: shared_consumers_bits;
};
template <typename T, shared_futex_parking_policy parking_policy>
class latch_descriptor {
	using counter_t = std::make_unsigned_t<T>;
	using storage_t = latch_descriptor_storage<counter_t, T, parking_policy>;

	static constexpr auto lock_held_bit_index = 0;
	static constexpr auto shared_consumers_bits = storage_t::shared_consumers_bits;

private:
	storage_t storage;

public:
	latch_descriptor() = default;
	bool operator==(const latch_descriptor &rhs) const noexcept {
		return static_cast<T>(*this) == static_cast<T>(rhs);
	}
	bool operator!=(const latch_descriptor &rhs) const noexcept { return !(*this == rhs); }

	// Counts number of active consumers
	template <modus_operandi mo>
	auto consumers() const noexcept {
		static constexpr auto exclusively_held = static_cast<T>(1) << lock_held_bit_index;
		switch (mo) {
		case modus_operandi::shared_lock:
			return storage.shared_consumers;
		case modus_operandi::upgradeable_lock:
			return storage.upgradeable_consumers;
		case modus_operandi::exclusive_lock:
		case modus_operandi::upgrade_to_exclusive_lock:
			// Exclusively owned iff lock is held and no shared consumers are in flight.
			return static_cast<T>(*this) == exclusively_held ? 
				static_cast<counter_t>(1) : 
				static_cast<counter_t>(0);
		default:
			return counter_t{};
		}
	}

	// Accessors and helpers
	
	explicit latch_descriptor(const T &l) { *this = *reinterpret_cast<const latch_descriptor*>(&l); }
	explicit operator T() const {
		T t = {};
		*reinterpret_cast<latch_descriptor*>(&t) = *this;
		return t;
	}

	template <modus_operandi mo>
	void inc_consumers(const counter_t &count) noexcept {
		switch (mo) {
		case modus_operandi::shared_lock:
			storage.shared_consumers += count;
			break;
		case modus_operandi::upgradeable_lock:
			storage.upgradeable_consumers += count;
		default:
			if constexpr (shared_futex_detail::debug_shared_futex)
				assert(count <= 1);
		}
	}
	
	void set_lock_held_flag() noexcept { storage.lock_held_flag_bit = true; }

	// Returns a dummy latch value with a single consumer
	template <modus_operandi mo>
	static latch_descriptor make_single_consumer() noexcept {
		latch_descriptor d = {};
		d.template inc_consumers<mo>(1);
		return d;
	}
	// Returns a dummy latch value with lock held by a single consumer
	template <modus_operandi mo>
	static latch_descriptor make_locked() noexcept {
		latch_descriptor d = {};
		d.set_lock_held_flag();
		d.template inc_consumers<mo>(1);
		return d;
	}
	static latch_descriptor make_exclusive_locked() noexcept {
		latch_descriptor d = {};
		d.set_lock_held_flag();
		return d;
	}
};

// Partial specializations for possible variations of waiters storage
template <typename T, typename Data, int shared_bits, int upgradeable_bits, int exclusive_bits, bool count_non_shared_parked, bool count_waiters>
struct waiters_descriptor_storage {};
template <typename T, typename Data, int shared_bits, int upgradeable_bits, int exclusive_bits>
struct waiters_descriptor_storage<T, Data, shared_bits, upgradeable_bits, exclusive_bits, false, false> {
	// Parked counters
	T upgradeable_parked			: upgradeable_bits;
	T exclusive_parked				: exclusive_bits;
	T upgrading_to_exclusive_parked : 1;
	// Waiter counters
};
template <typename T, typename Data, int shared_bits, int upgradeable_bits, int exclusive_bits>
struct waiters_descriptor_storage<T, Data, shared_bits, upgradeable_bits, exclusive_bits, true, false> {
	// Parked counters
	T shared_parked					: shared_bits;
	T upgradeable_parked			: upgradeable_bits;
	T exclusive_parked				: exclusive_bits;
	T upgrading_to_exclusive_parked : 1;
	// Waiter counters
};
template <typename T, typename Data, int shared_bits, int upgradeable_bits, int exclusive_bits>
struct waiters_descriptor_storage<T, Data, shared_bits, upgradeable_bits, exclusive_bits, false, true> {
	// Parked counters
	T upgradeable_parked			: upgradeable_bits;
	T exclusive_parked				: exclusive_bits;
	T upgrading_to_exclusive_parked : 1;
	// Waiter counters
	T upgradeable_waiters			: upgradeable_bits;
	T exclusive_waiters				: exclusive_bits;
};
template <typename T, typename Data, int shared_bits, int upgradeable_bits, int exclusive_bits>
struct waiters_descriptor_storage<T, Data, shared_bits, upgradeable_bits, exclusive_bits, true,true> {
	// Parked counters
	T shared_parked					: shared_bits;
	T upgradeable_parked			: upgradeable_bits;
	T exclusive_parked				: exclusive_bits;
	T upgrading_to_exclusive_parked : 1;
	// Waiter counters
	T upgradeable_waiters			: upgradeable_bits;
	T exclusive_waiters				: exclusive_bits;
};

template <typename T, int shared_bits, int upgradeable_bits, int exclusive_bits, bool count_non_shared_parked, bool count_waiters>
class waiters_descriptor {
	using counter_t = std::make_unsigned_t<T>;
	using storage_t = waiters_descriptor_storage<counter_t, T, shared_bits, upgradeable_bits, exclusive_bits, count_non_shared_parked, count_waiters>;

private:
	storage_t storage;

public:
	waiters_descriptor() = default;
	bool operator==(const waiters_descriptor &rhs) const noexcept {
		return static_cast<T>(*this) == static_cast<T>(rhs);
	}
	bool operator!=(const waiters_descriptor &rhs) const noexcept { return !(*this == rhs); }

	// Counts number of parked consumers
	template <modus_operandi mo>
	auto parked() const noexcept {
		switch (mo) {
		case modus_operandi::shared_lock:
			return storage.shared_parked;
		case modus_operandi::upgradeable_lock:
			if constexpr (count_non_shared_parked)
				return storage.upgradeable_parked;
			break;
		case modus_operandi::exclusive_lock:
			if constexpr (count_non_shared_parked)
				return storage.exclusive_parked;
			break;
		case modus_operandi::upgrade_to_exclusive_lock:
			if constexpr (count_non_shared_parked)
				return storage.upgrading_to_exclusive_parked;
			break;
		}
		
		return static_cast<counter_t>(0);
	}
	// Counts number of waiting consumers
	template <modus_operandi mo>
	auto waiters() const noexcept {
		static_assert(mo == modus_operandi::upgradeable_lock || mo == modus_operandi::exclusive_lock);

		if constexpr (count_waiters) {
			switch (mo) {
			case modus_operandi::upgradeable_lock:
				return storage.upgradeable_waiters;
			case modus_operandi::exclusive_lock:
				return storage.exclusive_waiters;
			}
		}
		
		return static_cast<counter_t>(0);
	}

	// Accessors and helpers
	
	explicit waiters_descriptor(const T &l) { *this = *reinterpret_cast<const waiters_descriptor*>(&l); }
	explicit operator T() const {
		T c = {};
		*reinterpret_cast<waiters_descriptor*>(&c) = *this;
		return c;
	}

	template <modus_operandi mo>
	void inc_parked(const counter_t &count) noexcept {
		switch (mo) {
		case modus_operandi::shared_lock:
			storage.shared_parked += count;
			break;
		case modus_operandi::upgradeable_lock:
			if constexpr (count_non_shared_parked)
				storage.upgradeable_parked += count;
			break;
		case modus_operandi::exclusive_lock:
			if constexpr (count_non_shared_parked)
				storage.exclusive_parked += count;
			break;
		case modus_operandi::upgrade_to_exclusive_lock:
			if constexpr (count_non_shared_parked)
				storage.upgrading_to_exclusive_parked += count;
			break;
		default:{}
		}
	}
	template <modus_operandi mo>
	void inc_waiters(const counter_t &count) noexcept {
		static_assert(mo == modus_operandi::upgradeable_lock || mo == modus_operandi::exclusive_lock);
		static_assert(count_waiters);
		switch (mo) {
		case modus_operandi::upgradeable_lock:
			storage.upgradeable_waiters += count;
			break;
		case modus_operandi::exclusive_lock:
			storage.exclusive_waiters += count;
			break;
		}
	}
};

}
