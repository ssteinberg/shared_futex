// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "../atomic/atomic_tsx.hpp"

#include <array>
#include <type_traits>
#include <new>

namespace strt::shared_futex_detail {


// Latch data storage.
// Multi-slot specialization
template <bool has_waiters_counter, typename waiters_type, typename latch_type, std::uint32_t slots = 1>
struct latch_storage {
	static_assert(slots > 1);

	using slot_type = decltype(slots);
	static constexpr auto count = slots;

	struct slot_t {
		static constexpr auto slot_alignment = 64;// std::hardware_destructive_interference_size;
		alignas(slot_alignment) latch_type latch;
		latch_type* operator->() noexcept { return &latch; }
		const latch_type* operator->() const noexcept { return &latch; }
	};

	// Slots
	std::array<slot_t, slots> latch_slots{};
	// Slot counter
	atomic_tsx<slot_type> active_slots{ 1 };

	// Parking/waiters counters
	waiters_type waiters{};
	
	auto& operator[](std::size_t idx) noexcept { return latch_slots[idx]; }
	const auto& operator[](std::size_t idx) const noexcept { return latch_slots[idx]; }
};
// Generic single-slot partial specialization
template <typename waiters_type, typename latch_type>
struct latch_storage<true, waiters_type, latch_type, 1> {
	// Parking/waiters counters
	waiters_type waiters{};
	// Latch
	latch_type latch{};
	
	auto* operator[](std::size_t idx) noexcept {
		assert(idx == 0);
		return &latch;
	}
	const auto* operator[](std::size_t idx) const noexcept {
		assert(idx == 0);
		return &latch;
	}
};
// Single-slot without waiters/parked counters partial specialization
template <typename waiters_type, typename latch_type>
struct latch_storage<false, waiters_type, latch_type, 1> {
	// Latch
	latch_type latch{};
	
	auto* operator[](std::size_t idx) noexcept {
		assert(idx == 0);
		return &latch;
	}
	const auto* operator[](std::size_t idx) const noexcept {
		assert(idx == 0);
		return &latch;
	}
};


template <typename T, typename Data, bool compact, shared_futex_parking_policy parking_policy>
struct latch_descriptor_storage {
	static constexpr auto shared_consumers_bits = sizeof(Data) * 8 - 2;

	T lock_held_flag_bit		: 1;
	T upgradeable_consumers		: 1;
	T shared_consumers			: shared_consumers_bits;
};
template <typename T, typename Data, shared_futex_parking_policy parking_policy>
struct latch_descriptor_storage<T, Data, false, parking_policy> {
	static constexpr auto shared_consumers_bits = sizeof(Data) * 8 - 8;

	// 6-bit padding allows accessing the lower 8-bit directly (e.g. via 8-bit registers)
	T lock_held_flag_bit		: 1;
	T upgradeable_consumers		: 1;
	T _unused					: 6;
	T shared_consumers			: shared_consumers_bits;
};
template <typename T, shared_futex_parking_policy parking_policy>
class latch_descriptor {
	static constexpr bool compact = sizeof(T) < 4;

	using counter_t = std::make_unsigned_t<T>;
	using storage_t = latch_descriptor_storage<counter_t, T, compact, parking_policy>;

public:
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
	template <operation op>
	auto consumers() const noexcept {
		static constexpr auto exclusively_held = static_cast<T>(1) << lock_held_bit_index;
		switch (op) {
		case operation::lock_shared:
			return storage.shared_consumers;
		case operation::lock_upgradeable:
			return storage.upgradeable_consumers;
		case operation::lock_exclusive:
		case operation::upgrade:
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

	template <operation op>
	void inc_consumers(const counter_t &count) noexcept {
		switch (op) {
		case operation::lock_shared:
			storage.shared_consumers += count;
			break;
		case operation::lock_upgradeable:
			storage.upgradeable_consumers += count;
		default:
			if constexpr (shared_futex_detail::debug_shared_futex)
				assert(count <= 1);
		}
	}
	
	void set_lock_held_flag() noexcept { storage.lock_held_flag_bit = true; }

	// Returns a dummy latch value with a single consumer
	template <operation op>
	static latch_descriptor make_single_consumer() noexcept {
		latch_descriptor d = {};
		d.template inc_consumers<op>(1);
		return d;
	}
	// Returns a dummy latch value with lock held by a single consumer
	template <operation op>
	static latch_descriptor make_locked() noexcept {
		latch_descriptor d = {};
		d.set_lock_held_flag();
		d.template inc_consumers<op>(1);
		return d;
	}
	static latch_descriptor make_exclusive_locked() noexcept {
		latch_descriptor d = {};
		d.set_lock_held_flag();
		return d;
	}
};

// Partial specializations for possible variations of waiters storage
template <
	typename T, typename Data, 
	int shared_bits, int upgradeable_bits, int exclusive_bits,
	bool count_waiters
>
struct waiters_descriptor_storage {};
template <typename T, typename Data, int shared_bits, int upgradeable_bits, int exclusive_bits>
struct waiters_descriptor_storage<T, Data, shared_bits, upgradeable_bits, exclusive_bits, false> {
	// Parked counters
	T shared_parked					: shared_bits;
	T upgradeable_parked			: upgradeable_bits;
	T exclusive_parked				: exclusive_bits;
	T upgrading_to_exclusive_parked : 1;
};
template <typename T, typename Data, int shared_bits, int upgradeable_bits, int exclusive_bits>
struct waiters_descriptor_storage<T, Data, shared_bits, upgradeable_bits, exclusive_bits, true> {
	// Parked counters
	T shared_parked					: shared_bits;
	T upgradeable_parked			: upgradeable_bits;
	T exclusive_parked				: exclusive_bits;
	T upgrading_to_exclusive_parked : 1;
	// Waiter counters
	T upgradeable_waiters			: upgradeable_bits;
	T exclusive_waiters				: exclusive_bits;
};

// Calculated storage size for waiters descriptor
template <int shared_bits, int upgradeable_bits, int exclusive_bits, bool count_waiters>
static constexpr auto waiters_descriptor_storage_size_v = sizeof(waiters_descriptor_storage<
	int, int,
	shared_bits, upgradeable_bits, exclusive_bits, 
	count_waiters
>);

template <typename T, int shared_bits, int upgradeable_bits, int exclusive_bits, bool count_waiters>
class waiters_descriptor {
	using counter_t = std::make_unsigned_t<T>;
	using storage_t = waiters_descriptor_storage<
		counter_t, T, 
		shared_bits, upgradeable_bits, exclusive_bits, 
		count_waiters
	>;

private:
	storage_t storage;

public:
	waiters_descriptor() = default;
	bool operator==(const waiters_descriptor &rhs) const noexcept {
		return static_cast<T>(*this) == static_cast<T>(rhs);
	}
	bool operator!=(const waiters_descriptor &rhs) const noexcept { return !(*this == rhs); }

	// Counts number of parked consumers
	template <operation op>
	auto parked() const noexcept {
		switch (op) {
		case operation::lock_shared:
			return storage.shared_parked;
		case operation::lock_upgradeable:
			return storage.upgradeable_parked;
		case operation::lock_exclusive:
			return storage.exclusive_parked;
		case operation::upgrade:
			return storage.upgrading_to_exclusive_parked;
		}
		
		return static_cast<counter_t>(0);
	}
	// Counts number of waiting consumers
	template <operation op>
	auto waiters() const noexcept {
		static_assert(op == operation::lock_upgradeable || op == operation::lock_exclusive);

		if constexpr (count_waiters) {
			switch (op) {
			case operation::lock_upgradeable:
				return storage.upgradeable_waiters;
			case operation::lock_exclusive:
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

	template <operation op>
	void inc_parked(const counter_t &count) noexcept {
		switch (op) {
		case operation::lock_shared:
			storage.shared_parked += count;
			break;
		case operation::lock_upgradeable:
			storage.upgradeable_parked += count;
			break;
		case operation::lock_exclusive:
			storage.exclusive_parked += count;
			break;
		case operation::upgrade:
			storage.upgrading_to_exclusive_parked += count;
			break;
		}
	}
	template <operation op>
	void inc_waiters(const counter_t &count) noexcept {
		static_assert(op == operation::lock_upgradeable || op == operation::lock_exclusive);
		static_assert(count_waiters);
		switch (op) {
		case operation::lock_upgradeable:
			storage.upgradeable_waiters += count;
			break;
		case operation::lock_exclusive:
			storage.exclusive_waiters += count;
			break;
		}
	}
};

}
