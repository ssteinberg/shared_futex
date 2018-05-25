// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "shared_futex_impl.hpp"

#include <type_traits>

namespace ste {

// Checks if T is of a shared_futex type
template <typename T>
struct is_shared_futex_type : std::false_type {};
template <typename FutexPolicy, template <typename> class Latch>
struct is_shared_futex_type<shared_futex_detail::shared_futex_t<FutexPolicy, Latch>> : std::true_type {};
// Checks if T is of a shared_futex type
template <typename T>
static constexpr bool is_shared_futex_type_v = is_shared_futex_type<T>::value;

// Checks if a shared_futex allows parking
template <typename T>
struct is_shared_futex_parkable : std::false_type {};
template <typename FutexPolicy, template <typename> class Latch>
struct is_shared_futex_parkable<shared_futex_detail::shared_futex_t<FutexPolicy, Latch>> {
	static constexpr bool value = FutexPolicy::parking_policy != shared_futex_detail::shared_futex_parking_policy::none;
};
// Checks if SharedFutex allows parking
template <typename T>
static constexpr bool is_shared_futex_parkable_v = is_shared_futex_parkable<T>::value;

enum class shared_futex_lock_class {
	shared,
	upgradeable,
	exclusive
};

namespace shared_futex_detail {

constexpr shared_futex_lock_class resolve_lock_class(operation op) noexcept {
	switch (op) {
	case operation::lock_shared:
		return shared_futex_lock_class::shared;
	case operation::lock_upgradeable:
		return shared_futex_lock_class::upgradeable;
	default:
		return shared_futex_lock_class::exclusive;
	}
}

}

// Describes the class of lock held by a lock_guard object
template <typename LockGuard>
struct lock_class {};
template <typename SharedFutex, typename LockingProtocol>
struct lock_class {
	static constexpr shared_futex_lock_class value = shared_futex_detail::resolve_lock_class(LockingProtocol::locking_protocol_operation);
};
// Describes the class of lock held by a lock_guard object
template <typename LockGuard>
static constexpr bool lock_class_v = lock_class<LockGuard>::value;

}
