// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include <atomic>
#include <immintrin.h>
#include <future>

namespace ste {

namespace _atomic_tsx_detail {
#if defined(_M_X64) || defined(__x86_64)
static constexpr bool is_x86_64 = true;
#else
static constexpr bool is_x86_64 = false;
#endif
}

enum class memory_order {
	relaxed = std::memory_order_relaxed,
	acquire = std::memory_order_acquire,
	release = std::memory_order_release,
	acq_rel = std::memory_order_acq_rel,
	seq_cst = std::memory_order_seq_cst,

	consume = std::memory_order_consume,

	xacquire = std::memory_order_acquire | 0x10000,
	xrelease = std::memory_order_release | 0x10000
};

namespace _atomic_tsx_detail {

struct memory_order_helper {
	memory_order order;
	memory_order_helper(memory_order mo) noexcept : order(mo) {}
	memory_order_helper(std::memory_order mo) noexcept : order(static_cast<memory_order>(mo)) {}
	
	operator memory_order() const noexcept { return order; }
	operator std::memory_order() const noexcept {
		const auto x = static_cast<std::underlying_type_t<memory_order>>(order);
		return static_cast<std::memory_order>(x & 0xFFFF);
	}
};

}

// MSVC 14.1 refuses to inline fetch_or() while happily inlining everything else. Forcing the inline generates much cleaner output.
#ifdef __ATOMIC_STX_FORCE_INLINE
#error Macro already in use
#endif
#if defined(__GNUC__) || defined(__clang__)
#define __ATOMIC_STX_FORCE_INLINE attribute((always_inline))
#elif defined(_MSC_VER)
#define __ATOMIC_STX_FORCE_INLINE __forceinline
#else
#define __ATOMIC_STX_FORCE_INLINE inline
#endif

/*
 *	@brief	Wrapper around std::atomic that adds xacquire and xrelease TSX prefixes for hardware lock-elision on modern x86-64 architectures.
 *			In addition also adds explicit bit-test-and-set and bit-test-and-rest atomics for x86-64.
 *			On non-x86 targets behaves identically to std::atomic, with xacquire and xrelease decaying into std::memory_order_acquire and 
 *			std::memory_order_release respectively.
 *			
 *			Interface is compatible with std::atomic.
 */
template <typename T>
class atomic_tsx {
	static_assert(std::atomic<T>::is_always_lock_free, "Only supported for lock-free atomics");

	static constexpr auto size = sizeof(T);
	static_assert(size == 4 || size == 8, "Only supported on 32/64-bit variables");
	static constexpr bool is64wide = size == 8;

	using intrinsic_hle_type = std::conditional_t<size == 4, long, long long>;
	using integral_op_type = std::conditional_t<std::is_pointer_v<T>, std::ptrdiff_t, T>;

public:
	static constexpr bool is_always_lock_free = true;

private:
	std::atomic<T> var;

private:
	static constexpr bool use_tsx(memory_order order) noexcept {
		return _atomic_tsx_detail::is_x86_64 && (order == memory_order::xacquire || order == memory_order::xrelease);
	}

	__ATOMIC_STX_FORCE_INLINE static void tsx_store(void *dst, T desired, memory_order order) noexcept {
		assert(order == memory_order::xrelease && "Incorrect memory order (Only XRELEASE allowed for TSX store operation)");
		
		if constexpr (is64wide)
			_Store64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), *reinterpret_cast<const intrinsic_hle_type*>(&desired));
		else
			_Store_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), *reinterpret_cast<const intrinsic_hle_type*>(&desired));
	}
	
	__ATOMIC_STX_FORCE_INLINE static T tsx_exchange(void* dst, T desired, memory_order order) noexcept {
		if constexpr (is64wide) {
			return order == memory_order::xacquire ?
				_InterlockedExchange64_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												  *reinterpret_cast<const intrinsic_hle_type*>(&desired)) :
				_InterlockedExchange64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												  *reinterpret_cast<const intrinsic_hle_type*>(&desired));
		}
		else {
			return order == memory_order::xacquire ?
				_InterlockedExchange_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												*reinterpret_cast<const intrinsic_hle_type*>(&desired)) :
				_InterlockedExchange_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												*reinterpret_cast<const intrinsic_hle_type*>(&desired));
		}
	}

	__ATOMIC_STX_FORCE_INLINE static bool tsx_compare_exchange(void *dst, T &expected, T desired,
															   _atomic_tsx_detail::memory_order_helper success) noexcept {
		if constexpr (is64wide) {
			const auto prev = success == memory_order::xacquire ?
				_InterlockedCompareExchange64_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
														 *reinterpret_cast<const intrinsic_hle_type*>(&desired), 
														 *reinterpret_cast<const intrinsic_hle_type*>(&expected)) :
				_InterlockedCompareExchange64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
														 *reinterpret_cast<const intrinsic_hle_type*>(&desired), 
														 *reinterpret_cast<const intrinsic_hle_type*>(&expected));
			const auto result = prev == expected;

			expected = prev;
			return result;
		}
		else {
			const auto prev = success == memory_order::xacquire ?
				_InterlockedCompareExchange_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
													   *reinterpret_cast<const intrinsic_hle_type*>(&desired), 
													   *reinterpret_cast<const intrinsic_hle_type*>(&expected)) :
				_InterlockedCompareExchange_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
													   *reinterpret_cast<const intrinsic_hle_type*>(&desired), 
													   *reinterpret_cast<const intrinsic_hle_type*>(&expected));
			const auto result = prev == expected;

			expected = prev;
			return result;
		}
	}
	
	__ATOMIC_STX_FORCE_INLINE static T tsx_fetch_add(void *dst, T arg, _atomic_tsx_detail::memory_order_helper order) noexcept {
		if constexpr (is64wide) {
			return order == memory_order::xacquire ?
				_InterlockedExchangeAdd64_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
													 *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedExchangeAdd64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
													 *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
		else {
			return order == memory_order::xacquire ?
				_InterlockedExchangeAdd_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												   *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedExchangeAdd_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												   *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
	}
	
	__ATOMIC_STX_FORCE_INLINE static T tsx_fetch_sub(void *dst, T arg, _atomic_tsx_detail::memory_order_helper order) noexcept {
		if constexpr (is64wide) {
			return order == memory_order::xacquire ?
				_InterlockedExchangeAdd64_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
													 -*reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedExchangeAdd64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
													 -*reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
		else {
			return order == memory_order::xacquire ?
				_InterlockedExchangeAdd_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												   -*reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedExchangeAdd_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
												   -*reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
	}
	
	__ATOMIC_STX_FORCE_INLINE static T tsx_fetch_and(void *dst, T arg, _atomic_tsx_detail::memory_order_helper order) noexcept {
		if constexpr (is64wide) {
			return order == memory_order::xacquire ?
				_InterlockedAnd64_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
											 *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedAnd64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
											 *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
		else {
			return order == memory_order::xacquire ?
				_InterlockedAnd_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
										   *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedAnd_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
										   *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
	}
	
	__ATOMIC_STX_FORCE_INLINE static T tsx_fetch_or(void *dst, T arg, _atomic_tsx_detail::memory_order_helper order) noexcept {
		if constexpr (is64wide) {
			return order == memory_order::xacquire ?
				_InterlockedOr64_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
											 *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedOr64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
											 *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
		else {
			return order == memory_order::xacquire ?
				_InterlockedOr_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
										   *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedOr_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
										   *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
	}
	
	__ATOMIC_STX_FORCE_INLINE static T tsx_fetch_xor(void *dst, T arg, _atomic_tsx_detail::memory_order_helper order) noexcept {
		if constexpr (is64wide) {
			return order == memory_order::xacquire ?
				_InterlockedXor64_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
											 *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedXor64_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
											 *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
		else {
			return order == memory_order::xacquire ?
				_InterlockedXor_HLEAcquire(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
										   *reinterpret_cast<const intrinsic_hle_type*>(&arg)) :
				_InterlockedXor_HLERelease(reinterpret_cast<intrinsic_hle_type volatile*>(dst), 
										   *reinterpret_cast<const intrinsic_hle_type*>(&arg));
		}
	}
	
	__ATOMIC_STX_FORCE_INLINE static bool bts(void *dst, int bit, _atomic_tsx_detail::memory_order_helper order) noexcept {
		if constexpr (is64wide) {
			if (order == memory_order::xacquire)
				return _interlockedbittestandset64_HLEAcquire(reinterpret_cast<intrinsic_hle_type*>(dst),
															  static_cast<intrinsic_hle_type>(bit)) == 1;
			if (order == memory_order::xrelease)
				return _interlockedbittestandset64_HLERelease(reinterpret_cast<intrinsic_hle_type*>(dst),
															  static_cast<intrinsic_hle_type>(bit)) == 1;
			return _interlockedbittestandset64(reinterpret_cast<intrinsic_hle_type*>(dst),
											   static_cast<intrinsic_hle_type>(bit)) == 1;
		}
		else {
			if (order == memory_order::xacquire)
				return _interlockedbittestandset_HLEAcquire(reinterpret_cast<intrinsic_hle_type*>(dst),
															static_cast<intrinsic_hle_type>(bit)) == 1;
			if (order == memory_order::xrelease)
				return _interlockedbittestandset_HLERelease(reinterpret_cast<intrinsic_hle_type*>(dst),
															static_cast<intrinsic_hle_type>(bit)) == 1;
			return _interlockedbittestandset(reinterpret_cast<intrinsic_hle_type*>(dst),
											 static_cast<intrinsic_hle_type>(bit)) == 1;
		}
	}
	
	__ATOMIC_STX_FORCE_INLINE static bool btr(void *dst, int bit, _atomic_tsx_detail::memory_order_helper order) noexcept {
		if constexpr (is64wide) {
			if (order == memory_order::xacquire)
				return _interlockedbittestandreset64_HLEAcquire(reinterpret_cast<intrinsic_hle_type*>(dst),
																static_cast<intrinsic_hle_type>(bit)) == 1;
			if (order == memory_order::xrelease)
				return _interlockedbittestandreset64_HLERelease(reinterpret_cast<intrinsic_hle_type*>(dst),
																static_cast<intrinsic_hle_type>(bit)) == 1;
			return _interlockedbittestandreset64(reinterpret_cast<intrinsic_hle_type*>(dst),
												 static_cast<intrinsic_hle_type>(bit)) == 1;
		}
		else {
			if (order == memory_order::xacquire)
				return _interlockedbittestandreset_HLEAcquire(reinterpret_cast<intrinsic_hle_type*>(dst),
															  static_cast<intrinsic_hle_type>(bit)) == 1;
			if (order == memory_order::xrelease)
				return _interlockedbittestandreset_HLERelease(reinterpret_cast<intrinsic_hle_type*>(dst),
															  static_cast<intrinsic_hle_type>(bit)) == 1;
			return _interlockedbittestandreset(reinterpret_cast<intrinsic_hle_type*>(dst),
											   static_cast<intrinsic_hle_type>(bit)) == 1;
		}
	}

public:
	atomic_tsx() noexcept = default;
	constexpr atomic_tsx(T desired) noexcept : var(desired) {}

	atomic_tsx(const atomic_tsx&) = delete;
	atomic_tsx(atomic_tsx&&) = delete;
	atomic_tsx& operator=(const atomic_tsx&) = delete;
	atomic_tsx& operator=(atomic_tsx&&) = delete;
	
	auto &atomic() noexcept { return var; }
	const auto &atomic() const noexcept { return var; }
	// Allows implicit conversion to underlying std::atomic
	operator std::atomic<T>&() noexcept { return atomic(); }
	operator const std::atomic<T>&() const noexcept { return atomic(); }

	__ATOMIC_STX_FORCE_INLINE T operator=(T desired) noexcept {
		store(desired);
		return desired;
	}

	static constexpr bool is_lock_free() noexcept { return true; }

	/*
	 *	@brief	Atomically replaces the value of the atomic object with a non-atomic argument.
	 */
	__ATOMIC_STX_FORCE_INLINE void store(T desired, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				tsx_store(this, desired, order);
		}
		
		var.store(desired, order);
	}
	/*
	 *	@brief	Atomically obtains the value of the atomic object.
	 */
	__ATOMIC_STX_FORCE_INLINE T load(_atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) const noexcept {
		if (use_tsx(order))
			assert("Incorrect memory order (No TSX operations for load)");
		return var.load(order);
	}
	/*
	 *	@brief	Loads a value from an atomic object, equivalent to load().
	 */
	__ATOMIC_STX_FORCE_INLINE operator T() const noexcept { return load(); }
	
	/*
	 *	@brief	Atomically replaces the value of the atomic object and obtains the value held previously.
	 */
	__ATOMIC_STX_FORCE_INLINE T exchange(T desired, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_exchange(this, desired, order);
		}

		return var.exchange(desired, order);
			
	}

	/*
	 *	@brief	Atomically compares the value of the atomic object with non-atomic argument and performs atomic exchange if equal or atomic 
	 *			load if not.
	 */
	__ATOMIC_STX_FORCE_INLINE bool compare_exchange_weak(T &expected, T desired,
														 _atomic_tsx_detail::memory_order_helper success,
														 _atomic_tsx_detail::memory_order_helper failure) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(success))
				return tsx_compare_exchange(this, expected, desired, success);
		}

		return var.compare_exchange_weak(expected, desired, success, failure);	
	}
	/*
	 *	@brief	Atomically compares the value of the atomic object with non-atomic argument and performs atomic exchange if equal or atomic 
	 *			load if not.
	 */
	__ATOMIC_STX_FORCE_INLINE bool compare_exchange_weak(T &expected, T desired,
														 _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_compare_exchange(this, expected, desired, order);
		}

		return var.compare_exchange_weak(expected, desired, order);	
	}
	
	/*
	 *	@brief	Atomically compares the value of the atomic object with non-atomic argument and performs atomic exchange if equal or atomic 
	 *			load if not.
	 */
	__ATOMIC_STX_FORCE_INLINE bool compare_exchange_strong(T &expected, T desired,
														   _atomic_tsx_detail::memory_order_helper success,
														   _atomic_tsx_detail::memory_order_helper failure) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(success))
				return tsx_compare_exchange(this, expected, desired, success);
		}

		return var.compare_exchange_strong(expected, desired, success, failure);	
	}
	/*
	 *	@brief	Atomically compares the value of the atomic object with non-atomic argument and performs atomic exchange if equal or atomic 
	 *			load if not.
	 */
	__ATOMIC_STX_FORCE_INLINE bool compare_exchange_strong(T &expected, T desired,
														   _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_compare_exchange(this, expected, desired, order);
		}

		return var.compare_exchange_strong(expected, desired, order);	
	}
	
	/*
	 *	@brief	Atomically adds the argument to the value stored in the atomic object and obtains the value held previously.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T fetch_add(integral_op_type arg, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_fetch_add(this, arg, order);
		}

		return var.fetch_add(arg, order);	
	}
	/*
	 *	@brief	Atomically adds the argument to the value stored in the atomic object. Returns a copy of the stored value after the operation.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator+=(integral_op_type arg) noexcept { return fetch_add(arg) + arg; }
	/*
	 *	@brief	Atomically increments the current value.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator++() noexcept { return fetch_add(1) + 1; }
	/*
	 *	@brief	Atomically increments the current value.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator++(int) noexcept { return fetch_add(1); }
	
	/*
	 *	@brief	Atomically subtracts the argument from the value stored in the atomic object and obtains the value held previously.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T fetch_sub(integral_op_type arg, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_fetch_sub(this, arg, order);
		}

		return var.fetch_sub(arg, order);	
	}
	/*
	 *	@brief	Atomically subtracts the argument from the value stored in the atomic object. Returns a copy of the stored value after the 
	 *			operation.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator-=(integral_op_type arg) noexcept { return fetch_sub(arg) - arg; }
	/*
	 *	@brief	Atomically decrements the current value.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator--() noexcept { return fetch_sub(1) - 1; }
	/*
	 *	@brief	Atomically decrements the current value.
	 *	
	 *			Only defined for integral, floating-point or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_floating_point_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator--(int) noexcept { return fetch_sub(1); }

	/*
	 *	@brief	Atomically performs bitwise AND between the argument and the value of the atomic object and obtains the value held previously.
	 *	
	 *			Only defined for integral types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T fetch_and(T arg, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_fetch_and(this, arg, order);
		}

		return var.fetch_and(arg, order);	
	}
	/*
	 *	@brief	Atomically performs bitwise AND between the argument and the value of the atomic object. Returns a copy of the stored value 
	 *			after the operation.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator&=(T arg) noexcept { return fetch_and(arg) & arg; }

	/*
	 *	@brief	Atomically performs bitwise OR between the argument and the value of the atomic object and obtains the value held previously.
	 *	
	 *			Only defined for integral types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T fetch_or(T arg, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_fetch_or(this, arg, order);
		}

		return var.fetch_or(arg, order);	
	}
	/*
	 *	@brief	Atomically performs bitwise OR between the argument and the value of the atomic object. Returns a copy of the stored value 
	 *			after the operation.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator|=(T arg) noexcept { return fetch_or(arg) | arg; }

	/*
	 *	@brief	Atomically performs bitwise XOR between the argument and the value of the atomic object and obtains the value held previously.
	 *	
	 *			Only defined for integral types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T fetch_xor(T arg, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64) {
			if (use_tsx(order))
				return tsx_fetch_xor(this, arg, order);
		}

		return var.fetch_xor(arg, order);	
	}
	/*
	 *	@brief	Atomically performs bitwise XOR between the argument and the value of the atomic object. Returns a copy of the stored value 
	 *			after the operation.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S>>>
	__ATOMIC_STX_FORCE_INLINE T operator^=(T arg) noexcept { return fetch_xor(arg) ^ arg; }

	/*
	 *	@brief	Atomically sets the bit at the specified position and returns the bit value before the set.
	 *	
	 *			Only defined for integral or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE bool bit_test_and_set(int bit, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64)
			return bts(this, bit, order);
		
		// Emulate with fetch_or
		const auto mask = static_cast<integral_op_type>(1) << bit;
		return !!(fetch_or(mask) & mask);
	}

	/*
	 *	@brief	Atomically resets the bit at the specified position and returns the bit value before the set.
	 *	
	 *			Only defined for integral or pointer types.
	 */
	template <typename S = T, typename = std::enable_if_t<std::is_integral_v<S> || std::is_pointer_v<S>>>
	__ATOMIC_STX_FORCE_INLINE bool bit_test_and_reset(int bit, _atomic_tsx_detail::memory_order_helper order = memory_order::seq_cst) noexcept {
		if constexpr (_atomic_tsx_detail::is_x86_64)
			return btr(this, bit, order);

		// Emulate with fetch_and
		const auto mask = static_cast<integral_op_type>(1) << bit;
		return !!(fetch_and(~mask) & mask);
	}
};


// Transactional memory
namespace transactional_memory {

using abort_code = std::uint8_t;
enum class status : std::uint8_t {
	started = 0,
	abort_explicit = 1 << 0,
	abort_retry = 1 << 1,
	abort_conflict = 1 << 2,
	abort_capacity = 1 << 3,
	abort_debug = 1 << 4,
	abort_nested = 1 << 5,
	abort_system = 1 << 6,
	abort_unknown = 1 << 7,
};
constexpr status operator|(const status &lhs, const status &rhs) noexcept {
	using T = std::underlying_type_t<status>;
	return static_cast<status>(static_cast<T>(lhs) | static_cast<T>(rhs));
}
constexpr status operator&(const status &lhs, const status &rhs) noexcept {
	using T = std::underlying_type_t<status>;
	return static_cast<status>(static_cast<T>(lhs) & static_cast<T>(rhs));
}

/*
 *	@brief	Starts a transaction. 
 *	@return	A pair of transaction status and abort code. Abort code is relevant only if status::abort_explicit is set.
 */
static __ATOMIC_STX_FORCE_INLINE std::pair<status, abort_code> transaction_begin() noexcept {
	static_assert(_atomic_tsx_detail::is_x86_64, "Only supported on x86-64");

	// Begin transaction
	const auto begin = _xbegin();
	if (begin == _XBEGIN_STARTED)
		return { status::started, 0 };

	// Check abort status
	auto ret = static_cast<status>(0);
	if (begin == 0) {
		// Return code of 0 indicates an abort due to system call, a serializing instruction, touching unmapped pages or other obscure
		// reasons. See https://software.intel.com/en-us/forums/intel-moderncode-for-parallel-architectures/topic/658265
		ret = ret | status::abort_system;
	}
	if (begin & _XABORT_CAPACITY)
		ret = ret | status::abort_capacity;
	if (begin & _XABORT_CONFLICT)
		ret = ret | status::abort_conflict;
	if (begin & _XABORT_DEBUG)
		ret = ret | status::abort_debug;
	if (begin & _XABORT_EXPLICIT)
		ret = ret | status::abort_explicit;
	if (begin & _XABORT_NESTED)
		ret = ret | status::abort_nested;
	if (begin & _XABORT_RETRY)
		ret = ret | status::abort_retry;
	if (ret == static_cast<status>(0))
		ret = status::abort_unknown;

	return { ret, static_cast<abort_code>(_XABORT_CODE(begin)) };
}
/*
 *	@brief	Aborts the transaction with a specified abort code
 */
template <abort_code code>
static __ATOMIC_STX_FORCE_INLINE void transaction_abort() noexcept {
	static_assert(_atomic_tsx_detail::is_x86_64, "Only supported on x86-64");
	_xabort(static_cast<unsigned int>(code));
}
/*
 *	@brief	Ends the transaction
 */
static __ATOMIC_STX_FORCE_INLINE void transaction_end() noexcept {
	static_assert(_atomic_tsx_detail::is_x86_64, "Only supported on x86-64");
	_xend();
}
/*
 *	@brief	Checks if a transaction is currently active
 */
static __ATOMIC_STX_FORCE_INLINE bool transaction_active() noexcept {
	static_assert(_atomic_tsx_detail::is_x86_64, "Only supported on x86-64");
	return _xtest() != 0;
}

}


#undef __ATOMIC_STX_FORCE_INLINE

}
