// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include "../atomic/atomic_tsx.hpp"

#if defined(__GNUC__) || defined(__clang__)
#include <x86intrin.h>
#else
#include <intrin.h>
#endif
#include <immintrin.h>
#include <algorithm>

namespace strt::shared_futex_utils {

/*
 *	@brief	Simple spin locker with a symmetry-breaking spin count modulation.
 *	
 *	@param	base_spins
 *	@param	symmetry_breaker
 */
template <int base_spins = 64, int symmetry_breaker = 64>
class spinner {
	atomic_tsx<std::uint32_t> f{ 0 };

public:
	spinner() noexcept = default;

	bool try_lock() noexcept {
		return !f.bit_test_and_set(0, std::memory_order_acq_rel);
	}
	void lock() noexcept {
		if (try_lock())
			return;

		do {
			// Spin
			const auto rdtsc = __rdtsc();
			const auto spins = static_cast<size_t>(rdtsc % symmetry_breaker) + base_spins;
			for (size_t j=0; j<spins; ++j)
				::_mm_pause();
		} while (!try_lock());
	}
	void unlock() noexcept {
		f.bit_test_and_reset(0, std::memory_order_release);
	}
};

}
