// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "../atomic/atomic_tsx.hpp"

#include <immintrin.h>
#include <algorithm>

namespace ste::utils {

/*
 *	@brief	Simple spin locker with linearly increasing pauses between lock attempts.
 *	@param	spins0	Spin count on first iteration
 *	@param	spins1	Final spin count
 *	@param	steps	Iterations count to reach 'spins1' spins. After performing this count of iterations spin ceases to increase.
 */
template <int spins0 = 1, int spins1 = 128, int steps = 24>
class spinner {
	atomic_tsx<std::uint32_t> f{ 0 };

public:
	void lock() noexcept {
		if (!f.bit_test_and_set(0, std::memory_order_acq_rel))
			return;

		for (auto i=1;; ++i) {
			// Spin
			const auto spins = (spins1 - spins0) * std::min(i, steps) / steps + spins0;
			for (auto j=0; j<spins; ++j)
				::_mm_pause();

			if (!f.bit_test_and_set(0, std::memory_order_acq_rel))
				return;
		}
	}
	void unlock() noexcept {
		f.bit_test_and_reset(0, std::memory_order_release);
	}
};

}
