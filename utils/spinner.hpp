// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include <atomic>
#include <immintrin.h>
#include <algorithm>

namespace ste::utils {

/*
 *	@brief	Simple spin locker with linearly increasing pauses between lock attempts.
 *	@param	spins0	Spin count on first iteration
 *	@param	spins1	Final spin count
 *	@param	steps	Iterations count to reach 'spins1' spins. After performing this count of iterations spin ceases to increase.
 */
template <int spins0 = 1, int spins1 = 64, int steps = 32>
class spinner {
	std::atomic_flag f = ATOMIC_FLAG_INIT;

public:
	void lock() noexcept {
		for (auto i=0; f.test_and_set(); ++i) {
			// Spin
			const auto spins = (spins1 - spins0) * std::min(i, steps) / steps + spins0;
			for (auto j=0; j<spins; ++j)
				::_mm_pause();
		}
	}
	void unlock() noexcept {
		f.clear();
	}
};

}
