// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include <functional>

namespace ste {

template <typename T>
struct hash_combine {
	void operator()(std::size_t &seed, const T &t) noexcept {
		using hasher = std::hash<T>;

		const auto hash = hasher{}(t);
		// From boost::hash_combine
		const auto x = hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= x;
	}
};

}