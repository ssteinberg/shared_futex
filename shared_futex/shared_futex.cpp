// shared_futex
// � Shlomi Steinberg, 2015-2018

#include "shared_futex.hpp"

#include <thread>
#include <chrono>
#include <functional>

using namespace strt;

inline std::mt19937 generate_seeded_random_engine() noexcept {
	const auto tse = std::chrono::high_resolution_clock::now().time_since_epoch();
	const auto time = std::chrono::duration_cast<std::chrono::nanoseconds>(tse).count();
	const auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());

	// Construct a seed sequence with two sources of entropy, time since epoch and thread id.
	std::seed_seq seq = { static_cast<std::uint64_t>(time), static_cast<std::uint64_t>(tid) };

	// Seed the Mersenne Twister engine
	return std::mt19937(seq);
}

shared_futex_detail::random_generator::seeded_mt19937::seeded_mt19937() noexcept : rand_engine(generate_seeded_random_engine()) {}
