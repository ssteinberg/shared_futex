// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include <type_traits>

/*
 *	@brief	Returns the smallest value that is greater than or equal to input t, and is a power-of-2.
 *	@param	t	Input, must be of an unsigned integral type.
 */
template <typename T>
static constexpr T ceil_power_of_two(T t) noexcept {
	static_assert(std::is_integral_v<T>, "T must be of integral type");
	static_assert(std::is_unsigned_v<T>, "T must be unsigned");

	auto x = t-1;
	for (auto i = 0; i < sizeof(T)*8; ++i)
		x |= x >> i;

	return x + 1;
}
