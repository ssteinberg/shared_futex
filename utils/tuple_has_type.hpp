// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include <tuple>
#include <type_traits>

namespace ste::utils {

template <typename T, typename Tuple>
struct tuple_has_type : std::false_type {};
template <typename T, typename... Ts>
struct tuple_has_type<T, std::tuple<Ts...>> {
	static constexpr bool value = std::disjunction_v<std::is_same<T, Ts>...>;
};
template <typename T, typename... Ts>
static constexpr bool tuple_has_type_v = tuple_has_type<T, std::tuple<Ts...>>::value;

}
