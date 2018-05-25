// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "../parking_lot/parking_lot.hpp"

namespace ste {

template <typename Data = void>
class condition_variable {
private:
	using parking_lot_t = parking_lot<std::size_t, Data>;

private:
	parking_lot_t parking_lot;

public:
	template <typename... Args>
	std::size_t signal(Args&&... args) const noexcept {
		
	}
};

}
