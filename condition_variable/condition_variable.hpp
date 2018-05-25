// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "../parking_lot/parking_lot.hpp"

namespace ste {

class condition_variable {
private:
	using parking_lot_t = parking_lot<void>;

private:
	parking_lot_t parking_lot;

public:

};

}
