// shared_futex
// � Shlomi Steinberg, 2015-2018

#include "parking_lot.hpp"

using namespace strt;

std::array<parking_lot_detail::parking_lot_slot, parking_lot_detail::parking_lot_slot::slots_count> parking_lot_detail::parking_lot_slot::slots;
