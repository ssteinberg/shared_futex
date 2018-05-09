// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "../parking_lot/parking_lot.hpp"

#include <optional>
#include <utility>
#include <type_traits>

namespace ste::shared_futex_detail {

template <typename LatchLock>
using shared_futex_park_return_t = std::pair<parking_lot_wait_state, std::optional<LatchLock>>;

template <shared_futex_parking_policy policy, typename LatchLock>
class shared_futex_parking {};


// Partial specialization for 'parking lot' policy
template <shared_futex_parking_policy policy, typename LatchLock>
class shared_futex_parking<shared_futex_parking_policy::parking_lot, LatchLock> {
	parking_lot<LatchLock> parking;

public:
	/*
	 *	@brief	If park_predicate returns true, parks the calling thread in the specified slot until the timeout has expired 
	 *			or the thread was unparked. 
	*/
	template <modus_operandi mo, typename ParkSlot, typename ParkPredicate, typename OnPark, typename Clock, typename Duration>
	shared_futex_park_return_t<LatchLock> park_until(ParkPredicate &&park_predicate,
													 OnPark &&on_park,
													 ParkSlot &&park_slot,
													 const std::chrono::time_point<Clock, Duration> &until) {
		return parking.park_until(std::forward<ParkPredicate>(park_predicate),
								  std::forward<OnPark>(on_park),
								  std::forward<ParkSlot>(park_slot),
								  until);
	}
};


// Partial specialization for 'local' policy
template <shared_futex_parking_policy policy, typename LatchLock>
class shared_futex_parking<shared_futex_parking_policy::local, LatchLock> {
	std::condition_variable_any shared_cond_var;
	utils::spinner<> shared_cond_var_lock;

public:
	class parking_slot {
		friend class shared_futex_parking;
		std::condition_variable cond_var;
		std::mutex<> m;
	};

private:
	template <typename ParkPredicate, typename OnPark, typename CondVar, typename Mutex, typename Clock, typename Duration>
	shared_futex_park_return_t<LatchLock> wait(ParkPredicate &&park_predicate,
											   OnPark &&on_park,
											   CondVar &cond_var,
											   Mutex &m,
											   const std::chrono::time_point<Clock, Duration> &until) {
		on_park();

		std::unique_lock<Mutex> ul(m);

		// Check predicate under lock
		if (park_predicate())
			return { false, parking_lot_wait_state::park_validation_failed };

		// Park
		do {
			if (until != std::chrono::time_point<Clock, Duration>::max()) {
				if (cond_var.wait_until(ul, until) == std::cv_status::timeout)
					return { true, parking_lot_wait_state::timeout };
			}
			else {
				cond_var.wait(ul);
			}
		}
		while (!park_predicate());

		return { true, parking_lot_wait_state::signaled };
	}

public:
	/*
	 *	@brief	Parks the calling thread in the specified slot until the timeout has expired or the thread was unparked. 
	*/
	template <
		modus_operandi mo, typename ParkPredicate, typename OnPark, typename Clock, typename Duration,
		typename = std::enable_if_t<mo != modus_operandi::shared_lock>
	>
	shared_futex_park_return_t<LatchLock> park_until(ParkPredicate &&park_predicate,
													 OnPark &&on_park,
													 parking_slot &park_slot,
													 const std::chrono::time_point<Clock, Duration> &until) {
		return wait(std::forward<ParkPredicate>(park_predicate),
					std::forward<OnPark>(on_park),
					park_slot.cond_var,
					park_slot.m,
					until);
	}
	
	/*
	 *	@brief	Parks the calling thread in the specified slot until the timeout has expired or the thread was unparked. 
	*/
	template <
		modus_operandi mo, typename ParkPredicate, typename OnPark, typename Clock, typename Duration,
		typename = std::enable_if_t<mo == modus_operandi::shared_lock>
	>
	shared_futex_park_return_t<LatchLock> park_until(ParkPredicate &&park_predicate,
													 OnPark &&on_park,
													 const std::chrono::time_point<Clock, Duration> &until) {
		return wait(std::forward<ParkPredicate>(park_predicate),
					std::forward<OnPark>(on_park),
					shared_cond_var,
					shared_cond_var_lock,
					until);
	}
};

}
