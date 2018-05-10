// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "../parking_lot/parking_lot.hpp"

#include <type_traits>

namespace ste::shared_futex_detail {

template <shared_futex_parking_policy policy>
class shared_futex_parking {};


// Partial specialization for 'parking lot' policy
template <>
class shared_futex_parking<shared_futex_parking_policy::parking_lot> {
	using parking_lot_t = parking_lot<>;
	parking_lot_t parking;

public:
	/*
	 *	@brief	If provides_accurate_unpark_count() returns true then return values from unpark() will always reflect accurate count
	 *			of unparked threads. Otherwise data is estimated or plainly unavailable and shouldn't be relied on.
	 */
	template <modus_operandi mo>
	static constexpr bool provides_accurate_unpark_count() noexcept { return true; }

	/*
	 *	@brief	If park_predicate returns true, parks the calling thread in the specified slot until the timeout has expired 
	 *			or the thread was unparked. 
	*/
	template <modus_operandi mo, typename ParkPredicate, typename OnPark, typename ParkSlot, typename Clock, typename Duration>
	parking_lot_wait_state park_until(ParkPredicate &&park_predicate,
									  OnPark &&on_park,
									  ParkSlot &&park_slot,
									  const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return parking.park_until(std::forward<ParkPredicate>(park_predicate),
								  std::forward<OnPark>(on_park),
								  std::forward<ParkSlot>(park_slot),
								  until).first;
	}
	
	/*
	 *	@brief	Unparks threads of a specified mo.
	 *	@return	Count of threads successfully unparked
	 */
	template <unpark_tactic tactic, modus_operandi mo, typename Key>
	std::size_t unpark(Key &&unpark_key) noexcept {
		// Choose function for given unpark tactic
		const auto unparking_function = tactic == unpark_tactic::all ?
			&parking_lot_t::unpark_all<Key> :
			&parking_lot_t::unpark_one<Key>;

		// Attempt unpark
		return std::invoke(unparking_function, parking, unpark_key);
	}
};


// Partial specialization for 'local' policy
template <>
class shared_futex_parking<shared_futex_parking_policy::local> {
	std::condition_variable_any shared_cond_var;
	utils::spinner<> shared_cond_var_lock;

public:
	class parking_slot_t {
		friend class shared_futex_parking;
		std::condition_variable cond_var;
		utils::spinner<> lock;
	};

private:
	template <typename ParkPredicate, typename OnPark, typename CondVar, typename Mutex, typename Clock, typename Duration>
	static parking_lot_wait_state wait(ParkPredicate &&park_predicate,
									   OnPark &&on_park,
									   CondVar &cond_var,
									   Mutex &m,
									   const std::chrono::time_point<Clock, Duration> &until) noexcept {
		on_park();

		std::unique_lock<Mutex> ul(m);

		// Check predicate under lock
		if (park_predicate())
			return parking_lot_wait_state::park_validation_failed;

		// Park
		do {
			if (until != std::chrono::time_point<Clock, Duration>::max()) {
				if (cond_var.wait_until(ul, until) == std::cv_status::timeout)
					return parking_lot_wait_state::timeout;
			}
			else {
				cond_var.wait(ul);
			}
		} while (!park_predicate());

		return parking_lot_wait_state::signaled;
	}

public:
	/*
	 *	@brief	If provides_accurate_unpark_count() returns true then return values from unpark() will always reflect accurate count
	 *			of unparked threads. Otherwise data is estimated or plainly unavailable and shouldn't be relied on.
	 */
	template <modus_operandi mo>
	static constexpr bool provides_accurate_unpark_count() noexcept {
		if constexpr (mo == modus_operandi::shared_lock)
			return false;
		else
			return true;
	}

	/*
	 *	@brief	Parks the calling thread in the specified slot until the timeout has expired or the thread was unparked. 
	*/
	template <
		modus_operandi mo, typename ParkPredicate, typename OnPark, typename Clock, typename Duration,
		typename = std::enable_if_t<mo != modus_operandi::shared_lock>
	>
	static parking_lot_wait_state park_until(ParkPredicate &&park_predicate,
											 OnPark &&on_park,
											 parking_slot_t &park_slot,
											 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return wait(std::forward<ParkPredicate>(park_predicate),
					std::forward<OnPark>(on_park),
					park_slot.cond_var,
					park_slot.lock,
					until);
	}

	/*
	 *	@brief	Parks the calling thread in the specified slot until the timeout has expired or the thread was unparked. 
	*/
	template <
		modus_operandi mo, typename ParkPredicate, typename OnPark, typename Clock, typename Duration,
		typename = std::enable_if_t<mo == modus_operandi::shared_lock>
	>
	parking_lot_wait_state park_until(ParkPredicate &&park_predicate,
									  OnPark &&on_park,
									  const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return wait(std::forward<ParkPredicate>(park_predicate),
					std::forward<OnPark>(on_park),
					shared_cond_var,
					shared_cond_var_lock,
					until);
	}
	
	/*
	 *	@brief	Unparks threads of a specified mo.
	 *	@return	Count of threads successfully unparked
	 */
	template <
		unpark_tactic tactic, modus_operandi mo,
		typename = std::enable_if_t<mo == modus_operandi::shared_lock>
	>
	std::size_t unpark() noexcept {
		using shared_cond_var_t = std::decay_t<decltype(shared_cond_var)>;
		using shared_cond_var_lock_t = std::decay_t<decltype(shared_cond_var_lock)>;
		
		// Choose function for given unpark tactic
		const auto unparking_function = tactic == unpark_tactic::all ?
			&shared_cond_var_t::notify_all :
			&shared_cond_var_t::notify_one;

		{
			// Attempt unpark
			std::unique_lock<shared_cond_var_lock_t> ul(shared_cond_var_lock);
			std::invoke(unparking_function, shared_cond_var);
		}

		// Unknown unpark count
		return 0;
	}
	
	/*
	 *	@brief	Unparks threads of a specified mo.
	 *	@return	Count of threads successfully unparked
	 */
	template <
		unpark_tactic tactic, modus_operandi mo,
		typename = std::enable_if_t<mo != modus_operandi::shared_lock>
	>
	static std::size_t unpark(parking_slot_t &slot) noexcept {
		static_assert(tactic == unpark_tactic::one, "Only 'unpark one' tactic is supported");
		
		using cond_var_lock_t = std::decay_t<decltype(slot.lock)>;
		
		{
			// Attempt unpark
			std::unique_lock<cond_var_lock_t> ul(slot.lock);
			slot.cond_var.notify_one();
		}

		return 1;
	}
};

}
