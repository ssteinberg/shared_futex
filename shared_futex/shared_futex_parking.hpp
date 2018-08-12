// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include "shared_futex_common.hpp"
#include "../parking_lot/parking_lot.hpp"
#include "../utils/shared_futex_spinner.hpp"

#include <type_traits>

namespace strt::shared_futex_detail {

template <typename ParkSlot, shared_futex_parking_policy policy>
class shared_futex_parking {
public:
	using park_return_t = parking_lot_wait_state;
	
	template <operation op>
	static constexpr bool provides_accurate_unpark_count() noexcept { return true; }
};

// Partial specialization for 'parking lot' policy
template <typename ParkSlot>
class shared_futex_parking<ParkSlot, shared_futex_parking_policy::parking_lot> {
public:
	using park_return_t = parking_lot_wait_state;

private:
	using parking_lot_t = parking_lot<ParkSlot>;
	parking_lot_t parking;

public:
	/*
	 *	@brief	If provides_accurate_unpark_count() returns true then return values from unpark() will always reflect accurate count
	 *			of unparked threads. Otherwise data is estimated or plainly unavailable and shouldn't be relied on.
	 */
	template <operation op>
	static constexpr bool provides_accurate_unpark_count() noexcept { return true; }

	/*
	 *	@brief	If park_predicate returns true, parks the calling thread in the specified slot until the timeout has expired 
	 *			or the thread was unparked. 
	*/
	template <operation op, typename ParkPredicate, typename OnPark, typename PostPark, typename Clock, typename Duration>
	park_return_t park_until(ParkPredicate &&park_predicate,
							 OnPark &&on_park,
							 PostPark &&post_park,
							 ParkSlot &&park_slot,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return parking.park_until(std::forward<ParkPredicate>(park_predicate),
								  std::forward<OnPark>(on_park),
								  std::forward<PostPark>(post_park),
								  std::move(park_slot),
								  until).first;
	}
	
	/*
	 *	@brief	Unparks threads of a specified op.
	 *	@return	Count of threads successfully unparked
	 */
	template <unpark_tactic tactic, operation op>
	std::size_t unpark(ParkSlot &&park_slot) noexcept {
        const auto unparking_function = tactic == unpark_tactic::all ? 
            &parking_lot_t::template unpark_all<> : 
            &parking_lot_t::template unpark_one<>;
		
        return std::invoke(unparking_function, parking, park_slot); 
	}
};


// Partial specialization for 'shared_local' policy
template <typename ParkSlot>
class shared_futex_parking<ParkSlot, shared_futex_parking_policy::shared_local> {
public:
	using park_return_t = parking_lot_wait_state;

private:
	// Local slot for shared
	using mutex_t = shared_futex_utils::spinner<>;
	std::condition_variable_any shared_cond_var;
	mutex_t shared_cond_var_lock;

	// Parking lot for non-shared
	using parking_lot_t = parking_lot<ParkSlot>;
	parking_lot_t parking;

private:
	template <typename ParkPredicate, typename OnPark, typename CondVar, typename Mutex, typename Clock, typename Duration>
	static park_return_t wait(ParkPredicate &&park_predicate,
							  OnPark &&on_park,
							  CondVar &cond_var,
							  Mutex &m,
							  const std::chrono::time_point<Clock, Duration> &until) noexcept {
		std::unique_lock<Mutex> ul(m);

		on_park();

		// Check predicate under lock
		if (park_predicate())
			return parking_lot_wait_state::predicate;

		// Park
		if (until != std::chrono::time_point<Clock, Duration>::max()) {
			if (cond_var.wait_until(ul, until) == std::cv_status::timeout)
				return parking_lot_wait_state::timeout;
		}
		else {
			cond_var.wait(ul);
		}

		return parking_lot_wait_state::signalled;
	}

public:
	/*
	 *	@brief	If provides_accurate_unpark_count() returns true then return values from unpark() will always reflect accurate count
	 *			of unparked threads. Otherwise the data is estimated or plainly unavailable.
	 */
	template <operation op>
	static constexpr bool provides_accurate_unpark_count() noexcept {
		return op != operation::lock_shared;
	}

	/*
	 *	@brief	Parks the calling thread in the specified slot until the timeout has expired or the thread was unparked. 
	*/
	template <
		operation op, typename ParkPredicate, typename OnPark, typename PostPark, typename Clock, typename Duration,
		typename = std::enable_if_t<op != operation::lock_shared>
	>
	park_return_t park_until(ParkPredicate &&park_predicate,
							 OnPark &&on_park,
							 PostPark &&post_park,
							 ParkSlot &&park_slot,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return parking.park_until(std::forward<ParkPredicate>(park_predicate),
								  std::forward<OnPark>(on_park),
								  std::forward<PostPark>(post_park),
								  std::move(park_slot),
								  until).first;
	}

	/*
	 *	@brief	Parks the calling thread in the specified slot until the timeout has expired or the thread was unparked. 
	*/
	template <
		operation op, typename ParkPredicate, typename OnPark, typename PostPark, typename Clock, typename Duration,
		typename = std::enable_if_t<op == operation::lock_shared>
	>
	park_return_t park_until(ParkPredicate &&park_predicate,
							 OnPark &&on_park,
							 PostPark &&post_park,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		auto result = wait(std::forward<ParkPredicate>(park_predicate),
						   std::forward<OnPark>(on_park),
						   shared_cond_var,
						   shared_cond_var_lock,
						   until);
		post_park();

		return result;
	}
	
	/*
	 *	@brief	Unparks threads of a specified op.
	 *	@return	Count of threads successfully unparked
	 */
	template <
		unpark_tactic tactic, operation op,
		typename = std::enable_if_t<op == operation::lock_shared>
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
	 *	@brief	Unparks threads of a specified op.
	 *	@return	Count of threads successfully unparked
	 */
	template <
		unpark_tactic tactic, operation op,
		typename = std::enable_if_t<op != operation::lock_shared>
	>
	std::size_t unpark(ParkSlot &&park_slot) noexcept {
        // Choose function for given unpark tactic 
        const auto unparking_function = tactic == unpark_tactic::all ? 
            &parking_lot_t::template unpark_all<> : 
            &parking_lot_t::template unpark_one<>;
		
        return std::invoke(unparking_function, parking, park_slot); 
	}
};

}
