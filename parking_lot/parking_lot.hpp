// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include <condition_variable>
#include <mutex>
#include <atomic>
#include <array>
#include <type_traits>
#include <functional>
#include <optional>
#include <cassert>

namespace ste {

enum class parking_lot_wait_state {
	// Signaled by condition variable and returned successfully
	signaled,
	// Park validation predicate triggered
	park_validation_failed,
	// Timeout (unspecified predicate success value)
	timeout,
};

namespace parking_lot_detail {

class parking_lot_node_base {
public:
	static constexpr std::size_t key_size = 8;

private:
	using mutex_t = std::mutex;

	std::function<bool()> park_predicate;
	mutex_t m;
	std::condition_variable cv;

	bool signaled{ false };

	// Node tag
	struct {
		void *id;
		std::aligned_storage_t<key_size> key;
	} tag{};

protected:
	/*
	 *	@brief	Attempts to signal node. Returns true on success, false if predicate is unsatisfied.
	 */
	bool signal() noexcept {
		// Check predicate
		if (!park_predicate())
			return false;

		// Signal
		std::unique_lock<mutex_t> ul(m);

		signaled = true;
		cv.notify_one();

		return true;
	}

public:
	template <typename P, typename K>
	parking_lot_node_base(P* id, K &&key) {
		using T = std::remove_cv_t<std::remove_reference_t<K>>;

		static_assert(std::is_trivially_destructible_v<T>, "key must be trivially destructible");
		static_assert(std::is_trivially_copy_constructible_v<T> || !std::is_lvalue_reference_v<K&&>,
					  "key must be trivially copy constructible when taking an l-value");
		static_assert(std::is_trivially_move_constructible_v<T> || !std::is_rvalue_reference_v<K&&>,
					  "key must be trivially move constructible when taking an r-value");
		static_assert(sizeof(T) <= key_size, "key must be no larger than key_size");

		tag.id = id;
		::new (&tag.key) T(std::forward<K>(key));
	}
	virtual ~parking_lot_node_base() noexcept = default;
	
	parking_lot_node_base(parking_lot_node_base&&) = delete;
	parking_lot_node_base(const parking_lot_node_base&) = delete;
	parking_lot_node_base &operator=(parking_lot_node_base&&) = delete;
	parking_lot_node_base &operator=(const parking_lot_node_base&) = delete;

	template <typename Pred>
	void set_predicate(Pred&& pred) noexcept {
		park_predicate = std::forward<Pred>(pred);
	}

	/*
	 *	@brief	Checks if the serialized tag equals to the supplied id and key.
	 *			K should be the same type as passed to the ctor.
	 */
	template <typename P, typename K>
	bool id_equals(P* id, const K &key) const noexcept {
		static_assert(sizeof(K) <= key_size, "key must be no larger than key_size");

		return tag.id == id && *reinterpret_cast<const K*>(&tag.key) == key;
	}
	bool is_signalled() const noexcept { return signaled; }

	/*
	 *	@brief	Parks
	 *	@return	Wait-performed boolean and the wait state as a pair.
	 */
	template <typename Clock, typename Duration>
	std::pair<bool, parking_lot_wait_state> wait_until(const std::chrono::time_point<Clock, Duration> &until) {
		const auto pred = [&]() { return signaled; };

		std::atomic_thread_fence(std::memory_order_acquire);
		if (pred())
			return { false, parking_lot_wait_state::signaled };

		{
			std::unique_lock<mutex_t> ul(m);

			// Park
			while(!pred()) {
				if (until != std::chrono::time_point<Clock, Duration>::max()) {
					// On cv timeout always return a timeout result, even if the predicate is true at that stage.
					// This allows the parker to distinguish between signaled and unsignalled cases.
					if (cv.wait_until(ul, until) == std::cv_status::timeout)
						return { true, parking_lot_wait_state::timeout };
				}
				else {
					cv.wait(ul);
				}
			}

			return { true, parking_lot_wait_state::signaled };
		}
	}

	// Intrusive list
	parking_lot_node_base *next{ nullptr };
	parking_lot_node_base *prev{ nullptr };
};
template <typename Data>
class parking_lot_node final : public parking_lot_node_base {
	std::optional<Data> data;

public:
	using parking_lot_node_base::parking_lot_node_base;

	/*
	*	@brief	Signals the node and constructs a Data object to be consumed by the waiter.
	*	@return	True on success, false if predicate is unsatisfied.
	*/
	template <typename... Args>
	bool signal(Args&&... args) noexcept {
		const auto result = parking_lot_node_base::signal();
		if (result)
			data.emplace(std::forward<Args>(args)...);

		return result;
	}
	/*
	*	@brief	Extracts the stored data object
	*/
	Data&& retrieve_data() && noexcept { return std::move(data).value(); }
};
template <>
class parking_lot_node<void> final : public parking_lot_node_base {
public:
	using parking_lot_node_base::parking_lot_node_base;
	using parking_lot_node_base::signal;

	/*
	*	@brief	Dummy
	*/
	int retrieve_data() && noexcept { return 0; }
};

class parking_lot_slot {
	static constexpr auto alignment = std::hardware_destructive_interference_size;

public:
	using mutex_t = std::mutex;
	alignas(alignment) mutex_t m;

	// Simple intrusive dlist
	alignas(alignment) parking_lot_node_base *head{ nullptr };
	parking_lot_node_base *tail{ nullptr };

	void push_back(parking_lot_node_base *node) noexcept {
		if (tail) {
			node->prev = tail;
			tail = tail->next = node;
		}
		else {
			head = tail = node;
		}
	}

	void erase(parking_lot_node_base *node) noexcept {
		if (node->next)
			node->next->prev = node->prev;
		else
			tail = node->prev;
		if (node->prev)
			node->prev->next = node->next;
		else
			head = node->next;
	}

	void clear() noexcept { head = tail = nullptr; }
	bool is_empty() const noexcept { return head == nullptr; }

public:
	static constexpr auto slots_count = 2048;

	/*
	*	@brief	Returns a static parking lot slot for a given id/key pair.
	*			See parking_lot_node_base::parking_lot_node_base(K&&).
	*/
	template <typename P, typename K>
	static parking_lot_slot& slot_for(P* id, const K &key) noexcept {
		const auto key_hash = std::hash<std::decay_t<K>>{}(key);
		const auto id_hash = std::hash<P*>{}(id);

		// boost::hash_combine
		const auto x = key_hash + 0x9e3779b9 + (id_hash << 6) + (id_hash >> 2);
		const auto idx = (id_hash ^ x) % slots_count;

		return slots[idx];
	}
	static std::array<parking_lot_slot, slots_count> slots;
};

}

template <typename Key, typename NodeData = void>
class parking_lot {
	using node_t = parking_lot_detail::parking_lot_node<NodeData>;
	using park_return_t = std::conditional_t<
		!std::is_void_v<NodeData>,
		std::pair<parking_lot_wait_state, std::optional<NodeData>>,
		std::pair<parking_lot_wait_state, std::optional<int>>
	>;

private:
	template <typename PostPark, typename Clock, typename Duration>
	park_return_t wait(parking_lot_detail::parking_lot_slot &park,
					   node_t &node,
					   PostPark &&post_park,
					   const std::chrono::time_point<Clock, Duration> &until) {
		// Park
		auto wait_result = node.wait_until(until);
		post_park();

		// Unregister node if wait has not been performed or timed-out,
		// Otherwise the signaling thread will do the unregistering, this avoids a deadlock on the park mutex.
		if (!wait_result.first || wait_result.second == parking_lot_wait_state::timeout) {
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> ul(park.m);

			// Recheck signaled state under lock
			if (!node.is_signalled()) {
				park.erase(&node);
				return { wait_result.second, std::nullopt };
			}

			// Node has been signaled
			wait_result.second = parking_lot_wait_state::signaled;
		}

		// We have been signaled, extract stored data, if any.
		auto data = std::move(node).retrieve_data();

		return { wait_result.second, std::move(data) };
	}

public:
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*.
	 *  
	 *  @param	park_predicate	Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if park_predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or park_predicate might be triggered.
	 *							Called while holding slot lock.
	 */
	template <typename ParkPredicate, typename OnPark>
	park_return_t park(ParkPredicate &&park_predicate,
					   OnPark &&on_park,
					   Key &&key) {
		return park(std::forward<ParkPredicate>(park_predicate),
					std::forward<OnPark>(on_park),
					[]() {},
					std::move(key));
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*.
	 *  
	 *  @param	park_predicate	Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if park_predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or park_predicate might be triggered.
	 *							Called while holding slot lock.
	 *	@param	post_park		Closure that will be called immediately after parking, irregardless of parking termination reason.
	 *							Call not guarded by a lock.
	 */
	template <typename ParkPredicate, typename OnPark, typename PostPark>
	park_return_t park(ParkPredicate &&park_predicate,
					   OnPark &&on_park,
					   PostPark &&post_park,
					   Key &&key) {
		return park_until(std::forward<ParkPredicate>(park_predicate),
						  std::forward<OnPark>(on_park),
						  std::forward<PostPark>(post_park),
						  std::move(key),
						  std::chrono::steady_clock::time_point::max());
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*
	 *			or timeout has expired.
	 *  
	 *  @param	park_predicate	Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if park_predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or park_predicate might be triggered.
	 *							Called while holding slot lock.
	*/
	template <typename ParkPredicate, typename OnPark, typename PostPark, typename Clock, typename Duration>
	park_return_t park_until(ParkPredicate &&park_predicate,
							 OnPark &&on_park,
							 Key &&key,
							 const std::chrono::time_point<Clock, Duration> &until) {
		return park_until(std::forward<ParkPredicate>(park_predicate),
						  std::forward<OnPark>(on_park),
						  []() {},
						  std::move(key),
						  until);
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*
	 *			or timeout has expired.
	 *  
	 *  @param	park_predicate	Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if park_predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or park_predicate might be triggered.
	 *							Called while holding slot lock.
	 *	@param	post_park		Closure that will be called immediately after parking, irregardless of parking termination reason.
	 *							Call not guarded by a lock.
	*/
	template <typename ParkPredicate, typename OnPark, typename PostPark, typename Clock, typename Duration>
	park_return_t park_until(ParkPredicate &&park_predicate,
							 OnPark &&on_park,
							 PostPark &&post_park,
							 Key &&key,
							 const std::chrono::time_point<Clock, Duration> &until) {
		// Create new node
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(this, key);
		node_t node(this, std::move(key));

		// Register node
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);

			// Call on_park closure under lock
			on_park();
			
			// Check if we still need to park, this is needed as the signaling condition is not guarded by the local mutex, creating 
			// a race against the cv.
			if (park_predicate())
				return { parking_lot_wait_state::park_validation_failed, std::nullopt };

			// Finally add node to slot and forward the predicate to the node
			park.push_back(&node);
			node.set_predicate(std::forward<ParkPredicate>(park_predicate));
		}

		// Park
		return wait(park,
					node,
					std::forward<PostPark>(post_park),
					until);
	}

	/*
	 *	@brief	Attempts to unpark a single node using args, which will be used to construct a NodeData object that
	 *			will be passed to the signaled thread.
	 *			
	 *	@return	Number of nodes that were signaled
	 */
	template <typename... Args>
	std::size_t unpark_one(const Key &key, Args&&... args) {
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(this, key);

		// Unpark one
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);
			
			for (auto node = park.head; node; ) {
				// Signalling might destroy the node once wait_until() goes out of scope, take a copy of next.
				auto next = node->next;

				if (node->id_equals(this, key)) {
					assert(!node->is_signalled());

					park.erase(node);
					if (!static_cast<node_t*>(node)->signal(std::forward<Args>(args)...))
						continue;

					return 1;
				}

				node = next;
			}
		}

		return 0;
	}

	/*
	 *	@brief	Attempts to unpark all nodes using args, which will be used to construct a NodeData object that will be passed to the 
	 *			signaled thread.
	 *			
	 *	@return	Number of nodes that were signaled
	 */
	template <typename... Args>
	std::size_t unpark_all(const Key &key, const Args&... args) {
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(this, key);
		std::size_t count = 0;

		// Unpark all
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);

			for (auto node = park.head; node; ) {
				// Signalling might destroy the node once wait_until() goes out of scope, take a copy of next.
				auto next = node->next;

				if (node->id_equals(this, key)) {
					assert(!node->is_signalled());

					// Erase from dlist, and unpark.
					park.erase(node);
					if constexpr (!std::is_void_v<NodeData>) {
						if (!static_cast<node_t*>(node)->signal(NodeData(args...)))
							continue;
					}
					else {
						if (!static_cast<node_t*>(node)->signal())
							continue;
					}

					++count;
				}

				node = next;
			}
		}

		return count;
	}

	/*
	 *	@brief	Attempts to unpark a single node using args. If a node to unpark is found, invokes f and if f returns true will unpark one node
	 *			similar to unpark_one().
	 *			
	 *	@return	Number of nodes that were signaled
	 */
	template <typename F, typename... Args>
	std::size_t try_unpark_one(const Key &key, F&& f, Args&&... args) {
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(this, key);

		// Unpark one
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);
			
			for (auto node = park.head; node; ) {
				// Signalling might destroy the node once wait_until() goes out of scope, take a copy of next.
				auto next = node->next;

				if (node->id_equals(this, key)) {
					assert(!node->is_signalled());

					if (!f(1))
						return 0;

					park.erase(node);
					if (!static_cast<node_t*>(node)->signal(std::forward<Args>(args)...))
						continue;

					return 1;
				}

				node = next;
			}
		}

		return 0;
	}

	/*
	 *	@brief	Checks atomically if the parking slot is empty
	 */
	bool is_slot_empty_hint(const Key &key, std::memory_order mo = std::memory_order_relaxed) const noexcept {
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(this, key);

		std::atomic_thread_fence(mo);
		return park.tail == nullptr;
	}
};

}
