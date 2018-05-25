// shared_futex
// © Shlomi Steinberg, 2015-2018

#pragma once

#include "../utils/hash_combine.hpp"

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

	std::function<bool()> predicate;
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
	 *	@brief	Attempts to signal node.
	 */
	void signal() noexcept {
		std::unique_lock<mutex_t> ul(m);

		signaled = true;
		cv.notify_one();
	}

public:
	template <typename UID, typename K>
	parking_lot_node_base(const UID &id, K &&key) noexcept {
		using T = std::decay_t<K>;
		
		static_assert(std::is_trivial_v<std::decay_t<UID>>, "UID must be trivial");
		static_assert(sizeof(UID) <= sizeof(decltype(tag.id)), "UID must be the size of a pointer or less");
		static_assert(std::is_trivially_destructible_v<T>, "key must be trivially destructible");
		static_assert(std::is_trivially_copy_constructible_v<T> || !std::is_lvalue_reference_v<K&&>,
					  "key must be trivially copy constructible when taking an l-value");
		static_assert(std::is_trivially_move_constructible_v<T> || !std::is_rvalue_reference_v<K&&>,
					  "key must be trivially move constructible when taking an r-value");
		static_assert(sizeof(T) <= key_size, "key must be no larger than key_size");

		*reinterpret_cast<UID*>(&tag.id) = id;
		::new (&tag.key) T(std::forward<K>(key));
	}
	virtual ~parking_lot_node_base() noexcept = default;
	
	parking_lot_node_base(parking_lot_node_base&&) = delete;
	parking_lot_node_base(const parking_lot_node_base&) = delete;
	parking_lot_node_base &operator=(parking_lot_node_base&&) = delete;
	parking_lot_node_base &operator=(const parking_lot_node_base&) = delete;

	template <typename Pred>
	void set_predicate(Pred&& pred) noexcept {
		predicate = std::forward<Pred>(pred);
	}
	bool check_predicate() const noexcept {
		return predicate && predicate();
	}

	/*
	 *	@brief	Checks if the serialized tag equals to the supplied id and key.
	 *			K should be the same type as passed to the ctor.
	 */
	template <typename UID, typename K>
	bool id_equals(const UID &id, const K &key) const noexcept {
		static_assert(sizeof(UID) <= sizeof(decltype(tag.id)), "UID must be the size of a pointer or less");
		static_assert(sizeof(K) <= key_size, "key must be no larger than key_size");

		return *reinterpret_cast<const UID*>(&tag.id) == id && *reinterpret_cast<const K*>(&tag.key) == key;
	}
	bool is_signalled() const noexcept { return signaled; }

	/*
	 *	@brief	Parks
	 *	@return	Wait-performed boolean and the wait state as a pair.
	 */
	template <typename Clock, typename Duration>
	[[nodiscard]] std::pair<bool, parking_lot_wait_state> wait_until(const std::chrono::time_point<Clock, Duration> &until) noexcept {
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
	*/
	template <typename... Args>
	void signal(Args&&... args) noexcept {
		data.emplace(std::forward<Args>(args)...);
		parking_lot_node_base::signal();
	}
	/*
	*	@brief	Extracts the stored data object
	*/
	[[nodiscard]] Data&& retrieve_data() && noexcept { return std::move(data).value(); }
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
	constexpr parking_lot_slot() noexcept = default;

	static constexpr auto slots_count = 2048;

	/*
	*	@brief	Returns a static parking lot slot for a given id/key pair.
	*			See parking_lot_node_base::parking_lot_node_base(K&&).
	*/
	template <typename UID, typename K>
	static parking_lot_slot& slot_for(const UID &id, const K &key) noexcept {
		auto x = std::hash<std::decay_t<K>>{}(key);
		hash_combine<std::decay_t<UID>>{}(x, id);

		return slots[x % slots_count];
	}
	static std::array<parking_lot_slot, slots_count> slots;
};

}

template <typename Key, typename NodeData = void>
class parking_lot {
	using park_return_t = std::conditional_t<
		!std::is_void_v<NodeData>,
		std::pair<parking_lot_wait_state, std::optional<NodeData>>,
		std::pair<parking_lot_wait_state, std::optional<int>>
	>;
	using uid_t = std::uint64_t;

	static constexpr uid_t unused_uid = {};

public:
	using node_t = parking_lot_detail::parking_lot_node<NodeData>;

private:
	uid_t lot_tag{ unused_uid };

private:
	template <typename PostPark, typename Clock, typename Duration>
	park_return_t wait(parking_lot_detail::parking_lot_slot &park,
					   node_t &node,
					   PostPark &&post_park,
					   const std::chrono::time_point<Clock, Duration> &until) noexcept {
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
	
	static std::atomic<uid_t> uid_gen;
	// Generates a UID for a parking lot using global atomic variable
	static uid_t generate_uid() noexcept {
		const uid_t uid = uid_gen++;
		if (uid != unused_uid)
			return uid;
		return uid_gen++;
	}

public:
	constexpr parking_lot() noexcept : lot_tag(generate_uid()) {}
	~parking_lot() noexcept = default;
	parking_lot(parking_lot &&o) noexcept : lot_tag(std::move(o.lot_tag)) {
		o.lot_tag = unused_uid;
	}
	parking_lot &operator=(parking_lot &&o) noexcept {
		lot_tag = std::move(o.lot_tag);
		o.lot_tag = unused_uid;
		return *this;
	}
	parking_lot(const parking_lot &o) = delete;
	parking_lot &operator=(const parking_lot &o) = delete;

	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*.
	 *  
	 *  @param	predicate		Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	 */
	template <typename Predicate, typename OnPark>
	park_return_t park(Predicate &&predicate,
					   OnPark &&on_park,
					   Key &&key) noexcept {
		return park(std::forward<Predicate>(predicate),
					std::forward<OnPark>(on_park),
					[]() {},
					std::move(key));
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*.
	 *  
	 *  @param	predicate		Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	 *	@param	post_park		Closure that will be called immediately after parking, irregardless of parking termination reason.
	 *							Call not guarded by a lock.
	 */
	template <typename Predicate, typename OnPark, typename PostPark>
	park_return_t park(Predicate &&predicate,
					   OnPark &&on_park,
					   PostPark &&post_park,
					   Key &&key) noexcept {
		return park_until(std::forward<Predicate>(predicate),
						  std::forward<OnPark>(on_park),
						  std::forward<PostPark>(post_park),
						  std::move(key),
						  std::chrono::steady_clock::time_point::max());
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*
	 *			or timeout has expired.
	 *  
	 *  @param	predicate		Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	*/
	template <typename Predicate, typename OnPark, typename PostPark, typename Clock, typename Duration>
	park_return_t park_until(Predicate &&predicate,
							 OnPark &&on_park,
							 Key &&key,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return park_until(std::forward<Predicate>(predicate),
						  std::forward<OnPark>(on_park),
						  []() {},
						  std::move(key),
						  until);
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*
	 *			or timeout has expired.
	 *  
	 *  @param	predicate		Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if predicate returns true.
	 *							Called while holding slot lock.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	 *	@param	post_park		Closure that will be called immediately after parking, irregardless of parking termination reason.
	 *							Call not guarded by a lock.
	*/
	template <typename Predicate, typename OnPark, typename PostPark, typename Clock, typename Duration>
	park_return_t park_until(Predicate &&predicate,
							 OnPark &&on_park,
							 PostPark &&post_park,
							 Key &&key,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);

		// Create new node
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);
		node_t node(lot_tag, std::move(key));

		// Register node
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);

			// Call on_park closure under lock
			on_park();
			
			// Check if we still need to park, this is needed as the signaling condition is not guarded by the local mutex, creating 
			// a race against the cv.
			if (predicate())
				return { parking_lot_wait_state::park_validation_failed, std::nullopt };

			// Finally add node to slot and forward the predicate to the node
			park.push_back(&node);
			node.set_predicate(std::forward<Predicate>(predicate));
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
	std::size_t unpark_one(const Key &key, Args&&... args) const noexcept {
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);

		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);

		// Unpark one
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);
			
			// Signalling might destroy the node once wait_until() goes out of scope, take a copy of next each iteration.
			auto node = park.head;
			for (decltype(node) next = node ? node->next : nullptr; 
				 node; 
				 node = next, next = node ? node->next : nullptr) {
				if (node->id_equals(lot_tag, key)) {
					assert(!node->is_signalled());
					auto n = static_cast<node_t*>(node);

					if (!n->check_predicate())
						continue;

					park.erase(node);
					n->signal(std::forward<Args>(args)...);

					return 1;
				}
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
	std::size_t unpark_all(const Key &key, const Args&... args) const noexcept {
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);

		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);
		std::size_t count = 0;

		// Unpark all
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);
			
			// Signalling might destroy the node once wait_until() goes out of scope, take a copy of next each iteration.
			auto node = park.head;
			for (decltype(node) next = node ? node->next : nullptr; 
				 node; 
				 node = next, next = node ? node->next : nullptr) {
				if (node->id_equals(lot_tag, key)) {
					assert(!node->is_signalled());
					auto n = static_cast<node_t*>(node);

					if (!n->check_predicate())
						continue;
					
					// Erase from dlist, and unpark.
					park.erase(node);
					n->signal(args...);

					++count;
				}
			}
		}

		return count;
	}
};

template <typename Key, typename NodeData>
std::atomic<typename parking_lot<Key, NodeData>::uid_t> parking_lot<Key, NodeData>::uid_gen;

}
