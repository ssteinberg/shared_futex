// shared_futex
// � Shlomi Steinberg, 2015-2018

#pragma once

#include <condition_variable>
#include <mutex>
#include <atomic>

#include <optional>
#include <array>
#include <vector>

#include <type_traits>
#include <functional>
#include <limits>
#include <hash_combine.hpp>

#include <cassert>

namespace strt {

enum class parking_lot_wait_state {
	// Signaled and returned successfully
	signalled,
	// Predicate was triggered before parking
	predicate,
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

	bool signalled{ false };

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

		signalled = true;
		cv.notify_one();
	}

public:
	template <typename UID, typename K, typename Pred>
	parking_lot_node_base(const UID &id, K &&key, Pred&& pred) noexcept : predicate(std::forward<Pred>(pred)) {
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
	template <typename UID, typename K>
	parking_lot_node_base(const UID &id, K &&key) noexcept 
		: parking_lot_node_base(id, std::forward<K>(key), std::function<bool()>{}) {}
	virtual ~parking_lot_node_base() noexcept = default;
	
	parking_lot_node_base(parking_lot_node_base&&) = delete;
	parking_lot_node_base(const parking_lot_node_base&) = delete;
	parking_lot_node_base &operator=(parking_lot_node_base&&) = delete;
	parking_lot_node_base &operator=(const parking_lot_node_base&) = delete;

	bool check_predicate() const noexcept {
		return !predicate || predicate();
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
	bool is_signalled() const noexcept { return signalled; }

	/*
	 *	@brief	Parks
	 *	@return	Wait-performed boolean and the wait state as a pair.
	 */
	template <typename ParkPredicate, typename OnPark, typename Clock, typename Duration>
	[[nodiscard]] std::pair<bool, parking_lot_wait_state> wait_until(ParkPredicate&& predicate,
																	 OnPark&& on_park,
																	 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		const auto is_signalled = [&]() { return signalled; };

		std::atomic_thread_fence(std::memory_order_acquire);
		if (is_signalled())
			return { false, parking_lot_wait_state::signalled };

		{
			std::unique_lock<mutex_t> ul(m);

			// Call on_park closure under lock
			on_park();
			
			// Check if we still need to park, this is needed as the signalling condition is not guarded by the local mutex, creating 
			// a race against the cv.
			if (predicate())
				return { false, parking_lot_wait_state::predicate };

			// Park
			while(!is_signalled()) {
				if (until != std::chrono::time_point<Clock, Duration>::max()) {
					// On cv timeout always return a timeout result, even if the predicate is true at that stage.
					// This allows the parker to distinguish between signalled and unsignalled cases.
					if (cv.wait_until(ul, until) == std::cv_status::timeout)
						return { true, parking_lot_wait_state::timeout };
				}
				else {
					cv.wait(ul);
				}
			}

			return { true, parking_lot_wait_state::signalled };
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
	static constexpr auto alignment = 64;// std::hardware_destructive_interference_size;

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
		x = hash_combine{}(x, id);

		return slots[x % slots_count];
	}
	static std::array<parking_lot_slot, slots_count> slots;
};

}

template <typename Key, typename NodeData = void>
class parking_lot {
private:
	using uid_t = std::uint64_t;
	static constexpr uid_t unused_uid = {};

public:
	using node_t = parking_lot_detail::parking_lot_node<NodeData>;
	using park_return_t = std::conditional_t<
		!std::is_void_v<NodeData>,
		std::pair<parking_lot_wait_state, std::optional<NodeData>>,
		std::pair<parking_lot_wait_state, std::optional<int>>
	>;

	// Nodes extracted from the parking lot via extract_n().
	class extracted_nodes {
		friend class parking_lot;

		std::vector<node_t*> nodes;
		
		extracted_nodes(std::vector<node_t*> &&nodes) noexcept : nodes(std::move(nodes)) {}

	public:
		extracted_nodes(extracted_nodes&&) noexcept = default;
		extracted_nodes &operator=(extracted_nodes&&) noexcept = default;
		extracted_nodes(const extracted_nodes&) noexcept = delete;
		extracted_nodes &operator=(const extracted_nodes&) noexcept = delete;
		~extracted_nodes() noexcept { assert(!nodes.size()); }

		/*
		 *	@brief	Signals all the nodes
		 */
		template <typename... Args>
		std::size_t signal(const Args&... args) && noexcept {
			for (auto &n : nodes)
				n->signal(args...);

			const auto size = nodes.size();
			nodes = {};
			return size;
		}

		auto size() const noexcept { return nodes.size(); }
	};

private:
	uid_t lot_tag{ unused_uid };

private:
	template <typename ParkPredicate, typename OnPark, typename PostPark, typename Clock, typename Duration>
	park_return_t wait(parking_lot_detail::parking_lot_slot &park,
					   node_t &node,
					   ParkPredicate&& predicate,
					   OnPark&& on_park,
					   PostPark&& post_park,
					   const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// Park
		const auto wait_result = node.wait_until(std::forward<ParkPredicate>(predicate),
												 std::forward<OnPark>(on_park),
												 until);
		// Execute post park closure
		post_park();

		const bool wait_performed = wait_result.first;
		auto state = wait_result.second;

		// Unregister node if wait has not been performed or timed-out,
		// Otherwise the signalling thread will do the unregistering, this avoids a deadlock on the park mutex.
		if (!wait_performed || state == parking_lot_wait_state::timeout) {
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> ul(park.m);

			// Recheck signalled state under lock
			if (!node.is_signalled()) {
				park.erase(&node);
				return { state, std::nullopt };
			}

			// Node has been signalled
			state = parking_lot_wait_state::signalled;
		}

		// We have been signalled, extract stored data, if any.
		auto data = std::move(node).retrieve_data();

		return { state, std::move(data) };
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
	 */
	park_return_t park(Key&& key) noexcept {
		return park([]() {},
					std::move(key));
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*.
	 *  
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	 */
	template <typename OnPark>
	park_return_t park(OnPark&& on_park,
					   Key&& key) noexcept {
		return park_until(std::forward<OnPark>(on_park),
						  []() {},
						  std::move(key),
						  std::chrono::steady_clock::time_point::max());
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*.
	 *  
	 *  @param	predicate		Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if predicate returns true.
	 *							Called while holding node lock, must be thread-safe.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	 */
	template <typename ParkPredicate, typename OnPark>
	park_return_t park(ParkPredicate&& predicate,
					   OnPark&& on_park,
					   Key&& key) noexcept {
		return park(std::forward<ParkPredicate>(predicate),
					std::forward<OnPark>(on_park),
					[]() {},
					std::move(key));
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*.
	 *  
	 *  @param	predicate		Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if predicate returns true.
	 *							Called while holding node lock, must be thread-safe.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	 *	@param	post_park		Closure that will be called immediately after parking, irregardless of parking termination reason.
	 *							Not guarded by lock, must be thread-safe.
	 */
	template <typename ParkPredicate, typename OnPark, typename PostPark>
	park_return_t park(ParkPredicate&& predicate,
					   OnPark&& on_park,
					   PostPark&& post_park,
					   Key&& key) noexcept {
		return park_until(std::forward<ParkPredicate>(predicate),
						  std::forward<OnPark>(on_park),
						  std::forward<PostPark>(post_park),
						  std::move(key),
						  std::chrono::steady_clock::time_point::max());
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*
	 *			or timeout has expired.
	*/
	template <typename Clock, typename Duration>
	park_return_t park_until(Key&& key,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return park_until(std::move(key),
						  []() {},
						  until);
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*
	 *			or timeout has expired.
	*/
	template <typename OnPark, typename Clock, typename Duration>
	park_return_t park_until(OnPark&& on_park,
							 Key&& key,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {{
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);

		// Create new node without a node predicate
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);
		node_t node(lot_tag, std::move(key));

		// Register node
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);
			park.push_back(&node);
		}

		// Park
		return wait(park,
					node,
					[]() { return false; },		// Predicate
					std::forward<OnPark>(on_park),
					[]() {},					// Post park closure
					until);
	}
	}
	/*
	 *  @brief	Attempts to park the calling thread in a parking slot selected via the supplied key until the thread is unparked via unpark_*
	 *			or timeout has expired.
	 *  
	 *  @param	predicate		Called after on_park and if it returns false thread is parked. When unparking the unparker checks the predicate
	 *							as well and only unparks if predicate returns true.
	 *							Called while holding node lock, must be thread-safe.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	*/
	template <typename ParkPredicate, typename OnPark, typename Clock, typename Duration>
	park_return_t park_until(ParkPredicate&& predicate,
							 OnPark&& on_park,
							 Key&& key,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		return park_until(std::forward<ParkPredicate>(predicate),
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
	 *							Called while holding node lock, must be thread-safe.
	 *	@param	on_park			Closure that will be called just before attempting to park. on_park being called does not mean that parking is
	 *							going to be actually performed, as signalling, timeout or predicate might be triggered.
	 *							Called while holding slot lock.
	 *	@param	post_park		Closure that will be called immediately after parking, irregardless of parking termination reason.
	 *							Not guarded by lock, must be thread-safe.
	*/
	template <typename ParkPredicate, typename OnPark, typename PostPark, typename Clock, typename Duration>
	park_return_t park_until(ParkPredicate&& predicate,
							 OnPark&& on_park,
							 PostPark&& post_park,
							 Key&& key,
							 const std::chrono::time_point<Clock, Duration> &until) noexcept {
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);

		// Create new node and set the node predicate
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);
		node_t node(lot_tag, std::move(key), predicate);	// Do not move predicate, we will need it later when for wait().

		// Register node
		{
			std::unique_lock<parking_lot_detail::parking_lot_slot::mutex_t> bucket_lock(park.m);
			park.push_back(&node);
		}

		// Park
		return wait(park,
					node,
					std::forward<ParkPredicate>(predicate),
					std::forward<OnPark>(on_park),
					std::forward<PostPark>(post_park),
					until);
	}
	
	/*
	 *	@brief	Attempts to extract up to count nodes from a parking_slot referenced by key.
	 *			The exracted nodes are to be signalled by calling signal(). It is an error to discard the nodes without signalling.
	 *			
	 *	@return	Extracted nodes
	 */
	[[nodiscard]] extracted_nodes extract_n(const std::size_t count, const Key &key) noexcept {
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);

		std::vector<node_t*> nodes;
		nodes.reserve(32);

		// Extract n
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

					// Only unpark nodes that satisfy their predicate
					if (!n->check_predicate())
						continue;

					park.erase(node);
					nodes.push_back(n);
					
					if (count != std::numeric_limits<std::size_t>::max() && nodes.size() == count)
						break;
				}
			}
		}

		return extracted_nodes{ std::move(nodes) };
	}

	/*
	 *	@brief	Attempts to unpark up to count nodes using args, which will be used to construct a NodeData object that
	 *			will be passed to the signalled thread.
	 *			
	 *	@return	Number of nodes that were signalled
	 */
	template <typename... Args>
	std::size_t unpark_n(const std::size_t count, const Key &key, const Args&... args) noexcept {
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);

		// Unpark n
		std::size_t unparked = 0;
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
					
					// Only unpark nodes that satisfy their predicate
					if (!n->check_predicate())
						continue;

					park.erase(node);
					// Signal
					n->signal(args...);

					if (count != std::numeric_limits<std::size_t>::max() && ++unparked == count)
						break;
				}
			}
		}

		return unparked;
	}

	/*
	 *	@brief	Attempts to unpark a single node using args, which will be used to construct a NodeData object that
	 *			will be passed to the signalled thread.
	 *			
	 *	@return	Number of nodes that were signalled
	 */
	template <typename... Args>
	std::size_t unpark_one(const Key &key, Args&&... args) noexcept {
		// This parking lot is no longer in use?
		assert(lot_tag != unused_uid);
		auto &park = parking_lot_detail::parking_lot_slot::slot_for(lot_tag, key);

		// Unpark n
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
					
					// Only unpark nodes that satisfy their predicate
					if (!n->check_predicate())
						continue;

					park.erase(node);
					// Signal
					n->signal(std::forward<Args>(args)...);

					return 1;
				}
			}
		}

		return 0;
	}

	/*
	 *	@brief	Attempts to unpark all nodes using args, which will be used to construct a NodeData object that will be passed to the 
	 *			signalled thread.
	 *			
	 *	@return	Number of nodes that were signalled
	 */
	template <typename... Args>
	std::size_t unpark_all(const Key &key, const Args&... args) noexcept {
		return unpark_n(std::numeric_limits<std::size_t>::max(), 
						key, 
						std::forward<Args>(args)...);
	}
};

template <typename Key, typename NodeData>
std::atomic<typename parking_lot<Key, NodeData>::uid_t> parking_lot<Key, NodeData>::uid_gen;

}
