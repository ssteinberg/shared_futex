// shared_futex_build.cpp
// © Shlomi Steinberg, 2015-2018
//
// Build test for shared_futex

#include "shared_futex/shared_futex.hpp"
#include "shared_futex/shared_futex_type_traits.hpp"
#include "condition_variable/condition_variable.hpp"

#include <atomic>
#include <thread>

struct global_class {
	global_class(ste::shared_futex &f) noexcept {
		// Lock mutex
		auto l = ste::make_exclusive_lock(f);
	}
};
static ste::shared_futex static_futex;
global_class global{ static_futex };

template <typename F>
void compile_futex(F&& f) noexcept {
	using namespace ste;
	using namespace shared_futex_policies;
	
	{
		// Lock exclusive
		auto l = make_exclusive_lock(f);
	}
	{
		// Lock exclusive
		auto l = make_lock<shared_futex_lock_class::exclusive>(f);
	}
	{
		// Lock shared
		auto l = make_shared_lock(f);
	}
	{
		// Lock upgradeable
		{
			auto l = make_upgradeable_lock(f);
			// Upgrade
			auto up = upgrade_lock(std::move(l));
		}
		{
			auto l = make_upgradeable_lock(f);
			// Upgrade with timeout
			auto up = try_upgrade_lock_until(std::move(l), std::chrono::steady_clock::now() + std::chrono::nanoseconds(1));
		}
		{
			auto l = make_upgradeable_lock(f);
			// Upgrade with timeout
			auto up = try_upgrade_lock_for(std::move(l), std::chrono::nanoseconds(1));
		}
	}
	
	{
		// Lock with custom policy
		auto l0 = make_shared_lock<relaxed_backoff_policy>(f);
		auto l1 = make_shared_lock<spinlock_backoff_policy>(f);
	}
	
	{
		// Defer lock
		auto l0 = make_shared_lock(f, std::defer_lock);
		auto l1 = make_shared_lock(f, std::defer_lock);
		// Lock multiple locks with deadlock avoidence
		std::lock(l0, l1);
	}

	{
		// Lock with timeout
		auto l0 = make_shared_lock(f, std::chrono::high_resolution_clock::now() + std::chrono::nanoseconds(100));	// Time point
		if (l0) {
			// Got lock
		}
		auto l1 = make_shared_lock(f, std::chrono::nanoseconds(100));	// Duration
	}

	{
		// Non blocking lock attempt
		auto l = make_exclusive_lock(f, std::try_to_lock);
		if (l) {
			// Got lock
		}
	}

	{
		// Manual locking
		auto l = make_exclusive_lock(f, std::defer_lock);
		if (l.try_lock()) {
			l.unlock();
		}
		if (l.try_lock_for(std::chrono::milliseconds(1))) {
			l.unlock();
		}
		if (l.try_lock_until(std::chrono::steady_clock::now() + std::chrono::milliseconds(1))) {
			l.unlock();
		}
		l.lock();
		l.unlock();
	}

	{
		// Drop lock
		auto l0 = make_exclusive_lock(f);
		auto&& lock_object = std::move(l0).drop();

		// And adopt lock
		auto l1 = make_exclusive_lock(f, std::move(lock_object));
		assert(!l0.owns_lock() && l1.owns_lock());

		// Dropping and not adopting the lock will trigger an assert
	}

	{
		// Swap
		auto l0 = make_exclusive_lock(f);
		auto l1 = make_exclusive_lock(f, std::defer_lock);

		std::swap(l0, l1);
		assert(!l0.owns_lock() && l1.owns_lock());

		l0.swap(l1);
		assert(l0.owns_lock() && !l1.owns_lock());

		// Move
		l1 = std::move(l0);
		assert(!l0.owns_lock() && l1.owns_lock());
		
		l1 = {};	// Will unlock
		assert(!l0.owns_lock() && !l1.owns_lock());
	}
	
	condition_variable cv;
	{
		std::atomic<bool> var = false;
		std::thread signalling_thread = std::thread([&]() {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));

			auto l = make_exclusive_lock(f);
			var = true;
			// Signal
			cv.signal(std::move(l));
		});

		// Acquire lock when predicate is true
		auto lg = make_lock_when<shared_futex_lock_class::exclusive>(f, cv, [&]() noexcept -> bool { return var.load(); });
		assert(lg);
		signalling_thread.join();
	}
	{
		std::atomic<bool> var = false;
		std::array<std::thread, 4> threads;
		for (auto &t : threads) {
			t = std::thread([&]() {
				// Wait upon cv and predicate with time-out
				auto lg = make_lock_when<shared_futex_lock_class::shared>(f, cv, [&]() noexcept -> bool { return var.load(); }, std::chrono::seconds(10));
				assert(lg);
			});
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		auto l = make_exclusive_lock(f);
		var = true;
		// Signal
		const auto signalled = cv.signal(std::move(l));
		assert(signalled == threads.size());
		
		for (auto &t : threads)
			t.join();
	}
	{
		// Wait upon a cv inside a critical section.
		auto lg = make_exclusive_lock(f);
		const auto wait_result = cv.wait(lg, []() noexcept -> bool { return true; });
		// No waiting will be performed, predicate will be triggered.
		assert(wait_result == parking_lot_wait_state::predicate);
		// cv.wait() always acquires lock.
		assert(lg);
	}

	// Type traits
	{
		auto l = make_exclusive_lock(f);
		constexpr auto c = lock_class_v<decltype(l)>;
		assert(c == shared_futex_lock_class::exclusive);

		constexpr auto is_shared_futex = is_shared_futex_type_v<std::decay_t<F>>;
		assert(is_shared_futex);
		constexpr auto is_parkable = is_shared_futex_parkable_v<std::decay_t<F>>;
	}
}

void compile() noexcept {}
template <typename F, typename... Fs>
void compile(F&& f, Fs&&... fs) noexcept {
	compile_futex(std::forward<F>(f));
	compile(std::forward<Fs>(fs)...);
}

int main() {
	ste::shared_futex f;
	ste::shared_futex_micro fmicro;
	ste::shared_futex_micro_hle fmicro_hle;
	ste::shared_futex_pico fpico;
	ste::shared_futex_concurrent fconcurrent;
	ste::shared_futex_hle fhle;
	ste::shared_futex_tsx_rtm frtm;

	// Test compilation
	compile(f, fmicro, fmicro_hle, fpico, fconcurrent, fhle, frtm);

	return 0;
}