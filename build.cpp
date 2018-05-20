// shared_futex_build.cpp
// © Shlomi Steinberg, 2015-2018
//
// Build test for shared_futex

#include "shared_futex/shared_futex.hpp"

template <typename F>
void test_futex(F&& f) noexcept {
	using namespace ste;
	using namespace shared_futex_policies;
	
	{
		auto l = make_exclusive_lock<exponential_backoff_policy>(f);
	}
	{
		auto l = make_shared_lock<exponential_backoff_policy>(f);
	}
	{
		auto l = make_upgradeable_lock<exponential_backoff_policy>(f);
		auto up = upgrade_lock<exponential_backoff_policy>(std::move(l));
	}
	
	{
		auto l = make_exclusive_lock<relaxed_backoff_policy>(f);
	}
	{
		auto l = make_exclusive_lock<spinlock_backoff_policy>(f);
	}
}

void test() noexcept {}
template <typename F, typename... Fs>
void test(F&& f, Fs&&... fs) noexcept {
	test_futex(std::forward<F>(f));
	test(std::forward<Fs>(fs)...);
}

int main() {
	ste::shared_futex f;
	ste::shared_futex_micro fmicro;
	ste::shared_futex_micro_hle fmicro_hle;
	ste::shared_futex_pico fpico;
	ste::shared_futex_concurrent fconcurrent;
	ste::shared_futex_tsx_hle fhle;
	ste::shared_futex_tsx_rtm frtm;

	test(f, fmicro, fmicro_hle, fpico, fconcurrent, fhle, frtm);

	return 0;
}