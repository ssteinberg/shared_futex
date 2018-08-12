### shared_futex 

___
[![Build status](https://ci.appveyor.com/api/projects/status/k8gjxssiq86i98ld?svg=true)](https://ci.appveyor.com/project/ssteinberg89928/shared-futex)

Fast, shared, upgradeable, non-recursive and non-fair mutex with support for x86 
hardware lock elision via Transactional Synchronization Extensions (TSX). 
Written in modern cross-platform c++17.<br/>
In active development.

#### Usage
`shared_futex` encourages a safe RAII interface.

```C++
// Lock futex in exclusive access mode
auto lock_guard = make_exclusive_lock(f);
// ...
// f will be unlocked as lock_guard goes out of scope
```

Similiarly `shared_futex` can be locked for shared access.
While exclusive locks are mutually exclusive with all other
holders, mutiple shared holders are allowed to access the guarded critical
section simultaneously.

```C++
// Lock futex in shared access mode
auto lock_guard = make_shared_lock(f);
// ...
```

`shared_futex` can also be locked in _upgradeable_ mode, which
allows later to upgrade the lock to an exclusive lock. 
Upgradeable holders are mutually exclusive with other upgradeable
and exclusive locks but not with shared holders. <br/>
This invariant allows concurrency between shared and upgradeable 
lockers and, more importantly, ensures that the state of a 
guarded resource does not change between the upgradeable 
acquisition and the upgrade to an exclusive lock.

```C++
// Lock futex in shared-upgradeable access mode
auto upgradeable_guard = make_upgradeable_lock(f);
// Find resource x to update...
// (only shared holders are permitted now)
auto exclusive_guard = upgrade_lock(std::move(upgradeable_guard));
// Update x
```

In addition, Lock acquisitions attempts can be made with a given time-out.
```C++
// Try lock until
const auto now = std::chrono::high_resolution_clock::now();
auto l = make_shared_lock(f, now + std::chrono::nanoseconds(100));
if (l) { /* lock acquired */ }
```
```C++
// Try lock for
auto l = make_shared_lock(f, std::chrono::nanoseconds(100));

```

Or in a non-blocking manner via `std::try_to_lock`

```C++
// Try lock
auto l = make_exclusive_lock(f, std::try_to_lock);
if (l) { /* lock acquired */ }
```

Lock guards can also be manipulated manually.

```C++
auto l = make_exclusive_lock(f, std::defer_lock); // Does not lock
if (l.try_lock()) {
	l.unlock();
}
if (l.try_lock_for(std::chrono::milliseconds(1))) {
	l.unlock();
}
const auto now = std::chrono::steady_clock::now();
if (l.try_lock_until(now + std::chrono::milliseconds(1))) {
	l.unlock();
}
l.lock();
l.unlock();
```

Lock guards meet the requirements of 
[BasicLockable](https://en.cppreference.com/w/cpp/concept/BasicLockable),
[Lockable](https://en.cppreference.com/w/cpp/concept/Lockable)
and 
[TimedLockable](https://en.cppreference.com/w/cpp/concept/TimedLockable)
therefore can be used in conjunction with standard library
utilities.<br/>
E.g. avoiding deadlocks when locking multiple mutexes can be done
via the standard library's `std::lock`.

```C++
shared_futex f0;
shared_futex f1;
std::mutex m;

// Defer lock
auto l0 = make_exclusive_lock(f0, std::defer_lock);
auto l1 = make_shared_lock(f1, std::defer_lock);
std::unique_lock<std::mutex> l2(m, std::defer_lock);
// Lock multiple locks with deadlock avoidence
std::lock(l0, l1, l2);
```

Likewise lock guards are 
[default constructible](https://en.cppreference.com/w/cpp/concept/DefaultConstructible)
and also meet the requirements of 
[MoveConstructible](https://en.cppreference.com/w/cpp/concept/MoveConstructible) 
and 
[MoveAssignable](https://en.cppreference.com/w/cpp/concept/MoveAssignable)
but not of 
[CopyConstructible](https://en.cppreference.com/w/cpp/concept/CopyConstructible)
or 
[CopyAssignable](https://en.cppreference.com/w/cpp/concept/CopyAssignable). 
Therefore lock guards can be safely moved around, swapped and empty assigned
via empty brace initialization.

```C++
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
```

Locks can also be adopted.
```C++
// Drop lock
auto l0 = make_exclusive_lock(f);
auto&& lock_object = std::move(l0).drop();

// And adopt lock
auto l1 = make_exclusive_lock(f, std::move(lock_object));
assert(!l0.owns_lock() && l1.owns_lock());

// Dropping and not adopting the lock will trigger an assert
```

`shared_futex` default constructor is `constexpr` therefore a `shared_futex`
is statically initialized making it safe to lock a mutex in the 
constructor of any static or global object.<br/>
See [c++ initialization order of non-local variables](http://en.cppreference.com/w/cpp/language/initialization#Non-local_variables).

#### Backoff policies

When an intial lock attempt fails the locking protocol keeps
retrying until either a timeout has been reached or lock was
successfully acquired. Between iterations a backoff policy
is executed. The backoff policy can spin, yield or park the 
thread.

Three backoff policies are provided:
1. ``exponential_backoff_policy`` - This is the default 
policy and generally provides a good balance between resource 
usages and latency, leading to best overall performance. The policy 
initally spins with linearly increasing spin count, and 
after a variable amount of spin iterations yields and then 
parks the thread. <br/>
Each spin iteration has a randomness injected into the calculated
spin count to break cross-thread symmetry.
2. ``relaxed_backoff_policy`` - Avoids spinning. Yields 
for a few iterations the then parks the thread. Useful when
the caller knows that there is contention, otherwise will 
perform poorly due to unnecessary contex switches.
3. ``spinlock_backoff_policy`` - Never parks and employs
aggressive spin tactic. Randomness is injected as well to 
break cross-thread symmetries.

Custom backoff-policies are simple to create. For examples
see ``shared_futex_policies.hpp``.

A policy can be selected via a template parameter
```
// Spin-lock
auto l = make_shared_lock<relaxed_backoff_policy>(f);
```
It is allowed to use distinct backoff policies with one `shared_futex`,
e.g. a system might want to employ spin-locking to minimize 
latency on one thread (for a variety of reasons) while on 
another thread use the default backoff policy.

#### Specialized variants

`shared_futex` comes in a few variations which are suitable
for different tasks.

* `shared_futex_micro` - Small 32-bit variant with very low 
overhead. Performs very well at the typical low contention 
environment with small critical sections typically encountered 
at general client-side applications.
* `shared_futex` - Large 128-byte variant. Aligned and does not 
share cachelines with local data. Provides additional machinery
and bookkeeping to improve performance under contention at the
expense of additional overhead.
* `shared_futex_pico` - Tiny 8-bit variant. Slightly slower
than the `micro` variant. **Limited** to 2^6 concurrent shared
holders, overflows result in undefined behaviour. Useful when
embedding locks into slots, nodes, etc..
* `shared_futex_concurrent` - Large 1-kbyte variant that employs
multiple slots on distinct cache lines to allow true concurrency
under heavy shared contention. Can vastly outperform other locks
under very high shared-to-exclusive workloads.<br/>
Extra slots are only employed when concurrency is detected.
* `shared_futex_hle`/`shared_futex_micro_hle` - 
Similar to `shared_futex` and `shared_futex_micro`, respectively, 
except also employs hardware lock elision (TSX HLE) on supported x86-64
systems. Can greatly increase performance in specific circumstances.
* `shared_futex_tsx_rtm` - **Experimental** variant that performs hardware
lock elision explcitly via transactional memory. 

#### Condition variables

`condition_variable` is designed to replace `std::condition_variable` when
working with a `shared_futex`.

```C++
condition_variable cv;
// Wait upon cv
auto lg = make_lock_when<shared_futex_lock_class::exclusive>(f, cv);
```
This will park until `cv` is signalled at which point the 
lock will be acquired in exclusive mode and a `lock_guard` returned. 

A predicate can also be supplied:
```C++
auto lg = make_lock_when<shared_futex_lock_class::shared>(f, cv,
	[]() noexcept -> bool { ... });
```
This form checks the predicate, and if the predicate
is unsatisfied, parks the calling thread in one atomic operation.
Upon signalling the lock will acquired and the predicate checked
again.

The above forms can also be used with a time-out:
```C++
auto lg = make_lock_when<shared_futex_lock_class::shared>(f, cv,
	std::chrono::seconds(10));
```
```C++
const auto now = std::chrono::steady_clock::now();
auto lg = make_lock_when<shared_futex_lock_class::shared>(f, cv,
	now + std::chrono::seconds(10));
```
```C++
auto lg = make_lock_when<shared_futex_lock_class::shared>(f, cv,
	[]() noexcept -> bool { ... },
	std::chrono::millisecond(500));
```
```C++
const auto now = std::chrono::steady_clock::now();
auto lg = make_lock_when<shared_futex_lock_class::shared>(f, cv,
	[]() noexcept -> bool { ... },
	now + std::chrono::millisecond(500));
```

The `condition_variable` can also be waited upon explicitly inside 
a critical section:
```C++
auto lg = make_exclusive_lock(f);
const auto predicate = []() noexcept -> bool { ... };
while (!pred())
	cv.wait(lg);
```
Which is functionally equivalent to 
`cv.wait(lg, predicate)`. In addition a timeout can
be provided via `wait_for()` and `wait_until()`. The 
`cv.wait*()` overloads return a `parking_lot_wait_state` indicating
wait result.

Signalling is performed explicitly by calling a `condition_variable`'s
`signal()` or `signal_n()`, where the later variant sets an upper limit
on the total signalled thread count. It is important to remember that 
unlike `std::condition_variable`, both forms **will always unpark up to
a single exclusive waiter or up to a single upgradeable waiter and 
multiple shared waiters**. 

```C++
auto lg = make_exclusive_lock(f);
const auto unparked_count = cv.signal(std::move(lg));
```
```C++
auto lg = make_exclusive_lock(f);
const auto unparked_count = cv.signal_n(3, std::move(lg));
assert(unparked_count <= 3);
```
Calling `signal*()` consumes the lock and releases it.

Unparks and contex-switched are expensive, therefore if a predicate
is supplied to `wait*()` the `condition_vartiable` will check 
the unpark candidates' predicates **before** unparking. This is done
while holding the lock supplied to `signal*`. It is important to
remember that the lock classes supplied to `wait*()` and `signal*()`
operations can be non-mutually exclusive which might result in
a concurrent access to a predicate. It is the user responsibility to
ensure the predicate's safety in such circumstances.

#### Type traits

A few type traits are provided in `shared_futex_type_traits.hpp`.

* Checks if T is a `shared_futex` variant:
```C++
template <typename T> struct is_shared_futex_type;
template <typename T> inline constexpr bool is_shared_futex_type_v;
```

* Checks if T is a `shared_futex` variant that supports parking:
```C++
template <typename T> struct is_shared_futex_parkable;
template <typename T> inline constexpr bool is_shared_futex_parkable_v;
```

* Provides the lock class (see `shared_futex_lock_class`) of a `lock_guard`:
```C++
template <typename T> struct lock_class;
template <typename T> inline constexpr shared_futex_lock_class lock_class_v;
```


#### Hardware lock elision

Hardware lock elision is performed via the Transactional Synchronization Extensions (TSX)
on modern x86-64 architectures.
(For more information on TSX, see 
[Intel� 64 and IA-32 Architectures Software Developer�s Manual, Volume 1](https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-1-manual.html).)


The `shared_futex*_hle` variants use the *`xacquire`*/*`xrelease`* x86
prefix hints for atomic operations to elide locks, when possible. 
This is backward compatible: On unsupported hardware the prefixes 
are harmlessly translated to *`REPNE`*/*`REPNZ`* and
*`REP`*/*`REPE`*/*`REPZ`* (repsectively) which have no side effects
on the used instructions. <br/>
Lock elision works by eliding the lock acquisition and optimistically 
executing the critical section as a memory transaction. The
transaction can be aborted due to cache line conflict (e.g. 
another consumer touched the same cache line), TSX capacity and other
reasons. In case of abort the execution is rolled back to the
lock acquisition instruction and retried without lock elision.<br/>
Excessive aborts degrade performance therefore `shared_futex`
variants that employ HLE are mostly suited for specific tasks, 
e.g. sparsely updating a vector.


`*_rtm` variants are experimental. Transactions are triggered
explicitly via *`xbeing`*/*`xend`* instructions, which are not
backward compatible. It is the users responsibility to ensure
their target system supports TSX RTM. Transactions can be 
explictly aborted inside a critical section falling back to 
non-elided lock acquisition. See `transactional_memory` namespace.
