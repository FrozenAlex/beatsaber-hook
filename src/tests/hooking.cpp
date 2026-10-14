#include "hooking.hpp"

#include "members.hpp"
#include "tests.hpp"

MAKE_HOOK(queue_test, ({"System.Collections", "Queue"}, "GetElement", true), void*, void* self, int i) {
    LOG_OK("Hook run, self -> {} | item -> {} | orig -> {}", fmt::ptr(self), i, queue_test(self, i));
    return reinterpret_cast<void*>(uintptr_t(5));
}

MAKE_HOOK(queue_minfo_test, ({"System.Collections", "Queue"}, "GetElement", true), void*, void* self, int i, MethodInfo* method) {
    LOG_OK("Hook with MethodInfo run, self -> {} | item -> {} | orig -> {}", fmt::ptr(self), i, queue_minfo_test(self, i, method));
    return reinterpret_cast<void*>(uintptr_t(10));
}

TEST(queue_hook) {
    LOG_OK("Starting hook test");

    try {
        auto queue = i2c::new_ctor({"System.Collections", "Queue"});
        LOG_OK("Created queue -> {}", fmt::ptr(queue));

        i2c::run_method(queue, "Enqueue", static_cast<Il2CppObject*>(nullptr));
        Il2CppObject* element = i2c::run_method<Il2CppObject*>(queue, "GetElement", 0);
        LOG_OK("Queue GetElement before hook -> {}", fmt::ptr(element));

        INSTALL_HOOK(i2c::logger, queue_test);
        LOG_OK("Hook installed");

        element = i2c::run_method<Il2CppObject*>(queue, "GetElement", 0);
        LOG_OK("Queue GetElement after hook install -> {}", fmt::ptr(element));

        UNINSTALL_HOOK(i2c::logger, queue_test);
        LOG_OK("Hook uninstalled");

        element = i2c::run_method<Il2CppObject*>(queue, "GetElement", 0);
        LOG_OK("Queue GetElement after hook uninstall -> {}", fmt::ptr(element));

        INSTALL_HOOK(i2c::logger, queue_minfo_test);
        LOG_OK("MethodInfo hook installed");

        element = i2c::run_method<Il2CppObject*>(queue, "GetElement", 0);
        LOG_OK("Queue GetElement after MethodInfo hook install -> {}", fmt::ptr(element));

        UNINSTALL_HOOK(i2c::logger, queue_minfo_test);
        LOG_OK("MethodInfo hook uninstalled");
    } catch (std::exception const& e) {
        LOG_FAIL("Error during hook test: {}", e.what());
        return;
    }

    LOG_OK("Hook test complete");
}

// Below only test for compilation

// Test match hook
static int foo(bool) {
    return 0;
}

template <>
struct i2c::metadata_getter<&foo> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};

MAKE_HOOK_MATCH(match_test, &foo, int, bool) {
    return 1;
}

MAKE_HOOK_MATCH(match_minfo_test, &foo, int, bool, MethodInfo*) {
    return 1;
}

MAKE_HOOK_MATCH(match_const_minfo_test, &foo, int, bool, MethodInfo const*) {
    return 1;
}

// Test exact overload selection, including the historical metadata key for noexcept functions.
static int bar(bool) noexcept {
    return 0;
}
static int bar(bool b, float) noexcept {
    return bar(b);
}

template <>
struct i2c::metadata_getter<static_cast<function_ptr_t<int, bool, float>>(&bar)> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 20;
    static constexpr uintptr_t addrs = 0x5678;
};

MAKE_HOOK_MATCH(match_overload_test, &bar, int, bool, float) {
    return 1;
}

// Test match hook with instance overloads
struct struct_a {
    int foo(int i) { return foo(i, false, i); }
    int foo(int, bool, int) { return 0; }
};

template <>
struct i2c::metadata_getter<static_cast<method_ptr_t<struct_a, int, int>>(&struct_a::foo)> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 60;
    static constexpr uintptr_t addrs = 0x999;
};

MAKE_HOOK_MATCH(match_inst_overload_test, &struct_a::foo, int, struct_a*, int) {
    return 1;
}

MAKE_HOOK_MATCH(match_inst_overload_minfo_test, &struct_a::foo, int, struct_a*, int, MethodInfo*) {
    return 1;
}

MAKE_HOOK_MATCH(match_inst_overload_const_minfo_test, &struct_a::foo, int, struct_a*, int, MethodInfo const*) {
    return 1;
}

// Test other hook constructions
MAKE_HOOK(test_addr_hook, (&foo), void, bool) {}
MAKE_HOOK(test_minfo_hook, (i2c::metadata_getter<&foo>::method_info()), void, int*) {}

static_assert(std::is_same_v<void*, std::invoke_result_t<decltype(hook_test_addr_hook::addr)>>);
static_assert(std::is_same_v<MethodInfo const*, std::invoke_result_t<decltype(hook_test_minfo_hook::addr)>>);

MAKE_HOOK(test_nullptr_hook, (nullptr), void, int*) {}

// Keep the target unqualified to also catch macro-local name shadowing.
static int target(bool value) noexcept {
    return value ? 1 : 0;
}

struct byref_hook_target {
    int readonly(by_ref<int const> value) { return *value; }
    int overload(by_ref<int>) { return 0; }
    int overload(by_ref<int const>) { return 0; }
    int ambiguous(by_ref<int>, by_ref<int const>) { return 0; }
    int ambiguous(by_ref<int const>, by_ref<int>) { return 0; }
    static int mixed(by_ref<int>, by_ref<int const>) { return 0; }
    static by_ref<int const> readonly_return(by_ref<int const> value) { return value; }
    static by_ref<int const> return_overload(by_ref<int const> value) { return value; }
    static by_ref<int const> return_overload(by_ref<int const> value, bool) { return value; }
    static void no_args() {}
    int no_throw_instance(by_ref<int const> value) noexcept { return *value; }
};

using readonly_byref_function = function_ptr_t<by_ref<int const>, by_ref<int const>>;
using mixed_byref_method = method_ptr_t<byref_hook_target, int, by_ref<int>, by_ref<int const>>;
using no_throw_function = function_ptr_t<int, bool>;
using no_throw_method = method_ptr_t<byref_hook_target, int, by_ref<int const>>;

template <>
struct i2c::metadata_getter<&byref_hook_target::readonly> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
template <>
struct i2c::metadata_getter<&byref_hook_target::mixed> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};

template <>
struct i2c::metadata_getter<&byref_hook_target::readonly_return> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
template <>
struct i2c::metadata_getter<static_cast<readonly_byref_function>(&byref_hook_target::return_overload)> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
template <>
struct i2c::metadata_getter<&byref_hook_target::no_args> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
template <>
struct i2c::metadata_getter<static_cast<mixed_byref_method>(&byref_hook_target::ambiguous)> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
template <>
struct i2c::metadata_getter<static_cast<no_throw_function>(&target)> {
    static inline MethodInfo info{};
    static MethodInfo const* method_info() { return &info; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
template <>
struct i2c::metadata_getter<static_cast<no_throw_method>(&byref_hook_target::no_throw_instance)> {
    static inline MethodInfo info{};
    static MethodInfo const* method_info() { return &info; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};

MAKE_HOOK_MATCH(match_readonly_byref_test, &byref_hook_target::readonly, int, byref_hook_target* self, by_ref<int> value) {
    *value += 10;
    return self->readonly(value);
}
MAKE_HOOK_MATCH(match_mixed_byref_test, &byref_hook_target::mixed, int, by_ref<int>, by_ref<int>, MethodInfo*) {
    return 0;
}

MAKE_HOOK_MATCH(match_byref_return_test, &byref_hook_target::readonly_return, by_ref<int>, by_ref<int> value, MethodInfo const* info) {
    *value += 10;
    return match_byref_return_test(value, info);
}
MAKE_HOOK_MATCH(
    match_overloaded_byref_return_test, static_cast<readonly_byref_function>(&byref_hook_target::return_overload), by_ref<int>, by_ref<int> value
) {
    return value;
}
MAKE_HOOK_MATCH(
    match_selected_byref_test,
    static_cast<mixed_byref_method>(&byref_hook_target::ambiguous),
    int,
    byref_hook_target* self,
    by_ref<int> first,
    by_ref<int> second
) {
    return self->readonly(first) + *second;
}
MAKE_HOOK_MATCH(match_no_args_test, &byref_hook_target::no_args, void) {}
MAKE_HOOK_MATCH(match_no_args_const_minfo_test, &byref_hook_target::no_args, void, MethodInfo const*) {}
MAKE_HOOK_MATCH(match_no_throw_test, &target, int, bool value) {
    return value ? 1 : 0;
}
MAKE_HOOK_MATCH(match_no_throw_instance_test, &byref_hook_target::no_throw_instance, int, byref_hook_target* self, by_ref<int> value) {
    return self->no_throw_instance(value);
}

static_assert(std::is_same_v<hook_match_readonly_byref_test::func_t, function_ptr_t<int, byref_hook_target*, by_ref<int>>>);
static_assert(std::is_same_v<hook_match_readonly_byref_test::cast_t, method_ptr_t<byref_hook_target, int, by_ref<int const>>>);
static_assert(std::is_same_v<hook_match_mixed_byref_test::cast_t, function_ptr_t<int, by_ref<int>, by_ref<int const>>>);
static_assert(std::is_same_v<hook_match_const_minfo_test::cast_t, hook_match_test::cast_t>);
static_assert(std::is_same_v<hook_match_inst_overload_const_minfo_test::cast_t, hook_match_inst_overload_test::cast_t>);
static_assert(std::is_same_v<hook_match_byref_return_test::cast_t, decltype(&byref_hook_target::readonly_return)>);
static_assert(std::is_same_v<hook_match_byref_return_test::func_t, function_ptr_t<by_ref<int>, by_ref<int>, MethodInfo const*>>);
static_assert(std::is_same_v<hook_match_overloaded_byref_return_test::cast_t, function_ptr_t<by_ref<int const>, by_ref<int const>>>);
static_assert(std::is_same_v<hook_match_no_args_const_minfo_test::cast_t, hook_match_no_args_test::cast_t>);
static_assert(std::is_same_v<hook_match_selected_byref_test::cast_t, mixed_byref_method>);
static_assert(std::is_same_v<hook_match_no_throw_test::cast_t, no_throw_function>);
static_assert(std::is_same_v<hook_match_no_throw_instance_test::cast_t, no_throw_method>);
static_assert(std::is_same_v<
              i2c::detail::method_check<
                  hook_match_readonly_byref_test::cast_test,
                  function_ptr_t<int, byref_hook_target*, by_ref<int>, MethodInfo*>,
                  decltype(&byref_hook_target::readonly)>::type,
              hook_match_readonly_byref_test::cast_t>);

static constexpr auto overloaded_byref_check = []<typename T>() {
    return requires { static_cast<T>(&byref_hook_target::overload); };
};
static constexpr auto ambiguous_byref_check = []<typename T>() {
    return requires { static_cast<T>(&byref_hook_target::ambiguous); };
};
static_assert(std::is_same_v<
              i2c::detail::method_check<overloaded_byref_check, function_ptr_t<int, byref_hook_target*, by_ref<int>>>::type,
              method_ptr_t<byref_hook_target, int, by_ref<int>>>);
static_assert(std::is_same_v<
              i2c::detail::method_check<overloaded_byref_check, function_ptr_t<int, byref_hook_target*, by_ref<int const>>>::type,
              method_ptr_t<byref_hook_target, int, by_ref<int const>>>);
using unresolved_byref_check = i2c::detail::method_check<ambiguous_byref_check, function_ptr_t<int, byref_hook_target*, by_ref<int>, by_ref<int>>>;
using incompatible_byref_check = i2c::detail::method_check<
    hook_match_readonly_byref_test::cast_test,
    function_ptr_t<int, byref_hook_target*, by_ref<float>>,
    decltype(&byref_hook_target::readonly)>;
static_assert(!unresolved_byref_check::resolved && !unresolved_byref_check::valid);
static_assert(incompatible_byref_check::resolved && !incompatible_byref_check::valid);

// A known target must never probe whole-signature casts, even with many converted parameters.
static constexpr auto forbidden_signature_probe = []<typename T>() {
    static_assert(std::is_void_v<T>, "Known method signatures should be checked parameter by parameter");
    return false;
};

// Exercise MAKE_HOOK_MATCH itself with sixteen converted parameters. An unresolved overload
// must fail immediately rather than trying 65,536 signatures; explicitly selecting it succeeds.
#define HOOK_TEST_MANY_ARGS(T) T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T
struct many_byref_hook_target {
    static void single(HOOK_TEST_MANY_ARGS(by_ref<int const>)) {}
    static void overloaded(HOOK_TEST_MANY_ARGS(by_ref<int const>)) {}
    static void overloaded(bool) {}
};
using many_readonly_byrefs = function_ptr_t<void, HOOK_TEST_MANY_ARGS(by_ref<int const>)>;
using many_mutable_byrefs = function_ptr_t<void, HOOK_TEST_MANY_ARGS(by_ref<int>)>;
template <>
struct i2c::metadata_getter<&many_byref_hook_target::single> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
template <>
struct i2c::metadata_getter<static_cast<many_readonly_byrefs>(&many_byref_hook_target::overloaded)> {
    static MethodInfo const* method_info() { return nullptr; }
    static constexpr size_t size = 24;
    static constexpr uintptr_t addrs = 0x1234;
};
MAKE_HOOK_MATCH(match_many_byrefs_test, &many_byref_hook_target::single, void, HOOK_TEST_MANY_ARGS(by_ref<int>)) {}
MAKE_HOOK_MATCH(
    match_many_overloaded_byrefs_test, static_cast<many_readonly_byrefs>(&many_byref_hook_target::overloaded), void, HOOK_TEST_MANY_ARGS(by_ref<int>)
) {}
#undef HOOK_TEST_MANY_ARGS

static constexpr auto many_overloads_check = []<typename T>() {
    return requires { static_cast<T>(&many_byref_hook_target::overloaded); };
};
using unresolved_many_check = i2c::detail::method_check<many_overloads_check, many_mutable_byrefs>;
static_assert(!unresolved_many_check::resolved && !unresolved_many_check::valid);
static_assert(std::is_same_v<hook_match_many_byrefs_test::cast_t, many_readonly_byrefs>);
static_assert(std::is_same_v<hook_match_many_overloaded_byrefs_test::cast_t, many_readonly_byrefs>);

template <typename Hook, typename Method>
constexpr bool hook_types_match = i2c::detail::method_check<forbidden_signature_probe, Hook, Method>::valid;

static_assert(hook_types_match<function_ptr_t<int, by_ref<int const>, by_ref<int>>, decltype(&byref_hook_target::mixed)>);
static_assert(hook_types_match<function_ptr_t<by_ref<int const>, by_ref<int>>, function_ptr_t<by_ref<int>, by_ref<int const>>>);
static_assert(hook_types_match<function_ptr_t<void>, function_ptr_t<void>>);
static_assert(hook_types_match<function_ptr_t<void, MethodInfo*>, function_ptr_t<void>>);
static_assert(!hook_types_match<function_ptr_t<void>, function_ptr_t<int>>);
static_assert(!hook_types_match<function_ptr_t<float, bool>, decltype(&foo)>);
static_assert(!hook_types_match<function_ptr_t<int, int>, decltype(&foo)>);
static_assert(!hook_types_match<function_ptr_t<int>, decltype(&foo)>);
static_assert(!hook_types_match<function_ptr_t<int, bool, bool>, decltype(&foo)>);
static_assert(!hook_types_match<function_ptr_t<int, by_ref<float>>, function_ptr_t<int, by_ref<int const>>>);
static_assert(!hook_types_match<function_ptr_t<int, by_ref<int*>>, function_ptr_t<int, by_ref<int const*>>>);
static_assert(!hook_types_match<function_ptr_t<int, by_ref<int>>, function_ptr_t<int, by_ref<int volatile>>>);
static_assert(!hook_types_match<function_ptr_t<int, int*>, function_ptr_t<int, int const*>>);
static_assert(hook_types_match<function_ptr_t<int, by_ref<int*>>, function_ptr_t<int, by_ref<int* const>>>);
// Only the final metadata argument is hidden; an earlier one is an ordinary method parameter.
static_assert(hook_types_match<function_ptr_t<int, MethodInfo const*, MethodInfo*>, function_ptr_t<int, MethodInfo const*>>);
static_assert(!hook_types_match<function_ptr_t<int, MethodInfo const*, MethodInfo*>, function_ptr_t<int>>);
static_assert(!hook_types_match<function_ptr_t<int, MethodInfo*, bool>, function_ptr_t<int, bool>>);

TEST(hook_byref_constness_matching) {
    byref_hook_target target;
    int value = 2;
    if (hook_match_readonly_byref_test::hook_m_match_readonly_byref_test(&target, value) != 12 || value != 12) {
        LOG_FAIL("Readonly metadata matching lost mutable hook access");
        return;
    }
    LOG_OK("Byref matching preserves mutable hooks, mixed constness, and exact overloads");
}

TEST(hook_overload_selection) {
    byref_hook_target target;
    int first = 3;
    int second = 4;
    if (hook_match_selected_byref_test::hook_m_match_selected_byref_test(&target, first, second) != 7) {
        LOG_FAIL("Explicit overload selection did not preserve byref arguments");
        return;
    }
    if (unresolved_byref_check::resolved || unresolved_many_check::resolved || incompatible_byref_check::valid) {
        LOG_FAIL("An unresolved or incompatible hook target was accepted");
        return;
    }
    LOG_OK("Explicitly selected overloads accept compatible byrefs; unresolved and incompatible targets are rejected");
}

TEST(hook_noexcept_metadata) {
    auto static_info = i2c::metadata_getter<static_cast<no_throw_function>(&target)>::method_info();
    auto instance_info = i2c::metadata_getter<static_cast<no_throw_method>(&byref_hook_target::no_throw_instance)>::method_info();
    if (hook_match_no_throw_test::addr() != static_info || hook_match_no_throw_instance_test::addr() != instance_info) {
        LOG_FAIL("Noexcept targets did not resolve the existing metadata specializations");
        return;
    }
    if (hook_types_match<function_ptr_t<float, bool>, decltype(&target)>) {
        LOG_FAIL("Noexcept normalization accepted an incompatible return type");
        return;
    }
    LOG_OK("Noexcept static and instance targets preserve metadata keys and type checking");
}

TEST(hook_parameter_and_return_matching) {
    int value = 2;
    static MethodInfo info{};
    static bool forwarded_info;
    forwarded_info = false;
    auto previous = hook_match_byref_return_test::match_byref_return_test;
    // A captureless trampoline checks the metadata pointer as well as byref storage.
    hook_match_byref_return_test::match_byref_return_test = [](by_ref<int> argument, MethodInfo const* method) -> by_ref<int> {
        forwarded_info = method == &info;
        return argument;
    };
    auto returned = hook_match_byref_return_test::hook_m_match_byref_return_test(value, &info);
    hook_match_byref_return_test::match_byref_return_test = previous;
    if (returned.ref != &value || *returned != 12 || value != 12 || !forwarded_info) {
        LOG_FAIL("Per-type matching changed return storage, mutable byref access, or metadata forwarding");
        return;
    }
    if (hook_types_match<function_ptr_t<int, by_ref<float>>, function_ptr_t<int, by_ref<int const>>> ||
        hook_types_match<function_ptr_t<float, bool>, decltype(&foo)>) {
        LOG_FAIL("Per-type matching accepted an incompatible parameter or return");
        return;
    }
    LOG_OK("Per-type matching preserves byref returns and metadata forwarding, and rejects incompatible types");
}

TEST(hook_const_method_info_lookup) {
    try {
        auto mutable_info =
            i2c::detail::resolve_addr<function_ptr_t<void*, void*, int, MethodInfo*>>{}({"System.Collections", "Queue"}, "GetElement", true);
        auto const_info =
            i2c::detail::resolve_addr<function_ptr_t<void*, void*, int, MethodInfo const*>>{}({"System.Collections", "Queue"}, "GetElement", true);
        auto no_info = i2c::detail::resolve_addr<function_ptr_t<void>>{}({"System", "GC"}, "Collect");
        auto const_info_only = i2c::detail::resolve_addr<function_ptr_t<void, MethodInfo const*>>{}({"System", "GC"}, "Collect", false);
        if (!mutable_info || mutable_info != const_info || !no_info || no_info != const_info_only) {
            LOG_FAIL("Const MethodInfo changed the resolved method's parameter count");
            return;
        }
        LOG_OK("Mutable and const MethodInfo resolve the same instance and zero-parameter static methods");
    } catch (std::exception const& e) {
        LOG_FAIL("Const MethodInfo lookup failed: {}", e.what());
    }
}
