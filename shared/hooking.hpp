#pragma once

#include "byref.hpp"
#include "find.hpp"
#include "flamingo/shared/hook-data.hpp"
#include "flamingo/shared/hook-metadata.hpp"
#include "flamingo/shared/installer.hpp"

#ifndef __aarch64__
#error Hooking is only supported on ARM64 platforms!
#endif

namespace i2c {
    namespace detail {
        template <typename T>
        concept is_logger = requires(T& l) {
            l.info("");
            l.debug("");
            l.error("");
            l.warn("");
            l.critical("");
        };

        template <typename T>
        concept hook_struct =
            requires {
                // Must have a name
                { T::name() } -> std::same_as<char const*>;
                // Must have a trampoline that returns the func_t
                { T::trampoline() } -> std::same_as<typename T::func_t*>;
                // Must have a hook that returns the func_t
                { T::hook() } -> std::same_as<typename T::func_t>;
                // Must have an installation handle
                { T::install_handle } -> std::same_as<flamingo::HookHandle&>;
                // Must have installation priority
                { T::install_priority } -> std::same_as<flamingo::HookPriority&>;
            } &&
            (
                // Must have an address
                requires {
                    { T::addr() } -> std::same_as<void*>;
                } ||
                requires {
                    { T::addr() } -> std::same_as<MethodInfo const*>;
                }
            );

        template <typename T, typename... TArgs>
        using last_t = std::tuple_element_t<sizeof...(TArgs), std::tuple<T, TArgs...>>;

        // A struct to remove the last parameter from a function if it is a specific type
        // https://godbolt.org/z/eT98hxo17
        template <typename D, typename T>
        struct remove_last_param {
            using type = T;
        };
        template <typename D, typename R, typename T, typename... TArgs>
        struct remove_last_param<D, function_ptr_t<R, T, TArgs...>> {
            using type = std::conditional_t<
                std::is_same_v<last_t<T, TArgs...>, D>,
                decltype([]<size_t... Is>(std::index_sequence<Is...>) {
                    return function_ptr_t<R, std::tuple_element_t<Is, std::tuple<T, TArgs...>>...>{};
                }(std::index_sequence_for<TArgs...>{})),
                function_ptr_t<R, T, TArgs...>>;
        };
        template <typename D, typename R, typename I, typename T, typename... TArgs>
        struct remove_last_param<D, method_ptr_t<I, R, T, TArgs...>> {
            using type = std::conditional_t<
                std::is_same_v<last_t<T, TArgs...>, D>,
                decltype([]<size_t... Is>(std::index_sequence<Is...>) {
                    return method_ptr_t<I, R, std::tuple_element_t<Is, std::tuple<T, TArgs...>>...>{};
                }(std::index_sequence_for<TArgs...>{})),
                method_ptr_t<I, R, T, TArgs...>>;
        };
        template <typename D, typename T>
        using remove_last_param_t = remove_last_param<D, T>::type;

        // A struct to find methods for hooks based on their function type and user-specified parameters
        template <typename T>
        struct resolve_addr;

        template <typename R>
        struct resolve_addr<R (*)()> {
            auto operator()(auto addr) { return (void*) addr; }
            auto operator()(MethodInfo const* addr) { return addr; }
            auto operator()(find_class_info klass, std::string_view name) { return find_method(klass, {name, 0}); }
        };

        template <typename R, typename T1, typename... TArgs>
        struct resolve_addr<R (*)(T1, TArgs...)> {
            auto operator()(auto addr) { return (void*) addr; }
            auto operator()(MethodInfo const* addr) { return addr; }
            auto operator()(find_class_info klass, std::string_view name, bool instance = std::is_pointer_v<T1> && type_check::full_class<T1>) {
                int args = sizeof...(TArgs) + int(!instance) - int(std::is_same_v<last_t<T1, TArgs...>, MethodInfo*>);
                return find_method(klass, {name, args});
            }
        };

        template <typename T>
        struct toggle_byref_const {
            using type = T;
        };
        template <typename T>
        struct toggle_byref_const<by_ref<T>> {
            using type = by_ref<std::conditional_t<std::is_const_v<T>, std::remove_const_t<T>, std::add_const_t<T>>>;
        };

        // Rebuild the signature, trying both constness choices for each by_ref.
        template <auto C, template <typename...> typename Ptr, typename Selected, typename Remaining>
        struct byref_matches;
        template <auto C, template <typename...> typename Ptr, typename... Selected>
        struct byref_matches<C, Ptr, std::tuple<Selected...>, std::tuple<>> {
            using candidate = Ptr<Selected...>;
            using type = std::conditional_t<C.template operator()<candidate>(), std::tuple<candidate>, std::tuple<>>;
        };
        template <auto C, template <typename...> typename Ptr, typename... Selected, typename First, typename... Rest>
        struct byref_matches<C, Ptr, std::tuple<Selected...>, std::tuple<First, Rest...>> {
            using other = typename toggle_byref_const<First>::type;
            using original = typename byref_matches<C, Ptr, std::tuple<Selected..., First>, std::tuple<Rest...>>::type;
            using changed = typename byref_matches<C, Ptr, std::tuple<Selected..., other>, std::tuple<Rest...>>::type;
            using type =
                std::conditional_t<std::is_same_v<First, other>, original, decltype(std::tuple_cat(std::declval<original>(), std::declval<changed>()))>;
        };

        template <auto C, typename Signature>
        struct hook_method_matches {
            using type = std::tuple<>;
        };
        template <auto C, typename R, typename... Args>
        struct hook_method_matches<C, function_ptr_t<R, Args...>> : byref_matches<C, function_ptr_t, std::tuple<R>, std::tuple<Args...>> {};
        template <auto C, typename I, typename R, typename... Args>
        struct hook_method_matches<C, method_ptr_t<I, R, Args...>> : byref_matches<C, method_ptr_t, std::tuple<I, R>, std::tuple<Args...>> {};

        template <typename T>
        struct hook_instance_type {
            using type = void;
        };
        template <typename R, typename I, typename... Args>
        requires(std::is_class_v<I> || std::is_union_v<I>)
        struct hook_instance_type<function_ptr_t<R, I*, Args...>> {
            using type = remove_last_param_t<MethodInfo*, method_ptr_t<I, R, Args...>>;
        };

        // Exact overloads win; otherwise require a unique constness-adjusted match.
        template <auto C, typename T>
        struct method_check {
            using static_type = remove_last_param_t<MethodInfo*, T>;
            using instance_type = typename hook_instance_type<T>::type;
            using type = typename decltype([] {
                if constexpr (!std::is_void_v<instance_type> && C.template operator()<instance_type>()) {
                    return std::type_identity<instance_type>{};
                } else if constexpr (C.template operator()<static_type>()) {
                    return std::type_identity<static_type>{};
                } else {
                    using matches = decltype(std::tuple_cat(
                        std::declval<typename hook_method_matches<C, static_type>::type>(),
                        std::declval<typename hook_method_matches<C, instance_type>::type>()
                    ));
                    static_assert(std::tuple_size_v<matches> <= 1, "Hook method signature is ambiguous after changing by_ref constness!");
                    if constexpr (std::tuple_size_v<matches> == 1) {
                        return std::type_identity<std::tuple_element_t<0, matches>>{};
                    } else {
                        return std::type_identity<static_type>{};
                    }
                }
            }())::type;
        };

        template <auto M>
#ifndef BS_HOOK_MATCH_UNSAFE
        constexpr bool match_hookable = metadata_getter<M>::size >= 0x5 * sizeof(uint32_t) && metadata_getter<M>::addrs != 0x0;
#else
        constexpr bool match_hookable = true;
#endif
    }

    template <detail::hook_struct T, detail::is_logger L>
    void install_hook(L&& logger = ::i2c::logger, void* addr = nullptr) {
        if (!addr) {
            auto info_or_addr = T::addr();
            if constexpr (std::is_same_v<decltype(info_or_addr), void*>) {
                addr = info_or_addr;
            } else if (info_or_addr) {
                addr = reinterpret_cast<void*>(info_or_addr->methodPointer);
            } else {
                MACRO_LOG(logger, critical, "Attempting to install hook: {}, but method could not be found!", T::name());
                SAFE_ABORT("Failure installing hook: {}", T::name());
            }
        }
        if (!addr) {
            MACRO_LOG(logger, critical, "Attempting to install hook: {} to invalid destination!", T::name());
            SAFE_ABORT("Failure installing hook: {}", T::name());
        }
        MACRO_LOG(logger, info, "Installing hook: {} to offset: {}", T::name(), fmt::ptr(addr));
        auto install_priority = T::install_priority;
        auto install_result = flamingo::Install(
            flamingo::HookInfo{
                reinterpret_cast<void*>(T::hook()),
                addr,
                reinterpret_cast<void**>(T::trampoline()),
                flamingo::HookNameMetadata{.name = T::name()},
                std::move(install_priority)
            }
        );
        if (install_result.has_value()) {
            MACRO_LOG(logger, info, "Hook: {} installed with flamingo!", T::name());
            T::install_handle = install_result.value().returned_handle;
        } else {
            MACRO_LOG(logger, critical, "Failed to install hook: {} with flamingo: {}", T::name(), install_result.error());
            SAFE_ABORT("Failure installing hook: {}", T::name());
        }
    }

    template <detail::hook_struct T, detail::is_logger L>
    void install_hook_orig(L&& logger = ::i2c::logger, void* addr = nullptr) {
        T::install_priority.is_final = true;
        install_hook<T>(logger, addr);
    }

    template <detail::hook_struct T, detail::is_logger L>
    void uninstall_hook(L&& logger = ::i2c::logger) {
        MACRO_LOG(logger, info, "Uninstalling hook: {}", T::name());
        auto uninstall_result = flamingo::Uninstall(T::install_handle);
        if (uninstall_result.has_value()) {
            MACRO_LOG(logger, info, "Hook: {} uninstalled with flamingo!", T::name());
            T::install_handle = {};
        } else if (uninstall_result.error()) {
            MACRO_LOG(logger, error, "Failed to uninstall hook: {} with flamingo: remapping error", T::name());
        } else {
            MACRO_LOG(logger, error, "Failed to uninstall hook: {} with flamingo: no target found (was the hook installed?)", T::name());
        }
    }
}

#define __INTERNAL_HOOK_STRUCT(name_, addr_, ret_type, ...) \
    constexpr static const char* name() { return #name_; }  \
    static auto addr() { return addr_; }                    \
    static func_t hook() { return hook_m_##name_; }         \
    static func_t* trampoline() { return &name_; }          \
    static inline flamingo::HookHandle install_handle;      \
    static inline flamingo::HookPriority install_priority;  \
    static ret_type hook_m_##name_(__VA_ARGS__); /* Hook */ \
    static inline ret_type (*name_)(__VA_ARGS__) = nullptr; /* Orig */

// Defines a hook to a manually found address or il2cpp method.
// addr_info must be in parentheses, and can either be an expression that produces a pointer,
// or a find_class_info, method name, and boolean flag if an instance method.
// If given an il2cpp method, it will search for one that matches the given return type and parameters.
#define MAKE_HOOK(name_, addr_info, ret_type, ...)                                                             \
    struct BS_HOOK_HIDDEN hook_##name_ {                                                                       \
        using func_t = ret_type (*)(__VA_ARGS__);                                                              \
        __INTERNAL_HOOK_STRUCT(name_, ::i2c::detail::resolve_addr<func_t>{} addr_info, ret_type, __VA_ARGS__) \
    };                                                                                                         \
    ret_type hook_##name_::hook_m_##name_(__VA_ARGS__)

// Defines a hook to a method with metadata provided through i2c::metadata_getter.
// Will automatically cast overloads, check types, and detect static/instance methods, based on the given return type and parameters.
// by_ref parameters may differ in constness from the target; exact matches take precedence and ambiguous fallbacks are rejected.
// Generic methods cannot be hooked with this macro.
#define MAKE_HOOK_MATCH(name_, method, ret_type, ...)                                                                            \
    struct BS_HOOK_HIDDEN hook_##name_ {                                                                                         \
        static constexpr auto cast_test = []<typename T>() { return requires { static_cast<T>(method); }; };                     \
        using func_t = ret_type (*)(__VA_ARGS__);                                                                                \
        using cast_t = ::i2c::detail::method_check<cast_test, func_t>::type;                                                    \
        static_assert(cast_test.operator()<cast_t>(), "Hook method signature does not match!");                                  \
        static_assert(::i2c::detail::match_hookable<static_cast<cast_t>(method)>, "Method cannot be hooked!");                  \
        __INTERNAL_HOOK_STRUCT(name_, ::i2c::metadata_getter<static_cast<cast_t>(method)>::method_info(), ret_type, __VA_ARGS__) \
    };                                                                                                                           \
    ret_type hook_##name_::hook_m_##name_(__VA_ARGS__)

// Tells a hook to be installed as the final hook, if other hooks are installed to the same target.
#define HOOK_ORIG(name_)                                \
    BS_HOOK_DLOPEN static void hook_##name_##_orig() {  \
        hook_##name_::install_priority.is_final = true; \
    }

// Tells a hook to be installed before another hook, based on the other hook's name.
#define HOOK_BEFORE(name_, before_name)                                    \
    BS_HOOK_DLOPEN static void CONCAT(hook_##name_##_before, __LINE__)() { \
        hook_##name_::install_priority.befores.emplace_back(before_name);  \
    }

// Tells a hook to be installed after another hook, based on the other hook's name.
#define HOOK_AFTER(name_, after_name)                                     \
    BS_HOOK_DLOPEN static void CONCAT(hook_##name_##_after, __LINE__)() { \
        hook_##name_::install_priority.afters.emplace_back(after_name);   \
    }

// Installs the provided hook using the logger provided, and optionally directly to an address.
// Name must be from either a MAKE_HOOK or MAKE_HOOK_MATCH macro.
#define INSTALL_HOOK(logger, name, ...) \
    ::i2c::install_hook<hook_##name>(logger __VA_OPT__(,) __VA_ARGS__);

// Installs the provided hook using the logger provided, and optionally directly to an address.
// The hook will be forced to be the final hook if multiple are installed to the same target.
// Name must be from either a MAKE_HOOK or MAKE_HOOK_MATCH macro.
#define INSTALL_HOOK_ORIG(logger, name, ...) \
    ::i2c::install_hook_orig<hook_##name>(logger __VA_OPT__(,) __VA_ARGS__);

// Uninstalls a previously installed hook.
// Name must be from either a MAKE_HOOK or MAKE_HOOK_MATCH macro.
#define UNINSTALL_HOOK(logger, name) \
    ::i2c::uninstall_hook<hook_##name>(logger);
