/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * Micro test framework — TEST() registers a case, CHECK and CHECK_EQ record
 * failures without aborting, the runner lives in test_main.cpp.
 */
#pragma once

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace avbtest {

struct Case {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<Case>& cases() {
    static std::vector<Case> c;
    return c;
}
inline int& failures() {
    static int f = 0;
    return f;
}
inline bool reg(const char* name, std::function<void()> fn) {
    cases().push_back({name, std::move(fn)});
    return true;
}

template <typename A, typename B>
void checkEq(const A& a, const B& b, const char* astr, const char* bstr,
             const char* file, int line) {
    if (a == b) return;
    std::ostringstream os;
    os << "    FAIL " << file << ":" << line << ": " << astr << " == " << bstr
       << "  (got: " << a << " vs " << b << ")";
    std::printf("%s\n", os.str().c_str());
    ++failures();
}

} // namespace avbtest

#define TEST(name)                                                          \
    static void test_##name();                                              \
    static const bool _reg_##name = ::avbtest::reg(#name, test_##name);     \
    static void test_##name()

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::printf("    FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++::avbtest::failures();                                        \
        }                                                                   \
    } while (0)

#define CHECK_EQ(a, b) ::avbtest::checkEq((a), (b), #a, #b, __FILE__, __LINE__)
