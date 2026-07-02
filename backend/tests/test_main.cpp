/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 */
#include "test.h"

int main() {
    int run = 0;
    for (auto& c : avbtest::cases()) {
        int before = avbtest::failures();
        std::printf("[ RUN  ] %s\n", c.name);
        c.fn();
        ++run;
        if (avbtest::failures() == before)
            std::printf("[  OK  ] %s\n", c.name);
        else
            std::printf("[ FAIL ] %s\n", c.name);
    }
    std::printf("%d tests, %d failure(s)\n", run, avbtest::failures());
    return avbtest::failures() ? 1 : 0;
}
