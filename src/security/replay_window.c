#include "replay_window.h"

#include <string.h>

static int bit_at(const uint8_t *bits, uint32_t index)
{
    return (bits[index / 8U] >> (index % 8U)) & 1;
}

static void bit_put(uint8_t *bits, uint32_t index, int value)
{
    uint8_t mask = (uint8_t)(1U << (index % 8U));

    if (value) {
        bits[index / 8U] |= mask;
    } else {
        bits[index / 8U] &= (uint8_t)~mask;
    }
}

static size_t byte_count(uint32_t width)
{
    return (size_t)((width + 7U) / 8U);
}

void dmp_replay_window_init(dmp_replay_window *window, uint32_t width)
{
    if (window == NULL) {
        return;
    }
    memset(window, 0, sizeof(*window));
    window->width = width;
}

void dmp_replay_window_clear(dmp_replay_window *window)
{
    uint32_t width;

    if (window == NULL) {
        return;
    }
    width = window->width;
    dmp_replay_window_init(window, width);
}

int dmp_replay_window_admit(const dmp_replay_window *window, uint64_t pn)
{
    uint32_t width;
    uint32_t index;

    if (window == NULL || window->width < DMP_REPLAY_WINDOW_MIN) {
        return 0;
    }
    if (!window->open) {
        return 1;
    }
    width = window->width;
    if (pn > window->highest) {
        return 1;
    }
    if (window->highest - pn >= width) {
        return 0;
    }
    index = (width - 1U) - (uint32_t)(window->highest - pn);
    return !bit_at(window->bits, index);
}

int dmp_replay_window_commit(dmp_replay_window *window, uint64_t pn)
{
    uint32_t width;
    uint32_t index;
    uint64_t shift;

    if (window == NULL || window->width < DMP_REPLAY_WINDOW_MIN ||
        !dmp_replay_window_admit(window, pn)) {
        return 0;
    }
    width = window->width;
    if (!window->open) {
        memset(window->bits, 0, byte_count(width));
        window->open = 1;
        window->highest = pn;
        bit_put(window->bits, width - 1U, 1);
        return 1;
    }
    if (pn > window->highest) {
        shift = pn - window->highest;
        if (shift >= width) {
            memset(window->bits, 0, byte_count(width));
        } else {
            for (index = 0U; index < width; ++index) {
                int value = 0;

                if ((uint64_t)index + shift < width) {
                    value = bit_at(window->bits, index + (uint32_t)shift);
                }
                bit_put(window->bits, index, value);
            }
        }
        window->highest = pn;
        bit_put(window->bits, width - 1U, 1);
        return 1;
    }
    index = (width - 1U) - (uint32_t)(window->highest - pn);
    if (bit_at(window->bits, index)) {
        return 0;
    }
    bit_put(window->bits, index, 1);
    return 1;
}
