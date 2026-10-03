#include "dmp/core.h"
#include "dmp/stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *ptr, size_t size);
void __real_free(void *ptr);

static int g_track_allocations;
static unsigned g_allocation_calls;

void *__wrap_malloc(size_t size)
{
    if (g_track_allocations) {
        ++g_allocation_calls;
    }
    return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    if (g_track_allocations) {
        ++g_allocation_calls;
    }
    return __real_calloc(count, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    if (g_track_allocations) {
        ++g_allocation_calls;
    }
    return __real_realloc(ptr, size);
}

void __wrap_free(void *ptr)
{
    if (g_track_allocations) {
        ++g_allocation_calls;
    }
    __real_free(ptr);
}

static int run_core_paths(void)
{
    static const uint8_t payload[] = { 0xAAU, 0xBBU };
    static const dmp_core_limits limits = { 256U, 128U, 8U };
    dmp_frame_spec frame;
    uint8_t encoded[64];
    size_t encoded_size = 0U;
    dmp_frame_view view;
    dmp_role_policy policy = { DMP_ROLE_ENDPOINT, 1U, false };

    memset(&frame, 0, sizeof frame);
    frame.fields.type = DMP_TYPE_TELEM;
    frame.payload = (dmp_bytes){ payload, sizeof payload };
    if (dmp_core_encode(&frame, &limits,
                        (dmp_buffer){ encoded, sizeof encoded },
                        &encoded_size) != DMP_OK ||
        dmp_core_parse((dmp_bytes){ encoded, encoded_size }, &limits,
                       &view).status != DMP_OK ||
        dmp_core_check_role(&view, &policy) != DMP_OK) {
        return 0;
    }
    return 1;
}

static int run_stream_paths(void)
{
    static const uint8_t core[] = { 0x45U, 0x02U, 0xAAU, 0xBBU };
    static const uint8_t r_sync = 0U;
    uint8_t wire_l[32], wire_r[32], storage_l[128], storage_r[134];
    uint8_t r_input[33];
    size_t written_l = 0U, written_r = 0U;
    dmp_stream_decoder decoder_l, decoder_r;
    dmp_stream_config config = { DMP_STREAM_L, 128U, 10U };
    dmp_stream_result result;

    if (dmp_stream_encode(DMP_STREAM_L, (dmp_bytes){ core, sizeof core },
                          (dmp_buffer){ wire_l, sizeof wire_l },
                          &written_l) != DMP_OK ||
        dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ core, sizeof core },
                          (dmp_buffer){ wire_r, sizeof wire_r },
                          &written_r) != DMP_OK ||
        written_r + 1U > sizeof r_input) {
        return 0;
    }
    r_input[0] = r_sync;
    memcpy(r_input + 1U, wire_r, written_r);
    if (dmp_stream_init(&decoder_l, config,
                        (dmp_buffer){ storage_l, sizeof storage_l }, 0U) != DMP_OK) {
        return 0;
    }
    result = dmp_stream_feed(&decoder_l,
                             (dmp_bytes){ wire_l, written_l }, 1U);
    if (result.status != DMP_OK || result.event != DMP_STREAM_FRAME) {
        return 0;
    }
    result = dmp_stream_poll(&decoder_l, 11U);
    if (result.status != DMP_OK || result.event != DMP_STREAM_NONE) {
        return 0;
    }

    config.mode = DMP_STREAM_R;
    if (dmp_stream_init(&decoder_r, config,
                        (dmp_buffer){ storage_r, sizeof storage_r }, 0U) != DMP_OK) {
        return 0;
    }
    result = dmp_stream_feed(&decoder_r, (dmp_bytes){ r_input, 1U }, 1U);
    if (result.consumed != 1U) {
        return 0;
    }
    result = dmp_stream_feed(&decoder_r,
                             (dmp_bytes){ r_input + 1U, written_r }, 1U);
    if (result.status != DMP_OK || result.event != DMP_STREAM_FRAME) {
        return 0;
    }
    result = dmp_stream_poll(&decoder_r, 11U);
    return result.status == DMP_OK && result.event == DMP_STREAM_NONE;
}

int main(void)
{
    int ok;
    g_track_allocations = 1;
    ok = run_core_paths() && run_stream_paths();
    g_track_allocations = 0;
    if (g_allocation_calls != 0U || !ok) {
        (void)fprintf(stderr,
                      "allocation probe failed: paths=%s, calls=%u\n",
                      ok ? "ok" : "failed", g_allocation_calls);
        return 1;
    }
    (void)puts("core parse/encode and Stream L/R paths made no wrapped allocations");
    return 0;
}
