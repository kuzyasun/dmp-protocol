#include "fuzz_stream.h"

#include "fuzz_limits.h"

#include "dmp/stream.h"

#include <string.h>

static volatile uint32_t g_observations;

uint32_t dmp_fuzz_stream_observations(void)
{
    return g_observations;
}

static void observe(uint32_t value)
{
    /* Count the call as well as the code. DMP_OK is 0 and must still move. */
    g_observations += 1U + value;
}

static void run_mode(dmp_stream_mode mode, const uint8_t *bytes, size_t size)
{
    uint8_t storage[DMP_FUZZ_STREAM_STORAGE];
    dmp_stream_decoder decoder;
    dmp_stream_config config;
    dmp_status status;
    size_t offset = 0U;
    unsigned step;

    config.mode = mode;
    config.max_core_bytes = DMP_FUZZ_STREAM_MAX_CORE;
    config.partial_timeout_ms = DMP_FUZZ_STREAM_TIMEOUT_MS;
    status = dmp_stream_init(&decoder, config,
                             (dmp_buffer){ storage, sizeof storage },
                             DMP_FUZZ_STREAM_INIT_NOW);
    observe((uint32_t)status);
    if (status != DMP_OK) {
        return;
    }

    for (step = 0U; step < DMP_FUZZ_MAX_FEED_STEPS && offset < size; ++step) {
        dmp_stream_result fed;
        size_t remaining = size - offset;

        fed = dmp_stream_feed(&decoder,
                              (dmp_bytes){ bytes + offset, remaining },
                              DMP_FUZZ_STREAM_FEED_NOW);
        observe((uint32_t)fed.status);
        observe((uint32_t)fed.event);
        if (fed.event == DMP_STREAM_FRAME && fed.frame.data != NULL &&
            fed.frame.size > 0U) {
            /* Borrowed until the next feed/poll. Framing only. */
            observe(fed.frame.data[0]);
            observe((uint32_t)fed.frame.size);
        }
        if (fed.consumed == 0U || fed.consumed > remaining ||
            fed.event == DMP_STREAM_SESSION_FAILED) {
            break;
        }
        offset += fed.consumed;
    }

    {
        dmp_stream_result polled = dmp_stream_poll(
            &decoder,
            (dmp_time_ms)DMP_FUZZ_STREAM_FEED_NOW + DMP_FUZZ_STREAM_TIMEOUT_MS);
        observe((uint32_t)polled.status);
        observe((uint32_t)polled.event);
    }
}

int dmp_fuzz_stream(const uint8_t *data, size_t size)
{
    uint8_t owned[DMP_FUZZ_MAX_INPUT];
    const uint8_t *bytes = NULL;

    if (size > DMP_FUZZ_MAX_INPUT || (size > 0U && data == NULL)) {
        return 0;
    }
    if (size > 0U) {
        memcpy(owned, data, size);
        bytes = owned;
    }

    /* Separate decoders and storage. L and R do not share a session. */
    run_mode(DMP_STREAM_L, bytes, size);
    run_mode(DMP_STREAM_R, bytes, size);
    return 0;
}

#ifdef DMP_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return dmp_fuzz_stream(data, size);
}
#endif
