#include "fuzz_core.h"

#include "fuzz_limits.h"

#include "dmp/core.h"

#include <string.h>

static volatile uint32_t g_observations;

uint32_t dmp_fuzz_core_observations(void)
{
    return g_observations;
}

static void observe(uint32_t value)
{
    /* Count the call as well as the code. DMP_OK is 0 and must still move. */
    g_observations += 1U + value;
}

static void observe_span(dmp_bytes span)
{
    if (span.size == 0U || span.data == NULL) {
        return;
    }
    observe(span.data[0]);
    observe(span.data[span.size - 1U]);
    observe((uint32_t)span.size);
}

int dmp_fuzz_core(const uint8_t *data, size_t size)
{
    uint8_t owned[DMP_FUZZ_MAX_INPUT];
    dmp_frame_view view;
    dmp_parse_result parsed;
    static const dmp_core_limits limits = {
        .max_frame_bytes = DMP_FUZZ_MAX_INPUT,
        .max_message_bytes = DMP_FUZZ_CORE_MAX_MESSAGE,
        .max_fragments = DMP_FUZZ_CORE_MAX_FRAGMENTS
    };

    if (size > DMP_FUZZ_MAX_INPUT || (size > 0U && data == NULL)) {
        return 0;
    }

    if (size == 0U) {
        parsed = dmp_core_parse((dmp_bytes){ NULL, 0U }, &limits, &view);
    } else {
        memcpy(owned, data, size);
        parsed = dmp_core_parse((dmp_bytes){ owned, size }, &limits, &view);
    }
    observe((uint32_t)parsed.status);
    observe((uint32_t)parsed.offset);
    if (parsed.status != DMP_OK) {
        return 0;
    }

    observe_span(view.header);
    observe_span(view.extensions);
    observe_span(view.payload);
    observe_span(view.trailer);
    {
        size_t cursor = 0U;
        unsigned walked = 0U;
        while (walked < DMP_FUZZ_MAX_EXTENSIONS) {
            dmp_extension_view extension;
            dmp_status status = dmp_extension_next(view.extensions, &cursor,
                                                   &extension);
            observe((uint32_t)status);
            if (status != DMP_OK) {
                break;
            }
            observe(extension.tag);
            observe_span(extension.value);
            ++walked;
        }
    }
    {
        /* Structural role compatibility only. DMP_OK is not endpoint,
         * authentication, security, or application acceptance. */
        const dmp_role_policy endpoint = {
            .role = DMP_ROLE_ENDPOINT, .default_service = 1U, .selective32 = false
        };
        const dmp_role_policy forwarder = {
            .role = DMP_ROLE_FORWARDER, .default_service = 1U, .selective32 = false
        };
        observe((uint32_t)dmp_core_check_role(&view, &endpoint));
        observe((uint32_t)dmp_core_check_role(&view, &forwarder));
    }
    return 0;
}

#ifdef DMP_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return dmp_fuzz_core(data, size);
}
#endif
