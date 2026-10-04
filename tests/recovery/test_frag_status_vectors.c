#include "dmp/core.h"

#include <stdio.h>

#include "frag_status_cases.h"

/* Structural parse of independently generated FRAG_STATUS frames.
 * dmp_core_parse does not authenticate. A successful parse is not suite
 * acceptance, plaintext, or recovery-state admission. */

static int fail(const char *name, int line, const char *condition)
{
    (void)fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, name, condition);
    (void)line;
    return 1;
}

int main(void)
{
    const dmp_core_limits limits = {4096U, 65519U, 32U};
    size_t index;
    size_t accepted = 0U;
    for (index = 0U; index < sizeof frag_cases / sizeof frag_cases[0]; ++index) {
        const frag_case *item = &frag_cases[index];
        dmp_frame_view view;
        dmp_parse_result parsed;
        dmp_role_policy policy;
        dmp_status expect;
        parsed = dmp_core_parse((dmp_bytes){item->data, item->size}, &limits, &view);
        expect = item->parse_expect == 0 ? DMP_OK :
                 item->parse_expect == 1 ? DMP_MALFORMED : DMP_UNSUPPORTED;
        if (parsed.status != expect) return fail(item->name, __LINE__, "parse status");
        if (parsed.status != DMP_OK) continue;
        if (view.fields.type != DMP_TYPE_FRAG_STATUS) return fail(item->name, __LINE__, "type");
        if (view.payload.size != 4U || view.trailer.size != 16U) return fail(item->name, __LINE__, "lengths");
        if (item->check_fields) {
            if (view.fields.seq != item->seq || view.fields.security.pn != item->pn ||
                view.fields.security.cipher != item->cipher) return fail(item->name, __LINE__, "fields");
        }
        policy.role = DMP_ROLE_ENDPOINT;
        policy.default_service = 1U;
        policy.selective32 = true;
        if (item->role_expect == 0) {
            if (dmp_core_check_role(&view, &policy) != DMP_OK) return fail(item->name, __LINE__, "role");
            policy.selective32 = false;
            if (dmp_core_check_role(&view, &policy) != DMP_UNSUPPORTED) return fail(item->name, __LINE__, "suite off");
            policy.role = DMP_ROLE_FORWARDER;
            policy.selective32 = false;
            if (dmp_core_check_role(&view, &policy) != DMP_OK) return fail(item->name, __LINE__, "forwarder");
            accepted++;
        } else if (item->role_expect == 1) {
            if (dmp_core_check_role(&view, &policy) != DMP_MALFORMED) return fail(item->name, __LINE__, "default service");
        } else if (item->role_expect == 2) {
            if (dmp_core_check_role(&view, &policy) != DMP_LIMIT_EXHAUSTED) return fail(item->name, __LINE__, "pn limit");
        }
    }
    (void)printf("frag_status structural cases %zu, role-accepted %zu; no AEAD claim\n",
                 sizeof frag_cases / sizeof frag_cases[0], accepted);
    return accepted == 0U ? 1 : 0;
}
