#include "harness.h"
#include "scenario.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed;

static void expect(int cond, const char *text, int line)
{
    if (!cond) {
        fprintf(stderr, "FAIL %s:%d %s\n", "test_port.c", line, text);
        g_failed++;
    }
}

#define EXPECT(cond) expect(!!(cond), #cond, __LINE__)

static harness_binding base_binding(void)
{
    harness_binding binding;
    memset(&binding, 0, sizeof binding);
    binding.encoded_mtu = 64;
    binding.frame_tx_ms = 1;
    binding.delay_ms[0] = 20;
    binding.delay_ms[1] = 20;
    binding.period_ms = 64;
    binding.width_ms = 42;
    binding.queue_ms = 64;
    binding.adapter_slots = 2;
    binding.borrow = 1;
    binding.synchronous_completion = 1;
    binding.until_ms = 100;
    binding.seed = 1;
    binding.loss_threshold = 0;
    memcpy(binding.sha256, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 65);
    memcpy(binding.seed_text, "00000001", 9);
    return binding;
}

static harness_action submit_action(uint32_t order, uint64_t at, uint32_t id, uint8_t link,
                                    const uint8_t *data, uint64_t not_after)
{
    harness_action action;
    memset(&action, 0, sizeof action);
    action.order = order;
    action.at_ms = at;
    action.id = id;
    action.link = link;
    action.data = data;
    action.data_len = 1;
    action.not_after_ms = not_after;
    return action;
}

static int run_trace(const harness_binding *binding, harness_action *actions, size_t nactions,
                     harness_fault *faults, size_t nfaults, char *trace, harness_result *result)
{
    return harness_execute(binding, actions, nactions, faults, nfaults, trace,
                           HARNESS_MAX_TRACE_BYTES, result);
}

static void test_known_values(void)
{
    uint8_t digest[32];
    static const uint8_t empty_sha[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    harness_sha256((const uint8_t *)"", 0, digest);
    EXPECT(memcmp(digest, empty_sha, 32) == 0);
    EXPECT(harness_xorshift32(1U) == 270369U);
    EXPECT(harness_trace_budget_self_check());
}

typedef struct cap {
    harness_adapter *adapter;
    int calls;
    int depth;
    dmp_tx_outcome outcome;
    dmp_tx_token token;
    dmp_time_ms when;
} cap;

static void on_cap(void *owner, dmp_tx_token token, dmp_tx_outcome outcome, dmp_time_ms when)
{
    cap *captured = owner;
    captured->calls++;
    captured->depth = harness_adapter_in_submit(captured->adapter);
    captured->outcome = outcome;
    captured->token = token;
    captured->when = when;
}

static void test_inline_and_ownership(void)
{
    harness_binding binding = base_binding();
    harness_adapter *adapter;
    dmp_transport *transport;
    dmp_tx_submission submission;
    cap captured;
    uint8_t buffer[1];
    uint8_t stored = 0;
    dmp_status status;
    binding.borrow = 0;
    binding.frame_tx_ms = 0;
    binding.synchronous_completion = 1;
    adapter = harness_adapter_create(&binding);
    EXPECT(adapter != NULL);
    transport = harness_adapter_transport(adapter);
    memset(&captured, 0, sizeof captured);
    captured.adapter = adapter;
    buffer[0] = 0x11;
    memset(&submission, 0, sizeof submission);
    submission.frame.data = buffer;
    submission.frame.size = 1;
    submission.not_after = 50;
    submission.complete = on_cap;
    submission.owner = &captured;
    harness_adapter_set_now(adapter, 0);
    harness_adapter_arm(adapter, 0, 7, 0, 0, 0, 0, 0, 0, 0);
    status = transport->submit(transport->context, &submission);
    EXPECT(status == DMP_OK);
    EXPECT(captured.calls == 1);
    EXPECT(captured.depth == 1);
    EXPECT(captured.outcome == DMP_TX_TRANSMITTED);
    EXPECT(captured.token.generation == 1U);
    buffer[0] = 0x22;
    EXPECT(harness_adapter_stored_byte(adapter, 7, &stored));
    EXPECT(stored == 0x11);
    harness_adapter_destroy(adapter);

    binding = base_binding();
    binding.borrow = 0;
    binding.frame_tx_ms = 1;
    adapter = harness_adapter_create(&binding);
    transport = harness_adapter_transport(adapter);
    memset(&captured, 0, sizeof captured);
    captured.adapter = adapter;
    buffer[0] = 0x33;
    submission.frame.data = buffer;
    submission.owner = &captured;
    harness_adapter_set_now(adapter, 0);
    harness_adapter_arm(adapter, 0, 8, 0, 0, 0, 5, 0, 0, 0);
    status = transport->submit(transport->context, &submission);
    EXPECT(status == DMP_OK);
    EXPECT(captured.calls == 0);
    buffer[0] = 0x44;
    harness_adapter_run(adapter);
    EXPECT(captured.calls == 1);
    EXPECT(captured.depth == 0);
    EXPECT(harness_adapter_stored_byte(adapter, 8, &stored));
    EXPECT(stored == 0x33);
    status = transport->cancel(transport->context, captured.token);
    EXPECT(status == DMP_STALE_HANDLE);
    EXPECT(captured.calls == 1);
    harness_adapter_destroy(adapter);

    binding = base_binding();
    adapter = harness_adapter_create(&binding);
    transport = harness_adapter_transport(adapter);
    memset(&captured, 0, sizeof captured);
    captured.adapter = adapter;
    buffer[0] = 0x55;
    submission.frame.data = buffer;
    submission.owner = &captured;
    harness_adapter_set_now(adapter, 0);
    harness_adapter_arm(adapter, 0, 9, 0, 0, 0, 0, 0, 0, 0);
    status = transport->submit(transport->context, &submission);
    EXPECT(status == DMP_OK);
    EXPECT(harness_adapter_borrowed(adapter, 9) == buffer);
    EXPECT(captured.calls == 0);
    harness_adapter_run(adapter);
    EXPECT(captured.calls == 1);
    EXPECT(harness_adapter_borrowed(adapter, 9) == NULL);
    harness_adapter_destroy(adapter);
}

static void test_schedule_traces(void)
{
    char *trace = malloc(HARNESS_MAX_TRACE_BYTES);
    harness_binding binding = base_binding();
    harness_result result;
    uint8_t byte = 0xab;
    harness_action actions[4];
    harness_fault faults[4];
    EXPECT(trace != NULL);
    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    EXPECT(run_trace(&binding, actions, 1, NULL, 0, trace, &result) == 0);
    EXPECT(result.exit_code == 0);
    EXPECT(result.accepted == 1 && result.rejected == 0 && result.delivered == 1);
    EXPECT(result.events == 4);
    EXPECT(strstr(trace, "\"event\":\"submit\",\"id\":1,\"link\":0,\"bytes\":1,\"status\":\"ok\",\"slot\":1,\"generation\":\"0000000000000001\"") != NULL);
    EXPECT(strstr(trace, "\"time_ms\":1,\"event\":\"terminal\"") != NULL);
    EXPECT(strstr(trace, "\"outcome\":\"transmitted\"") != NULL);
    EXPECT(strstr(trace, "\"time_ms\":21,\"event\":\"arrival\"") != NULL);
    EXPECT(strstr(trace, "\"copy\":0") != NULL);
    EXPECT(strstr(trace, "0xab") == NULL);
    EXPECT(strstr(trace, "\"ab\"") == NULL);

    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    memset(&actions[1], 0, sizeof actions[1]);
    actions[1].cancel = 1;
    actions[1].at_ms = 0;
    actions[1].order = 1;
    actions[1].id = 1;
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(result.delivered == 0);
    EXPECT(strstr(trace, "\"event\":\"cancel\",\"id\":1,\"status\":\"ok\"") != NULL);
    EXPECT(strstr(trace, "\"outcome\":\"cancelled_unsent\"") != NULL);
    EXPECT(strstr(trace, "\"event\":\"arrival\"") == NULL);

    memset(faults, 0, sizeof faults);
    faults[0].link = 0;
    faults[0].ordinal = 1;
    faults[0].completion_delay_ms = 10;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    actions[1].cancel = 1;
    actions[1].at_ms = 1;
    actions[1].order = 1;
    actions[1].id = 1;
    EXPECT(run_trace(&binding, actions, 2, faults, 1, trace, &result) == 0);
    EXPECT(result.exit_code == 0);
    EXPECT(strstr(trace, "\"time_ms\":1,\"event\":\"cancel\"") != NULL);
    EXPECT(strstr(trace, "\"outcome\":\"possibly_transmitted\"") != NULL);
    EXPECT(strstr(trace, "\"event\":\"arrival\"") != NULL);

    actions[0] = submit_action(0, 0, 1, 0, &byte, 0);
    EXPECT(run_trace(&binding, actions, 1, NULL, 0, trace, &result) == 0);
    EXPECT(result.rejected == 1 && result.accepted == 0 && result.terminal == 0);
    EXPECT(strstr(trace, "\"status\":\"deadline_expired\"") != NULL);

    binding.adapter_slots = 4;
    binding.until_ms = 200;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 200);
    actions[1] = submit_action(1, 0, 2, 0, &byte, 200);
    actions[2] = submit_action(2, 0, 3, 0, &byte, 200);
    EXPECT(run_trace(&binding, actions, 3, NULL, 0, trace, &result) == 0);
    EXPECT(result.accepted == 2 && result.rejected == 1);
    EXPECT(strstr(trace, "\"id\":3,\"link\":0,\"bytes\":1,\"status\":\"busy\"") != NULL);

    binding = base_binding();
    binding.adapter_slots = 1;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    actions[1] = submit_action(1, 0, 2, 1, &byte, 100);
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(result.accepted == 1 && result.rejected == 1);
    EXPECT(strstr(trace, "\"status\":\"busy\"") != NULL);

    binding = base_binding();
    binding.loss_threshold = 300000;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    EXPECT(run_trace(&binding, actions, 1, NULL, 0, trace, &result) == 0);
    EXPECT(result.accepted == 1 && result.delivered == 0);
    EXPECT(strstr(trace, "\"outcome\":\"transmitted\"") != NULL);
    EXPECT(strstr(trace, "\"event\":\"arrival\"") == NULL);

    binding = base_binding();
    binding.stress = 1;
    binding.until_ms = 80;
    memset(faults, 0, sizeof faults);
    faults[0].link = 0;
    faults[0].ordinal = 1;
    faults[0].duplicates = 1;
    actions[0] = submit_action(0, 0, 4, 0, &byte, 80);
    EXPECT(run_trace(&binding, actions, 1, faults, 1, trace, &result) == 0);
    EXPECT(result.delivered == 2);
    EXPECT(strstr(trace, "\"copy\":0") != NULL);
    EXPECT(strstr(trace, "\"copy\":1") != NULL);
    EXPECT(strstr(trace, "\"stress\":true") != NULL);

    binding.until_ms = 150;
    faults[0].duplicates = 0;
    faults[0].delivery_delay_ms = 80;
    faults[1].link = 0;
    faults[1].ordinal = 2;
    faults[1].delivery_delay_ms = 0;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 150);
    actions[1] = submit_action(1, 0, 2, 0, &byte, 150);
    EXPECT(run_trace(&binding, actions, 2, faults, 2, trace, &result) == 0);
    EXPECT(strstr(trace, "\"time_ms\":85,\"event\":\"arrival\",\"id\":2") != NULL);
    EXPECT(strstr(trace, "\"time_ms\":101,\"event\":\"arrival\",\"id\":1") != NULL);
    EXPECT(strstr(trace, "\"time_ms\":85") < strstr(trace, "\"time_ms\":101,\"event\":\"arrival\",\"id\":1"));

    binding = base_binding();
    faults[0].link = 0;
    faults[0].ordinal = 1;
    faults[0].duplicates = 0;
    faults[0].delivery_delay_ms = 0;
    faults[0].completion_delay_ms = 100;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    EXPECT(run_trace(&binding, actions, 1, faults, 1, trace, &result) == 0);
    EXPECT(result.pending_local == 1);
    EXPECT(result.pending_delivery == 0);
    EXPECT(result.delivered == 1);
    EXPECT(strstr(trace, "\"outcome\":\"possibly_transmitted\"") != NULL);

    binding.stress = 1;
    faults[0].delivery_delay_ms = 100;
    faults[0].completion_delay_ms = 100;
    EXPECT(run_trace(&binding, actions, 1, faults, 1, trace, &result) == 0);
    EXPECT(result.pending_local == 1 && result.pending_delivery == 1 && result.delivered == 0);

    binding = base_binding();
    faults[0].delivery_delay_ms = 0;
    faults[0].completion_delay_ms = 0;
    faults[0].ordinal = 2;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    EXPECT(run_trace(&binding, actions, 1, faults, 1, trace, &result) == 0);
    EXPECT(result.exit_code == 2);
    EXPECT(strstr(trace, "\"event\":\"submit\"") != NULL);
    EXPECT(strstr(trace, "\"outcome\":\"invalid_input\"") != NULL);
    EXPECT(strstr(trace, "\"exit_code\":2") != NULL);

    binding.until_ms = 80;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 80);
    memset(&actions[1], 0, sizeof actions[1]);
    actions[1].cancel = 1;
    actions[1].at_ms = 50;
    actions[1].order = 1;
    actions[1].id = 1;
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(strstr(trace, "\"status\":\"stale_handle\"") != NULL);
    EXPECT(result.terminal == 1);

    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    actions[1] = submit_action(1, 2, 2, 0, &byte, 100);
    binding = base_binding();
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(strstr(trace, "\"id\":1,\"link\":0,\"bytes\":1,\"status\":\"ok\",\"slot\":1,\"generation\":\"0000000000000001\"") != NULL);
    EXPECT(strstr(trace, "\"id\":2,\"link\":0,\"bytes\":1,\"status\":\"ok\",\"slot\":1,\"generation\":\"0000000000000002\"") != NULL);

    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    actions[1] = submit_action(1, 22, 2, 1, &byte, 100);
    actions[1].reply_to = 1;
    actions[1].return_slot = 1;
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(result.accepted == 2);
    EXPECT(strstr(trace, "\"time_ms\":22,\"event\":\"submit\",\"id\":2") != NULL);
    EXPECT(strstr(trace, "\"time_ms\":43,\"event\":\"arrival\",\"id\":2") != NULL);

    actions[1].at_ms = 23;
    actions[1].order = 1;
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(strstr(trace, "\"id\":2,\"link\":1,\"bytes\":1,\"status\":\"busy\"") != NULL);

    actions[1] = submit_action(1, 22, 2, 0, &byte, 100);
    actions[1].reply_to = 1;
    actions[1].return_slot = 1;
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(strstr(trace, "\"status\":\"invalid_argument\"") != NULL);

    binding = base_binding();
    binding.frame_tx_ms = 0;
    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    EXPECT(run_trace(&binding, actions, 1, NULL, 0, trace, &result) == 0);
    EXPECT(result.exit_code == 0);
    EXPECT(result.terminal == 1);
    EXPECT(strstr(trace, "\"time_ms\":0,\"event\":\"terminal\"") != NULL);
    EXPECT(strstr(trace, "\"outcome\":\"transmitted\"") != NULL);
    EXPECT(strstr(trace, "\"outcome\":\"possibly_transmitted\"") == NULL);
    {
        const char *terminal_at = strstr(trace, "\"event\":\"terminal\"");
        const char *arrival_at = strstr(trace, "\"event\":\"arrival\"");
        EXPECT(terminal_at != NULL && arrival_at != NULL && terminal_at < arrival_at);
    }

    actions[0] = submit_action(0, 0, 1, 0, &byte, 100);
    memset(&actions[1], 0, sizeof actions[1]);
    actions[1].cancel = 1;
    actions[1].at_ms = 0;
    actions[1].order = 1;
    actions[1].id = 1;
    EXPECT(run_trace(&binding, actions, 2, NULL, 0, trace, &result) == 0);
    EXPECT(strstr(trace, "\"outcome\":\"cancelled_unsent\"") != NULL);
    EXPECT(strstr(trace, "\"outcome\":\"transmitted\"") == NULL);
    EXPECT(strstr(trace, "\"event\":\"arrival\"") == NULL);
    free(trace);
}

static void test_zero_duration_terminal_follows_start(void)
{
    harness_binding binding = base_binding();
    harness_adapter *adapter;
    dmp_transport *transport;
    dmp_tx_submission submission;
    cap captured;
    uint8_t buffer[1];
    uint8_t stored = 0;
    dmp_status status;
    binding.borrow = 1;
    binding.frame_tx_ms = 0;
    binding.synchronous_completion = 1;
    adapter = harness_adapter_create(&binding);
    EXPECT(adapter != NULL);
    transport = harness_adapter_transport(adapter);
    memset(&captured, 0, sizeof captured);
    captured.adapter = adapter;
    buffer[0] = 0x55;
    memset(&submission, 0, sizeof submission);
    submission.frame.data = buffer;
    submission.frame.size = 1;
    submission.not_after = 100;
    submission.complete = on_cap;
    submission.owner = &captured;
    harness_adapter_set_now(adapter, 0);
    harness_adapter_arm(adapter, 0, 11, 0, 0, 0, 0, 0, 0, 0);
    status = transport->submit(transport->context, &submission);
    EXPECT(status == DMP_OK);
    EXPECT(captured.calls == 0);
    buffer[0] = 0x66;
    harness_adapter_run(adapter);
    EXPECT(captured.calls == 1);
    EXPECT(captured.depth == 0);
    EXPECT(captured.outcome == DMP_TX_TRANSMITTED);
    EXPECT(captured.when == 0);
    EXPECT(harness_adapter_stored_byte(adapter, 11, &stored));
    EXPECT(stored == 0x66);
    EXPECT(harness_adapter_borrowed(adapter, 11) == NULL);
    harness_adapter_destroy(adapter);

    binding = base_binding();
    binding.borrow = 0;
    binding.frame_tx_ms = 0;
    binding.synchronous_completion = 1;
    adapter = harness_adapter_create(&binding);
    transport = harness_adapter_transport(adapter);
    memset(&captured, 0, sizeof captured);
    captured.adapter = adapter;
    buffer[0] = 0x77;
    submission.frame.data = buffer;
    submission.owner = &captured;
    harness_adapter_set_now(adapter, 1);
    harness_adapter_arm(adapter, 0, 12, 0, 0, 0, 0, 0, 0, 0);
    status = transport->submit(transport->context, &submission);
    EXPECT(status == DMP_OK);
    EXPECT(captured.calls == 0);
    harness_adapter_run(adapter);
    EXPECT(captured.calls == 1);
    EXPECT(captured.depth == 0);
    EXPECT(captured.outcome == DMP_TX_TRANSMITTED);
    EXPECT(captured.when == 64);
    harness_adapter_destroy(adapter);
}

static int parse_text(const char *text, harness_plan *plan)
{
    return scenario_parse((const uint8_t *)text, strlen(text), plan);
}

static void test_schedule_order_and_nul_strings(void)
{
    harness_plan plan;
    static const char earlier_submit_later_in_array[] =
        "{\"interface_version\":1,\"mode\":\"transport-selftest\","
        "\"manifest_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"seed\":\"00000001\",\"until_ms\":1000,\"stress\":false,\"loss_threshold\":0,"
        "\"actions\":[{\"at_ms\":10,\"op\":\"cancel\",\"id\":1},"
        "{\"at_ms\":0,\"op\":\"submit\",\"link\":0,\"id\":1,\"data_hex\":\"aa\","
        "\"not_after_ms\":1000,\"reply_to\":0,\"return_slot\":0}],\"faults\":[]}";
    static const char same_time_submit_first[] =
        "{\"interface_version\":1,\"mode\":\"transport-selftest\","
        "\"manifest_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"seed\":\"00000001\",\"until_ms\":1000,\"stress\":false,\"loss_threshold\":0,"
        "\"actions\":[{\"at_ms\":0,\"op\":\"submit\",\"link\":0,\"id\":1,\"data_hex\":\"aa\","
        "\"not_after_ms\":1000,\"reply_to\":0,\"return_slot\":0},"
        "{\"at_ms\":0,\"op\":\"cancel\",\"id\":1}],\"faults\":[]}";
    static const char same_time_cancel_first[] =
        "{\"interface_version\":1,\"mode\":\"transport-selftest\","
        "\"manifest_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"seed\":\"00000001\",\"until_ms\":1000,\"stress\":false,\"loss_threshold\":0,"
        "\"actions\":[{\"at_ms\":0,\"op\":\"cancel\",\"id\":1},"
        "{\"at_ms\":0,\"op\":\"submit\",\"link\":0,\"id\":1,\"data_hex\":\"aa\","
        "\"not_after_ms\":1000,\"reply_to\":0,\"return_slot\":0}],\"faults\":[]}";
    static const char mode_nul[] =
        "{\"interface_version\":1,\"mode\":\"transport-selftest\\u0000\","
        "\"manifest_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"seed\":\"00000001\",\"until_ms\":1000,\"stress\":false,\"loss_threshold\":0,"
        "\"actions\":[],\"faults\":[]}";
    static const char op_nul[] =
        "{\"interface_version\":1,\"mode\":\"transport-selftest\","
        "\"manifest_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"seed\":\"00000001\",\"until_ms\":1000,\"stress\":false,\"loss_threshold\":0,"
        "\"actions\":[{\"at_ms\":0,\"op\":\"submit\\u0000\",\"link\":0,\"id\":1,\"data_hex\":\"aa\","
        "\"not_after_ms\":1000,\"reply_to\":0,\"return_slot\":0}],\"faults\":[]}";
    static const char key_nul[] =
        "{\"interface_version\":1,\"mode\":\"transport-selftest\","
        "\"manifest_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"seed\":\"00000001\",\"until_ms\":1000,\"stress\":false,\"loss_threshold\":0,"
        "\"actions\":[{\"at_ms\":0,\"op\":\"submit\",\"link\":0,\"id\\u0000\":1,\"data_hex\":\"aa\","
        "\"not_after_ms\":1000,\"reply_to\":0,\"return_slot\":0}],\"faults\":[]}";
    static const char hex_nul[] =
        "{\"interface_version\":1,\"mode\":\"transport-selftest\","
        "\"manifest_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"seed\":\"00000001\",\"until_ms\":1000,\"stress\":false,\"loss_threshold\":0,"
        "\"actions\":[{\"at_ms\":0,\"op\":\"submit\",\"link\":0,\"id\":1,\"data_hex\":\"aa\\u0000\","
        "\"not_after_ms\":1000,\"reply_to\":0,\"return_slot\":0}],\"faults\":[]}";
    EXPECT(parse_text(earlier_submit_later_in_array, &plan) == 0);
    EXPECT(plan.nactions == 2);
    EXPECT(plan.actions[0].cancel == 1);
    EXPECT(plan.actions[1].cancel == 0);
    EXPECT(plan.actions[1].at_ms == 0);
    scenario_plan_free(&plan);
    EXPECT(parse_text(same_time_submit_first, &plan) == 0);
    scenario_plan_free(&plan);
    EXPECT(parse_text(same_time_cancel_first, &plan) == 2);
    EXPECT(parse_text(mode_nul, &plan) == 2);
    EXPECT(parse_text(op_nul, &plan) == 2);
    EXPECT(parse_text(key_nul, &plan) == 2);
    EXPECT(parse_text(hex_nul, &plan) == 2);
}

int main(void)
{
    test_known_values();
    test_inline_and_ownership();
    test_schedule_traces();
    test_zero_duration_terminal_follows_start();
    test_schedule_order_and_nul_strings();
    if (g_failed != 0) {
        fprintf(stderr, "%d harness port checks failed\n", g_failed);
        return 1;
    }
    return 0;
}
