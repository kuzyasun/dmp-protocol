#include "scenario.h"

#include "json.h"

#include <stdlib.h>
#include <string.h>

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static int key_count(const json_value *object)
{
    return object != NULL && object->type == JSON_OBJECT ? (int)object->count : -1;
}

static int has_only(const json_value *object, const char **keys, size_t nkeys)
{
    size_t i;
    if (key_count(object) != (int)nkeys) {
        return 0;
    }
    for (i = 0; i < nkeys; i++) {
        if (json_object_get(object, keys[i]) == NULL) {
            return 0;
        }
    }
    return 1;
}

static int u64_of(const json_value *v, uint64_t *out)
{
    if (v == NULL || v->type != JSON_INT || v->negative || !v->u64_ok) {
        return 0;
    }
    *out = v->u64;
    return 1;
}

static int hex_bytes(const char *text, size_t n, uint8_t *dest, size_t *out_len)
{
    size_t i;
    if (text == NULL || n == 0U || (n & 1U) != 0U) {
        return 0;
    }
    for (i = 0; i < n; i += 2U) {
        int hi = hex_nibble(text[i]);
        int lo = hex_nibble(text[i + 1U]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        dest[i / 2U] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2U;
    return 1;
}

void scenario_plan_free(harness_plan *plan)
{
    if (plan == NULL) {
        return;
    }
    free(plan->actions);
    free(plan->faults);
    free(plan->payload);
    memset(plan, 0, sizeof *plan);
}

int scenario_parse(const uint8_t *bytes, size_t length, harness_plan *plan)
{
    static const char *root_keys[] = {
        "interface_version", "mode", "manifest_sha256", "seed", "until_ms", "stress",
        "loss_threshold", "actions", "faults"
    };
    static const char *submit_keys[] = {
        "at_ms", "op", "link", "id", "data_hex", "not_after_ms", "reply_to", "return_slot"
    };
    static const char *cancel_keys[] = {"at_ms", "op", "id"};
    static const char *fault_keys[] = {
        "link", "ordinal", "drop", "duplicates", "delivery_delay_ms", "completion_delay_ms"
    };
    json_arena *arena;
    json_error error;
    json_value *root;
    const json_value *actions;
    const json_value *faults;
    const json_value *mode;
    const json_value *sha;
    const json_value *seed;
    const json_value *stress;
    uint64_t version = 0;
    uint64_t until_ms = 0;
    uint64_t loss = 0;
    uint32_t seed_value = 0;
    size_t i;
    memset(plan, 0, sizeof *plan);
    memset(&error, 0, sizeof error);
    if (bytes == NULL || length == 0U || length > HARNESS_SCENARIO_MAX_BYTES) {
        return 2;
    }
    if (length >= 3U && bytes[0] == 0xefU && bytes[1] == 0xbbU && bytes[2] == 0xbfU) {
        return 2;
    }
    arena = json_arena_create(16U * 1024U * 1024U);
    if (arena == NULL) {
        return 4;
    }
    root = json_parse(arena, bytes, length, 24U, &error);
    if (root == NULL || root->type != JSON_OBJECT || !has_only(root, root_keys, 9U)) {
        json_arena_destroy(arena);
        return 2;
    }
    if (!u64_of(json_object_get(root, "interface_version"), &version) || version != 1U ||
        !u64_of(json_object_get(root, "until_ms"), &until_ms) || until_ms < 1U ||
        until_ms > HARNESS_MAX_VIRTUAL_MS ||
        !u64_of(json_object_get(root, "loss_threshold"), &loss) || loss > 4294967296ULL) {
        json_arena_destroy(arena);
        return 2;
    }
    mode = json_object_get(root, "mode");
    sha = json_object_get(root, "manifest_sha256");
    seed = json_object_get(root, "seed");
    stress = json_object_get(root, "stress");
    actions = json_object_get(root, "actions");
    faults = json_object_get(root, "faults");
    if (mode == NULL || mode->type != JSON_STRING ||
        !json_text_eq(mode->text, mode->text_len, "transport-selftest") ||
        sha == NULL || sha->type != JSON_STRING || sha->text_len != 64U ||
        seed == NULL || seed->type != JSON_STRING || seed->text_len != 8U ||
        stress == NULL || stress->type != JSON_BOOL || actions == NULL || actions->type != JSON_ARRAY ||
        faults == NULL || faults->type != JSON_ARRAY) {
        json_arena_destroy(arena);
        return 2;
    }
    for (i = 0; i < 64U; i++) {
        char c = sha->text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            json_arena_destroy(arena);
            return 2;
        }
    }
    for (i = 0; i < 8U; i++) {
        int nibble = hex_nibble(seed->text[i]);
        if (nibble < 0) {
            json_arena_destroy(arena);
            return 2;
        }
        seed_value = (seed_value << 4) | (uint32_t)nibble;
    }
    if (seed_value == 0U) {
        json_arena_destroy(arena);
        return 2;
    }
    if (actions->count > HARNESS_MAX_ACTIONS || faults->count > HARNESS_MAX_FAULTS) {
        json_arena_destroy(arena);
        return 3;
    }
    plan->actions = calloc(actions->count == 0U ? 1U : actions->count, sizeof *plan->actions);
    plan->faults = calloc(faults->count == 0U ? 1U : faults->count, sizeof *plan->faults);
    plan->payload = malloc(length + 1U);
    if (plan->actions == NULL || plan->faults == NULL || plan->payload == NULL) {
        scenario_plan_free(plan);
        json_arena_destroy(arena);
        return 4;
    }
    plan->stress = stress->boolean;
    plan->until_ms = until_ms;
    plan->loss_threshold = loss;
    plan->seed = seed_value;
    memcpy(plan->seed_text, seed->text, 8U);
    plan->seed_text[8] = '\0';
    memcpy(plan->sha256, sha->text, 64U);
    plan->sha256[64] = '\0';
    plan->nactions = actions->count;
    plan->nfaults = faults->count;
    for (i = 0; i < faults->count; i++) {
        const json_value *item = faults->items[i];
        uint64_t link = 0;
        uint64_t ordinal = 0;
        uint64_t duplicates = 0;
        uint64_t delivery = 0;
        uint64_t completion = 0;
        const json_value *drop;
        size_t j;
        if (!has_only(item, fault_keys, 6U) || !u64_of(json_object_get(item, "link"), &link) ||
            (link != 0U && link != 1U) || !u64_of(json_object_get(item, "ordinal"), &ordinal) ||
            ordinal < 1U || ordinal > 4294967295ULL ||
            !u64_of(json_object_get(item, "duplicates"), &duplicates) || duplicates > 1U ||
            !u64_of(json_object_get(item, "delivery_delay_ms"), &delivery) || delivery > until_ms ||
            !u64_of(json_object_get(item, "completion_delay_ms"), &completion) || completion > until_ms) {
            scenario_plan_free(plan);
            json_arena_destroy(arena);
            return 2;
        }
        drop = json_object_get(item, "drop");
        if (drop == NULL || drop->type != JSON_BOOL) {
            scenario_plan_free(plan);
            json_arena_destroy(arena);
            return 2;
        }
        for (j = 0; j < i; j++) {
            if (plan->faults[j].link == (uint8_t)link && plan->faults[j].ordinal == (uint32_t)ordinal) {
                scenario_plan_free(plan);
                json_arena_destroy(arena);
                return 2;
            }
        }
        if (!plan->stress && (delivery != 0U || duplicates != 0U)) {
            scenario_plan_free(plan);
            json_arena_destroy(arena);
            return 2;
        }
        plan->faults[i].link = (uint8_t)link;
        plan->faults[i].ordinal = (uint32_t)ordinal;
        plan->faults[i].drop = drop->boolean;
        plan->faults[i].duplicates = (uint8_t)duplicates;
        plan->faults[i].delivery_delay_ms = (uint32_t)delivery;
        plan->faults[i].completion_delay_ms = (uint32_t)completion;
    }
    for (i = 0; i < actions->count; i++) {
        const json_value *item = actions->items[i];
        const json_value *op;
        uint64_t at = 0;
        uint64_t id = 0;
        size_t j;
        if (item == NULL || item->type != JSON_OBJECT) {
            scenario_plan_free(plan);
            json_arena_destroy(arena);
            return 2;
        }
        op = json_object_get(item, "op");
        if (op == NULL || op->type != JSON_STRING || !u64_of(json_object_get(item, "at_ms"), &at) ||
            at > until_ms || !u64_of(json_object_get(item, "id"), &id) || id < 1U || id > 4294967295ULL) {
            scenario_plan_free(plan);
            json_arena_destroy(arena);
            return 2;
        }
        plan->actions[i].at_ms = at;
        plan->actions[i].order = (uint32_t)i;
        plan->actions[i].id = (uint32_t)id;
        if (json_text_eq(op->text, op->text_len, "cancel")) {
            if (!has_only(item, cancel_keys, 3U)) {
                scenario_plan_free(plan);
                json_arena_destroy(arena);
                return 2;
            }
            plan->actions[i].cancel = 1;
            continue;
        }
        if (!json_text_eq(op->text, op->text_len, "submit") || !has_only(item, submit_keys, 8U)) {
            scenario_plan_free(plan);
            json_arena_destroy(arena);
            return 2;
        }
        {
            uint64_t link = 0;
            uint64_t not_after = 0;
            uint64_t reply = 0;
            uint64_t slot = 0;
            const json_value *data;
            size_t decoded = 0;
            if (!u64_of(json_object_get(item, "link"), &link) || (link != 0U && link != 1U) ||
                !u64_of(json_object_get(item, "not_after_ms"), &not_after) || not_after < at ||
                not_after > until_ms || !u64_of(json_object_get(item, "reply_to"), &reply) ||
                reply > 4294967295ULL || !u64_of(json_object_get(item, "return_slot"), &slot) ||
                slot > 2U) {
                scenario_plan_free(plan);
                json_arena_destroy(arena);
                return 2;
            }
            if ((reply == 0U && slot != 0U) || (reply != 0U && slot == 0U)) {
                scenario_plan_free(plan);
                json_arena_destroy(arena);
                return 2;
            }
            for (j = 0; j < i; j++) {
                if (!plan->actions[j].cancel && plan->actions[j].id == (uint32_t)id) {
                    scenario_plan_free(plan);
                    json_arena_destroy(arena);
                    return 2;
                }
            }
            data = json_object_get(item, "data_hex");
            if (data == NULL || data->type != JSON_STRING) {
                scenario_plan_free(plan);
                json_arena_destroy(arena);
                return 2;
            }
            if (plan->payload_len > length || data->text_len / 2U > length - plan->payload_len ||
                !hex_bytes(data->text, data->text_len, plan->payload + plan->payload_len, &decoded)) {
                scenario_plan_free(plan);
                json_arena_destroy(arena);
                return 2;
            }
            plan->actions[i].link = (uint8_t)link;
            plan->actions[i].data = plan->payload + plan->payload_len;
            plan->actions[i].data_len = decoded;
            plan->actions[i].not_after_ms = not_after;
            plan->actions[i].reply_to = (uint32_t)reply;
            plan->actions[i].return_slot = (uint8_t)slot;
            plan->payload_len += decoded;
        }
    }
    for (i = 0; i < actions->count; i++) {
        size_t j;
        int found = 0;
        if (!plan->actions[i].cancel) {
            continue;
        }
        for (j = 0; j < actions->count; j++) {
            const harness_action *prior = &plan->actions[j];
            if (j == i || prior->cancel || prior->id != plan->actions[i].id) {
                continue;
            }
            if (prior->at_ms < plan->actions[i].at_ms ||
                (prior->at_ms == plan->actions[i].at_ms && prior->order < plan->actions[i].order)) {
                found = 1;
                break;
            }
        }
        if (!found) {
            scenario_plan_free(plan);
            json_arena_destroy(arena);
            return 2;
        }
    }
    json_arena_destroy(arena);
    return 0;
}
