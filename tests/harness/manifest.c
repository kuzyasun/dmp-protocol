#include "manifest.h"

#include "json.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct vstate {
    int failed;
    int internal;
    char code[32];
    char path[192];
} vstate;

typedef struct num {
    uint64_t v;
    int big;
} num;

static void fail(vstate *st, const char *code, const char *path)
{
    if (st->failed) {
        return;
    }
    st->failed = 1;
    if (strcmp(code, "internal") == 0) {
        st->internal = 1;
    }
    snprintf(st->code, sizeof st->code, "%s", code);
    snprintf(st->path, sizeof st->path, "%s", path);
}

static int need(vstate *st, int cond, const char *code, const char *path)
{
    if (st->failed) {
        return 0;
    }
    if (!cond) {
        fail(st, code, path);
        return 0;
    }
    return 1;
}

static num nu(uint64_t v)
{
    num n;
    n.v = v;
    n.big = 0;
    return n;
}

static num nadd(num a, num b)
{
    num n;
    if (a.big || b.big || a.v > UINT64_MAX - b.v) {
        n.v = 0;
        n.big = 1;
        return n;
    }
    n.v = a.v + b.v;
    n.big = 0;
    return n;
}

static num nmul(num a, num b)
{
    num n;
    if (a.big || b.big || (a.v != 0U && b.v > UINT64_MAX / a.v)) {
        n.v = 0;
        n.big = 1;
        return n;
    }
    n.v = a.v * b.v;
    n.big = 0;
    return n;
}

static int ge_u(uint64_t left, num right)
{
    return !right.big && left >= right.v;
}

static int le_u(uint64_t left, num right)
{
    return right.big || left <= right.v;
}

static uint64_t uleb_width(uint64_t value)
{
    uint32_t bits = 0;
    uint64_t cursor = value;
    uint64_t width;
    while (cursor > 0U) {
        bits++;
        cursor >>= 1;
    }
    width = ((uint64_t)bits + 6U) / 7U;
    return width == 0U ? 1U : width;
}

static int identifier_ok(const char *text, size_t text_len)
{
    size_t i;
    if (text == NULL || text_len == 0U) {
        return 0;
    }
    for (i = 0; i < text_len; i++) {
        unsigned char c = (unsigned char)text[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':' ||
                 c == '/' || c == '+' || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

static int enum_match(const json_value *value, const json_value *candidate)
{
    if (value->type != candidate->type) {
        return 0;
    }
    if (value->type == JSON_BOOL) {
        return value->boolean == candidate->boolean;
    }
    if (value->type == JSON_INT) {
        return value->negative == candidate->negative && value->u64_ok &&
               candidate->u64_ok && value->u64 == candidate->u64 &&
               value->negative == 0;
    }
    if (value->type == JSON_STRING) {
        return value->text_len == candidate->text_len &&
               (value->text_len == 0U || memcmp(value->text, candidate->text, value->text_len) == 0);
    }
    return 0;
}

static int keyword_ok(const char *key, size_t key_len)
{
    static const char *names[] = {
        "$schema", "$id", "type", "enum", "minimum", "maximum", "minLength",
        "maxLength", "pattern", "additionalProperties", "required", "properties",
        "minItems", "maxItems", "items"
    };
    size_t i;
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (json_text_eq(key, key_len, names[i])) {
            return 1;
        }
    }
    return 0;
}

static void schema_apply(vstate *st, const json_value *value, const json_value *spec,
                         const char *path);

static int spec_u64(const json_value *spec, const char *key, uint64_t *out)
{
    const json_value *v = json_object_get(spec, key);
    if (v == NULL || v->type != JSON_INT || v->negative || !v->u64_ok) {
        return 0;
    }
    *out = v->u64;
    return 1;
}

static void schema_apply(vstate *st, const json_value *value, const json_value *spec,
                         const char *path)
{
    const json_value *type_v;
    const json_value *enum_v;
    const char *kind = NULL;
    size_t i;
    if (st->failed) {
        return;
    }
    if (spec == NULL || spec->type != JSON_OBJECT || value == NULL) {
        fail(st, "internal", path);
        return;
    }
    for (i = 0; i < spec->count; i++) {
        if (!keyword_ok(spec->keys[i], spec->key_lens[i])) {
            fail(st, "internal", path);
            return;
        }
    }
    enum_v = json_object_get(spec, "enum");
    if (enum_v != NULL) {
        int matched = 0;
        if (enum_v->type != JSON_ARRAY) {
            fail(st, "internal", path);
            return;
        }
        for (i = 0; i < enum_v->count; i++) {
            if (enum_match(value, enum_v->items[i])) {
                matched = 1;
                break;
            }
        }
        if (!need(st, matched, "schema", path)) {
            return;
        }
    }
    type_v = json_object_get(spec, "type");
    if (type_v != NULL) {
        if (type_v->type != JSON_STRING) {
            fail(st, "internal", path);
            return;
        }
        kind = type_v->text;
        if (json_text_eq(kind, type_v->text_len, "object")) {
            if (!need(st, value->type == JSON_OBJECT, "schema", path)) {
                return;
            }
        } else if (json_text_eq(kind, type_v->text_len, "array")) {
            if (!need(st, value->type == JSON_ARRAY, "schema", path)) {
                return;
            }
        } else if (json_text_eq(kind, type_v->text_len, "integer")) {
            if (!need(st, value->type == JSON_INT, "schema", path)) {
                return;
            }
        } else if (json_text_eq(kind, type_v->text_len, "string")) {
            if (!need(st, value->type == JSON_STRING, "schema", path)) {
                return;
            }
        } else if (json_text_eq(kind, type_v->text_len, "boolean")) {
            if (!need(st, value->type == JSON_BOOL, "schema", path)) {
                return;
            }
        } else {
            fail(st, "internal", path);
            return;
        }
    }
    if (type_v != NULL && json_text_eq(type_v->text, type_v->text_len, "object")) {
        const json_value *props;
        const json_value *req;
        const json_value *add;
        char child[192];
        props = json_object_get(spec, "properties");
        req = json_object_get(spec, "required");
        add = json_object_get(spec, "additionalProperties");
        if (add == NULL || add->type != JSON_BOOL || add->boolean) {
            fail(st, "internal", path);
            return;
        }
        if (props == NULL || props->type != JSON_OBJECT || req == NULL ||
            req->type != JSON_ARRAY) {
            fail(st, "internal", path);
            return;
        }
        for (i = 0; i < req->count; i++) {
            if (req->items[i]->type != JSON_STRING ||
                json_object_get_n(value, req->items[i]->text, req->items[i]->text_len) == NULL) {
                fail(st, "schema", path);
                return;
            }
        }
        for (i = 0; i < value->count; i++) {
            if (json_object_get_n(props, value->keys[i], value->key_lens[i]) == NULL) {
                fail(st, "schema", path);
                return;
            }
        }
        for (i = 0; i < value->count; i++) {
            int wrote = snprintf(child, sizeof child, "%s.%s", path, value->keys[i]);
            if (wrote < 0 || (size_t)wrote >= sizeof child) {
                fail(st, "internal", path);
                return;
            }
            schema_apply(st, value->items[i],
                         json_object_get_n(props, value->keys[i], value->key_lens[i]), child);
            if (st->failed) {
                return;
            }
        }
    } else if (type_v != NULL && json_text_eq(type_v->text, type_v->text_len, "array")) {
        const json_value *items;
        uint64_t min_items = 0;
        uint64_t max_items = 0;
        char child[192];
        items = json_object_get(spec, "items");
        if (items == NULL || !spec_u64(spec, "minItems", &min_items) ||
            !spec_u64(spec, "maxItems", &max_items)) {
            fail(st, "internal", path);
            return;
        }
        if (!need(st, value->count >= min_items && value->count <= max_items, "schema", path)) {
            return;
        }
        for (i = 0; i < value->count; i++) {
            int wrote = snprintf(child, sizeof child, "%s[%u]", path, (unsigned)i);
            if (wrote < 0 || (size_t)wrote >= sizeof child) {
                fail(st, "internal", path);
                return;
            }
            schema_apply(st, value->items[i], items, child);
            if (st->failed) {
                return;
            }
        }
    } else if (type_v != NULL && json_text_eq(type_v->text, type_v->text_len, "integer")) {
        uint64_t min_v = 0;
        uint64_t max_v = 0;
        if (!spec_u64(spec, "minimum", &min_v) || !spec_u64(spec, "maximum", &max_v)) {
            fail(st, "internal", path);
            return;
        }
        if (value->negative || !value->u64_ok || value->u64 < min_v || value->u64 > max_v) {
            fail(st, "schema", path);
        }
    } else if (type_v != NULL && json_text_eq(type_v->text, type_v->text_len, "string")) {
        uint64_t min_v = 0;
        uint64_t max_v = 0;
        const json_value *pattern = json_object_get(spec, "pattern");
        if (!spec_u64(spec, "minLength", &min_v) || !spec_u64(spec, "maxLength", &max_v) ||
            pattern == NULL || pattern->type != JSON_STRING) {
            fail(st, "internal", path);
            return;
        }
        if (!need(st, value->codepoints >= min_v && value->codepoints <= max_v, "schema", path)) {
            return;
        }
        if (!json_text_eq(pattern->text, pattern->text_len, "^[A-Za-z0-9_.:/+-]+$")) {
            fail(st, "internal", path);
            return;
        }
        if (!identifier_ok(value->text, value->text_len)) {
            fail(st, "schema", path);
        }
    }
}

static int mu(vstate *st, const json_value *v, uint64_t *out)
{
    if (st->failed) {
        return 0;
    }
    if (v == NULL || v->type != JSON_INT || v->negative || !v->u64_ok) {
        fail(st, "internal", "$");
        return 0;
    }
    *out = v->u64;
    return 1;
}

static uint64_t fu(vstate *st, const json_value *obj, const char *key)
{
    uint64_t value = 0;
    if (!mu(st, json_object_get(obj, key), &value)) {
        return 0;
    }
    return value;
}

static const char *fs(vstate *st, const json_value *obj, const char *key)
{
    const json_value *v;
    if (st->failed) {
        return "";
    }
    v = json_object_get(obj, key);
    if (v == NULL || v->type != JSON_STRING) {
        fail(st, "internal", "$");
        return "";
    }
    return v->text;
}

static int fb(vstate *st, const json_value *obj, const char *key)
{
    const json_value *v;
    if (st->failed) {
        return 0;
    }
    v = json_object_get(obj, key);
    if (v == NULL || v->type != JSON_BOOL) {
        fail(st, "internal", "$");
        return 0;
    }
    return v->boolean;
}

static const json_value *fo(vstate *st, const json_value *obj, const char *key)
{
    const json_value *v;
    if (st->failed) {
        return NULL;
    }
    v = json_object_get(obj, key);
    if (v == NULL || (v->type != JSON_OBJECT && v->type != JSON_ARRAY)) {
        fail(st, "internal", "$");
        return NULL;
    }
    return v;
}

static const json_value *limits_of(const json_value *m)
{
    return json_object_get(m, "limits");
}

static void check_identity(vstate *st, const json_value *m, int *direct_out, int *selective_out)
{
    const json_value *profile = fo(st, m, "profile");
    const json_value *binding = fo(st, m, "binding");
    const json_value *ident = fo(st, m, "identity");
    const json_value *services = fo(st, m, "services");
    const json_value *relays = fo(st, m, "relays");
    const json_value *limits = fo(st, m, "limits");
    const json_value *nodes;
    const char *pid;
    const char *owner;
    int direct;
    int test;
    int selective;
    uint64_t revision;
    uint64_t ttl;
    uint64_t producer;
    uint64_t seen_ids[2];
    size_t i;
    if (st->failed) {
        return;
    }
    pid = fs(st, profile, "id");
    owner = fs(st, profile, "owner");
    revision = fu(st, profile, "revision");
    if (st->failed) {
        return;
    }
    direct = strcmp(pid, "DIRECT-1") == 0;
    selective = strcmp(pid, "RADIO-1") == 0;
    test = strcmp(pid, "TEST-RADIO-RETRY-ALL") == 0;
    if (!need(st, (test ? strcmp(owner, "DMP-test") == 0 : strcmp(owner, "DMP-reference") == 0) &&
                     (test ? revision == 1U : revision == 4U),
              "profile", "$.profile")) {
        return;
    }
    {
        const char *id = fs(st, binding, "id");
        const char *kind = fs(st, binding, "kind");
        const char *topology = fs(st, binding, "topology");
        const char *context = fs(st, binding, "context");
        int match = direct ? (strcmp(id, "DMP-test/SIM-STREAM-R") == 0 &&
                              strcmp(kind, "stream-r") == 0 &&
                              strcmp(topology, "point-to-point") == 0 &&
                              strcmp(context, "association") == 0)
                           : (strcmp(id, "DMP-test/SIM-PACKET") == 0 &&
                              strcmp(kind, "packet") == 0 &&
                              strcmp(topology, "static-unicast") == 0 &&
                              strcmp(context, "origin-explicit") == 0);
        if (!need(st, match, "profile", "$.binding")) {
            return;
        }
    }
    ttl = fu(st, binding, "ttl");
    if (st->failed) {
        return;
    }
    if (!need(st, (!direct || (relays->count == 0U && ttl == 0U)) && ttl >= relays->count,
              "profile", "$.binding.ttl")) {
        return;
    }
    nodes = fo(st, ident, "nodes");
    producer = fu(st, ident, "sample_producer");
    if (st->failed || nodes == NULL || nodes->type != JSON_ARRAY) {
        fail(st, "internal", "$.identity");
        return;
    }
    {
        uint64_t ids[6];
        size_t nids = 0;
        size_t j;
        int producer_ok = 0;
        for (i = 0; i < nodes->count && i < 2U; i++) {
            uint64_t id = 0;
            if (!mu(st, nodes->items[i], &id)) {
                return;
            }
            ids[nids++] = id;
            if (id == producer) {
                producer_ok = 1;
            }
        }
        for (i = 0; i < relays->count && nids < 6U; i++) {
            uint64_t id = fu(st, relays->items[i], "node");
            if (st->failed) {
                return;
            }
            ids[nids++] = id;
        }
        for (i = 0; i < nids; i++) {
            for (j = i + 1U; j < nids; j++) {
                if (ids[i] == ids[j]) {
                    fail(st, "identity", "$.identity");
                    return;
                }
            }
        }
        if (!need(st, producer_ok, "identity", "$.identity")) {
            return;
        }
    }
    if (services->count != 2U) {
        fail(st, "service", "$.services");
        return;
    }
    for (i = 0; i < 2U; i++) {
        seen_ids[i] = fu(st, services->items[i], "id");
    }
    if (st->failed) {
        return;
    }
    if (!need(st, (seen_ids[0] == 1U && seen_ids[1] == 2U) ||
                     (seen_ids[0] == 2U && seen_ids[1] == 1U),
              "service", "$.services")) {
        return;
    }
    for (i = 0; i < services->count; i++) {
        const json_value *service = services->items[i];
        const json_value *acl;
        char path[64];
        uint64_t sid = fu(st, service, "id");
        uint64_t reply = fu(st, service, "reply_service");
        uint64_t def = fu(st, ident, "default_service");
        uint64_t request = fu(st, service, "request_bytes");
        uint64_t result = fu(st, service, "result_bytes");
        uint64_t message = fu(st, limits, "message_bytes");
        const char *encoding = fs(st, service, "service_encoding");
        const char *schema = fs(st, service, "schema");
        const char *recovery = fs(st, service, "recovery");
        int fresh = fb(st, service, "freshness");
        (void)fresh;
        snprintf(path, sizeof path, "$.services[%u]", (unsigned)i);
        if (st->failed) {
            return;
        }
        if (!need(st, reply == sid && strcmp(encoding, sid == def ? "omitted" : "explicit") == 0,
                  "service", path)) {
            return;
        }
        {
            char rec_path[80];
            snprintf(rec_path, sizeof rec_path, "%s.recovery", path);
            if (!need(st, strcmp(recovery, selective ? "selective-32" : "retry-all") == 0,
                      "profile", rec_path)) {
                return;
            }
        }
        if (!need(st, strcmp(schema, sid == 1U ? "DMP-reference/SAMPLE-1/2" : "DMP-test/OPAQUE-1/1") == 0,
                  "service", path)) {
            return;
        }
        acl = fo(st, service, "acl");
        if (st->failed || acl->type != JSON_ARRAY) {
            return;
        }
        {
            char acl_path[80];
            uint64_t node_ids[2];
            size_t a;
            snprintf(acl_path, sizeof acl_path, "%s.acl", path);
            if (acl->count != nodes->count) {
                fail(st, "service", acl_path);
                return;
            }
            for (a = 0; a < acl->count && a < 2U; a++) {
                node_ids[a] = fu(st, acl->items[a], "node");
            }
            if (st->failed) {
                return;
            }
            for (a = 0; a < nodes->count && a < 2U; a++) {
                uint64_t id = 0;
                size_t b;
                int found = 0;
                if (!mu(st, nodes->items[a], &id)) {
                    return;
                }
                for (b = 0; b < acl->count && b < 2U; b++) {
                    if (node_ids[b] == id) {
                        found++;
                    }
                }
                if (found != 1) {
                    fail(st, "service", acl_path);
                    return;
                }
            }
            for (a = 0; a < acl->count; a++) {
                const json_value *actions = fo(st, acl->items[a], "actions");
                uint64_t node = fu(st, acl->items[a], "node");
                const char *expect[4];
                size_t nexpect = 0;
                size_t b;
                if (st->failed || actions == NULL || actions->type != JSON_ARRAY) {
                    return;
                }
                if (sid == 1U) {
                    if (node == producer) {
                        expect[0] = "produce";
                        expect[1] = "result";
                        nexpect = 2;
                    } else {
                        expect[0] = "read";
                        expect[1] = "status";
                        nexpect = 2;
                    }
                } else {
                    expect[0] = "data";
                    expect[1] = "result";
                    nexpect = 2;
                }
                if (actions->count != nexpect) {
                    fail(st, "service", acl_path);
                    return;
                }
                for (b = 0; b < nexpect; b++) {
                    size_t c;
                    int found = 0;
                    for (c = 0; c < actions->count; c++) {
                        if (actions->items[c]->type == JSON_STRING &&
                            strcmp(actions->items[c]->text, expect[b]) == 0) {
                            found++;
                        }
                    }
                    if (found != 1) {
                        fail(st, "service", acl_path);
                        return;
                    }
                }
            }
        }
        if (!need(st, (request > result ? request : result) <= message, "service", path)) {
            return;
        }
        if (sid == 1U &&
            !need(st, request == 1U && result == 17U && !fb(st, service, "freshness"),
                  "service", path)) {
            return;
        }
    }
    *direct_out = direct;
    *selective_out = selective;
}

static void check_security(vstate *st, const json_value *m)
{
    const json_value *s = fo(st, m, "security");
    const json_value *t = fo(st, m, "timing");
    uint64_t crypto;
    uint64_t pending;
    uint64_t preauth;
    uint64_t pre_bytes;
    uint64_t drain;
    uint64_t association;
    uint64_t correlation;
    uint64_t queue;
    uint64_t pairing;
    uint64_t attempt;
    uint64_t crypto_attempt;
    uint64_t attempts;
    uint64_t episode;
    uint64_t backoff;
    uint64_t episode_crypto;
    uint64_t episode_tx;
    uint64_t attempt_tx;
    uint64_t later_window;
    uint64_t global_crypto;
    uint64_t later_episodes;
    uint64_t slots;
    const char *mode;
    const char *credential;
    if (st->failed) {
        return;
    }
    mode = fs(st, s, "mode");
    credential = fs(st, s, "credential");
    crypto = fu(st, s, "crypto_slots");
    pending = fu(st, s, "pending_per_pair");
    preauth = fu(st, s, "preauth_slots");
    pre_bytes = fu(st, s, "preauth_bytes");
    drain = fu(st, s, "drain_ms");
    association = fu(st, s, "association_ms");
    correlation = fu(st, t, "correlation_ms");
    queue = fu(st, t, "queue_ms");
    pairing = fu(st, s, "pairing_timeout_ms");
    attempt = fu(st, s, "attempt_ms");
    crypto_attempt = fu(st, s, "crypto_per_attempt_ms");
    attempts = fu(st, s, "episode_attempts");
    episode = fu(st, s, "episode_ms");
    backoff = fu(st, s, "restart_backoff_ms");
    episode_crypto = fu(st, s, "episode_crypto_ms");
    episode_tx = fu(st, s, "episode_tx_bytes");
    attempt_tx = fu(st, s, "attempt_tx_bytes");
    later_window = fu(st, s, "later_window_ms");
    global_crypto = fu(st, s, "global_crypto_ms_per_window");
    later_episodes = fu(st, s, "later_episodes_per_window");
    slots = crypto;
    if (st->failed) {
        return;
    }
    if (!need(st, strcmp(credential, strcmp(mode, "NNpsk0") == 0 ? "provisioned-pairwise-psk"
                                                                  : "authenticated-oob-xx") == 0,
              "security", "$.security.credential")) {
        return;
    }
    if (!need(st, crypto <= pending && pending <= preauth, "security", "$.security")) {
        return;
    }
    if (!need(st, ge_u(pre_bytes, nmul(nu(120), nu(preauth))), "security", "$.security.preauth_bytes")) {
        return;
    }
    if (!need(st, drain < association && (fu(st, s, "draining_per_pair") > 0U || drain == 0U),
              "security", "$.security.drain_ms")) {
        return;
    }
    if (!need(st, ge_u(association, nadd(nu(correlation), nu(queue))), "security",
              "$.security.association_ms")) {
        return;
    }
    if (!need(st, pairing <= attempt && crypto_attempt <= attempt, "security", "$.security.attempt_ms")) {
        return;
    }
    if (attempts == 0U) {
        fail(st, "security", "$.security.episode_ms");
        return;
    }
    if (!need(st, ge_u(episode, nadd(nmul(nu(attempts), nu(attempt)),
                                    nmul(nu(attempts - 1U), nu(backoff)))),
              "security", "$.security.episode_ms")) {
        return;
    }
    if (!need(st, ge_u(episode_crypto, nmul(nu(attempts), nu(crypto_attempt))) &&
                     le_u(episode_crypto, nmul(nu(episode), nu(slots))),
              "security", "$.security.episode_crypto_ms")) {
        return;
    }
    if (!need(st, ge_u(episode_tx, nmul(nu(attempts), nu(attempt_tx))), "security",
              "$.security.episode_tx_bytes")) {
        return;
    }
    if (!need(st, later_window >= episode &&
                     ge_u(global_crypto, nmul(nu(later_episodes), nu(episode_crypto))) &&
                     le_u(global_crypto, nmul(nu(later_window), nu(slots))),
              "security", "$.security")) {
        return;
    }
}

typedef struct derived {
    uint64_t fragment_count;
    uint64_t bootstrap_fragment_count;
    uint64_t encoded_frame_bytes;
    uint64_t response_floor_ms;
    uint64_t transfer_frame_reserve;
    uint64_t establishment_frame_reserve;
    uint64_t establishment_ms;
    uint64_t bootstrap_flight_span_ms;
} derived;

static void check_frames(vstate *st, const json_value *m, int direct, derived *out)
{
    const json_value *limits = fo(st, m, "limits");
    const json_value *binding = fo(st, m, "binding");
    const json_value *ident = fo(st, m, "identity");
    const json_value *services = fo(st, m, "services");
    const json_value *nodes;
    uint64_t size;
    uint64_t chunk;
    uint64_t count;
    uint64_t boot_chunk;
    uint64_t boot_count;
    uint64_t fragments;
    uint64_t boot_fragments;
    uint64_t node_width = 1;
    uint64_t context;
    uint64_t route = 1;
    uint64_t base;
    num app_header_max = nu(0);
    num app_frame_max = nu(0);
    num status_max = nu(0);
    uint64_t forward;
    uint64_t back;
    uint64_t core;
    uint64_t encoded;
    size_t i;
    if (st->failed) {
        return;
    }
    size = fu(st, limits, "message_bytes");
    chunk = fu(st, limits, "chunk_bytes");
    fragments = fu(st, limits, "fragments");
    boot_chunk = fu(st, limits, "bootstrap_chunk_bytes");
    boot_fragments = fu(st, limits, "bootstrap_fragments");
    if (st->failed) {
        return;
    }
    if (!need(st, chunk < size, "geometry", "$.limits.chunk_bytes")) {
        return;
    }
    count = (size + chunk - 1U) / chunk;
    boot_count = (120U + boot_chunk - 1U) / boot_chunk;
    if (!need(st, count <= fragments && fragments <= (direct ? 16U : 32U), "geometry",
              "$.limits.fragments")) {
        return;
    }
    if (!need(st, boot_count <= boot_fragments, "geometry", "$.limits.bootstrap_fragments")) {
        return;
    }
    nodes = fo(st, ident, "nodes");
    if (st->failed || nodes == NULL) {
        return;
    }
    for (i = 0; i < nodes->count; i++) {
        uint64_t id = 0;
        uint64_t width;
        if (!mu(st, nodes->items[i], &id)) {
            return;
        }
        width = uleb_width(id);
        if (width > node_width) {
            node_width = width;
        }
        route = route + width;
    }
    context = 2U + uleb_width(fu(st, ident, "namespace")) + 8U;
    base = 18U + (direct ? 0U : route + context);
    for (i = 0; i < services->count; i++) {
        const json_value *service = services->items[i];
        uint64_t sid = fu(st, service, "id");
        uint64_t def = fu(st, ident, "default_service");
        int fresh = fb(st, service, "freshness");
        uint64_t service_ext = sid == def ? 0U : 2U + uleb_width(sid);
        uint64_t frag = uleb_width(count - 1U) + uleb_width(chunk) + uleb_width(size);
        num header = nadd(nu(base + 7U + 7U + service_ext + frag), nu(fresh ? 18U : 0U));
        num app = nadd(header, nu(chunk + 16U));
        num status = nu(base + 7U + service_ext + 4U + 16U);
        if (st->failed) {
            return;
        }
        if (!app_header_max.big && (header.big || header.v > app_header_max.v)) {
            app_header_max = header;
        }
        if (!app_frame_max.big && (app.big || app.v > app_frame_max.v)) {
            app_frame_max = app;
        }
        if (!status_max.big && (status.big || status.v > status_max.v)) {
            status_max = status;
        }
    }
    forward = fu(st, binding, "forward_mtu");
    back = fu(st, binding, "return_mtu");
    if (st->failed) {
        return;
    }
    {
        num control = nu(base + 7U + 3U + 21U + 16U);
        num sample = nu(base + 7U + 7U + 17U + 16U);
        num boot = nadd(nu(5U + context + (direct ? 2U + node_width : route)),
                        nu(uleb_width(boot_count - 1U) + uleb_width(boot_chunk) + uleb_width(120U)));
        num boot_frame = nadd(boot, nu(boot_chunk + 4U));
        uint64_t header_bound = app_header_max.big ? UINT64_MAX : app_header_max.v;
        int header_big = app_header_max.big;
        uint64_t frame_bound = app_frame_max.big ? UINT64_MAX : app_frame_max.v;
        int frame_big = app_frame_max.big;
        uint64_t candidates_h[3];
        uint64_t candidates_f[4];
        int i_h;
        if (boot.big) {
            header_big = 1;
        } else if (!header_big && boot.v > header_bound) {
            header_bound = boot.v;
        }
        if (!header_big && base + 10U > header_bound) {
            header_bound = base + 10U;
        }
        candidates_f[0] = status_max.big ? UINT64_MAX : status_max.v;
        candidates_f[1] = control.v;
        candidates_f[2] = sample.v;
        candidates_f[3] = boot_frame.big ? UINT64_MAX : boot_frame.v;
        if (status_max.big || boot_frame.big) {
            frame_big = 1;
        }
        for (i_h = 0; i_h < 4; i_h++) {
            if (!frame_big && candidates_f[i_h] > frame_bound) {
                frame_bound = candidates_f[i_h];
            }
        }
        (void)candidates_h;
        core = forward > back ? forward : back;
        if (header_big || header_bound > 255U || frame_big ||
            frame_bound > (forward < back ? forward : back)) {
            fail(st, "mtu", "$.binding");
            return;
        }
        if (direct) {
            uint64_t n = core + 4U;
            if (n < core) {
                fail(st, "mtu", "$.binding.encoded_mtu");
                return;
            }
            encoded = n + n / 254U + 2U;
        } else {
            encoded = core;
        }
        if (!need(st, encoded <= fu(st, binding, "encoded_mtu"), "mtu", "$.binding.encoded_mtu")) {
            return;
        }
        out->fragment_count = count;
        out->bootstrap_fragment_count = boot_count;
        out->encoded_frame_bytes = encoded;
    }
}

static void check_timing(vstate *st, const json_value *m, int selective, derived *d)
{
    const json_value *t = fo(st, m, "timing");
    const json_value *b = fo(st, m, "binding");
    const json_value *services = fo(st, m, "services");
    const json_value *starts;
    uint64_t f;
    uint64_t r;
    uint64_t span;
    uint64_t margin;
    uint64_t horizon;
    uint64_t queue;
    uint64_t delay;
    uint64_t floor;
    uint64_t bursts;
    uint64_t period;
    uint64_t window;
    uint64_t traversal;
    uint64_t frames;
    uint64_t history;
    uint64_t processing = 0;
    size_t i;
    if (st->failed) {
        return;
    }
    f = fu(st, t, "forward_delay_ms");
    r = fu(st, t, "return_delay_ms");
    span = fu(st, t, "burst_span_ms");
    margin = fu(st, t, "record_margin_ms");
    horizon = fu(st, t, "send_horizon_ms");
    queue = fu(st, t, "queue_ms");
    delay = f > r ? f : r;
    floor = f + fu(st, t, "receipt_delay_ms") + r;
    if (selective) {
        uint64_t guard = fu(st, t, "feedback_guard_ms");
        uint64_t feedback = fu(st, t, "feedback_delay_ms");
        uint64_t a = 2U * f + span + guard + feedback + r;
        uint64_t b2 = 2U * r + span + guard + feedback + f;
        if (a < f || b2 < r) {
            fail(st, "timing", "$.timing.response_timeout_ms");
            return;
        }
        if (a > floor) {
            floor = a;
        }
        if (b2 > floor) {
            floor = b2;
        }
    }
    if (st->failed) {
        return;
    }
    if (!need(st, fu(st, t, "response_timeout_ms") >= floor, "timing", "$.timing.response_timeout_ms")) {
        return;
    }
    d->response_floor_ms = floor;
    bursts = fu(st, t, "max_bursts");
    starts = fo(st, t, "burst_starts_ms");
    if (st->failed || starts == NULL || starts->type != JSON_ARRAY) {
        return;
    }
    if (!need(st, starts->count == bursts && starts->count > 0U &&
                     starts->items[0]->type == JSON_INT && !starts->items[0]->negative &&
                     starts->items[0]->u64_ok && starts->items[0]->u64 == 0U,
              "schedule", "$.timing.burst_starts_ms")) {
        return;
    }
    for (i = 1; i < starts->count; i++) {
        uint64_t left = 0;
        uint64_t right = 0;
        num gap;
        if (!mu(st, starts->items[i - 1U], &left) || !mu(st, starts->items[i], &right)) {
            return;
        }
        gap = nadd(nadd(nu(span), nu(fu(st, t, "response_timeout_ms"))), nu(fu(st, t, "jitter_ms")));
        if (!need(st, ge_u(right, nadd(nu(left), gap)), "schedule", "$.timing.burst_starts_ms")) {
            return;
        }
    }
    {
        uint64_t last = 0;
        if (!mu(st, starts->items[starts->count - 1U], &last)) {
            return;
        }
        if (!need(st, le_u(0U, nu(0)) && ge_u(horizon, nadd(nu(last), nu(span))), "schedule",
                  "$.timing.send_horizon_ms")) {
            return;
        }
    }
    if (selective) {
        if (!need(st, fu(st, t, "max_probes") <= bursts - 1U && fu(st, t, "max_probes") >= 1U &&
                         fu(st, t, "max_status") >= bursts,
                  "schedule", "$.timing")) {
            return;
        }
    } else if (!need(st, fu(st, t, "max_probes") == 0U && fu(st, t, "max_status") == 0U, "schedule",
                     "$.timing")) {
        return;
    }
    period = fu(st, b, "return_slot_period_ms");
    window = fu(st, b, "return_slot_width_ms");
    traversal = fu(st, b, "frame_tx_ms") + delay;
    if (period < window) {
        fail(st, "schedule", "$.binding");
        return;
    }
    {
        uint64_t receipt = fu(st, t, "receipt_delay_ms");
        uint64_t feedback = fu(st, t, "feedback_delay_ms");
        uint64_t smaller = receipt < feedback ? receipt : feedback;
        if (!need(st, window >= 2U * traversal && period - window >= traversal &&
                         period + window <= smaller,
                  "schedule", "$.binding")) {
            return;
        }
    }
    {
        uint64_t need_n = d->fragment_count > d->bootstrap_fragment_count ? d->fragment_count
                                                                         : d->bootstrap_fragment_count;
        if (!need(st, span >= need_n * period && queue >= period, "schedule", "$.timing")) {
            return;
        }
        for (i = 0; i < starts->count; i++) {
            uint64_t start = 0;
            if (!mu(st, starts->items[i], &start)) {
                return;
            }
            if (period == 0U || start % period != 0U) {
                fail(st, "schedule", "$.timing");
                return;
            }
        }
    }
    if (!need(st, fu(st, t, "receipt_limit") >= bursts &&
                     fu(st, limits_of(m), "control_slots") >= fu(st, t, "feedback_buffers") + 1U,
              "schedule", "$.timing")) {
        return;
    }
    frames = bursts * (d->fragment_count + d->bootstrap_fragment_count) + fu(st, t, "max_status") +
             fu(st, t, "receipt_limit");
    d->transfer_frame_reserve = frames;
    if (!need(st, ge_u(fu(st, t, "max_transfer_airtime_ms"), nmul(nu(frames), nu(fu(st, b, "frame_tx_ms")))),
              "schedule", "$.timing.max_transfer_airtime_ms")) {
        return;
    }
    if (!need(st, fu(st, t, "collect_ms") >= horizon + delay &&
                     fu(st, t, "assembly_ms") >=
                         (horizon + delay > fu(st, t, "collect_ms") ? horizon + delay
                                                                   : fu(st, t, "collect_ms")) +
                             margin,
              "timing", "$.timing.assembly_ms")) {
        return;
    }
    history = horizon + queue + f + r + margin;
    {
        static const char *keys[] = {"dedup_ms", "rejection_ms", "result_cache_ms", "tombstone_ms"};
        for (i = 0; i < 4U; i++) {
            char path[64];
            snprintf(path, sizeof path, "$.timing.%s", keys[i]);
            if (!need(st, fu(st, t, keys[i]) >= history, "timing", path)) {
                return;
            }
        }
    }
    for (i = 0; i < services->count; i++) {
        uint64_t p = fu(st, services->items[i], "processing_ms");
        if (p > processing) {
            processing = p;
        }
    }
    {
        num result = nadd(nmul(nu(2), nadd(nadd(nu(queue), nu(horizon)), nu(delay))),
                          nadd(nu(processing), nu(fu(st, t, "receipt_delay_ms"))));
        if (!need(st, ge_u(fu(st, t, "result_deadline_ms"), result) &&
                         ge_u(fu(st, t, "correlation_ms"),
                              nadd(nadd(nu(fu(st, t, "result_deadline_ms")), nu(fu(st, t, "late_result_ms"))),
                                   nu(margin))) &&
                         fu(st, t, "tombstone_ms") >= fu(st, t, "correlation_ms"),
                  "timing", "$.timing")) {
            return;
        }
    }
    {
        const json_value *sample = fo(st, m, "sample");
        uint64_t init_attempts = fu(st, sample, "init_attempts");
        if (init_attempts == 0U) {
            fail(st, "timing", "$.sample.init_deadline_ms");
            return;
        }
        if (!need(st, ge_u(fu(st, sample, "init_deadline_ms"),
                           nadd(nmul(nu(init_attempts), nu(fu(st, t, "result_deadline_ms"))),
                                nmul(nu(init_attempts - 1U), nu(fu(st, sample, "init_retry_ms"))))),
                  "timing", "$.sample.init_deadline_ms")) {
            return;
        }
    }
    {
        const json_value *fresh = fo(st, m, "freshness");
        int any_fresh = 0;
        num need_age;
        for (i = 0; i < services->count; i++) {
            if (fb(st, services->items[i], "freshness")) {
                any_fresh = 1;
            }
        }
        need_age = nadd(nu(fu(st, fresh, "grant_delivery_age_ms")),
                        nadd(nadd(nu(queue), nu(horizon)), nu(delay)));
        d->response_floor_ms = floor;
        if (any_fresh) {
            const json_value *grant_nodes = fo(st, fresh, "grant_nodes");
            const json_value *nodes = fo(st, fo(st, m, "identity"), "nodes");
            if (!need(st, fu(st, fresh, "lease_ms") > 0U && ge_u(fu(st, fresh, "lease_ms"), need_age),
                      "timing", "$.freshness")) {
                return;
            }
            if (st->failed || grant_nodes == NULL || nodes == NULL) {
                return;
            }
            if (grant_nodes->count != 2U || nodes->count != 2U) {
                fail(st, "security", "$.freshness");
                return;
            }
            {
                uint64_t g0 = 0;
                uint64_t g1 = 0;
                uint64_t n0 = 0;
                uint64_t n1 = 0;
                if (!mu(st, grant_nodes->items[0], &g0) || !mu(st, grant_nodes->items[1], &g1) ||
                    !mu(st, nodes->items[0], &n0) || !mu(st, nodes->items[1], &n1)) {
                    return;
                }
                if (!need(st, g0 != g1 && ((g0 == n0 && g1 == n1) || (g0 == n1 && g1 == n0)) &&
                                 fu(st, fresh, "grant_requests_per_pair") > 0U &&
                                 fu(st, fresh, "grant_requests_per_pair") <=
                                     fu(st, fresh, "tokens_per_association") &&
                                 fu(st, fresh, "tokens_per_association") <=
                                     fu(st, fresh, "tokens_per_principal") &&
                                 fu(st, fresh, "token_record_ms") >= fu(st, fresh, "lease_ms") &&
                                 fu(st, fresh, "grant_result_ms") >= history,
                          "security", "$.freshness")) {
                    return;
                }
            }
        } else {
            static const char *zeros[] = {
                "lease_ms", "grant_delivery_age_ms", "tokens_per_association",
                "tokens_per_principal", "grant_requests_per_pair", "token_record_ms",
                "grant_result_ms"
            };
            const json_value *grant_nodes = fo(st, fresh, "grant_nodes");
            for (i = 0; i < 7U; i++) {
                if (fu(st, fresh, zeros[i]) != 0U) {
                    fail(st, "timing", "$.freshness");
                    return;
                }
            }
            if (grant_nodes == NULL || grant_nodes->count != 0U) {
                fail(st, "timing", "$.freshness");
                return;
            }
        }
    }
}

static void check_establishment(vstate *st, const json_value *m, derived *d)
{
    const json_value *s = fo(st, m, "security");
    const json_value *b = fo(st, m, "binding");
    const json_value *t = fo(st, m, "timing");
    uint64_t period;
    uint64_t delay;
    uint64_t flight_span;
    uint64_t flights;
    uint64_t xx;
    uint64_t responses;
    uint64_t frames;
    uint64_t mode_xx;
    num retry_floor;
    num confirmation_floor;
    num traffic;
    num duration;
    if (st->failed) {
        return;
    }
    period = fu(st, b, "return_slot_period_ms");
    delay = fu(st, t, "forward_delay_ms");
    if (fu(st, t, "return_delay_ms") > delay) {
        delay = fu(st, t, "return_delay_ms");
    }
    flight_span = d->bootstrap_fragment_count * period;
    d->bootstrap_flight_span_ms = flight_span;
    retry_floor = nadd(nmul(nu(2), nadd(nu(flight_span), nu(delay))),
                       nadd(nu(fu(st, s, "crypto_per_attempt_ms")), nu(fu(st, s, "pairing_timeout_ms"))));
    if (st->failed) {
        return;
    }
    if (!need(st, ge_u(fu(st, s, "flight_retry_ms"), retry_floor) && period != 0U &&
                     fu(st, s, "flight_retry_ms") % period == 0U,
              "security", "$.security.flight_retry_ms")) {
        return;
    }
    mode_xx = strcmp(fs(st, s, "mode"), "XX") == 0;
    xx = mode_xx ? fu(st, s, "confirmation_attempts") : 0U;
    confirmation_floor = nadd(nmul(nu(2), nadd(nu(period), nu(delay))), nu(fu(st, t, "receipt_delay_ms")));
    if (xx != 0U) {
        confirmation_floor = nadd(confirmation_floor, nadd(nu(flight_span), nu(delay)));
    }
    if (!need(st, ge_u(fu(st, s, "confirmation_timeout_ms"), confirmation_floor) &&
                     fu(st, s, "confirmation_timeout_ms") % period == 0U,
              "security", "$.security.confirmation_timeout_ms")) {
        return;
    }
    flights = mode_xx ? 3U : 2U;
    frames = (flights * fu(st, s, "flight_attempts") + fu(st, s, "duplicate_responses_per_attempt") + xx) *
                 d->bootstrap_fragment_count +
             2U * fu(st, s, "confirmation_attempts");
    responses = flights * fu(st, s, "flight_attempts") + fu(st, s, "duplicate_responses_per_attempt") + xx +
                2U * fu(st, s, "confirmation_attempts");
    traffic = nmul(nu(frames), nu(d->encoded_frame_bytes));
    duration = nmul(nadd(nmul(nu(flights), nu(fu(st, s, "flight_attempts"))),
                         nu(fu(st, s, "duplicate_responses_per_attempt"))),
                    nu(fu(st, s, "flight_retry_ms")));
    duration = nadd(duration, nmul(nu(fu(st, s, "confirmation_attempts")), nu(fu(st, s, "confirmation_timeout_ms"))));
    duration = nadd(duration, nadd(nu(fu(st, s, "pairing_timeout_ms")), nu(fu(st, s, "crypto_per_attempt_ms"))));
    if (!need(st, ge_u(fu(st, s, "attempt_ms"), duration) && ge_u(fu(st, s, "attempt_tx_bytes"), traffic),
              "security", "$.security")) {
        return;
    }
    if (!need(st, fu(st, s, "response_window_ms") <= fu(st, s, "attempt_ms") &&
                     ge_u(fu(st, s, "responses_per_window"), nu(responses)) &&
                     ge_u(fu(st, s, "response_bytes_per_window"), traffic),
              "security", "$.security")) {
        return;
    }
    if (!need(st, ge_u(fu(st, s, "ingress_packets_per_window"), nu(frames)), "security",
              "$.security.ingress_packets_per_window")) {
        return;
    }
    if (!need(st, ge_u(fu(st, s, "encryption_limit"),
                       nadd(nu(d->transfer_frame_reserve), nmul(nu(2), nu(fu(st, s, "confirmation_attempts"))))) &&
                     ge_u(fu(st, s, "plaintext_limit"),
                          nmul(nu(d->transfer_frame_reserve), nu(fu(st, limits_of(m), "message_bytes")))),
              "security", "$.security")) {
        return;
    }
    d->establishment_frame_reserve = frames;
    d->establishment_ms = duration.big ? UINT64_MAX : duration.v;
}

static int burst_gap_ok(vstate *st, const json_value *starts, uint64_t low, uint64_t span, uint64_t high,
                        uint64_t tail, uint64_t serial, uint64_t cooldown)
{
    size_t i;
    for (i = 1; i < starts->count; i++) {
        uint64_t prev = 0;
        uint64_t next = 0;
        num right;
        num left;
        if (!mu(st, starts->items[i - 1U], &prev) || !mu(st, starts->items[i], &next)) {
            return 0;
        }
        right = nadd(nu(next), nu(low));
        left = nadd(nadd(nadd(nu(prev), nu(span)), nadd(nu(high), nu(tail))), nadd(nu(serial), nu(cooldown)));
        if (right.big || left.big || right.v < left.v) {
            return 0;
        }
    }
    return !st->failed;
}

static void check_relays(vstate *st, const json_value *m, derived *d)
{
    const json_value *t = fo(st, m, "timing");
    const json_value *relays = fo(st, m, "relays");
    const json_value *starts;
    const json_value *security;
    uint64_t span;
    size_t direction;
    if (st->failed) {
        return;
    }
    starts = fo(st, t, "burst_starts_ms");
    security = fo(st, m, "security");
    span = fu(st, t, "burst_span_ms");
    if (st->failed || starts == NULL || relays == NULL) {
        return;
    }
    for (direction = 0; direction < 2U; direction++) {
        uint64_t preceding = 0;
        size_t n = relays->count;
        size_t step;
        for (step = 0; step < n; step++) {
            const json_value *relay = relays->items[direction == 0U ? step : n - 1U - step];
            char path[80];
            uint64_t node = fu(st, relay, "node");
            uint64_t low;
            uint64_t high;
            uint64_t copies;
            uint64_t serial;
            uint64_t tail;
            uint64_t tx;
            uint64_t end;
            const char *which = direction == 0U ? "forward" : "return";
            char key_min[40];
            char key_max[40];
            snprintf(path, sizeof path, "$.relays[node=%llu]", (unsigned long long)node);
            snprintf(key_min, sizeof key_min, "%s_arrival_min_ms", which);
            snprintf(key_max, sizeof key_max, "%s_arrival_max_ms", which);
            low = fu(st, relay, key_min);
            high = fu(st, relay, key_max);
            tx = fu(st, relay, "frame_tx_ms");
            tail = fu(st, relay, "duplicate_tail_ms");
            copies = 1U + fu(st, relay, "lower_duplicates");
            if (st->failed) {
                return;
            }
            if (!need(st, preceding <= low && low <= high, "relay", path)) {
                return;
            }
            serial = copies * tx;
            end = high + tail + serial;
            if (end < high) {
                fail(st, "relay", path);
                return;
            }
            preceding = end;
            if (!need(st, preceding <= fu(st, t, direction == 0U ? "forward_delay_ms" : "return_delay_ms"),
                      "relay", path)) {
                return;
            }
            if (!burst_gap_ok(st, starts, low, span, high, tail, serial, fu(st, relay, "cooldown_ms"))) {
                if (!st->failed) {
                    fail(st, "relay", path);
                }
                return;
            }
            {
                uint64_t boot = fu(st, security, "flight_attempts") +
                                fu(st, security, "duplicate_responses_per_attempt");
                uint64_t confirmation_span = fu(st, fo(st, m, "binding"), "return_slot_period_ms");
                uint64_t confirmations = fu(st, security, "confirmation_attempts");
                uint64_t bursts = fu(st, t, "max_bursts");
                uint64_t last = 0;
                uint64_t opportunity;
                num airtime;
                if (strcmp(fs(st, security, "mode"), "XX") == 0) {
                    boot += confirmations;
                    confirmation_span = d->bootstrap_flight_span_ms;
                }
                opportunity = bursts;
                if (boot > opportunity) {
                    opportunity = boot;
                }
                if (confirmations > opportunity) {
                    opportunity = confirmations;
                }
                if (!mu(st, starts->items[starts->count - 1U], &last)) {
                    return;
                }
                if (!need(st, ge_u(fu(st, relay, "max_forwards_per_key"), nmul(nu(opportunity), nu(copies))),
                          "relay", path)) {
                    return;
                }
                if (!need(st, ge_u(fu(st, relay, "expiry_ms"),
                                   nadd(nadd(nadd(nu(last), nu(span)), nadd(nu(high - low), nu(tail))),
                                        nadd(nu(serial), nu(fu(st, t, "record_margin_ms"))))),
                          "relay", path)) {
                    return;
                }
                if (!need(st, ge_u(fu(st, security, "flight_retry_ms") + low,
                                   nadd(nadd(nu(d->bootstrap_flight_span_ms), nu(high)),
                                        nadd(nadd(nu(tail), nu(serial)), nu(fu(st, relay, "cooldown_ms"))))) &&
                                 ge_u(fu(st, security, "confirmation_timeout_ms") + low,
                                      nadd(nadd(nu(confirmation_span), nu(high)),
                                           nadd(nadd(nu(tail), nu(serial)), nu(fu(st, relay, "cooldown_ms"))))) &&
                                 ge_u(fu(st, relay, "expiry_ms"),
                                      nadd(nadd(nu(d->establishment_ms), nu(high - low)),
                                           nadd(nadd(nu(tail), nu(serial)), nu(fu(st, t, "record_margin_ms"))))),
                          "relay", path)) {
                    return;
                }
                airtime = nmul(nadd(nmul(nu(2U * 2U), nu(d->transfer_frame_reserve)),
                                    nmul(nu(d->establishment_frame_reserve), nu(fu(st, security, "episode_attempts")))),
                               nmul(nu(copies), nu(tx)));
                if (!need(st, ge_u(fu(st, relay, "per_origin_airtime_ms"), airtime) &&
                                 ge_u(fu(st, relay, "global_airtime_ms"), nmul(nu(2), airtime)),
                          "relay", path)) {
                    return;
                }
            }
        }
    }
}

static uint64_t count_for(const char *key, int endpoint, uint64_t associations, uint64_t crypto,
                          uint64_t operations, uint64_t assemblies,
                          uint64_t assembly_tombstones, uint64_t grants, uint64_t control,
                          uint64_t adapter, uint64_t tokens)
{
    if (!endpoint && strcmp(key, "relay_cache") != 0) {
        return 1U;
    }
    if (strcmp(key, "provider_retained") == 0) {
        return associations;
    }
    if (strcmp(key, "association") == 0) {
        return 1U;
    }
    if (strcmp(key, "provider_scratch") == 0) {
        return crypto;
    }
    if (strcmp(key, "bootstrap") == 0) {
        return endpoint ? 0U : 1U;
    }
    if (strcmp(key, "sender") == 0) {
        return operations;
    }
    if (strcmp(key, "assembly") == 0) {
        return assemblies;
    }
    if (strcmp(key, "assembly_tombstone") == 0) {
        return assembly_tombstones;
    }
    if (strcmp(key, "result") == 0 || strcmp(key, "correlation") == 0) {
        return operations + grants;
    }
    if (strcmp(key, "history") == 0) {
        return 2U * (operations + grants);
    }
    if (strcmp(key, "control") == 0) {
        return control;
    }
    if (strcmp(key, "application_queue") == 0) {
        return 1U;
    }
    if (strcmp(key, "adapter") == 0) {
        return adapter;
    }
    if (strcmp(key, "stacks") == 0 || strcmp(key, "relay_cache") == 0) {
        return strcmp(key, "relay_cache") == 0 && endpoint ? 0U : 1U;
    }
    if (strcmp(key, "freshness_tokens") == 0) {
        return endpoint ? tokens : 1U;
    }
    return 0U;
}

static void check_resources(vstate *st, const json_value *m, const derived *d)
{
    static const char *components[] = {
        "provider_retained", "provider_scratch", "association", "bootstrap", "sender", "assembly",
        "result", "history", "correlation", "control", "application_queue", "adapter", "stacks",
        "relay_cache", "freshness_tokens", "assembly_tombstone"
    };
    const json_value *resources = fo(st, m, "resources");
    const json_value *security = fo(st, m, "security");
    const json_value *limits = limits_of(m);
    const json_value *relays = fo(st, m, "relays");
    const json_value *fresh = fo(st, m, "freshness");
    const json_value *timing = fo(st, m, "timing");
    int want_relay;
    size_t i;
    uint64_t associations;
    uint64_t operations;
    uint64_t grants;
    uint64_t message;
    uint64_t encoded;
    if (st->failed) {
        return;
    }
    want_relay = relays->count != 0U;
    if (resources->count != (want_relay ? 2U : 1U)) {
        fail(st, "resources", "$.resources");
        return;
    }
    {
        int saw_endpoint = 0;
        int saw_relay = 0;
        for (i = 0; i < resources->count; i++) {
            const char *role = fs(st, resources->items[i], "role");
            if (strcmp(role, "endpoint") == 0) {
                saw_endpoint++;
            } else if (strcmp(role, "relay") == 0) {
                saw_relay++;
            }
        }
        if (!need(st, saw_endpoint == 1 && saw_relay == (want_relay ? 1 : 0), "resources", "$.resources")) {
            return;
        }
    }
    associations = fu(st, security, "pending_per_pair") + fu(st, security, "active_per_pair") +
                   fu(st, security, "draining_per_pair");
    operations = fu(st, limits, "sender_slots");
    grants = fu(st, fresh, "grant_requests_per_pair");
    message = fu(st, limits, "message_bytes");
    encoded = d->encoded_frame_bytes;
    if (!need(st, fu(st, limits, "control_slots") >= fu(st, timing, "feedback_buffers") + grants + 1U,
              "resources", "$.limits.control_slots")) {
        return;
    }
    if (!need(st, fu(st, limits, "assembly_tombstones_per_peer") >=
                     fu(st, limits, "assemblies_per_peer"),
              "resources", "$.limits.assembly_tombstones_per_peer")) {
        return;
    }
    for (i = 0; i < resources->count; i++) {
        const json_value *resource = resources->items[i];
        const json_value *regions;
        const json_value *charges;
        const char *role = fs(st, resource, "role");
        char path[80];
        int endpoint = strcmp(role, "endpoint") == 0;
        int seen[16];
        char region_ids[8][97];
        uint64_t region_limit[8];
        num region_used[8];
        size_t nregions;
        size_t c;
        memset(seen, 0, sizeof seen);
        snprintf(path, sizeof path, "$.resources[%s]", role);
        if (!need(st, fu(st, resource, "flash_reserved_bytes") <= fu(st, resource, "flash_limit_bytes"),
                  "resources", path)) {
            return;
        }
        regions = fo(st, resource, "regions");
        charges = fo(st, resource, "charges");
        if (st->failed || regions == NULL || charges == NULL) {
            return;
        }
        if (regions->count > 8U) {
            fail(st, "resources", path);
            return;
        }
        nregions = regions->count;
        for (c = 0; c < nregions; c++) {
            const char *id = fs(st, regions->items[c], "id");
            size_t p;
            region_limit[c] = fu(st, regions->items[c], "limit_bytes");
            region_used[c] = nu(0);
            if (strlen(id) >= sizeof region_ids[c]) {
                fail(st, "resources", path);
                return;
            }
            memcpy(region_ids[c], id, strlen(id) + 1U);
            for (p = 0; p < c; p++) {
                if (strcmp(region_ids[p], region_ids[c]) == 0) {
                    fail(st, "resources", path);
                    return;
                }
            }
        }
        if (charges->count != 16U) {
            fail(st, "resources", path);
            return;
        }
        for (c = 0; c < charges->count; c++) {
            const json_value *charge = charges->items[c];
            const char *key = fs(st, charge, "component");
            const char *region = fs(st, charge, "region");
            uint64_t have_count = fu(st, charge, "count");
            uint64_t have_bytes = fu(st, charge, "bytes_each");
            uint64_t need_count;
            uint64_t need_bytes = 1U;
            size_t k;
            size_t region_index = nregions;
            int component_index = -1;
            char cpath[128];
            for (k = 0; k < 16U; k++) {
                if (strcmp(key, components[k]) == 0) {
                    component_index = (int)k;
                }
            }
            if (component_index < 0 || seen[component_index]) {
                fail(st, "resources", path);
                return;
            }
            seen[component_index] = 1;
            need_count = count_for(key, endpoint, associations, fu(st, security, "crypto_slots"),
                                   operations,
                                   fu(st, limits, "assemblies_per_peer"),
                                   fu(st, limits, "peers") *
                                       fu(st, limits, "assembly_tombstones_per_peer"), grants,
                                   fu(st, limits, "control_slots"),
                                   fu(st, limits, "adapter_slots"), fu(st, fresh, "tokens_per_principal"));
            if (!endpoint && strcmp(key, "relay_cache") == 0) {
                need_count = operations * (d->fragment_count + d->bootstrap_fragment_count) +
                             fu(st, timing, "max_status") + fu(st, timing, "receipt_limit");
                need_count += d->establishment_frame_reserve * fu(st, security, "episode_attempts");
            }
            if (strcmp(key, "sender") == 0 || strcmp(key, "assembly") == 0 ||
                strcmp(key, "application_queue") == 0) {
                need_bytes = endpoint ? message : 1U;
            }
            if (strcmp(key, "result") == 0) {
                uint64_t floor = grants != 0U ? 21U : 1U;
                need_bytes = endpoint ? (message > floor ? message : floor) : 1U;
            }
            if (strcmp(key, "bootstrap") == 0) {
                need_bytes = endpoint ? 0U : 1U;
            }
            if (strcmp(key, "freshness_tokens") == 0) {
                need_bytes = endpoint ? (grants != 0U ? 16U : 0U) : 1U;
            }
            if (strcmp(key, "relay_cache") == 0 && endpoint) {
                need_bytes = 0U;
            }
            if (strcmp(key, "assembly_tombstone") == 0) {
                need_bytes = endpoint ? 48U : 1U;
            }
            if (strcmp(key, "control") == 0 || strcmp(key, "adapter") == 0) {
                need_bytes = endpoint && strcmp(key, "control") == 0 ? 0U : encoded;
            }
            snprintf(cpath, sizeof cpath, "%s.%s", path, key);
            if (!need(st, have_count >= need_count && have_bytes >= need_bytes, "resources", cpath)) {
                return;
            }
            for (k = 0; k < nregions; k++) {
                if (strcmp(region_ids[k], region) == 0) {
                    region_index = k;
                }
            }
            if (region_index == nregions) {
                fail(st, "resources", path);
                return;
            }
            if (!(endpoint && (strcmp(key, "provider_scratch") == 0 ||
                               strcmp(key, "control") == 0))) {
                region_used[region_index] = nadd(region_used[region_index],
                                                 nmul(nu(have_count), nu(have_bytes)));
            }
            if (region_used[region_index].big || region_used[region_index].v > region_limit[region_index]) {
                fail(st, "resources", path);
                return;
            }
        }
    }
}

static char *read_bounded(const char *path, size_t *length_out)
{
    FILE *file = fopen(path, "rb");
    char *buf;
    size_t used = 0;
    if (file == NULL) {
        return NULL;
    }
    buf = malloc(MANIFEST_MAX_BYTES + 1U);
    if (buf == NULL) {
        fclose(file);
        return NULL;
    }
    while (used < MANIFEST_MAX_BYTES + 1U) {
        size_t got = fread(buf + used, 1, MANIFEST_MAX_BYTES + 1U - used, file);
        used += got;
        if (got == 0U) {
            break;
        }
    }
    fclose(file);
    if (used > MANIFEST_MAX_BYTES) {
        free(buf);
        return NULL;
    }
    *length_out = used;
    return buf;
}

int manifest_validate(const uint8_t *bytes, size_t length, const char *expected_sha256,
                      const char *schema_path, manifest_view *view, manifest_failure *failure)
{
    json_arena *arena;
    json_error error;
    json_value *root;
    json_arena *schema_arena;
    json_value *schema;
    char *schema_bytes = NULL;
    size_t schema_len = 0;
    vstate st;
    derived derived_values;
    memset(&st, 0, sizeof st);
    memset(&error, 0, sizeof error);
    memset(&derived_values, 0, sizeof derived_values);
    if (failure != NULL) {
        failure->code[0] = '\0';
        failure->path[0] = '\0';
    }
    if (bytes == NULL || length == 0U || length > MANIFEST_MAX_BYTES) {
        fail(&st, "encoding", "$");
    } else if (length >= 3U && bytes[0] == 0xefU && bytes[1] == 0xbbU && bytes[2] == 0xbfU) {
        fail(&st, "encoding", "$");
    }
    if (st.failed) {
        if (failure != NULL) {
            snprintf(failure->code, sizeof failure->code, "%s", st.code);
            snprintf(failure->path, sizeof failure->path, "%s", st.path);
        }
        return st.internal ? -1 : 1;
    }
    arena = json_arena_create(8U * 1024U * 1024U);
    if (arena == NULL || schema_path == NULL) {
        json_arena_destroy(arena);
        return -1;
    }
    root = json_parse(arena, bytes, length, 24U, &error);
    if (root == NULL) {
        if (failure != NULL) {
            snprintf(failure->code, sizeof failure->code, "%s", error.code != NULL ? error.code : "json");
            snprintf(failure->path, sizeof failure->path, "%s", error.path != NULL ? error.path : "$");
        }
        json_arena_destroy(arena);
        return 1;
    }
    schema_bytes = read_bounded(schema_path, &schema_len);
    schema_arena = json_arena_create(2U * 1024U * 1024U);
    if (schema_bytes == NULL || schema_arena == NULL) {
        free(schema_bytes);
        json_arena_destroy(schema_arena);
        json_arena_destroy(arena);
        return -1;
    }
    schema = json_parse(schema_arena, (const uint8_t *)schema_bytes, schema_len, 24U, &error);
    free(schema_bytes);
    if (schema == NULL) {
        json_arena_destroy(schema_arena);
        json_arena_destroy(arena);
        return -1;
    }
    schema_apply(&st, root, schema, "$");
    if (!st.failed) {
        char digest[65];
        harness_sha256_hex(bytes, length, digest);
        if (expected_sha256 != NULL) {
            size_t i;
            int hex_ok = strlen(expected_sha256) == 64U;
            for (i = 0; hex_ok && i < 64U; i++) {
                char c = expected_sha256[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                    hex_ok = 0;
                }
            }
            if (!hex_ok || strcmp(digest, expected_sha256) != 0) {
                fail(&st, "digest", "$");
            }
        }
        if (!st.failed && view != NULL) {
            memcpy(view->sha256, digest, 65U);
        }
    }
    if (!st.failed) {
        int direct = 0;
        int selective = 0;
        const json_value *binding;
        const json_value *timing;
        check_identity(&st, root, &direct, &selective);
        check_security(&st, root);
        check_frames(&st, root, direct, &derived_values);
        check_timing(&st, root, selective, &derived_values);
        check_establishment(&st, root, &derived_values);
        check_relays(&st, root, &derived_values);
        check_resources(&st, root, &derived_values);
        binding = json_object_get(root, "binding");
        timing = json_object_get(root, "timing");
        if (!st.failed && view != NULL && binding != NULL && timing != NULL) {
            const char *ownership = fs(&st, binding, "tx_ownership");
            view->borrow = strcmp(ownership, "borrow") == 0;
            view->synchronous_completion = fb(&st, binding, "synchronous_completion");
            view->encoded_mtu = (uint32_t)fu(&st, binding, "encoded_mtu");
            view->frame_tx_ms = (uint32_t)fu(&st, binding, "frame_tx_ms");
            view->period_ms = (uint32_t)fu(&st, binding, "return_slot_period_ms");
            view->width_ms = (uint32_t)fu(&st, binding, "return_slot_width_ms");
            view->forward_delay_ms = (uint32_t)fu(&st, timing, "forward_delay_ms");
            view->return_delay_ms = (uint32_t)fu(&st, timing, "return_delay_ms");
            view->queue_ms = (uint32_t)fu(&st, timing, "queue_ms");
            view->adapter_slots = (uint32_t)fu(&st, limits_of(root), "adapter_slots");
            {
                const char *topology = fs(&st, binding, "topology");
                const char *context = fs(&st, binding, "context");
                uint64_t ttl = fu(&st, binding, "ttl");
                if (!st.failed && strcmp(topology, "point-to-point") == 0 &&
                    strcmp(context, "association") == 0) {
                    view->origin_route = 0U;
                    view->origin_ttl = 0U;
                } else if (!st.failed && strcmp(topology, "static-unicast") == 0 &&
                           strcmp(context, "origin-explicit") == 0 && ttl <= 15U) {
                    view->origin_route = 1U;
                    view->origin_ttl = (uint8_t)ttl;
                } else if (!st.failed) {
                    fail(&st, "profile", "$.binding");
                }
            }
        }
    }
    json_arena_destroy(schema_arena);
    json_arena_destroy(arena);
    if (!st.failed) {
        return 0;
    }
    if (failure != NULL) {
        snprintf(failure->code, sizeof failure->code, "%s", st.code);
        snprintf(failure->path, sizeof failure->path, "%s", st.path);
    }
    return st.internal ? -1 : 1;
}
