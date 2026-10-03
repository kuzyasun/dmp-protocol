#include "dmp/identity.h"

#include <stdio.h>
#include <string.h>

/* Two-pass manifest-v2 admission. Pass A matches validate_bytes through the
 * surrogate scan: length, BOM, strict UTF-8, bracket depth, JSON syntax,
 * decoded duplicate keys, then unpaired surrogates. Pass B applies the closed
 * schema in document order and the same cross-field checks. The digest callback
 * runs only after the schema succeeds and before cross-field checks, matching
 * the offline tool. Scratch is caller-owned; this file does not allocate.
 * The first 419424 bytes hold the open-object key index and decoded key bytes.
 * Empty keys are the peak: 52428 index entries of 8 bytes. */

enum { KEY_REGION = 419424 };

typedef struct {
    int failed;
    char code[32];
    char path[192];
} err;

typedef struct {
    const uint8_t *b;
    size_t n;
    size_t i;
    char path[192];
    size_t path_len;
    err *e;
} ps;

static void set_err(err *e, const char *code, const char *path)
{
    size_t i;
    if (e == NULL || e->failed) {
        return;
    }
    e->failed = 1;
    for (i = 0U; i < sizeof e->code - 1U && code[i] != '\0'; i++) {
        e->code[i] = code[i];
    }
    e->code[i] = '\0';
    for (i = 0U; i < sizeof e->path - 1U && path[i] != '\0'; i++) {
        e->path[i] = path[i];
    }
    e->path[i] = '\0';
}

static int fail_at(ps *p, const char *code)
{
    set_err(p->e, code, p->path);
    return 0;
}

static int path_set(ps *p, const char *path)
{
    size_t n = 0U;
    while (path[n] != '\0') {
        n++;
    }
    if (n >= sizeof p->path) {
        return fail_at(p, "schema");
    }
    memcpy(p->path, path, n + 1U);
    p->path_len = n;
    return 1;
}

static int path_add(ps *p, const char *suffix)
{
    size_t n = 0U;
    size_t i;
    while (suffix[n] != '\0') {
        n++;
    }
    if (p->path_len + n >= sizeof p->path) {
        return fail_at(p, "schema");
    }
    for (i = 0U; i < n; i++) {
        p->path[p->path_len + i] = suffix[i];
    }
    p->path_len += n;
    p->path[p->path_len] = '\0';
    return 1;
}

static void path_pop(ps *p, size_t mark)
{
    p->path_len = mark;
    p->path[mark] = '\0';
}

static int ws(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void skip_ws(ps *p)
{
    while (p->i < p->n && ws(p->b[p->i])) {
        p->i++;
    }
}

static int utf8_ok(const uint8_t *b, size_t n)
{
    size_t i = 0U;
    while (i < n) {
        uint8_t c = b[i];
        size_t need = 1U;
        uint32_t cp = c;
        size_t j;
        if (c <= 0x7fU) {
            i++;
            continue;
        }
        if (c >= 0xc2U && c <= 0xdfU) {
            need = 2U;
            cp = c & 0x1fU;
        } else if (c == 0xe0U) {
            need = 3U;
            cp = c & 0x0fU;
        } else if ((c >= 0xe1U && c <= 0xecU) || c == 0xeeU || c == 0xefU) {
            need = 3U;
            cp = c & 0x0fU;
        } else if (c == 0xedU) {
            need = 3U;
            cp = c & 0x0fU;
        } else if (c == 0xf0U) {
            need = 4U;
            cp = c & 0x07U;
        } else if (c >= 0xf1U && c <= 0xf3U) {
            need = 4U;
            cp = c & 0x07U;
        } else if (c == 0xf4U) {
            need = 4U;
            cp = c & 0x07U;
        } else {
            return 0;
        }
        if (n - i < need) {
            return 0;
        }
        for (j = 1U; j < need; j++) {
            if ((b[i + j] & 0xc0U) != 0x80U) {
                return 0;
            }
            cp = (cp << 6U) | (uint32_t)(b[i + j] & 0x3fU);
        }
        if (c == 0xe0U && b[i + 1U] < 0xa0U) {
            return 0;
        }
        if (c == 0xedU && b[i + 1U] >= 0xa0U) {
            return 0;
        }
        if (c == 0xf0U && b[i + 1U] < 0x90U) {
            return 0;
        }
        if (c == 0xf4U && b[i + 1U] >= 0x90U) {
            return 0;
        }
        (void)cp;
        i += need;
    }
    return 1;
}

static int depth_ok(const uint8_t *b, size_t n)
{
    size_t i;
    int depth = 0;
    int quoted = 0;
    int escaped = 0;
    for (i = 0U; i < n; i++) {
        unsigned char c = b[i];
        if (quoted) {
            if (escaped) {
                escaped = 0;
            } else if (c == '\\') {
                escaped = 1;
            } else if (c == '"') {
                quoted = 0;
            }
        } else if (c == '"') {
            quoted = 1;
        } else if (c == '[' || c == '{') {
            depth++;
            if (depth > 24) {
                return 0;
            }
        } else if (c == ']' || c == '}') {
            depth--;
        }
    }
    return 1;
}

typedef struct {
    uint8_t *base;
    size_t nkeys;
    size_t blob_used;
} keys;

typedef struct {
    size_t nkeys;
    size_t blob_used;
} keymark;

static int key_put(keys *k, const uint8_t *text, size_t len, err *e)
{
    size_t index_bytes = (k->nkeys + 1U) * 8U;
    size_t blob = k->blob_used + len;
    uint8_t *slot;
    uint32_t off;
    uint32_t stored;
    if (index_bytes + blob > KEY_REGION) {
        set_err(e, "json", "$");
        return 0;
    }
    off = (uint32_t)(KEY_REGION - blob);
    if (len != 0U) {
        memmove(k->base + off, text, len);
    }
    slot = k->base + k->nkeys * 8U;
    stored = off;
    memcpy(slot, &stored, 4U);
    stored = (uint32_t)len;
    memcpy(slot + 4U, &stored, 4U);
    k->nkeys++;
    k->blob_used = blob;
    return 1;
}

static int key_dup(const keys *k, size_t begin, const uint8_t *text, size_t len)
{
    size_t i;
    for (i = begin; i < k->nkeys; i++) {
        uint32_t off = 0U;
        uint32_t have = 0U;
        memcpy(&off, k->base + i * 8U, 4U);
        memcpy(&have, k->base + i * 8U + 4U, 4U);
        if (have == len && (len == 0U || memcmp(k->base + off, text, len) == 0)) {
            return 1;
        }
    }
    return 0;
}

typedef struct {
    ps *p;
    keys *keys;
    size_t obj_keys;
    int lone;
    int hold;
    uint32_t held;
    uint8_t *out;
    size_t cap;
    size_t len;
    int storing;
    int strict;
    int overflow;
} dec;

static int emit_cp(dec *d, uint32_t cp)
{
    uint8_t tmp[4];
    size_t n = 0U;
    if (cp >= 0xd800U && cp <= 0xdfffU) {
        d->lone = 1;
    }
    if (!d->storing) {
        return 1;
    }
    if (cp < 0x80U) {
        tmp[0] = (uint8_t)cp;
        n = 1U;
    } else if (cp < 0x800U) {
        tmp[0] = (uint8_t)(0xc0U | (cp >> 6U));
        tmp[1] = (uint8_t)(0x80U | (cp & 0x3fU));
        n = 2U;
    } else if (cp < 0x10000U) {
        tmp[0] = (uint8_t)(0xe0U | (cp >> 12U));
        tmp[1] = (uint8_t)(0x80U | ((cp >> 6U) & 0x3fU));
        tmp[2] = (uint8_t)(0x80U | (cp & 0x3fU));
        n = 3U;
    } else {
        tmp[0] = (uint8_t)(0xf0U | (cp >> 18U));
        tmp[1] = (uint8_t)(0x80U | ((cp >> 12U) & 0x3fU));
        tmp[2] = (uint8_t)(0x80U | ((cp >> 6U) & 0x3fU));
        tmp[3] = (uint8_t)(0x80U | (cp & 0x3fU));
        n = 4U;
    }
    if (d->len + n > d->cap) {
        d->overflow = 1;
        d->storing = 0;
        return d->strict ? 0 : 1;
    }
    memcpy(d->out + d->len, tmp, n);
    d->len += n;
    return 1;
}

static int feed_unit(dec *d, uint32_t unit)
{
    if (d->hold) {
        d->hold = 0;
        if (unit >= 0xdc00U && unit <= 0xdfffU) {
            uint32_t cp = 0x10000U + (((d->held - 0xd800U) << 10U) | (unit - 0xdc00U));
            return emit_cp(d, cp);
        }
        d->lone = 1;
        if (!emit_cp(d, d->held)) {
            return 0;
        }
    }
    if (unit >= 0xd800U && unit <= 0xdbffU) {
        d->hold = 1;
        d->held = unit;
        return 1;
    }
    if (unit >= 0xdc00U && unit <= 0xdfffU) {
        d->lone = 1;
    }
    return emit_cp(d, unit);
}

static int hex4(ps *p, uint32_t *out)
{
    uint32_t v = 0U;
    int i;
    for (i = 0; i < 4; i++) {
        unsigned char c;
        uint32_t d;
        if (p->i >= p->n) {
            return 0;
        }
        c = p->b[p->i++];
        if (c >= '0' && c <= '9') {
            d = (uint32_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            d = (uint32_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            d = (uint32_t)(c - 'A' + 10);
        } else {
            return 0;
        }
        v = (v << 4U) | d;
    }
    *out = v;
    return 1;
}

static int decode_string(ps *p, dec *d)
{
    if (p->i >= p->n || p->b[p->i] != '"') {
        return fail_at(p, "json");
    }
    p->i++;
    while (p->i < p->n) {
        unsigned char c = p->b[p->i++];
        uint32_t unit = c;
        if (c == '"') {
            if (d->hold) {
                d->lone = 1;
                d->hold = 0;
                if (!emit_cp(d, d->held)) {
                    return fail_at(p, "json");
                }
            }
            return 1;
        }
        if (c < 0x20U) {
            return fail_at(p, "json");
        }
        if (c == '\\') {
            unsigned char e;
            if (p->i >= p->n) {
                return fail_at(p, "json");
            }
            e = p->b[p->i++];
            if (e == '"' || e == '\\' || e == '/') {
                unit = e;
            } else if (e == 'b') {
                unit = 0x08U;
            } else if (e == 'f') {
                unit = 0x0cU;
            } else if (e == 'n') {
                unit = 0x0aU;
            } else if (e == 'r') {
                unit = 0x0dU;
            } else if (e == 't') {
                unit = 0x09U;
            } else if (e == 'u') {
                if (!hex4(p, &unit)) {
                    return fail_at(p, "json");
                }
            } else {
                return fail_at(p, "json");
            }
        } else if (c >= 0x80U) {
            /* Already validated UTF-8. Reparse this codepoint from c. */
            size_t start = p->i - 1U;
            size_t need = (c & 0xe0U) == 0xc0U ? 2U : (c & 0xf0U) == 0xe0U ? 3U : 4U;
            size_t j;
            unit = c & (need == 2U ? 0x1fU : need == 3U ? 0x0fU : 0x07U);
            if (p->n - start < need) {
                return fail_at(p, "json");
            }
            for (j = 1U; j < need; j++) {
                unit = (unit << 6U) | (uint32_t)(p->b[start + j] & 0x3fU);
            }
            p->i = start + need;
        }
        if (!feed_unit(d, unit)) {
            return fail_at(p, "json");
        }
    }
    return fail_at(p, "json");
}

static int lex_number(ps *p)
{
    size_t start;
    size_t digits = 0U;
    if (p->i < p->n && p->b[p->i] == '-') {
        p->i++;
    }
    start = p->i;
    if (p->i >= p->n || p->b[p->i] < '0' || p->b[p->i] > '9') {
        return fail_at(p, "json");
    }
    if (p->b[p->i] == '0') {
        p->i++;
        digits = 1U;
    } else {
        while (p->i < p->n && p->b[p->i] >= '0' && p->b[p->i] <= '9') {
            p->i++;
            digits++;
        }
    }
    if (digits > 20U) {
        return fail_at(p, "json");
    }
    if (p->b[start] == '0' && p->i - start != 1U) {
        return fail_at(p, "json");
    }
    if (p->i < p->n && (p->b[p->i] == '.' || p->b[p->i] == 'e' || p->b[p->i] == 'E')) {
        return fail_at(p, "json");
    }
    return 1;
}

static int lex_lit(ps *p, const char *lit)
{
    size_t n = 0U;
    while (lit[n] != '\0') {
        n++;
    }
    if (p->n - p->i < n || memcmp(p->b + p->i, lit, n) != 0) {
        return fail_at(p, "json");
    }
    p->i += n;
    return 1;
}

static int lex_value(ps *p, keys *k, int *lone);

static int lex_string_value(ps *p, int *lone)
{
    dec d;
    memset(&d, 0, sizeof d);
    d.p = p;
    d.lone = *lone;
    if (!decode_string(p, &d)) {
        return 0;
    }
    *lone = d.lone;
    return 1;
}

static int lex_key(ps *p, keys *k, size_t begin, int *lone)
{
    dec d;
    size_t room;
    memset(&d, 0, sizeof d);
    d.p = p;
    d.lone = *lone;
    d.storing = 1;
    d.strict = 1;
    {
        size_t reserve = (k->nkeys + 1U) * 8U + k->blob_used;
        if (reserve > KEY_REGION) {
            return fail_at(p, "json");
        }
        room = KEY_REGION - reserve;
    }
    d.out = k->base + (k->nkeys + 1U) * 8U;
    d.cap = room;
    if (!decode_string(p, &d)) {
        return 0;
    }
    *lone = d.lone;
    if (key_dup(k, begin, d.out, d.len)) {
        return fail_at(p, "json");
    }
    return key_put(k, d.out, d.len, p->e);
}

static int lex_object(ps *p, keys *k, int *lone)
{
    keymark mark;
    mark.nkeys = k->nkeys;
    mark.blob_used = k->blob_used;
    if (p->i >= p->n || p->b[p->i] != '{') {
        return fail_at(p, "json");
    }
    p->i++;
    skip_ws(p);
    if (p->i < p->n && p->b[p->i] == '}') {
        p->i++;
        return 1;
    }
    for (;;) {
        skip_ws(p);
        if (!lex_key(p, k, mark.nkeys, lone)) {
            return 0;
        }
        skip_ws(p);
        if (p->i >= p->n || p->b[p->i] != ':') {
            return fail_at(p, "json");
        }
        p->i++;
        if (!lex_value(p, k, lone)) {
            return 0;
        }
        skip_ws(p);
        if (p->i < p->n && p->b[p->i] == ',') {
            p->i++;
            continue;
        }
        if (p->i < p->n && p->b[p->i] == '}') {
            p->i++;
            k->nkeys = mark.nkeys;
            k->blob_used = mark.blob_used;
            return 1;
        }
        return fail_at(p, "json");
    }
}

static int lex_array(ps *p, keys *k, int *lone)
{
    if (p->i >= p->n || p->b[p->i] != '[') {
        return fail_at(p, "json");
    }
    p->i++;
    skip_ws(p);
    if (p->i < p->n && p->b[p->i] == ']') {
        p->i++;
        return 1;
    }
    for (;;) {
        if (!lex_value(p, k, lone)) {
            return 0;
        }
        skip_ws(p);
        if (p->i < p->n && p->b[p->i] == ',') {
            p->i++;
            continue;
        }
        if (p->i < p->n && p->b[p->i] == ']') {
            p->i++;
            return 1;
        }
        return fail_at(p, "json");
    }
}

static int lex_value(ps *p, keys *k, int *lone)
{
    unsigned char c;
    skip_ws(p);
    if (p->i >= p->n) {
        return fail_at(p, "json");
    }
    c = p->b[p->i];
    if (c == '"') {
        return lex_string_value(p, lone);
    }
    if (c == '{') {
        return lex_object(p, k, lone);
    }
    if (c == '[') {
        return lex_array(p, k, lone);
    }
    if (c == 't') {
        return lex_lit(p, "true");
    }
    if (c == 'f') {
        return lex_lit(p, "false");
    }
    if (c == 'n') {
        return lex_lit(p, "null");
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        return lex_number(p);
    }
    return fail_at(p, "json");
}

static int lex_document(ps *p, uint8_t *scratch, int *lone)
{
    keys k;
    memset(&k, 0, sizeof k);
    k.base = scratch;
    *lone = 0;
    if (!lex_value(p, &k, lone)) {
        return 0;
    }
    skip_ws(p);
    if (p->i != p->n) {
        return fail_at(p, "json");
    }
    return 1;
}

/* ---- schema walk (pass B). Wrong JSON types are schema errors. ---- */

enum {
    ACT_PRODUCE = 1,
    ACT_READ = 2,
    ACT_STATUS = 4,
    ACT_DATA = 8,
    ACT_RESULT = 16
};

typedef struct {
    uint32_t node;
    uint8_t actions;
    uint8_t action_count;
    uint8_t action_dup;
} acl_entry;

typedef struct {
    uint32_t id, reply, request_bytes, result_bytes, processing_ms;
    int omitted, sample_schema, selective, freshness;
    acl_entry acl[2];
} service_rec;

typedef struct {
    uint32_t node, cooldown_ms, expiry_ms, max_forwards, frame_tx_ms;
    uint32_t per_origin, global_air, lower_dups, dup_tail;
    uint32_t fwd_min, fwd_max, ret_min, ret_max;
} relay_rec;

typedef struct {
    char id[97];
    uint32_t limit;
} region_rec;

typedef struct {
    int component;
    char region[97];
    uint32_t count, bytes_each;
} charge_rec;

typedef struct {
    int relay;
    char target[97];
    uint32_t flash_limit, flash_reserved;
    int nregions, ncharges;
    region_rec regions[8];
    charge_rec charges[112];
} resource_rec;

typedef struct {
    int direct, selective, testfam, owner_test;
    uint32_t profile_revision, namespace_id, node_id[2], sample_producer;
    uint32_t ttl, forward_mtu, return_mtu, encoded_mtu, frame_tx_ms, period_ms, width_ms;
    int tx_borrow, sync_completion, context_assoc, kind_stream, topo_p2p, bind_stream;
    service_rec services[2];
    uint32_t message_bytes, fragments, chunk_bytes, boot_chunk, boot_frags;
    uint32_t peers, assemblies, assembly_tombstones, operations, control_slots, app_queue, adapter_slots;
    int mode_xx;
    int credential_oob;
    uint32_t pending, active, draining, crypto_slots, failed_aead, replay_bits;
    uint32_t encryption_limit, plaintext_limit, association_ms, drain_ms, pairing_ms;
    uint32_t preauth_slots, preauth_bytes, attempt_ms, flight_attempts, flight_retry_ms;
    uint32_t confirm_attempts, confirm_timeout, dup_responses, response_window_ms;
    uint32_t responses_per_window, response_bytes_per_window, episode_attempts, episode_ms;
    uint32_t episode_crypto_ms, crypto_per_attempt, episode_tx, attempt_tx, restart_backoff;
    uint32_t later_episodes, later_window, ingress_packets, ingress_window, global_crypto;
    uint32_t queue_ms, forward_delay, return_delay, receipt_delay, burst_span;
    uint32_t feedback_guard, feedback_delay, response_timeout, send_horizon;
    uint32_t max_bursts, max_probes, max_status, jitter_ms, record_margin;
    uint32_t collect_ms, assembly_ms, inactivity_ms, dedup_ms, rejection_ms;
    uint32_t result_cache_ms, result_deadline_ms, correlation_ms, tombstone_ms;
    uint32_t late_result_ms, max_airtime, receipt_limit, feedback_buffers;
    uint32_t burst_starts[32];
    int nbursts;
    uint32_t lease_ms, grant_age, tokens_assoc, tokens_principal, grant_requests;
    uint32_t token_record_ms, grant_result_ms, grant_nodes[2];
    int ngrants;
    uint32_t init_attempts, init_retry_ms, init_deadline_ms;
    relay_rec relays[4];
    int nrelays;
    resource_rec resources[2];
    int nresources;
} manifest;

typedef char manifest_fits_scratch[(sizeof(manifest) + 64U < 419936U) ? 1 : -1];

static int skip_value(ps *p);

static int skip_string(ps *p)
{
    dec d;
    memset(&d, 0, sizeof d);
    d.p = p;
    return decode_string(p, &d);
}

static int skip_value(ps *p)
{
    unsigned char c;
    skip_ws(p);
    if (p->i >= p->n) {
        return fail_at(p, "json");
    }
    c = p->b[p->i];
    if (c == '"') {
        return skip_string(p);
    }
    if (c == '{') {
        p->i++;
        skip_ws(p);
        if (p->i < p->n && p->b[p->i] == '}') {
            p->i++;
            return 1;
        }
        for (;;) {
            skip_ws(p);
            if (!skip_string(p)) {
                return 0;
            }
            skip_ws(p);
            if (p->i >= p->n || p->b[p->i] != ':') {
                return fail_at(p, "json");
            }
            p->i++;
            if (!skip_value(p)) {
                return 0;
            }
            skip_ws(p);
            if (p->i < p->n && p->b[p->i] == ',') {
                p->i++;
                continue;
            }
            if (p->i < p->n && p->b[p->i] == '}') {
                p->i++;
                return 1;
            }
            return fail_at(p, "json");
        }
    }
    if (c == '[') {
        p->i++;
        skip_ws(p);
        if (p->i < p->n && p->b[p->i] == ']') {
            p->i++;
            return 1;
        }
        for (;;) {
            if (!skip_value(p)) {
                return 0;
            }
            skip_ws(p);
            if (p->i < p->n && p->b[p->i] == ',') {
                p->i++;
                continue;
            }
            if (p->i < p->n && p->b[p->i] == ']') {
                p->i++;
                return 1;
            }
            return fail_at(p, "json");
        }
    }
    if (c == 't') {
        return lex_lit(p, "true");
    }
    if (c == 'f') {
        return lex_lit(p, "false");
    }
    if (c == 'n') {
        return lex_lit(p, "null");
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        return lex_number(p);
    }
    return fail_at(p, "json");
}

static int read_str(ps *p, char *buf, size_t cap, size_t *len)
{
    dec d;
    skip_ws(p);
    if (p->i >= p->n || p->b[p->i] != '"') {
        return fail_at(p, "schema");
    }
    memset(&d, 0, sizeof d);
    d.p = p;
    d.storing = 1;
    d.out = (uint8_t *)buf;
    d.cap = cap == 0U ? 0U : cap - 1U;
    if (!decode_string(p, &d)) {
        return 0;
    }
    if (d.overflow) {
        return fail_at(p, "schema");
    }
    buf[d.len] = '\0';
    *len = d.len;
    return 1;
}

static int take_u32(ps *p, uint32_t *dst, uint32_t min, uint32_t max)
{
    int neg = 0;
    uint64_t v = 0U;
    size_t digits = 0U;
    skip_ws(p);
    if (p->i < p->n && p->b[p->i] == '-') {
        neg = 1;
        p->i++;
    }
    if (p->i >= p->n || p->b[p->i] < '0' || p->b[p->i] > '9') {
        return fail_at(p, "schema");
    }
    if (p->b[p->i] == '0') {
        p->i++;
        digits = 1U;
        if (p->i < p->n && p->b[p->i] >= '0' && p->b[p->i] <= '9') {
            return fail_at(p, "json");
        }
    } else {
        while (p->i < p->n && p->b[p->i] >= '0' && p->b[p->i] <= '9') {
            uint8_t digit = (uint8_t)(p->b[p->i] - '0');
            if (v > (UINT64_MAX - digit) / 10U) {
                v = UINT64_MAX;
            } else {
                v = v * 10U + digit;
            }
            p->i++;
            digits++;
        }
    }
    if (digits > 20U || (p->i < p->n && (p->b[p->i] == '.' || p->b[p->i] == 'e' || p->b[p->i] == 'E'))) {
        return fail_at(p, "json");
    }
    /* JSON -0 is zero. Any other negative value misses the unsigned minimum. */
    if ((neg && v != 0U) || v < min || v > max) {
        return fail_at(p, "schema");
    }
    *dst = (uint32_t)v;
    return 1;
}

static int take_bool(ps *p, int *dst)
{
    skip_ws(p);
    if (p->n - p->i >= 4U && memcmp(p->b + p->i, "true", 4) == 0) {
        p->i += 4U;
        *dst = 1;
        return 1;
    }
    if (p->n - p->i >= 5U && memcmp(p->b + p->i, "false", 5) == 0) {
        p->i += 5U;
        *dst = 0;
        return 1;
    }
    return fail_at(p, "schema");
}

static int take_enum(ps *p, const char *const *opts, int n, int *dst)
{
    char buf[96];
    size_t len = 0U;
    int i;
    if (!read_str(p, buf, sizeof buf, &len)) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        size_t k = 0U;
        while (opts[i][k] != '\0') {
            k++;
        }
        if (k == len && memcmp(opts[i], buf, len) == 0) {
            *dst = i;
            return 1;
        }
    }
    return fail_at(p, "schema");
}

static int take_enum_u(ps *p, const uint32_t *opts, int n, uint32_t *dst)
{
    uint32_t v = 0U;
    int i;
    if (!take_u32(p, &v, 0U, UINT32_MAX)) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (opts[i] == v) {
            *dst = v;
            return 1;
        }
    }
    return fail_at(p, "schema");
}

static int ident_text(const char *s, size_t n)
{
    size_t i;
    if (n < 1U || n > 96U) {
        return 0;
    }
    for (i = 0U; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '.' || c == ':' || c == '/' || c == '+' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

typedef int (*take_fn)(ps *p, void *obj);
typedef struct {
    const char *name;
    take_fn take;
} fld;

static int lookup_field(const fld *fields, int n, const char *key, size_t len)
{
    int i;
    for (i = 0; i < n; i++) {
        size_t k = 0U;
        while (fields[i].name[k] != '\0') {
            k++;
        }
        if (k == len && memcmp(fields[i].name, key, len) == 0) {
            return i;
        }
    }
    return -1;
}

static int closed_object(ps *p, void *obj, const fld *fields, int n)
{
    uint32_t at[48];
    uint8_t order[48];
    int norder = 0;
    int unknown = 0;
    uint64_t seen = 0U;
    size_t path_mark = p->path_len;
    if (n <= 0 || n > 48) {
        return fail_at(p, "schema");
    }
    skip_ws(p);
    if (p->i >= p->n || p->b[p->i] != '{') {
        return fail_at(p, "schema");
    }
    p->i++;
    skip_ws(p);
    if (p->i < p->n && p->b[p->i] == '}') {
        p->i++;
        return fail_at(p, "schema");
    }
    for (;;) {
        char key[80];
        size_t klen = 0U;
        int id;
        skip_ws(p);
        if (!read_str(p, key, sizeof key, &klen)) {
            if (p->e->failed && strcmp(p->e->code, "schema") == 0 &&
                (p->i == 0U || p->b[p->i - 1U] != '"')) {
                /* non-string key is invalid JSON, already rejected in pass A */
            }
            if (!p->e->failed) {
                return fail_at(p, "schema");
            }
            /* A too-long key cannot be a known field. Treat overflow as unknown
             * only when a string was present; read_str already failed schema. */
            return 0;
        }
        id = lookup_field(fields, n, key, klen);
        skip_ws(p);
        if (p->i >= p->n || p->b[p->i] != ':') {
            return fail_at(p, "json");
        }
        p->i++;
        if (id < 0) {
            unknown = 1;
            if (!skip_value(p)) {
                return 0;
            }
        } else {
            if ((seen & (1ULL << id)) != 0U) {
                return fail_at(p, "json");
            }
            seen |= 1ULL << id;
            skip_ws(p);
            at[id] = (uint32_t)p->i;
            order[norder++] = (uint8_t)id;
            if (!skip_value(p)) {
                return 0;
            }
        }
        skip_ws(p);
        if (p->i < p->n && p->b[p->i] == ',') {
            p->i++;
            continue;
        }
        if (p->i < p->n && p->b[p->i] == '}') {
            p->i++;
            break;
        }
        return fail_at(p, "json");
    }
    if (unknown || seen != ((1ULL << n) - 1ULL)) {
        path_pop(p, path_mark);
        return fail_at(p, "schema");
    }
    {
        int i;
        for (i = 0; i < norder; i++) {
            int id = order[i];
            char suffix[80];
            size_t mark = p->path_len;
            size_t sl = 0U;
            suffix[0] = '.';
            while (fields[id].name[sl] != '\0' && sl + 2U < sizeof suffix) {
                suffix[sl + 1U] = fields[id].name[sl];
                sl++;
            }
            suffix[sl + 1U] = '\0';
            if (!path_add(p, suffix)) {
                return 0;
            }
            p->i = at[id];
            if (!fields[id].take(p, obj)) {
                return 0;
            }
            path_pop(p, mark);
        }
    }
    return 1;
}

static int parse_u32_array(ps *p, uint32_t *dst, int *count, int min_n, int max_n,
                           uint32_t lo, uint32_t hi)
{
    uint32_t offs[112];
    int n = 0;
    int overflow = 0;
    skip_ws(p);
    if (p->i >= p->n || p->b[p->i] != '[') {
        return fail_at(p, "schema");
    }
    p->i++;
    skip_ws(p);
    if (p->i < p->n && p->b[p->i] == ']') {
        p->i++;
    } else {
        for (;;) {
            skip_ws(p);
            if (n < max_n && n < 112) {
                offs[n] = (uint32_t)p->i;
            } else {
                overflow = 1;
            }
            n++;
            if (!skip_value(p)) {
                return 0;
            }
            skip_ws(p);
            if (p->i < p->n && p->b[p->i] == ',') {
                p->i++;
                continue;
            }
            if (p->i < p->n && p->b[p->i] == ']') {
                p->i++;
                break;
            }
            return fail_at(p, "json");
        }
    }
    if (overflow || n < min_n || n > max_n) {
        return fail_at(p, "schema");
    }
    {
        int i;
        for (i = 0; i < n; i++) {
            char suffix[16];
            size_t mark = p->path_len;
            snprintf(suffix, sizeof suffix, "[%d]", i);
            if (!path_add(p, suffix)) {
                return 0;
            }
            p->i = offs[i];
            if (!take_u32(p, &dst[i], lo, hi)) {
                return 0;
            }
            path_pop(p, mark);
        }
    }
    *count = n;
    return 1;
}

static int expect_str(ps *p, const char *want)
{
    char buf[96];
    size_t len = 0U;
    size_t n = 0U;
    if (!read_str(p, buf, sizeof buf, &len)) {
        return 0;
    }
    while (want[n] != '\0') {
        n++;
    }
    if (n != len || memcmp(buf, want, len) != 0) {
        return fail_at(p, "schema");
    }
    return 1;
}

static int expect_one(ps *p, uint32_t want)
{
    uint32_t v = 0U;
    if (!take_u32(p, &v, want, want)) {
        return 0;
    }
    return 1;
}

static int parse_items(ps *p, void *base, size_t stride, int *count, int min_n, int max_n,
                       int (*one)(ps *, void *))
{
    uint32_t offs[112];
    int n = 0;
    int overflow = 0;
    skip_ws(p);
    if (p->i >= p->n || p->b[p->i] != '[') {
        return fail_at(p, "schema");
    }
    p->i++;
    skip_ws(p);
    if (!(p->i < p->n && p->b[p->i] == ']')) {
        for (;;) {
            skip_ws(p);
            if (n < max_n && n < 112) {
                offs[n] = (uint32_t)p->i;
            } else {
                overflow = 1;
            }
            n++;
            if (!skip_value(p)) {
                return 0;
            }
            skip_ws(p);
            if (p->i < p->n && p->b[p->i] == ',') {
                p->i++;
                continue;
            }
            if (p->i < p->n && p->b[p->i] == ']') {
                p->i++;
                break;
            }
            return fail_at(p, "json");
        }
    } else {
        p->i++;
    }
    if (overflow || n < min_n || n > max_n) {
        return fail_at(p, "schema");
    }
    {
        int i;
        uint8_t *cursor = (uint8_t *)base;
        for (i = 0; i < n; i++) {
            char suffix[16];
            size_t mark = p->path_len;
            snprintf(suffix, sizeof suffix, "[%d]", i);
            if (!path_add(p, suffix)) {
                return 0;
            }
            p->i = offs[i];
            if (!one(p, cursor + (size_t)i * stride)) {
                return 0;
            }
            path_pop(p, mark);
        }
    }
    *count = n;
    return 1;
}

static int take_ident(ps *p, char *dst, size_t cap)
{
    size_t len = 0U;
    if (!read_str(p, dst, cap, &len)) {
        return 0;
    }
    if (!ident_text(dst, len)) {
        return fail_at(p, "schema");
    }
    return 1;
}

static const char *const ACTION_NAMES[] = {"produce", "read", "status", "data", "result"};
static const uint8_t ACTION_BITS[] = {1U, 2U, 4U, 8U, 16U};

static int parse_acl(ps *p, void *obj)
{
    acl_entry *a = (acl_entry *)obj;
    {
        uint32_t at_node = 0U, at_actions = 0U;
        int have_node = 0, have_actions = 0, unknown = 0;
        int order[2];
        int norder = 0;
        skip_ws(p);
        if (p->i >= p->n || p->b[p->i] != '{') {
            return fail_at(p, "schema");
        }
        p->i++;
        skip_ws(p);
        if (p->i < p->n && p->b[p->i] == '}') {
            p->i++;
            return fail_at(p, "schema");
        }
        for (;;) {
            char key[32];
            size_t klen = 0U;
            skip_ws(p);
            if (!read_str(p, key, sizeof key, &klen)) {
                return 0;
            }
            skip_ws(p);
            if (p->i >= p->n || p->b[p->i] != ':') {
                return fail_at(p, "json");
            }
            p->i++;
            skip_ws(p);
            if (klen == 4U && memcmp(key, "node", 4) == 0) {
                if (have_node) {
                    return fail_at(p, "json");
                }
                have_node = 1;
                at_node = (uint32_t)p->i;
                order[norder++] = 0;
            } else if (klen == 7U && memcmp(key, "actions", 7) == 0) {
                if (have_actions) {
                    return fail_at(p, "json");
                }
                have_actions = 1;
                at_actions = (uint32_t)p->i;
                order[norder++] = 1;
            } else {
                unknown = 1;
            }
            if (!skip_value(p)) {
                return 0;
            }
            skip_ws(p);
            if (p->i < p->n && p->b[p->i] == ',') {
                p->i++;
                continue;
            }
            if (p->i < p->n && p->b[p->i] == '}') {
                p->i++;
                break;
            }
            return fail_at(p, "json");
        }
        if (unknown || !have_node || !have_actions) {
            return fail_at(p, "schema");
        }
        {
            int i;
            for (i = 0; i < norder; i++) {
                size_t mark = p->path_len;
                if (order[i] == 0) {
                    if (!path_add(p, ".node") || (p->i = at_node, !take_u32(p, &a->node, 0U, UINT32_MAX))) {
                        return 0;
                    }
                } else {
                    uint32_t offs[5];
                    int n = 0;
                    int overflow = 0;
                    int j;
                    if (!path_add(p, ".actions")) {
                        return 0;
                    }
                    p->i = at_actions;
                    skip_ws(p);
                    if (p->i >= p->n || p->b[p->i] != '[') {
                        return fail_at(p, "schema");
                    }
                    p->i++;
                    skip_ws(p);
                    if (!(p->i < p->n && p->b[p->i] == ']')) {
                        for (;;) {
                            skip_ws(p);
                            if (n < 5) {
                                offs[n] = (uint32_t)p->i;
                            } else {
                                overflow = 1;
                            }
                            n++;
                            if (!skip_value(p)) {
                                return 0;
                            }
                            skip_ws(p);
                            if (p->i < p->n && p->b[p->i] == ',') {
                                p->i++;
                                continue;
                            }
                            if (p->i < p->n && p->b[p->i] == ']') {
                                p->i++;
                                break;
                            }
                            return fail_at(p, "json");
                        }
                    } else {
                        p->i++;
                    }
                    if (overflow || n < 1 || n > 5) {
                        return fail_at(p, "schema");
                    }
                    a->actions = 0U;
                    a->action_count = 0U;
                    a->action_dup = 0U;
                    for (j = 0; j < n; j++) {
                        char name[16];
                        size_t len = 0U;
                        int k;
                        int found = 0;
                        char suffix[8];
                        size_t amark = p->path_len;
                        snprintf(suffix, sizeof suffix, "[%d]", j);
                        if (!path_add(p, suffix)) {
                            return 0;
                        }
                        p->i = offs[j];
                        if (!read_str(p, name, sizeof name, &len)) {
                            return 0;
                        }
                        for (k = 0; k < 5; k++) {
                            size_t kn = 0U;
                            while (ACTION_NAMES[k][kn] != '\0') {
                                kn++;
                            }
                            if (kn == len && memcmp(ACTION_NAMES[k], name, len) == 0) {
                                if ((a->actions & ACTION_BITS[k]) != 0U) {
                                    a->action_dup = 1U;
                                }
                                a->actions = (uint8_t)(a->actions | ACTION_BITS[k]);
                                a->action_count = (uint8_t)(a->action_count + 1U);
                                found = 1;
                                break;
                            }
                        }
                        if (!found) {
                            return fail_at(p, "schema");
                        }
                        path_pop(p, amark);
                    }
                }
                path_pop(p, mark);
            }
        }
    }
    return 1;
}

#define TAKE_U32(fn, type, member, lo, hi) \
    static int fn(ps *p, void *o) { return take_u32(p, &((type *)o)->member, (lo), (hi)); }
#define TAKE_LIT(fn, lit) \
    static int fn(ps *p, void *o) { (void)o; return expect_str(p, lit); }
#define TAKE_ONE(fn, value) \
    static int fn(ps *p, void *o) { (void)o; return expect_one(p, (value)); }

static int take_service_id(ps *p, void *o) { return take_u32(p, &((service_rec *)o)->id, 1U, UINT32_MAX); }
static int take_service_reply(ps *p, void *o) { return take_u32(p, &((service_rec *)o)->reply, 1U, UINT32_MAX); }
static int take_service_req(ps *p, void *o) { return take_u32(p, &((service_rec *)o)->request_bytes, 1U, 1024U); }
static int take_service_res(ps *p, void *o) { return take_u32(p, &((service_rec *)o)->result_bytes, 1U, 1024U); }
static int take_service_ms(ps *p, void *o) { return take_u32(p, &((service_rec *)o)->processing_ms, 1U, 2147483647U); }
static int take_service_fresh(ps *p, void *o) { return take_bool(p, &((service_rec *)o)->freshness); }
static int take_service_true(ps *p, void *o)
{
    int v = 0;
    (void)o;
    if (!take_bool(p, &v) || !v) {
        return fail_at(p, "schema");
    }
    return 1;
}
static int take_service_encoding(ps *p, void *o)
{
    static const char *const opts[] = {"omitted", "explicit"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((service_rec *)o)->omitted = v == 0;
    return 1;
}
static int take_service_schema(ps *p, void *o)
{
    static const char *const opts[] = {"DMP-reference/SAMPLE-1/2", "DMP-test/OPAQUE-1/1"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((service_rec *)o)->sample_schema = v == 0;
    return 1;
}
static int take_service_recovery(ps *p, void *o)
{
    static const char *const opts[] = {"retry-all", "selective-32"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((service_rec *)o)->selective = v == 1;
    return 1;
}
TAKE_LIT(take_service_sec, "SEC-1")
TAKE_LIT(take_service_payload, "omitted")
static int take_service_acl(ps *p, void *o)
{
    service_rec *s = (service_rec *)o;
    int n = 0;
    if (!parse_items(p, s->acl, sizeof s->acl[0], &n, 2, 2, parse_acl)) {
        return 0;
    }
    return 1;
}

static int parse_service(ps *p, void *obj)
{
    static const fld fields[] = {
        {"id", take_service_id},
        {"reply_service", take_service_reply},
        {"service_encoding", take_service_encoding},
        {"schema", take_service_schema},
        {"payload_desc", take_service_payload},
        {"recovery", take_service_recovery},
        {"security", take_service_sec},
        {"freshness", take_service_fresh},
        {"idempotent", take_service_true},
        {"request_bytes", take_service_req},
        {"result_bytes", take_service_res},
        {"processing_ms", take_service_ms},
        {"acl", take_service_acl}
    };
    return closed_object(p, obj, fields, (int)(sizeof fields / sizeof fields[0]));
}

static int take_region_id(ps *p, void *o) { return take_ident(p, ((region_rec *)o)->id, sizeof ((region_rec *)o)->id); }
TAKE_U32(take_region_limit, region_rec, limit, 1U, 2147483647U)
static int parse_region(ps *p, void *obj)
{
    static const fld fields[] = {{"id", take_region_id}, {"limit_bytes", take_region_limit}};
    return closed_object(p, obj, fields, 2);
}

static const char *const COMPONENT_NAMES[] = {
    "provider_retained", "provider_scratch", "association", "bootstrap", "sender", "assembly",
    "result", "history", "correlation", "control", "application_queue", "adapter", "stacks",
    "relay_cache", "freshness_tokens", "assembly_tombstone"
};
enum {
    COMPONENT_SENDER = 4,
    COMPONENT_ASSEMBLY = 5,
    COMPONENT_RESULT = 6,
    COMPONENT_HISTORY = 7,
    COMPONENT_CORRELATION = 8,
    COMPONENT_ADAPTER = 11,
    COMPONENT_ASSEMBLY_TOMBSTONE = 15
};

static uint32_t endpoint_charge_count(const manifest *m, int component)
{
    int resource;
    int charge;

    for (resource = 0; resource < m->nresources; resource++) {
        const resource_rec *r = &m->resources[resource];
        if (!r->relay) {
            for (charge = 0; charge < r->ncharges; charge++) {
                if (r->charges[charge].component == component) {
                    return r->charges[charge].count;
                }
            }
            break;
        }
    }
    return 0U;
}

static int take_component(ps *p, void *o)
{
    int v = 0;
    if (!take_enum(p, COMPONENT_NAMES, 16, &v)) {
        return 0;
    }
    ((charge_rec *)o)->component = v;
    return 1;
}
static int take_charge_region(ps *p, void *o)
{
    return take_ident(p, ((charge_rec *)o)->region, sizeof ((charge_rec *)o)->region);
}
TAKE_U32(take_charge_count, charge_rec, count, 1U, 2147483647U)
TAKE_U32(take_charge_bytes, charge_rec, bytes_each, 1U, 2147483647U)
static int parse_charge(ps *p, void *obj)
{
    static const fld fields[] = {
        {"component", take_component}, {"region", take_charge_region},
        {"count", take_charge_count}, {"bytes_each", take_charge_bytes}
    };
    return closed_object(p, obj, fields, 4);
}

static int take_role(ps *p, void *o)
{
    static const char *const opts[] = {"endpoint", "relay"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((resource_rec *)o)->relay = v == 1;
    return 1;
}
static int take_target(ps *p, void *o)
{
    return take_ident(p, ((resource_rec *)o)->target, sizeof ((resource_rec *)o)->target);
}
TAKE_U32(take_flash_limit, resource_rec, flash_limit, 1U, 2147483647U)
TAKE_U32(take_flash_reserved, resource_rec, flash_reserved, 1U, 2147483647U)
static int take_regions(ps *p, void *o)
{
    resource_rec *r = (resource_rec *)o;
    return parse_items(p, r->regions, sizeof r->regions[0], &r->nregions, 1, 8, parse_region);
}
static int take_charges(ps *p, void *o)
{
    resource_rec *r = (resource_rec *)o;
    return parse_items(p, r->charges, sizeof r->charges[0], &r->ncharges, 1, 112, parse_charge);
}
static int parse_resource(ps *p, void *obj)
{
    static const fld fields[] = {
        {"role", take_role}, {"target", take_target},
        {"flash_limit_bytes", take_flash_limit}, {"flash_reserved_bytes", take_flash_reserved},
        {"regions", take_regions}, {"charges", take_charges}
    };
    return closed_object(p, obj, fields, 6);
}

TAKE_U32(take_relay_node, relay_rec, node, 0U, UINT32_MAX)
static int take_pn_filter(ps *p, void *o)
{
    static const char *const opts[] = {"reject-ge-2pow24", "forward-structurally-valid"};
    int v = 0;
    (void)o;
    return take_enum(p, opts, 2, &v);
}
TAKE_LIT(take_cooldown_anchor, "last-forward-completion")
TAKE_U32(take_relay_cool, relay_rec, cooldown_ms, 1U, 2147483647U)
TAKE_U32(take_relay_exp, relay_rec, expiry_ms, 1U, 2147483647U)
TAKE_U32(take_relay_fwd, relay_rec, max_forwards, 1U, 2147483647U)
TAKE_U32(take_relay_tx, relay_rec, frame_tx_ms, 1U, 2147483647U)
TAKE_U32(take_relay_origin, relay_rec, per_origin, 1U, 2147483647U)
TAKE_U32(take_relay_global, relay_rec, global_air, 1U, 2147483647U)
TAKE_U32(take_relay_dups, relay_rec, lower_dups, 0U, 16U)
TAKE_U32(take_relay_tail, relay_rec, dup_tail, 0U, 2147483647U)
TAKE_U32(take_fwd_min, relay_rec, fwd_min, 0U, 2147483647U)
TAKE_U32(take_fwd_max, relay_rec, fwd_max, 1U, 2147483647U)
TAKE_U32(take_ret_min, relay_rec, ret_min, 0U, 2147483647U)
TAKE_U32(take_ret_max, relay_rec, ret_max, 1U, 2147483647U)
static int parse_relay(ps *p, void *obj)
{
    static const fld fields[] = {
        {"node", take_relay_node}, {"public_pn_filter", take_pn_filter},
        {"cooldown_anchor", take_cooldown_anchor}, {"cooldown_ms", take_relay_cool},
        {"expiry_ms", take_relay_exp}, {"max_forwards_per_key", take_relay_fwd},
        {"frame_tx_ms", take_relay_tx}, {"per_origin_airtime_ms", take_relay_origin},
        {"global_airtime_ms", take_relay_global}, {"lower_duplicates", take_relay_dups},
        {"duplicate_tail_ms", take_relay_tail}, {"forward_arrival_min_ms", take_fwd_min},
        {"forward_arrival_max_ms", take_fwd_max},         {"return_arrival_min_ms", take_ret_min},
        {"return_arrival_max_ms", take_ret_max}
    };
    return closed_object(p, obj, fields, (int)(sizeof fields / sizeof fields[0]));
}

TAKE_ONE(take_rev_core, 10U)
TAKE_ONE(take_rev_sec, 5U)
TAKE_ONE(take_rev_boot, 2U)
TAKE_ONE(take_rev_rec, 1U)
TAKE_ONE(take_rev_app, 2U)
static int parse_revisions(ps *p, void *obj)
{
    static const fld fields[] = {
        {"core", take_rev_core}, {"security", take_rev_sec}, {"bootstrap", take_rev_boot},
        {"recovery", take_rev_rec}, {"application", take_rev_app}
    };
    return closed_object(p, obj, fields, 5);
}

static int take_owner(ps *p, void *o)
{
    static const char *const opts[] = {"DMP-reference", "DMP-test"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->owner_test = v == 1;
    return 1;
}
static int take_profile_id(ps *p, void *o)
{
    static const char *const opts[] = {"DIRECT-1", "RADIO-1", "TEST-RADIO-RETRY-ALL"};
    int v = 0;
    manifest *m = (manifest *)o;
    if (!take_enum(p, opts, 3, &v)) {
        return 0;
    }
    m->direct = v == 0;
    m->selective = v == 1;
    m->testfam = v == 2;
    return 1;
}
TAKE_U32(take_profile_rev, manifest, profile_revision, 1U, 4U)
static int parse_profile(ps *p, void *obj)
{
    static const fld fields[] = {
        {"owner", take_owner}, {"id", take_profile_id}, {"revision", take_profile_rev}
    };
    return closed_object(p, obj, fields, 3);
}

TAKE_U32(take_namespace, manifest, namespace_id, 0U, UINT32_MAX)
static int take_nodes(ps *p, void *o)
{
    manifest *m = (manifest *)o;
    int n = 0;
    return parse_u32_array(p, m->node_id, &n, 2, 2, 0U, UINT32_MAX);
}
TAKE_ONE(take_default_service, 1U)
TAKE_LIT(take_epoch_source, "sec1-association")
TAKE_LIT(take_restart, "fresh-handshake")
TAKE_LIT(take_sample_epoch, "persistent-never-reused-u64")
TAKE_U32(take_producer, manifest, sample_producer, 0U, UINT32_MAX)
static int parse_identity(ps *p, void *obj)
{
    static const fld fields[] = {
        {"namespace", take_namespace}, {"nodes", take_nodes},
        {"default_service", take_default_service}, {"epoch_source", take_epoch_source},
        {"restart", take_restart}, {"sample_epoch", take_sample_epoch},
        {"sample_producer", take_producer}
    };
    return closed_object(p, obj, fields, 7);
}

static int take_bind_id(ps *p, void *o)
{
    static const char *const opts[] = {"DMP-test/SIM-STREAM-R", "DMP-test/SIM-PACKET"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->bind_stream = v == 0;
    return 1;
}
TAKE_ONE(take_bind_rev, 1U)
static int take_kind(ps *p, void *o)
{
    static const char *const opts[] = {"stream-r", "packet"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->kind_stream = v == 0;
    return 1;
}
TAKE_LIT(take_seg, "none")
TAKE_LIT(take_route_change, "fail-active-transfer")
static int take_topo(ps *p, void *o)
{
    static const char *const opts[] = {"point-to-point", "static-unicast"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->topo_p2p = v == 0;
    return 1;
}
static int take_context_kind(ps *p, void *o)
{
    static const char *const opts[] = {"association", "origin-explicit"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->context_assoc = v == 0;
    return 1;
}
TAKE_U32(take_ttl, manifest, ttl, 0U, 4U)
TAKE_U32(take_fwd_mtu, manifest, forward_mtu, 32U, 65535U)
TAKE_U32(take_ret_mtu, manifest, return_mtu, 32U, 65535U)
TAKE_U32(take_enc_mtu, manifest, encoded_mtu, 32U, 66000U)
TAKE_U32(take_frame_tx, manifest, frame_tx_ms, 1U, 2147483647U)
static int take_ownership(ps *p, void *o)
{
    static const char *const opts[] = {"copy", "borrow"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->tx_borrow = v == 1;
    return 1;
}
TAKE_LIT(take_completion, "exactly-once-generation-tagged")
static int take_sync(ps *p, void *o) { return take_bool(p, &((manifest *)o)->sync_completion); }
TAKE_LIT(take_cancel, "terminal-event-releases-buffer")
TAKE_LIT(take_disconnect, "settle-all-submissions-fail-transfers")
TAKE_LIT(take_access, "reserved-half-duplex-slots")
TAKE_LIT(take_burst_gate, "serialize-pair-services-directions-and-bootstrap")
TAKE_U32(take_period, manifest, period_ms, 1U, 2147483647U)
TAKE_U32(take_width, manifest, width_ms, 1U, 2147483647U)
TAKE_LIT(take_boot_int, "CRC32C")
static int parse_binding(ps *p, void *obj)
{
    static const fld fields[] = {
        {"id", take_bind_id}, {"revision", take_bind_rev}, {"kind", take_kind},
        {"segmentation", take_seg}, {"route_change", take_route_change}, {"topology", take_topo},
        {"context", take_context_kind}, {"ttl", take_ttl}, {"forward_mtu", take_fwd_mtu},
        {"return_mtu", take_ret_mtu}, {"encoded_mtu", take_enc_mtu}, {"frame_tx_ms", take_frame_tx},
        {"tx_ownership", take_ownership}, {"completion", take_completion},
        {"synchronous_completion", take_sync}, {"cancellation", take_cancel},
        {"disconnect", take_disconnect}, {"access", take_access},
        {"return_opportunity", take_service_true}, {"burst_gate", take_burst_gate},
        {"return_slot_period_ms", take_period}, {"return_slot_width_ms", take_width},
        {"bootstrap_integrity", take_boot_int}
    };
    return closed_object(p, obj, fields, (int)(sizeof fields / sizeof fields[0]));
}

TAKE_U32(take_message, manifest, message_bytes, 17U, 1024U)
TAKE_U32(take_fragments, manifest, fragments, 2U, 32U)
TAKE_U32(take_chunk, manifest, chunk_bytes, 1U, 1023U)
TAKE_U32(take_boot_chunk, manifest, boot_chunk, 1U, 119U)
TAKE_U32(take_boot_frags, manifest, boot_frags, 2U, 120U)
TAKE_U32(take_peers, manifest, peers, 1U, 1U)
TAKE_U32(take_assemblies, manifest, assemblies, 1U, 1U)
TAKE_U32(take_assembly_tombstones, manifest, assembly_tombstones, 1U, 64U)
TAKE_U32(take_operations, manifest, operations, 1U, 1U)
TAKE_U32(take_control_slots, manifest, control_slots, 2U, 64U)
TAKE_U32(take_app_queue, manifest, app_queue, 1U, 2147483647U)
TAKE_U32(take_adapter, manifest, adapter_slots, 1U, 2147483647U)
static int parse_limits(ps *p, void *obj)
{
    static const fld fields[] = {
        {"message_bytes", take_message}, {"fragments", take_fragments}, {"chunk_bytes", take_chunk},
        {"bootstrap_chunk_bytes", take_boot_chunk}, {"bootstrap_fragments", take_boot_frags},
        {"peers", take_peers}, {"assemblies_per_peer", take_assemblies},
        {"assembly_tombstones_per_peer", take_assembly_tombstones},
        {"operations_per_service", take_operations}, {"control_slots", take_control_slots},
        {"application_queue_slots", take_app_queue}, {"adapter_slots", take_adapter}
    };
    return closed_object(p, obj, fields, 12);
}

static int take_mode(ps *p, void *o)
{
    static const char *const opts[] = {"NNpsk0", "XX"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->mode_xx = v == 1;
    return 1;
}
TAKE_ONE(take_cipher, 1U)
static int take_credential(ps *p, void *o)
{
    static const char *const opts[] = {"provisioned-pairwise-psk", "authenticated-oob-xx"};
    int v = 0;
    if (!take_enum(p, opts, 2, &v)) {
        return 0;
    }
    ((manifest *)o)->credential_oob = v == 1;
    return 1;
}
TAKE_LIT(take_trust, "owner-authorized-atomic-pin-and-acl")
TAKE_U32(take_pending, manifest, pending, 1U, 4U)
TAKE_U32(take_active, manifest, active, 1U, 4U)
TAKE_U32(take_draining, manifest, draining, 0U, 4U)
TAKE_U32(take_crypto_slots, manifest, crypto_slots, 1U, 4U)
TAKE_LIT(take_full_cap, "reject-new-until-capacity")
TAKE_LIT(take_peer_restart, "retain-live-until-explicit-retirement")
TAKE_U32(take_failed_aead, manifest, failed_aead, 1U, 65536U)
static int take_replay(ps *p, void *o)
{
    static const uint32_t opts[] = {64U, 128U, 256U, 512U, 1024U};
    return take_enum_u(p, opts, 5, &((manifest *)o)->replay_bits);
}
TAKE_U32(take_enc_limit, manifest, encryption_limit, 1U, 16777216U)
TAKE_U32(take_plain_limit, manifest, plaintext_limit, 1U, 1073741824U)
TAKE_U32(take_assoc_ms, manifest, association_ms, 1U, 2147483647U)
TAKE_U32(take_drain_ms, manifest, drain_ms, 0U, 2147483647U)
TAKE_U32(take_pairing, manifest, pairing_ms, 1U, 2147483647U)
TAKE_U32(take_preauth_slots, manifest, preauth_slots, 1U, 2147483647U)
TAKE_U32(take_preauth_bytes, manifest, preauth_bytes, 1U, 2147483647U)
TAKE_U32(take_attempt, manifest, attempt_ms, 1U, 2147483647U)
TAKE_U32(take_flight_attempts, manifest, flight_attempts, 1U, 32U)
TAKE_U32(take_flight_retry, manifest, flight_retry_ms, 1U, 2147483647U)
TAKE_U32(take_confirm_attempts, manifest, confirm_attempts, 1U, 32U)
TAKE_U32(take_confirm_timeout, manifest, confirm_timeout, 1U, 2147483647U)
TAKE_U32(take_dup_responses, manifest, dup_responses, 0U, 64U)
TAKE_U32(take_response_window, manifest, response_window_ms, 1U, 2147483647U)
TAKE_U32(take_responses_window, manifest, responses_per_window, 1U, 2147483647U)
TAKE_U32(take_response_bytes, manifest, response_bytes_per_window, 1U, 2147483647U)
TAKE_U32(take_episode_attempts, manifest, episode_attempts, 1U, 2147483647U)
TAKE_U32(take_episode_ms, manifest, episode_ms, 1U, 2147483647U)
TAKE_U32(take_episode_crypto, manifest, episode_crypto_ms, 1U, 2147483647U)
TAKE_U32(take_crypto_attempt, manifest, crypto_per_attempt, 1U, 2147483647U)
TAKE_U32(take_episode_tx, manifest, episode_tx, 1U, 2147483647U)
TAKE_U32(take_attempt_tx, manifest, attempt_tx, 1U, 2147483647U)
TAKE_U32(take_restart_backoff, manifest, restart_backoff, 1U, 2147483647U)
TAKE_U32(take_later_episodes, manifest, later_episodes, 1U, 2147483647U)
TAKE_U32(take_later_window, manifest, later_window, 1U, 2147483647U)
TAKE_U32(take_ingress_packets, manifest, ingress_packets, 1U, 2147483647U)
TAKE_U32(take_ingress_window, manifest, ingress_window, 1U, 2147483647U)
TAKE_U32(take_global_crypto, manifest, global_crypto, 1U, 2147483647U)
static int parse_security(ps *p, void *obj)
{
    static const fld fields[] = {
        {"mode", take_mode}, {"cipher", take_cipher}, {"credential", take_credential},
        {"trust_change", take_trust}, {"pending_per_pair", take_pending},
        {"active_per_pair", take_active}, {"draining_per_pair", take_draining},
        {"crypto_slots", take_crypto_slots}, {"full_capacity", take_full_cap},
        {"peer_restart", take_peer_restart}, {"failed_aead_limit", take_failed_aead},
        {"replay_window_bits", take_replay}, {"encryption_limit", take_enc_limit},
        {"plaintext_limit", take_plain_limit}, {"association_ms", take_assoc_ms},
        {"drain_ms", take_drain_ms}, {"pairing_timeout_ms", take_pairing},
        {"preauth_slots", take_preauth_slots}, {"preauth_bytes", take_preauth_bytes},
        {"attempt_ms", take_attempt}, {"flight_attempts", take_flight_attempts},
        {"flight_retry_ms", take_flight_retry}, {"confirmation_attempts", take_confirm_attempts},
        {"confirmation_timeout_ms", take_confirm_timeout},
        {"duplicate_responses_per_attempt", take_dup_responses},
        {"response_window_ms", take_response_window}, {"responses_per_window", take_responses_window},
        {"response_bytes_per_window", take_response_bytes}, {"episode_attempts", take_episode_attempts},
        {"episode_ms", take_episode_ms}, {"episode_crypto_ms", take_episode_crypto},
        {"crypto_per_attempt_ms", take_crypto_attempt}, {"episode_tx_bytes", take_episode_tx},
        {"attempt_tx_bytes", take_attempt_tx}, {"restart_backoff_ms", take_restart_backoff},
        {"later_episodes_per_window", take_later_episodes}, {"later_window_ms", take_later_window},
        {"ingress_packets_per_window", take_ingress_packets}, {"ingress_window_ms", take_ingress_window},
        {"global_crypto_ms_per_window", take_global_crypto}
    };
    return closed_object(p, obj, fields, (int)(sizeof fields / sizeof fields[0]));
}

TAKE_U32(take_queue, manifest, queue_ms, 1U, 2147483647U)
TAKE_U32(take_forward_delay, manifest, forward_delay, 1U, 2147483647U)
TAKE_U32(take_return_delay, manifest, return_delay, 1U, 2147483647U)
TAKE_U32(take_receipt_delay, manifest, receipt_delay, 1U, 2147483647U)
TAKE_U32(take_burst_span, manifest, burst_span, 1U, 2147483647U)
TAKE_U32(take_feedback_guard, manifest, feedback_guard, 1U, 2147483647U)
TAKE_U32(take_feedback_delay, manifest, feedback_delay, 1U, 2147483647U)
TAKE_U32(take_response_timeout, manifest, response_timeout, 1U, 2147483647U)
TAKE_LIT(take_deadline_order, "available-terminal-or-feedback-first")
TAKE_U32(take_horizon, manifest, send_horizon, 1U, 2147483647U)
TAKE_U32(take_max_bursts, manifest, max_bursts, 1U, 32U)
TAKE_U32(take_max_probes, manifest, max_probes, 0U, 31U)
TAKE_U32(take_max_status, manifest, max_status, 0U, 32U)
static int take_burst_starts(ps *p, void *o)
{
    manifest *m = (manifest *)o;
    return parse_u32_array(p, m->burst_starts, &m->nbursts, 1, 32, 0U, 2147483647U);
}
TAKE_U32(take_jitter, manifest, jitter_ms, 0U, 2147483647U)
TAKE_U32(take_margin, manifest, record_margin, 1U, 2147483647U)
TAKE_U32(take_collect, manifest, collect_ms, 1U, 2147483647U)
TAKE_U32(take_assembly, manifest, assembly_ms, 1U, 2147483647U)
TAKE_U32(take_inactivity, manifest, inactivity_ms, 0U, 0U)
TAKE_U32(take_dedup, manifest, dedup_ms, 1U, 2147483647U)
TAKE_U32(take_rejection, manifest, rejection_ms, 1U, 2147483647U)
TAKE_U32(take_result_cache, manifest, result_cache_ms, 1U, 2147483647U)
TAKE_U32(take_result_deadline, manifest, result_deadline_ms, 1U, 2147483647U)
TAKE_U32(take_correlation, manifest, correlation_ms, 1U, 2147483647U)
TAKE_U32(take_tombstone, manifest, tombstone_ms, 1U, 2147483647U)
TAKE_U32(take_late, manifest, late_result_ms, 1U, 2147483647U)
TAKE_U32(take_airtime, manifest, max_airtime, 1U, 2147483647U)
TAKE_U32(take_receipt_limit, manifest, receipt_limit, 1U, 2147483647U)
TAKE_U32(take_feedback_buffers, manifest, feedback_buffers, 1U, 2147483647U)
static int parse_timing(ps *p, void *obj)
{
    static const fld fields[] = {
        {"queue_ms", take_queue}, {"forward_delay_ms", take_forward_delay},
        {"return_delay_ms", take_return_delay}, {"receipt_delay_ms", take_receipt_delay},
        {"burst_span_ms", take_burst_span}, {"feedback_guard_ms", take_feedback_guard},
        {"feedback_delay_ms", take_feedback_delay}, {"response_timeout_ms", take_response_timeout},
        {"deadline_order", take_deadline_order}, {"send_horizon_ms", take_horizon},
        {"max_bursts", take_max_bursts}, {"max_probes", take_max_probes},
        {"max_status", take_max_status}, {"burst_starts_ms", take_burst_starts},
        {"jitter_ms", take_jitter}, {"record_margin_ms", take_margin},
        {"collect_ms", take_collect}, {"assembly_ms", take_assembly},
        {"inactivity_ms", take_inactivity}, {"dedup_ms", take_dedup},
        {"rejection_ms", take_rejection}, {"result_cache_ms", take_result_cache},
        {"result_deadline_ms", take_result_deadline}, {"correlation_ms", take_correlation},
        {"tombstone_ms", take_tombstone}, {"late_result_ms", take_late},
        {"max_transfer_airtime_ms", take_airtime}, {"receipt_limit", take_receipt_limit},
        {"feedback_buffers", take_feedback_buffers}
    };
    return closed_object(p, obj, fields, (int)(sizeof fields / sizeof fields[0]));
}

TAKE_U32(take_lease, manifest, lease_ms, 0U, 60000U)
TAKE_U32(take_grant_age, manifest, grant_age, 0U, 2147483647U)
static int take_grant_nodes(ps *p, void *o)
{
    manifest *m = (manifest *)o;
    return parse_u32_array(p, m->grant_nodes, &m->ngrants, 0, 2, 0U, UINT32_MAX);
}
TAKE_LIT(take_grant_acl, "same-authorized-service-only")
TAKE_U32(take_tokens_assoc, manifest, tokens_assoc, 0U, 64U)
TAKE_U32(take_tokens_principal, manifest, tokens_principal, 0U, 256U)
TAKE_U32(take_grant_requests, manifest, grant_requests, 0U, 64U)
TAKE_U32(take_token_record, manifest, token_record_ms, 0U, 2147483647U)
TAKE_U32(take_grant_result, manifest, grant_result_ms, 0U, 2147483647U)
static int parse_freshness(ps *p, void *obj)
{
    static const fld fields[] = {
        {"lease_ms", take_lease}, {"grant_delivery_age_ms", take_grant_age},
        {"grant_nodes", take_grant_nodes}, {"grant_acl", take_grant_acl},
        {"tokens_per_association", take_tokens_assoc}, {"tokens_per_principal", take_tokens_principal},
        {"grant_requests_per_pair", take_grant_requests}, {"token_record_ms", take_token_record},
        {"grant_result_ms", take_grant_result}
    };
    return closed_object(p, obj, fields, 9);
}

TAKE_U32(take_init_attempts, manifest, init_attempts, 1U, 2147483647U)
TAKE_U32(take_init_retry, manifest, init_retry_ms, 1U, 2147483647U)
TAKE_U32(take_init_deadline, manifest, init_deadline_ms, 1U, 2147483647U)
TAKE_LIT(take_sync_mode, "correlated-read-current-generation")
TAKE_ONE(take_no_sample, 64U)
TAKE_ONE(take_telemetry, 16U)
TAKE_ONE(take_read_req, 1U)
TAKE_ONE(take_read_res, 17U)
TAKE_ONE(take_status_req, 1U)
TAKE_ONE(take_status_res, 2U)
static int parse_sample(ps *p, void *obj)
{
    static const fld fields[] = {
        {"init_attempts", take_init_attempts}, {"init_retry_ms", take_init_retry},
        {"init_deadline_ms", take_init_deadline}, {"synchronization", take_sync_mode},
        {"no_sample_status", take_no_sample}, {"telemetry_bytes", take_telemetry},
        {"read_request_bytes", take_read_req}, {"read_result_bytes", take_read_res},
        {"status_request_bytes", take_status_req}, {"status_result_bytes", take_status_res}
    };
    return closed_object(p, obj, fields, (int)(sizeof fields / sizeof fields[0]));
}

TAKE_LIT(take_contract, "DMP-test-manifest/2")
static int take_revisions(ps *p, void *o) { (void)o; return parse_revisions(p, o); }
static int take_profile_obj(ps *p, void *o) { return parse_profile(p, o); }
static int take_identity_obj(ps *p, void *o) { return parse_identity(p, o); }
static int take_binding_obj(ps *p, void *o) { return parse_binding(p, o); }
static int take_services(ps *p, void *o)
{
    manifest *m = (manifest *)o;
    int n = 0;
    return parse_items(p, m->services, sizeof m->services[0], &n, 2, 2, parse_service);
}
static int take_limits_obj(ps *p, void *o) { return parse_limits(p, o); }
static int take_security_obj(ps *p, void *o) { return parse_security(p, o); }
static int take_timing_obj(ps *p, void *o) { return parse_timing(p, o); }
static int take_fresh_obj(ps *p, void *o) { return parse_freshness(p, o); }
static int take_sample_obj(ps *p, void *o) { return parse_sample(p, o); }
static int take_relays(ps *p, void *o)
{
    manifest *m = (manifest *)o;
    return parse_items(p, m->relays, sizeof m->relays[0], &m->nrelays, 0, 4, parse_relay);
}
static int take_resources(ps *p, void *o)
{
    manifest *m = (manifest *)o;
    return parse_items(p, m->resources, sizeof m->resources[0], &m->nresources, 1, 2, parse_resource);
}
static int parse_root(ps *p, manifest *m)
{
    static const fld fields[] = {
        {"contract", take_contract}, {"revisions", take_revisions}, {"profile", take_profile_obj},
        {"identity", take_identity_obj}, {"binding", take_binding_obj}, {"services", take_services},
        {"limits", take_limits_obj}, {"security", take_security_obj}, {"timing", take_timing_obj},
        {"freshness", take_fresh_obj}, {"sample", take_sample_obj}, {"relays", take_relays},
        {"resources", take_resources}
    };
    return closed_object(p, m, fields, 13);
}

static int reqp(ps *p, int ok, const char *code, const char *path)
{
    if (ok) {
        return 1;
    }
    if (!path_set(p, path)) {
        return 0;
    }
    return fail_at(p, code);
}

static uint32_t uwidth(uint32_t value)
{
    uint32_t bits = 0U;
    uint32_t w;
    while (value != 0U) {
        bits++;
        value >>= 1U;
    }
    w = (bits + 6U) / 7U;
    return w == 0U ? 1U : w;
}

static int umul(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0U && b > UINT64_MAX / a) {
        return 0;
    }
    *out = a * b;
    return 1;
}

static int uadd(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) {
        return 0;
    }
    *out = a + b;
    return 1;
}

static uint64_t umax(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

typedef struct {
    uint32_t fragment_count;
    uint32_t boot_count;
    uint32_t encoded;
    uint64_t transfer_frames;
    uint64_t establishment_frames;
    uint64_t establishment_ms;
    uint64_t flight_span;
} derived;

static int cross_identity(ps *p, const manifest *m)
{
    char path[64];
    int i;
    int have1 = 0;
    int have2 = 0;
    uint32_t ids[6];
    int nids = 2 + m->nrelays;
    int family_ok = m->testfam ? (m->owner_test && m->profile_revision == 1U)
                               : (!m->owner_test && m->profile_revision == 4U);
    int binding_ok = m->direct ? (m->bind_stream && m->kind_stream && m->topo_p2p && m->context_assoc)
                               : (!m->bind_stream && !m->kind_stream && !m->topo_p2p && !m->context_assoc);
    int ttl_ok = ((!m->direct) || (m->nrelays == 0 && m->ttl == 0U)) && m->ttl >= (uint32_t)m->nrelays;
    if (!reqp(p, family_ok, "profile", "$.profile") ||
        !reqp(p, binding_ok, "profile", "$.binding") ||
        !reqp(p, ttl_ok, "profile", "$.binding.ttl")) {
        return 0;
    }
    ids[0] = m->node_id[0];
    ids[1] = m->node_id[1];
    for (i = 0; i < m->nrelays; i++) {
        ids[2 + i] = m->relays[i].node;
    }
    for (i = 0; i < nids; i++) {
        int j;
        for (j = i + 1; j < nids; j++) {
            if (ids[i] == ids[j]) {
                return reqp(p, 0, "identity", "$.identity");
            }
        }
    }
    if (m->sample_producer != m->node_id[0] && m->sample_producer != m->node_id[1]) {
        return reqp(p, 0, "identity", "$.identity");
    }
    for (i = 0; i < 2; i++) {
        if (m->services[i].id == 1U) {
            have1++;
        } else if (m->services[i].id == 2U) {
            have2++;
        }
    }
    if (!reqp(p, have1 == 1 && have2 == 1, "service", "$.services")) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        const service_rec *s = &m->services[i];
        int seen0 = 0;
        int seen1 = 0;
        int a;
        snprintf(path, sizeof path, "$.services[%d]", i);
        if (!reqp(p, s->reply == s->id && s->omitted == (s->id == 1U), "service", path)) {
            return 0;
        }
        snprintf(path, sizeof path, "$.services[%d].recovery", i);
        if (!reqp(p, s->selective == m->selective, "profile", path)) {
            return 0;
        }
        snprintf(path, sizeof path, "$.services[%d]", i);
        if (!reqp(p, s->sample_schema == (s->id == 1U), "service", path)) {
            return 0;
        }
        snprintf(path, sizeof path, "$.services[%d].acl", i);
        for (a = 0; a < 2; a++) {
            if (s->acl[a].node == m->node_id[0]) {
                seen0++;
            } else if (s->acl[a].node == m->node_id[1]) {
                seen1++;
            }
        }
        if (!reqp(p, seen0 == 1 && seen1 == 1, "service", path)) {
            return 0;
        }
        for (a = 0; a < 2; a++) {
            uint8_t expect = s->id == 1U
                                 ? (s->acl[a].node == m->sample_producer ? 17U : 6U)
                                 : 24U;
            int actions_ok = s->acl[a].action_dup == 0U && s->acl[a].action_count == 2U &&
                             s->acl[a].actions == expect;
            if (!reqp(p, actions_ok, "service", path)) {
                return 0;
            }
        }
        snprintf(path, sizeof path, "$.services[%d]", i);
        if (!reqp(p, umax(s->request_bytes, s->result_bytes) <= m->message_bytes, "service", path)) {
            return 0;
        }
        if (s->id == 1U &&
            !reqp(p, s->request_bytes == 1U && s->result_bytes == 17U && !s->freshness, "service", path)) {
            return 0;
        }
    }
    return 1;
}

static int cross_security(ps *p, const manifest *m)
{
    uint64_t attempts = m->episode_attempts;
    uint64_t episode_need = 0U;
    uint64_t crypto_need = 0U;
    uint64_t crypto_cap = 0U;
    uint64_t tx_need = 0U;
    uint64_t later_crypto = 0U;
    uint64_t later_cap = 0U;
    uint64_t backoff = 0U;
    uint64_t attempt_span = 0U;
    int episode_ok;
    int crypto_ok;
    int later_ok;
    if (!reqp(p, m->credential_oob == m->mode_xx, "security", "$.security.credential")) {
        return 0;
    }
    if (!reqp(p, m->crypto_slots <= m->pending && m->pending <= m->preauth_slots, "security", "$.security")) {
        return 0;
    }
    if (!reqp(p, (uint64_t)m->preauth_bytes >= 120ULL * m->preauth_slots, "security", "$.security.preauth_bytes")) {
        return 0;
    }
    if (!reqp(p, m->drain_ms < m->association_ms && (m->draining > 0U || m->drain_ms == 0U),
              "security", "$.security.drain_ms")) {
        return 0;
    }
    if (!reqp(p, (uint64_t)m->association_ms >= (uint64_t)m->correlation_ms + m->queue_ms,
              "security", "$.security.association_ms")) {
        return 0;
    }
    if (!reqp(p, m->pairing_ms <= m->attempt_ms && m->crypto_per_attempt <= m->attempt_ms,
              "security", "$.security.attempt_ms")) {
        return 0;
    }
    episode_ok = umul(attempts, m->attempt_ms, &attempt_span) &&
                 umul(attempts - 1U, m->restart_backoff, &backoff) &&
                 uadd(attempt_span, backoff, &episode_need) &&
                 m->episode_ms >= episode_need;
    if (!reqp(p, episode_ok, "security", "$.security.episode_ms")) {
        return 0;
    }
    crypto_ok = umul(attempts, m->crypto_per_attempt, &crypto_need) &&
                umul(m->episode_ms, m->crypto_slots, &crypto_cap) &&
                m->episode_crypto_ms >= crypto_need && m->episode_crypto_ms <= crypto_cap;
    if (!reqp(p, crypto_ok, "security", "$.security.episode_crypto_ms")) {
        return 0;
    }
    if (!reqp(p, umul(attempts, m->attempt_tx, &tx_need) && m->episode_tx >= tx_need,
              "security", "$.security.episode_tx_bytes")) {
        return 0;
    }
    later_ok = m->later_window >= m->episode_ms &&
               umul(m->later_episodes, m->episode_crypto_ms, &later_crypto) &&
               umul(m->later_window, m->crypto_slots, &later_cap) &&
               m->global_crypto >= later_crypto && m->global_crypto <= later_cap;
    return reqp(p, later_ok, "security", "$.security");
}

static int cross_frames(ps *p, const manifest *m, derived *d)
{
    uint32_t size = m->message_bytes;
    uint32_t chunk = m->chunk_bytes;
    uint32_t count;
    uint32_t boot_count;
    uint32_t node_width;
    uint32_t context;
    uint32_t route;
    uint32_t base;
    uint32_t frag;
    uint32_t max_header = 0U;
    uint32_t max_frame = 0U;
    uint32_t boot_header;
    uint32_t boot_frame;
    uint32_t control;
    uint32_t sample;
    uint32_t core;
    uint32_t encoded;
    uint32_t mtu;
    int i;
    if (!reqp(p, chunk < size, "geometry", "$.limits.chunk_bytes")) {
        return 0;
    }
    count = (size + chunk - 1U) / chunk;
    boot_count = (120U + m->boot_chunk - 1U) / m->boot_chunk;
    if (!reqp(p, count <= m->fragments && m->fragments <= (m->direct ? 16U : 32U),
              "geometry", "$.limits.fragments") ||
        !reqp(p, boot_count <= m->boot_frags, "geometry", "$.limits.bootstrap_fragments")) {
        return 0;
    }
    node_width = uwidth(m->node_id[0]);
    if (uwidth(m->node_id[1]) > node_width) {
        node_width = uwidth(m->node_id[1]);
    }
    context = 2U + uwidth(m->namespace_id) + 8U;
    route = 1U + uwidth(m->node_id[0]) + uwidth(m->node_id[1]);
    base = 18U + (m->direct ? 0U : route + context);
    frag = uwidth(count - 1U) + uwidth(chunk) + uwidth(size);
    for (i = 0; i < 2; i++) {
        uint32_t service_ext = m->services[i].id == 1U ? 0U : 2U + uwidth(m->services[i].id);
        uint32_t header = base + 14U + service_ext + (m->services[i].freshness ? 18U : 0U) + frag;
        uint32_t frame = header + chunk + 16U;
        uint32_t status = base + 7U + service_ext + 20U;
        if (header > max_header) {
            max_header = header;
        }
        if (frame > max_frame) {
            max_frame = frame;
        }
        if (status > max_frame) {
            max_frame = status;
        }
    }
    control = base + 47U;
    sample = base + 47U;
    boot_header = 5U + context + (m->direct ? 2U + node_width : route);
    boot_header += uwidth(boot_count - 1U) + uwidth(m->boot_chunk) + uwidth(120U);
    boot_frame = boot_header + m->boot_chunk + 4U;
    if (control > max_frame) {
        max_frame = control;
    }
    if (sample > max_frame) {
        max_frame = sample;
    }
    if (boot_frame > max_frame) {
        max_frame = boot_frame;
    }
    if (boot_header > max_header) {
        max_header = boot_header;
    }
    if (base + 10U > max_header) {
        max_header = base + 10U;
    }
    mtu = m->forward_mtu < m->return_mtu ? m->forward_mtu : m->return_mtu;
    if (!reqp(p, max_header <= 255U && max_frame <= mtu, "mtu", "$.binding")) {
        return 0;
    }
    core = m->forward_mtu > m->return_mtu ? m->forward_mtu : m->return_mtu;
    encoded = m->direct ? core + 4U + (core + 4U) / 254U + 2U : core;
    if (!reqp(p, encoded <= m->encoded_mtu, "mtu", "$.binding.encoded_mtu")) {
        return 0;
    }
    d->fragment_count = count;
    d->boot_count = boot_count;
    d->encoded = encoded;
    return 1;
}

static int cross_timing(ps *p, const manifest *m, derived *d)
{
    uint64_t delay = umax(m->forward_delay, m->return_delay);
    uint64_t floor = (uint64_t)m->forward_delay + m->receipt_delay + m->return_delay;
    uint64_t span = m->burst_span;
    uint64_t horizon = m->send_horizon;
    uint64_t queue = m->queue_ms;
    uint64_t history;
    uint64_t result;
    uint64_t frames;
    uint64_t air;
    uint64_t sample_need = 0U;
    uint64_t init_gap = 0U;
    uint32_t processing = m->services[0].processing_ms;
    int i;
    int fresh = m->services[0].freshness || m->services[1].freshness;
    static const char *const history_keys[] = {
        "$.timing.dedup_ms", "$.timing.rejection_ms", "$.timing.result_cache_ms", "$.timing.tombstone_ms"
    };
    uint32_t history_values[4];
    if (m->selective) {
        uint64_t a = 2U * (uint64_t)m->forward_delay + span + m->feedback_guard + m->feedback_delay + m->return_delay;
        uint64_t b = 2U * (uint64_t)m->return_delay + span + m->feedback_guard + m->feedback_delay + m->forward_delay;
        floor = umax(floor, umax(a, b));
    }
    if (!reqp(p, m->response_timeout >= floor, "timing", "$.timing.response_timeout_ms")) {
        return 0;
    }
    if (!reqp(p, m->nbursts == (int)m->max_bursts && m->burst_starts[0] == 0U,
              "schedule", "$.timing.burst_starts_ms")) {
        return 0;
    }
    for (i = 1; i < m->nbursts; i++) {
        uint64_t need = (uint64_t)m->burst_starts[i - 1] + span + m->response_timeout + m->jitter_ms;
        if (!reqp(p, m->burst_starts[i] >= need, "schedule", "$.timing.burst_starts_ms")) {
            return 0;
        }
    }
    if (!reqp(p, (uint64_t)m->burst_starts[m->nbursts - 1] + span <= horizon,
              "schedule", "$.timing.send_horizon_ms")) {
        return 0;
    }
    if (m->selective) {
        if (!reqp(p, m->max_probes <= m->max_bursts - 1U && m->max_probes >= 1U && m->max_status >= m->max_bursts,
                  "schedule", "$.timing")) {
            return 0;
        }
    } else if (!reqp(p, m->max_probes <= m->max_bursts - 1U && m->max_probes == 0U && m->max_status == 0U,
                     "schedule", "$.timing")) {
        return 0;
    }
    {
        uint64_t traversal = (uint64_t)m->frame_tx_ms + delay;
        uint64_t period = m->period_ms;
        uint64_t width = m->width_ms;
        uint64_t slot_sum = period + width;
        uint64_t receipt_cap = umax(0U, m->receipt_delay < m->feedback_delay ? m->receipt_delay : m->feedback_delay);
        int super_ok = width >= 2U * traversal && period >= width && period - width >= traversal &&
                       slot_sum <= receipt_cap;
        if (!reqp(p, super_ok, "schedule", "$.binding")) {
            return 0;
        }
        {
            uint64_t pieces = umax(d->fragment_count, d->boot_count);
            int phase_ok = 1;
            for (i = 0; i < m->nbursts; i++) {
                if (period == 0U || m->burst_starts[i] % (uint32_t)period != 0U) {
                    phase_ok = 0;
                }
            }
            if (!reqp(p, span >= pieces * period && phase_ok && queue >= period, "schedule", "$.timing")) {
                return 0;
            }
        }
    }
    if (!reqp(p, m->receipt_limit >= m->max_bursts && m->control_slots >= m->feedback_buffers + 1U,
              "schedule", "$.timing")) {
        return 0;
    }
    frames = (uint64_t)m->max_bursts * ((uint64_t)d->fragment_count + d->boot_count) + m->max_status + m->receipt_limit;
    air = frames * m->frame_tx_ms;
    if (!reqp(p, m->max_airtime >= air, "schedule", "$.timing.max_transfer_airtime_ms")) {
        return 0;
    }
    if (!reqp(p, m->collect_ms >= horizon + delay &&
                     m->assembly_ms >= umax(horizon + delay, m->collect_ms) + m->record_margin,
              "timing", "$.timing.assembly_ms")) {
        return 0;
    }
    history = horizon + queue + m->forward_delay + m->return_delay + m->record_margin;
    history_values[0] = m->dedup_ms;
    history_values[1] = m->rejection_ms;
    history_values[2] = m->result_cache_ms;
    history_values[3] = m->tombstone_ms;
    for (i = 0; i < 4; i++) {
        if (!reqp(p, history_values[i] >= history, "timing", history_keys[i])) {
            return 0;
        }
    }
    if (m->services[1].processing_ms > processing) {
        processing = m->services[1].processing_ms;
    }
    result = 2U * (queue + horizon + delay) + processing + m->receipt_delay;
    if (!reqp(p, m->result_deadline_ms >= result &&
                     (uint64_t)m->correlation_ms >= (uint64_t)m->result_deadline_ms + m->late_result_ms + m->record_margin &&
                     m->tombstone_ms >= m->correlation_ms,
              "timing", "$.timing")) {
        return 0;
    }
    if (!(umul(m->init_attempts, m->result_deadline_ms, &sample_need) &&
          umul(m->init_attempts - 1U, m->init_retry_ms, &init_gap) &&
          uadd(sample_need, init_gap, &sample_need))) {
        sample_need = UINT64_MAX;
    }
    if (!reqp(p, m->init_deadline_ms >= sample_need, "timing", "$.sample.init_deadline_ms")) {
        return 0;
    }
    {
        uint64_t need = (uint64_t)m->grant_age + queue + horizon + delay;
        if (fresh) {
            int nodes_ok = m->ngrants == 2 &&
                           ((m->grant_nodes[0] == m->node_id[0] && m->grant_nodes[1] == m->node_id[1]) ||
                            (m->grant_nodes[0] == m->node_id[1] && m->grant_nodes[1] == m->node_id[0]));
            if (!reqp(p, m->lease_ms > 0U && need <= m->lease_ms, "timing", "$.freshness")) {
                return 0;
            }
            if (!reqp(p, nodes_ok && m->grant_requests > 0U && m->grant_requests <= m->tokens_assoc &&
                             m->tokens_assoc <= m->tokens_principal && m->token_record_ms >= m->lease_ms &&
                             m->grant_result_ms >= history,
                      "security", "$.freshness")) {
                return 0;
            }
        } else {
            int disabled = m->lease_ms == 0U && m->grant_age == 0U && m->tokens_assoc == 0U &&
                           m->tokens_principal == 0U && m->grant_requests == 0U && m->token_record_ms == 0U &&
                           m->grant_result_ms == 0U && m->ngrants == 0;
            if (!reqp(p, disabled, "timing", "$.freshness")) {
                return 0;
            }
        }
        d->transfer_frames = frames;
    }
    return 1;
}

static int cross_establishment(ps *p, const manifest *m, derived *d)
{
    uint64_t period = m->period_ms;
    uint64_t delay = umax(m->forward_delay, m->return_delay);
    uint64_t flight_span = (uint64_t)d->boot_count * period;
    uint64_t retry_floor = 2U * (flight_span + delay) + m->crypto_per_attempt + m->pairing_ms;
    uint32_t xx_flights = m->mode_xx ? m->confirm_attempts : 0U;
    uint64_t confirm_floor = 2U * (period + delay) + m->receipt_delay;
    uint32_t flights = m->mode_xx ? 3U : 2U;
    uint64_t responses;
    uint64_t frames;
    uint64_t traffic;
    uint64_t duration;
    uint64_t opp;
    int attempt_ok;
    if (xx_flights != 0U) {
        confirm_floor += flight_span + delay;
    }
    if (!reqp(p, m->flight_retry_ms >= retry_floor && period != 0U && m->flight_retry_ms % (uint32_t)period == 0U,
              "security", "$.security.flight_retry_ms") ||
        !reqp(p, m->confirm_timeout >= confirm_floor && m->confirm_timeout % (uint32_t)period == 0U,
              "security", "$.security.confirmation_timeout_ms")) {
        return 0;
    }
    opp = (uint64_t)flights * m->flight_attempts + m->dup_responses;
    responses = opp + xx_flights + 2U * (uint64_t)m->confirm_attempts;
    frames = (opp + xx_flights) * d->boot_count + 2U * (uint64_t)m->confirm_attempts;
    traffic = frames * d->encoded;
    duration = (opp)*m->flight_retry_ms + (uint64_t)m->confirm_attempts * m->confirm_timeout +
               m->pairing_ms + m->crypto_per_attempt;
    attempt_ok = m->attempt_ms >= duration && m->attempt_tx >= traffic;
    if (!reqp(p, attempt_ok, "security", "$.security")) {
        return 0;
    }
    if (!reqp(p, m->response_window_ms <= m->attempt_ms && m->responses_per_window >= responses &&
                     m->response_bytes_per_window >= traffic,
              "security", "$.security")) {
        return 0;
    }
    if (!reqp(p, m->ingress_packets >= frames, "security", "$.security.ingress_packets_per_window")) {
        return 0;
    }
    if (!reqp(p, (uint64_t)m->encryption_limit >= d->transfer_frames + 2U * (uint64_t)m->confirm_attempts &&
                     (uint64_t)m->plaintext_limit >= d->transfer_frames * m->message_bytes,
              "security", "$.security")) {
        return 0;
    }
    d->establishment_frames = frames;
    d->establishment_ms = duration;
    d->flight_span = flight_span;
    return 1;
}

static int cross_relays(ps *p, const manifest *m, const derived *d)
{
    int direction;
    for (direction = 0; direction < 2; direction++) {
        int forward = direction == 0;
        int count = m->nrelays;
        int index = forward ? 0 : count - 1;
        int step = forward ? 1 : -1;
        int n;
        uint64_t preceding = 0U;
        for (n = 0; n < count; n++, index += step) {
            const relay_rec *r = &m->relays[index];
            char path[64];
            uint32_t low = forward ? r->fwd_min : r->ret_min;
            uint32_t high = forward ? r->fwd_max : r->ret_max;
            uint32_t bound = forward ? m->forward_delay : m->return_delay;
            uint64_t copies = 1ULL + r->lower_dups;
            uint64_t serial = 0U;
            uint64_t end = 0U;
            uint64_t boot_opp;
            uint64_t confirm_span;
            uint64_t need_fwd;
            uint64_t expiry_need;
            uint64_t boot_need;
            uint64_t confirm_need;
            uint64_t est_need;
            uint64_t air = 0U;
            uint64_t part = 0U;
            int burst_ok = 1;
            int i;
            snprintf(path, sizeof path, "$.relays[node=%u]", r->node);
            if (!reqp(p, preceding <= low && low <= high, "relay", path)) {
                return 0;
            }
            if (!umul(copies, r->frame_tx_ms, &serial) || !uadd((uint64_t)high + r->dup_tail, serial, &end)) {
                return reqp(p, 0, "relay", path);
            }
            preceding = end;
            if (!reqp(p, preceding <= bound, "relay", path)) {
                return 0;
            }
            for (i = 1; i < m->nbursts; i++) {
                uint64_t left = (uint64_t)m->burst_starts[i - 1] + m->burst_span + high + r->dup_tail + serial + r->cooldown_ms;
                if ((uint64_t)m->burst_starts[i] + low < left) {
                    burst_ok = 0;
                }
            }
            if (!reqp(p, burst_ok, "relay", path)) {
                return 0;
            }
            boot_opp = (uint64_t)m->flight_attempts + m->dup_responses;
            confirm_span = m->period_ms;
            if (m->mode_xx) {
                boot_opp += m->confirm_attempts;
                confirm_span = d->flight_span;
            }
            if (!umul(umax(m->max_bursts, umax(boot_opp, m->confirm_attempts)), copies, &need_fwd)) {
                return reqp(p, 0, "relay", path);
            }
            if (!reqp(p, r->max_forwards >= need_fwd, "relay", path)) {
                return 0;
            }
            expiry_need = (uint64_t)m->burst_starts[m->nbursts - 1] + m->burst_span + (uint64_t)high - low +
                          r->dup_tail + serial + m->record_margin;
            if (!reqp(p, r->expiry_ms >= expiry_need, "relay", path)) {
                return 0;
            }
            boot_need = d->flight_span + high + r->dup_tail + serial + r->cooldown_ms;
            confirm_need = confirm_span + high + r->dup_tail + serial + r->cooldown_ms;
            est_need = d->establishment_ms + (uint64_t)high - low + r->dup_tail + serial + m->record_margin;
            if (!reqp(p, (uint64_t)m->flight_retry_ms + low >= boot_need &&
                             (uint64_t)m->confirm_timeout + low >= confirm_need &&
                             r->expiry_ms >= est_need,
                      "relay", path)) {
                return 0;
            }
            if (!umul(2U * 2U, d->transfer_frames, &part) ||
                !umul(d->establishment_frames, m->episode_attempts, &air) ||
                !uadd(part, air, &air) || !umul(air, copies, &air) || !umul(air, r->frame_tx_ms, &air)) {
                return reqp(p, 0, "relay", path);
            }
            {
                uint64_t twice = 0U;
                if (!umul(air, 2U, &twice)) {
                    return reqp(p, 0, "relay", path);
                }
                if (!reqp(p, r->per_origin >= air && r->global_air >= twice, "relay", path)) {
                    return 0;
                }
            }
        }
    }
    return 1;
}

static int component_floor(const manifest *m, const derived *d, int relay_role, int component,
                           uint64_t associations, uint64_t grants, uint64_t *count, uint64_t *size)
{
    uint64_t operations = 4U;
    uint64_t c = 1U;
    uint64_t s = 1U;
    switch (component) {
    case 0:
    case 2:
        c = associations;
        break;
    case 1:
        c = m->crypto_slots;
        break;
    case 3:
        c = m->preauth_slots;
        s = 120U;
        break;
    case 4:
        c = operations;
        s = m->message_bytes;
        break;
    case 5:
        c = m->assemblies;
        if (!uadd(m->message_bytes, 512U, &s)) {
            return 0;
        }
        break;
    case 6:
        c = operations + grants;
        s = umax(m->message_bytes, grants != 0U ? 21U : 1U);
        break;
    case 7:
        c = 2U * (operations + grants);
        break;
    case 8:
        c = operations + grants;
        break;
    case 9:
        c = m->control_slots;
        s = d->encoded;
        break;
    case 10:
        c = m->app_queue;
        s = m->message_bytes;
        break;
    case 11:
        c = m->adapter_slots;
        s = d->encoded;
        break;
    case 12:
        break;
    case 13:
        break;
    case 14:
        c = m->tokens_principal == 0U ? 1U : m->tokens_principal;
        s = grants != 0U ? 16U : 1U;
        break;
    case COMPONENT_ASSEMBLY_TOMBSTONE:
        if (!umul(m->peers, m->assembly_tombstones, &c)) {
            return 0;
        }
        s = 48U;
        break;
    default:
        return 0;
    }
    if (relay_role) {
        c = 1U;
        s = 1U;
        if (component == 13) {
            uint64_t extra = 0U;
            uint64_t bodies = 0U;
            if (!umul(operations, (uint64_t)d->fragment_count + d->boot_count, &bodies) ||
                !uadd(bodies, (uint64_t)m->max_status + m->receipt_limit, &bodies) ||
                !umul(d->establishment_frames, m->episode_attempts, &extra) ||
                !uadd(bodies, extra, &c)) {
                return 0;
            }
        }
        if (component == 9 || component == 11) {
            s = d->encoded;
        }
    }
    *count = c;
    *size = s;
    return 1;
}

static int cross_resources(ps *p, const manifest *m, const derived *d)
{
    int endpoints = 0;
    int relays = 0;
    int i;
    uint64_t associations = (uint64_t)m->pending + m->active + m->draining;
    uint64_t grants = m->grant_requests;
    int expect_relay = m->nrelays != 0;
    for (i = 0; i < m->nresources; i++) {
        if (m->resources[i].relay) {
            relays++;
        } else {
            endpoints++;
        }
    }
    if (!reqp(p, expect_relay ? (endpoints == 1 && relays == 1) : (endpoints == 1 && relays == 0),
              "resources", "$.resources")) {
        return 0;
    }
    if (!reqp(p, (uint64_t)m->control_slots >= (uint64_t)m->feedback_buffers + grants + 1U,
              "resources", "$.limits.control_slots")) {
        return 0;
    }
    if (!reqp(p, m->assembly_tombstones >= m->assemblies,
              "resources", "$.limits.assembly_tombstones_per_peer")) {
        return 0;
    }
    for (i = 0; i < m->nresources; i++) {
        const resource_rec *r = &m->resources[i];
        char path[80];
        char cpath[96];
        int seen_comp[16];
        uint64_t used[8];
        int overflow[8];
        int region;
        int charge;
        int bit;
        snprintf(path, sizeof path, "$.resources[%s]", r->relay ? "relay" : "endpoint");
        if (!reqp(p, r->flash_reserved <= r->flash_limit, "resources", path)) {
            return 0;
        }
        for (region = 0; region < r->nregions; region++) {
            int other;
            used[region] = 0U;
            overflow[region] = 0;
            for (other = 0; other < region; other++) {
                if (strcmp(r->regions[region].id, r->regions[other].id) == 0) {
                    return reqp(p, 0, "resources", path);
                }
            }
        }
        if (r->ncharges != 16) {
            return reqp(p, 0, "resources", path);
        }
        for (bit = 0; bit < 16; bit++) {
            seen_comp[bit] = 0;
        }
        for (charge = 0; charge < r->ncharges; charge++) {
            int component = r->charges[charge].component;
            if (component < 0 || component >= 16 || seen_comp[component]) {
                return reqp(p, 0, "resources", path);
            }
            seen_comp[component] = 1;
        }
        for (charge = 0; charge < r->ncharges; charge++) {
            const charge_rec *c = &r->charges[charge];
            uint64_t need_count = 0U;
            uint64_t need_size = 0U;
            uint64_t product = 0U;
            int at = -1;
            int region_index;
            for (region_index = 0; region_index < r->nregions; region_index++) {
                if (strcmp(r->regions[region_index].id, c->region) == 0) {
                    at = region_index;
                    break;
                }
            }
            if (!reqp(p, at >= 0, "resources", path)) {
                return 0;
            }
            if (!component_floor(m, d, r->relay, c->component, associations, grants, &need_count, &need_size)) {
                snprintf(cpath, sizeof cpath, "%s.%s", path, COMPONENT_NAMES[c->component]);
                return reqp(p, 0, "resources", cpath);
            }
            snprintf(cpath, sizeof cpath, "%s.%s", path, COMPONENT_NAMES[c->component]);
            if (!reqp(p, c->count >= need_count && c->bytes_each >= need_size, "resources", cpath)) {
                return 0;
            }
            if (!umul(c->count, c->bytes_each, &product) || used[at] > UINT64_MAX - product) {
                overflow[at] = 1;
            } else {
                used[at] += product;
            }
        }
        for (region = 0; region < r->nregions; region++) {
            if (overflow[region] || used[region] > r->regions[region].limit) {
                return reqp(p, 0, "resources", path);
            }
        }
    }
    return 1;
}

static int cross_all(ps *p, const manifest *m)
{
    derived d;
    memset(&d, 0, sizeof d);
    return cross_identity(p, m) && cross_security(p, m) && cross_frames(p, m, &d) &&
           cross_timing(p, m, &d) && cross_establishment(p, m, &d) && cross_relays(p, m, &d) &&
           cross_resources(p, m, &d);
}

static void publish(dmp_profile_failure *failure, const err *e)
{
    size_t i;
    memset(failure, 0, sizeof *failure);
    for (i = 0U; i + 1U < sizeof failure->code && e->code[i] != '\0'; i++) {
        failure->code[i] = e->code[i];
    }
    for (i = 0U; i + 1U < sizeof failure->path && e->path[i] != '\0'; i++) {
        failure->path[i] = e->path[i];
    }
}

static dmp_status contract_status(const char *code)
{
    if (strcmp(code, "encoding") == 0 || strcmp(code, "json") == 0) {
        return DMP_MALFORMED;
    }
    if (strcmp(code, "digest") == 0) {
        return DMP_INTEGRITY_FAILURE;
    }
    return DMP_UNSUPPORTED;
}

static void fill_profile(dmp_admitted_profile *out, const manifest *m, const uint8_t digest[32])
{
    int i;
    memset(out, 0, sizeof *out);
    memcpy(out->sha256, digest, 32U);
    out->namespace_id = m->namespace_id;
    out->node_id[0] = m->node_id[0];
    out->node_id[1] = m->node_id[1];
    out->default_service = 1U;
    for (i = 0; i < 2; i++) {
        out->service_id[i] = m->services[i].id;
        out->recovery[i] = m->services[i].selective ? DMP_PROFILE_RECOVERY_SELECTIVE32
                                                    : DMP_PROFILE_RECOVERY_RETRY_ALL;
    }
    out->peers = m->peers;
    out->operations_per_service = m->operations;
    out->assemblies_per_peer = m->assemblies;
    out->assembly_tombstones_per_peer = m->assembly_tombstones;
    out->sender_slots = endpoint_charge_count(m, COMPONENT_SENDER);
    out->assembly_slots = endpoint_charge_count(m, COMPONENT_ASSEMBLY);
    out->assembly_tombstone_slots = endpoint_charge_count(m, COMPONENT_ASSEMBLY_TOMBSTONE);
    out->result_slots = endpoint_charge_count(m, COMPONENT_RESULT);
    out->history_slots = endpoint_charge_count(m, COMPONENT_HISTORY);
    out->correlation_slots = endpoint_charge_count(m, COMPONENT_CORRELATION);
    out->adapter_slots = endpoint_charge_count(m, COMPONENT_ADAPTER);
    out->application_queue_slots = m->app_queue;
    out->control_slots = m->control_slots;
    out->message_bytes = m->message_bytes;
    out->fragments = m->fragments;
    out->chunk_bytes = m->chunk_bytes;
    out->encoded_mtu = m->encoded_mtu;
    out->forward_mtu = m->forward_mtu;
    out->return_mtu = m->return_mtu;
    out->queue_ms = m->queue_ms;
    out->response_timeout_ms = m->response_timeout;
    out->jitter_ms = m->jitter_ms;
    out->send_horizon_ms = m->send_horizon;
    out->max_bursts = m->max_bursts;
    out->receipt_delay_ms = m->receipt_delay;
    out->receipt_limit = m->receipt_limit;
    out->dedup_ms = m->dedup_ms;
    out->rejection_ms = m->rejection_ms;
    out->result_cache_ms = m->result_cache_ms;
    out->result_deadline_ms = m->result_deadline_ms;
    out->correlation_ms = m->correlation_ms;
    out->tombstone_ms = m->tombstone_ms;
    out->late_result_ms = m->late_result_ms;
    out->collect_ms = m->collect_ms;
    out->assembly_ms = m->assembly_ms;
    out->tx_borrow = m->tx_borrow ? true : false;
    out->synchronous_completion = m->sync_completion ? true : false;
}

static manifest *place_manifest(uint8_t *scratch, size_t capacity)
{
    uintptr_t base = (uintptr_t)scratch;
    uintptr_t aligned = (base + 7U) & ~(uintptr_t)7U;
    size_t pad = (size_t)(aligned - base);
    if (capacity < pad || capacity - pad < sizeof(manifest)) {
        return NULL;
    }
    return (manifest *)(void *)aligned;
}

static dmp_status fail_contract(dmp_profile_failure *failure, const err *e)
{
    publish(failure, e);
    return contract_status(e->code);
}

dmp_status dmp_profile_admit(dmp_bytes raw,
                             const uint8_t expected_sha256[DMP_PROFILE_SHA256_BYTES],
                             dmp_profile_sha256_fn sha256, void *sha256_context,
                             dmp_buffer scratch, dmp_admitted_profile *out,
                             dmp_profile_failure *failure)
{
    err e;
    ps parser;
    int lone = 0;
    manifest *m;
    uint8_t digest[DMP_PROFILE_SHA256_BYTES];
    dmp_status status;

    if (out == NULL || failure == NULL || sha256 == NULL || scratch.data == NULL ||
        scratch.capacity < DMP_PROFILE_ADMIT_SCRATCH_BYTES || (raw.size != 0U && raw.data == NULL)) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(&e, 0, sizeof e);
    memset(&parser, 0, sizeof parser);
    parser.b = raw.data;
    parser.n = raw.size;
    parser.e = &e;
    if (!path_set(&parser, "$")) {
        return DMP_INVALID_ARGUMENT;
    }
    if (raw.size == 0U || raw.size > DMP_PROFILE_MAX_BYTES) {
        set_err(&e, "encoding", "$");
        return fail_contract(failure, &e);
    }
    if (raw.size >= 3U && raw.data[0] == 0xefU && raw.data[1] == 0xbbU && raw.data[2] == 0xbfU) {
        set_err(&e, "encoding", "$");
        return fail_contract(failure, &e);
    }
    if (!utf8_ok(raw.data, raw.size)) {
        set_err(&e, "encoding", "$");
        return fail_contract(failure, &e);
    }
    if (!depth_ok(raw.data, raw.size)) {
        set_err(&e, "json", "$");
        return fail_contract(failure, &e);
    }
    if (!lex_document(&parser, scratch.data, &lone)) {
        return fail_contract(failure, &e);
    }
    if (lone) {
        set_err(&e, "encoding", "$");
        return fail_contract(failure, &e);
    }
    m = place_manifest(scratch.data, scratch.capacity);
    if (m == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(m, 0, sizeof *m);
    memset(&parser, 0, sizeof parser);
    parser.b = raw.data;
    parser.n = raw.size;
    parser.e = &e;
    if (!path_set(&parser, "$") || !parse_root(&parser, m)) {
        return fail_contract(failure, &e);
    }
    status = sha256(sha256_context, raw, digest);
    if (status != DMP_OK) {
        return status;
    }
    if (expected_sha256 != NULL && memcmp(expected_sha256, digest, sizeof digest) != 0) {
        set_err(&e, "digest", "$");
        return fail_contract(failure, &e);
    }
    if (!cross_all(&parser, m)) {
        return fail_contract(failure, &e);
    }
    fill_profile(out, m, digest);
    return DMP_OK;
}
