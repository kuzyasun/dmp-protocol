#include "dmp/reassembly.h"
#include "dmp/reliability.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(DMP_PROFILE_ADMIT_SCRATCH_BYTES) || defined(DMP_PROFILE_MAX_BYTES)
#error removed profile admission constants
#endif

#ifndef DMP_SOURCE_DIR
#error DMP_SOURCE_DIR is required
#endif

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

enum {
    DIRECT_MESSAGE = 1024,
    DIRECT_FRAGMENTS = 16,
    DIRECT_CHUNK = 64,
    DIRECT_MTU = 263,
    DIRECT_SENDER = 4,
    DIRECT_RESULT = 4,
    DIRECT_HISTORY = 8,
    DIRECT_CORRELATION = 4,
    DIRECT_ASSEMBLY = 1,
    DIRECT_TOMBSTONES = 16,
    DIRECT_ADAPTER = 2,
    DIRECT_CONTROL = 2,
    RESERVE_ADAPTER = 3
};

static void valid_config(dmp_config *config)
{
    unsigned i;
    memset(config, 0, sizeof *config);
    for (i = 0U; i < DMP_PROFILE_SHA256_BYTES; i++) {
        config->sha256[i] = (uint8_t)(0xA0U + i);
    }
    config->namespace_id = 1U;
    config->node_id[0] = 10U;
    config->node_id[1] = 20U;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->peers = 1U;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = 1U;
    config->assembly_tombstones_per_peer = 1U;
    config->sender_slots = 1U;
    config->assembly_slots = 1U;
    config->assembly_tombstone_slots = 1U;
    config->result_slots = 1U;
    config->history_slots = 1U;
    config->correlation_slots = 1U;
    config->adapter_slots = 2U;
    config->application_queue_slots = 1U;
    config->control_slots = 1U;
    config->message_bytes = 64U;
    config->fragments = 2U;
    config->chunk_bytes = 16U;
    config->encoded_mtu = 32U;
    config->forward_mtu = 32U;
    config->return_mtu = 32U;
    config->tx_borrow = true;
    config->synchronous_completion = false;
}

#define REJECT(setup, status)                                                \
    do {                                                                     \
        dmp_config in_;                                                      \
        dmp_admitted_profile out_;                                           \
        dmp_admitted_profile saved_;                                         \
        valid_config(&in_);                                                  \
        setup;                                                               \
        memset(&out_, 0x3C, sizeof out_);                                    \
        saved_ = out_;                                                       \
        CHECK(dmp_config_admit(&in_, &out_) == (status));                    \
        if ((status) == DMP_OK) {                                            \
            CHECK(memcmp(&in_, &out_, sizeof in_) == 0);                     \
        } else {                                                             \
            CHECK(memcmp(&out_, &saved_, sizeof out_) == 0);                 \
        }                                                                    \
    } while (0)

static int test_arguments_and_copy(void)
{
    dmp_config in;
    dmp_admitted_profile out;
    dmp_admitted_profile same;
    dmp_admitted_profile saved;
    unsigned i;

    memset(&out, 0x3C, sizeof out);
    saved = out;
    CHECK(dmp_config_admit(NULL, &out) == DMP_INVALID_ARGUMENT);
    CHECK(memcmp(&out, &saved, sizeof out) == 0);
    valid_config(&in);
    CHECK(dmp_config_admit(&in, NULL) == DMP_INVALID_ARGUMENT);

    memset(&same, 0xA5, sizeof same);
    saved = same;
    CHECK(dmp_config_admit(&same, &same) == DMP_INVALID_ARGUMENT);
    CHECK(memcmp(&same, &saved, sizeof same) == 0);

    valid_config(&in);
    memset(&out, 0x3C, sizeof out);
    CHECK(dmp_config_admit(&in, &out) == DMP_OK);
    CHECK(memcmp(&in, &out, sizeof in) == 0);
    for (i = 0U; i < DMP_PROFILE_SHA256_BYTES; i++) {
        CHECK(out.sha256[i] == (uint8_t)(0xA0U + i));
    }
    CHECK(out.tx_borrow == true);
    CHECK(out.synchronous_completion == false);

    REJECT(in_.message_bytes = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.chunk_bytes = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.encoded_mtu = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.fragments = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.fragments = 33U, DMP_INVALID_ARGUMENT);
    REJECT(in_.fragments = 1U, DMP_OK);
    REJECT(in_.fragments = 32U, DMP_OK);
    REJECT(in_.sender_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.result_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.history_slots = 16843010U, DMP_INVALID_ARGUMENT);
    REJECT(in_.correlation_slots = 16843010U, DMP_INVALID_ARGUMENT);
    REJECT(in_.adapter_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.assembly_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.assembly_slots = 16843010U; in_.message_bytes = 64U;
           in_.chunk_bytes = 16U, DMP_INVALID_ARGUMENT);
    REJECT(in_.peers = 65536U; in_.assembly_tombstones_per_peer = 65536U;
           in_.assembly_tombstone_slots = 0U, DMP_INVALID_ARGUMENT);

    REJECT(in_.default_service = 0U, DMP_UNSUPPORTED);
    REJECT(in_.default_service = 3U, DMP_UNSUPPORTED);
    REJECT(in_.service_id[0] = 1U; in_.service_id[1] = 1U; in_.default_service = 1U,
           DMP_UNSUPPORTED);
    REJECT(in_.chunk_bytes = in_.message_bytes, DMP_UNSUPPORTED);
    REJECT(in_.chunk_bytes = in_.message_bytes + 1U, DMP_UNSUPPORTED);
    REJECT(in_.peers = 0U, DMP_UNSUPPORTED);
    REJECT(in_.assembly_tombstones_per_peer = 0U, DMP_UNSUPPORTED);
    REJECT(in_.peers = 2U; in_.assembly_tombstone_slots = 1U, DMP_UNSUPPORTED);
    REJECT(in_.default_service = 2U, DMP_OK);
    REJECT(in_.peers = 2U; in_.assembly_tombstone_slots = 2U, DMP_OK);
    return 0;
}

static int header_closed(void)
{
    FILE *in;
    char chunk[1024];
    size_t n;
    int saw_new = 0;
    char window[2048];
    size_t filled = 0U;
    static const char scratch[] = "419936";
    static const char old_fn[] = "dmp_profile_admit";
    static const char old_scratch[] = "DMP_PROFILE_ADMIT_SCRATCH_BYTES";
    static const char old_max[] = "DMP_PROFILE_MAX_BYTES";
    static const char new_fn[] = "dmp_config_admit";

    in = fopen(DMP_SOURCE_DIR "/include/dmp/identity.h", "rb");
    CHECK(in != NULL);
    memset(window, 0, sizeof window);
    while ((n = fread(chunk, 1U, sizeof chunk, in)) != 0U) {
        size_t i;
        for (i = 0U; i < n; i++) {
            if (filled + 1U >= sizeof window) {
                memmove(window, window + filled / 2U, filled - filled / 2U);
                filled -= filled / 2U;
            }
            window[filled++] = chunk[i];
            window[filled] = '\0';
            if (strstr(window, scratch) != NULL || strstr(window, old_fn) != NULL ||
                strstr(window, old_scratch) != NULL || strstr(window, old_max) != NULL) {
                (void)fclose(in);
                (void)fprintf(stderr, "public header still exposes removed admission API\n");
                return 1;
            }
            if (strstr(window, new_fn) != NULL) {
                saw_new = 1;
            }
        }
    }
    CHECK(ferror(in) == 0);
    (void)fclose(in);
    CHECK(saw_new == 1);
    return 0;
}

static void direct_limits(dmp_config *config, uint32_t adapter_slots)
{
    memset(config, 0, sizeof *config);
    config->namespace_id = 1U;
    config->node_id[0] = 10U;
    config->node_id[1] = 20U;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->peers = 1U;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = 1U;
    config->assembly_tombstones_per_peer = DIRECT_TOMBSTONES;
    config->sender_slots = DIRECT_SENDER;
    config->assembly_slots = DIRECT_ASSEMBLY;
    config->assembly_tombstone_slots = DIRECT_TOMBSTONES;
    config->result_slots = DIRECT_RESULT;
    config->history_slots = DIRECT_HISTORY;
    config->correlation_slots = DIRECT_CORRELATION;
    config->adapter_slots = adapter_slots;
    config->application_queue_slots = 2U;
    config->control_slots = DIRECT_CONTROL;
    config->message_bytes = DIRECT_MESSAGE;
    config->fragments = DIRECT_FRAGMENTS;
    config->chunk_bytes = DIRECT_CHUNK;
    config->encoded_mtu = DIRECT_MTU;
    config->forward_mtu = 256U;
    config->return_mtu = 256U;
}

static void smaller_unfragmented(dmp_config *config)
{
    direct_limits(config, RESERVE_ADAPTER);
    config->sender_slots = 1U;
    config->result_slots = 1U;
    config->assembly_slots = 0U;
    config->assembly_tombstone_slots = 0U;
    config->assemblies_per_peer = 0U;
    config->assembly_tombstones_per_peer = 0U;
    config->fragments = 2U;
}

static uint64_t eight_sum(const dmp_config *config)
{
    return (uint64_t)config->sender_slots * config->message_bytes +
           (uint64_t)config->result_slots * config->message_bytes +
           config->message_bytes +
           (uint64_t)config->history_slots * (uint64_t)DMP_MAX_HEADER_BYTES +
           (uint64_t)config->correlation_slots * (uint64_t)DMP_MAX_HEADER_BYTES +
           (uint64_t)config->adapter_slots * config->encoded_mtu +
           (uint64_t)config->assembly_slots * config->message_bytes +
           (uint64_t)config->assembly_slots * (uint64_t)DMP_REASSEMBLY_METADATA_BYTES;
}

static size_t state_bytes(int reassembly, uint32_t assembly_slots)
{
    size_t bytes = sizeof(dmp_identity_slot) + sizeof(dmp_reliability);
    if (reassembly) {
        bytes += sizeof(dmp_reassembly_slot) * (size_t)assembly_slots + sizeof(dmp_reassembly);
    }
    return bytes;
}

static int test_budget(void)
{
    static const uint32_t budgets[6] = {1024U, 2048U, 3072U, 4096U, 8192U, 16384U};
    dmp_config manifest;
    dmp_config reserve;
    dmp_config smaller;
    dmp_admitted_profile out;
    uint64_t manifest_sum;
    uint64_t smaller_sum;
    uint64_t reserve_sum;
    size_t tombstone_one;
    unsigned i;

    CHECK(sizeof(dmp_reassembly_tombstone) == 48U);
    tombstone_one = sizeof(dmp_reassembly_tombstone);
    direct_limits(&manifest, DIRECT_ADAPTER);
    direct_limits(&reserve, RESERVE_ADAPTER);
    smaller_unfragmented(&smaller);
    CHECK(dmp_config_admit(&manifest, &out) == DMP_OK);
    CHECK(memcmp(&manifest, &out, sizeof manifest) == 0);
    CHECK(manifest.adapter_slots == manifest.control_slots);
    CHECK(dmp_config_admit(&reserve, &out) == DMP_OK);
    CHECK(dmp_config_admit(&smaller, &out) == DMP_OK);
    CHECK(smaller.adapter_slots > smaller.control_slots);
    CHECK(smaller.control_slots >= 1U);
    CHECK(smaller.message_bytes == DIRECT_MESSAGE);
    CHECK(smaller.history_slots == DIRECT_HISTORY);
    CHECK(smaller.correlation_slots == DIRECT_CORRELATION);
    CHECK(reserve.assembly_tombstone_slots == DIRECT_TOMBSTONES);
    CHECK(reserve.assembly_tombstones_per_peer >= reserve.assemblies_per_peer);
    CHECK(reserve.assembly_tombstone_slots >=
          reserve.peers * reserve.assembly_tombstones_per_peer);

    manifest_sum = eight_sum(&manifest);
    reserve_sum = eight_sum(&reserve);
    smaller_sum = eight_sum(&smaller);
    CHECK(manifest_sum == 14081ULL);
    CHECK(reserve_sum == 14344ULL);
    CHECK(smaller_sum == 6921ULL);
    {
        dmp_config unfragmented;
        memset(&unfragmented, 0, sizeof unfragmented);
        unfragmented.sender_slots = DIRECT_SENDER;
        unfragmented.result_slots = DIRECT_RESULT;
        unfragmented.history_slots = DIRECT_HISTORY;
        unfragmented.correlation_slots = DIRECT_CORRELATION;
        unfragmented.adapter_slots = DIRECT_ADAPTER;
        unfragmented.message_bytes = DIRECT_MESSAGE;
        unfragmented.encoded_mtu = DIRECT_MTU;
        CHECK(eight_sum(&unfragmented) == 12802ULL);
        CHECK(12802ULL > 8192ULL);
    }

    (void)printf("SIZE identity_slot=%zu reliability=%zu reassembly_slot=%zu "
                 "reassembly=%zu tombstone=%zu\n",
                 sizeof(dmp_identity_slot), sizeof(dmp_reliability),
                 sizeof(dmp_reassembly_slot), sizeof(dmp_reassembly), tombstone_one);
    (void)printf("NOTE manifest adapter_slots=%u control_slots=%u eight_sum=%llu "
                 "admits; reliability reserve is a separate engine rule\n",
                 manifest.adapter_slots, manifest.control_slots,
                 (unsigned long long)manifest_sum);

    for (i = 0U; i < 6U; i++) {
        const dmp_config *config;
        int supported;
        int reassembly;
        uint64_t sum;
        size_t tombs;
        size_t state;
        const char *capability;

        if (budgets[i] >= 16384U) {
            config = &reserve;
            supported = 1;
            reassembly = 1;
            capability = "direct-nnpsk0 reassembly limits; adapter_slots 3 so "
                         "adapter_slots > control_slots 2; manifest pair is 2 and 2";
        } else if (budgets[i] >= 8192U) {
            config = &smaller;
            supported = 1;
            reassembly = 0;
            capability = "unfragmented reliability; omits assembly payload and "
                         "assembly metadata; tombstones omitted; direct message, "
                         "history 8, correlation 4, control_slots 2, adapter_slots 3; "
                         "sender and result concurrency 1";
        } else {
            config = &smaller;
            supported = 0;
            reassembly = 0;
            capability = "unsupported; preserved direct message 1024, history 8, "
                         "correlation 4, control_slots 2, adapter_slots 3; "
                         "unfragmented; eight-array sum exceeds the budget";
        }
        sum = eight_sum(config);
        tombs = reassembly ? (size_t)config->assembly_tombstone_slots * tombstone_one : 0U;
        state = state_bytes(reassembly, config->assembly_slots);
        if (supported) {
            CHECK(sum <= budgets[i]);
            CHECK(config->adapter_slots > config->control_slots);
            CHECK(config->control_slots >= 1U);
        } else {
            CHECK(sum > budgets[i]);
            CHECK(config->message_bytes == DIRECT_MESSAGE);
            CHECK(config->history_slots == DIRECT_HISTORY);
            CHECK(config->control_slots == DIRECT_CONTROL);
            CHECK(config->adapter_slots > config->control_slots);
        }
        if (reassembly) {
            CHECK(tombs == 16U * 48U);
            CHECK(config->assembly_slots != 0U);
        } else {
            CHECK(config->assembly_slots == 0U);
            CHECK(tombs == 0U);
        }
        (void)printf(
            "BUDGET_ROW budget=%u supported=%d capability=\"%s\" message_bytes=%u "
            "fragments=%u chunk_bytes=%u peers=%u sender=%u result=%u history=%u "
            "correlation=%u adapter=%u control=%u assembly=%u tombstone_slots=%u "
            "eight_sum=%llu state_bytes=%zu tombstone_bytes=%zu crypto=excluded "
            "stack=excluded json_scratch=0\n",
            budgets[i], supported, capability, config->message_bytes, config->fragments,
            config->chunk_bytes, config->peers, config->sender_slots, config->result_slots,
            config->history_slots, config->correlation_slots, config->adapter_slots,
            config->control_slots, config->assembly_slots, config->assembly_tombstone_slots,
            (unsigned long long)sum, state, tombs);
    }
    return 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_hex(const char *text, uint8_t out[32])
{
    unsigned i;
    for (i = 0U; i < 32U; i++) {
        int hi = hex_nibble(text[i * 2U]);
        int lo = hex_nibble(text[i * 2U + 1U]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return text[64] == '\0';
}

static void print_hex(const uint8_t raw[32])
{
    unsigned i;
    for (i = 0U; i < 32U; i++) {
        (void)printf("%02x", raw[i]);
    }
}

static int read_u32(const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;
    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }
    value = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || value > 0xFFFFFFFFUL) {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

static char *trim(char *line)
{
    size_t n;
    while (*line == ' ' || *line == '\t') {
        line++;
    }
    n = strlen(line);
    while (n > 0U && (line[n - 1U] == '\n' || line[n - 1U] == '\r' || line[n - 1U] == ' ')) {
        line[--n] = '\0';
    }
    return line;
}

static int take_line(char *key, size_t key_n, char *value, size_t value_n)
{
    char line[256];
    char *body;
    char *split;
    if (fgets(line, (int)sizeof line, stdin) == NULL) {
        return 0;
    }
    body = trim(line);
    split = strchr(body, ' ');
    if (split == NULL) {
        return 0;
    }
    *split = '\0';
    if (strlen(body) + 1U > key_n || strlen(split + 1) + 1U > value_n) {
        return 0;
    }
    memcpy(key, body, strlen(body) + 1U);
    memcpy(value, split + 1, strlen(split + 1) + 1U);
    return 1;
}

static int expect_key(const char *name, char *value, size_t value_n)
{
    char key[64];
    if (!take_line(key, sizeof key, value, value_n) || strcmp(key, name) != 0) {
        (void)fprintf(stderr, "expected field %s\n", name);
        return 0;
    }
    return 1;
}

static int expect_u32(const char *name, uint32_t *out)
{
    char value[64];
    if (!expect_key(name, value, sizeof value) || !read_u32(value, out)) {
        return 0;
    }
    return 1;
}

static int admit_config_stdio(void)
{
    dmp_config in;
    dmp_admitted_profile out;
    dmp_status status;
    char value[80];
    uint32_t recovery0;
    uint32_t recovery1;
    uint32_t flag;

    memset(&in, 0, sizeof in);
    memset(&out, 0x5A, sizeof out);
    if (!expect_key("sha256", value, sizeof value) || !parse_hex(value, in.sha256) ||
        !expect_u32("namespace_id", &in.namespace_id) ||
        !expect_u32("node_id0", &in.node_id[0]) || !expect_u32("node_id1", &in.node_id[1]) ||
        !expect_u32("default_service", &in.default_service) ||
        !expect_u32("service_id0", &in.service_id[0]) ||
        !expect_u32("service_id1", &in.service_id[1]) || !expect_u32("recovery0", &recovery0) ||
        !expect_u32("recovery1", &recovery1) || !expect_u32("peers", &in.peers) ||
        !expect_u32("operations_per_service", &in.operations_per_service) ||
        !expect_u32("assemblies_per_peer", &in.assemblies_per_peer) ||
        !expect_u32("assembly_tombstones_per_peer", &in.assembly_tombstones_per_peer) ||
        !expect_u32("sender_slots", &in.sender_slots) ||
        !expect_u32("assembly_slots", &in.assembly_slots) ||
        !expect_u32("assembly_tombstone_slots", &in.assembly_tombstone_slots) ||
        !expect_u32("result_slots", &in.result_slots) ||
        !expect_u32("history_slots", &in.history_slots) ||
        !expect_u32("correlation_slots", &in.correlation_slots) ||
        !expect_u32("adapter_slots", &in.adapter_slots) ||
        !expect_u32("application_queue_slots", &in.application_queue_slots) ||
        !expect_u32("control_slots", &in.control_slots) ||
        !expect_u32("message_bytes", &in.message_bytes) ||
        !expect_u32("fragments", &in.fragments) || !expect_u32("chunk_bytes", &in.chunk_bytes) ||
        !expect_u32("encoded_mtu", &in.encoded_mtu) ||
        !expect_u32("forward_mtu", &in.forward_mtu) ||
        !expect_u32("return_mtu", &in.return_mtu) || !expect_u32("queue_ms", &in.queue_ms) ||
        !expect_u32("response_timeout_ms", &in.response_timeout_ms) ||
        !expect_u32("jitter_ms", &in.jitter_ms) ||
        !expect_u32("send_horizon_ms", &in.send_horizon_ms) ||
        !expect_u32("max_bursts", &in.max_bursts) ||
        !expect_u32("receipt_delay_ms", &in.receipt_delay_ms) ||
        !expect_u32("receipt_limit", &in.receipt_limit) ||
        !expect_u32("dedup_ms", &in.dedup_ms) || !expect_u32("rejection_ms", &in.rejection_ms) ||
        !expect_u32("result_cache_ms", &in.result_cache_ms) ||
        !expect_u32("result_deadline_ms", &in.result_deadline_ms) ||
        !expect_u32("correlation_ms", &in.correlation_ms) ||
        !expect_u32("tombstone_ms", &in.tombstone_ms) ||
        !expect_u32("late_result_ms", &in.late_result_ms) ||
        !expect_u32("collect_ms", &in.collect_ms) ||
        !expect_u32("assembly_ms", &in.assembly_ms) || !expect_u32("tx_borrow", &flag)) {
        return 2;
    }
    if (flag > 1U) {
        return 2;
    }
    in.tx_borrow = flag == 1U;
    if (!expect_u32("synchronous_completion", &flag) || flag > 1U || recovery0 > 1U ||
        recovery1 > 1U) {
        return 2;
    }
    in.synchronous_completion = flag == 1U;
    in.recovery[0] = (dmp_profile_recovery)recovery0;
    in.recovery[1] = (dmp_profile_recovery)recovery1;
    status = dmp_config_admit(&in, &out);
    (void)printf("status %s\nsha256 ", dmp_status_name(status));
    if (status == DMP_OK) {
        print_hex(out.sha256);
    }
    (void)printf("\n");
    if (status != DMP_OK) {
        return 0;
    }
    (void)printf(
        "namespace_id %u\nnode_id0 %u\nnode_id1 %u\ndefault_service %u\n"
        "service_id0 %u\nservice_id1 %u\nrecovery0 %u\nrecovery1 %u\npeers %u\n"
        "operations_per_service %u\nassemblies_per_peer %u\n"
        "assembly_tombstones_per_peer %u\nsender_slots %u\nassembly_slots %u\n"
        "assembly_tombstone_slots %u\nresult_slots %u\nhistory_slots %u\n"
        "correlation_slots %u\nadapter_slots %u\napplication_queue_slots %u\n"
        "control_slots %u\nmessage_bytes %u\nfragments %u\nchunk_bytes %u\n"
        "encoded_mtu %u\nforward_mtu %u\nreturn_mtu %u\nqueue_ms %u\n"
        "response_timeout_ms %u\njitter_ms %u\nsend_horizon_ms %u\nmax_bursts %u\n"
        "receipt_delay_ms %u\nreceipt_limit %u\ndedup_ms %u\nrejection_ms %u\n"
        "result_cache_ms %u\nresult_deadline_ms %u\ncorrelation_ms %u\n"
        "tombstone_ms %u\nlate_result_ms %u\ncollect_ms %u\nassembly_ms %u\n"
        "tx_borrow %u\nsynchronous_completion %u\n",
        out.namespace_id, out.node_id[0], out.node_id[1], out.default_service, out.service_id[0],
        out.service_id[1], (unsigned)out.recovery[0], (unsigned)out.recovery[1], out.peers,
        out.operations_per_service, out.assemblies_per_peer, out.assembly_tombstones_per_peer,
        out.sender_slots, out.assembly_slots, out.assembly_tombstone_slots, out.result_slots,
        out.history_slots, out.correlation_slots, out.adapter_slots, out.application_queue_slots,
        out.control_slots, out.message_bytes, out.fragments, out.chunk_bytes, out.encoded_mtu,
        out.forward_mtu, out.return_mtu, out.queue_ms, out.response_timeout_ms, out.jitter_ms,
        out.send_horizon_ms, out.max_bursts, out.receipt_delay_ms, out.receipt_limit, out.dedup_ms,
        out.rejection_ms, out.result_cache_ms, out.result_deadline_ms, out.correlation_ms,
        out.tombstone_ms, out.late_result_ms, out.collect_ms, out.assembly_ms,
        out.tx_borrow ? 1U : 0U, out.synchronous_completion ? 1U : 0U);
    return 0;
}

static int run_tests(void)
{
    CHECK(test_arguments_and_copy() == 0);
    CHECK(header_closed() == 0);
    CHECK(test_budget() == 0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--config") == 0) {
        return admit_config_stdio();
    }
    if (argc != 1) {
        (void)fprintf(stderr, "usage: dmp_test_profile_admit [--config]\n");
        return 2;
    }
    return run_tests();
}
