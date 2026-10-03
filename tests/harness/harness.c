#include "harness.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SLOTS 8192U

typedef struct hevent {
    uint64_t time_ms;
    uint8_t phase;
    uint32_t seq;
    uint8_t kind;
    uint32_t index;
    uint8_t copy;
    int live;
} hevent;

typedef struct hsub {
    int present;
    int accepted;
    int started;
    int finished;
    int dropped;
    uint32_t id;
    uint8_t link;
    uint32_t slot;
    uint64_t generation;
    uint64_t start_ms;
    uint64_t not_after_ms;
    uint64_t terminal_ms;
    uint64_t arrival_ms;
    uint8_t copies;
    int is_source;
    int period_held;
    uint64_t period_start;
    int reverse_used[3];
    int source_index;
    uint8_t *stored;
    size_t stored_len;
    const uint8_t *borrow;
    dmp_tx_complete_fn complete;
    void *owner;
    dmp_tx_token token;
} hsub;

typedef struct harm {
    int active;
    uint8_t link;
    uint32_t id;
    int is_return;
    uint32_t reply_to;
    uint8_t return_slot;
    uint32_t completion_delay_ms;
    uint32_t delivery_delay_ms;
    int drop;
    uint8_t duplicates;
} harm;

enum { EV_ACTION = 1, EV_START = 2, EV_ARRIVAL = 3, EV_TERMINAL = 4 };

struct harness_adapter {
    harness_binding binding;
    dmp_transport transport;
    harm arm;
    hsub *subs;
    uint32_t nsubs;
    hevent *events;
    uint32_t nevents;
    uint32_t next_seq;
    harness_action *actions;
    uint32_t nactions;
    harness_fault *faults;
    uint32_t nfaults;
    uint32_t accept_count[2];
    uint64_t periods[HARNESS_MAX_ACTIONS];
    uint32_t nperiods;
    int slot_used[MAX_SLOTS + 1U];
    uint32_t live_slots;
    uint64_t generation;
    uint32_t rng;
    uint64_t now;
    int in_submit;
    int budget;
    int fatal;
    uint32_t accepted;
    uint32_t rejected;
    uint32_t delivered;
    uint32_t terminal_count;
    uint32_t executed;
    uint32_t pending_local;
    uint32_t pending_delivery;
    uint32_t trace_records;
    uint32_t trace_seq;
    char *trace;
    size_t trace_len;
    size_t trace_cap;
    uint8_t *arena;
    size_t arena_used;
    size_t arena_cap;
    int ran_horizon;
};

static int add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (b > UINT64_MAX - a) {
        return 0;
    }
    *out = a + b;
    return 1;
}

uint32_t harness_xorshift32(uint32_t state)
{
    uint32_t x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

static int trace_room(const harness_adapter *a, size_t add, int terminal)
{
    size_t need_tail = terminal ? 0U : HARNESS_TRACE_RESERVE_BYTES;
    uint32_t need_records = terminal ? 1U : 2U;
    if ((uint64_t)a->trace_records + need_records > HARNESS_MAX_TRACE_RECORDS) {
        return 0;
    }
    if (a->trace_len > HARNESS_MAX_TRACE_BYTES || add > HARNESS_MAX_TRACE_BYTES - a->trace_len) {
        return 0;
    }
    if (a->trace_len + add + need_tail > HARNESS_MAX_TRACE_BYTES) {
        return 0;
    }
    if (a->trace == NULL || a->trace_len + add > a->trace_cap) {
        return 0;
    }
    return 1;
}

static int trace_write(harness_adapter *a, const char *line, int terminal)
{
    size_t n = strlen(line);
    if (a->trace == NULL) {
        a->trace_records++;
        a->trace_seq++;
        return 1;
    }
    if (!trace_room(a, n + 1U, terminal)) {
        a->budget = 1;
        return 0;
    }
    memcpy(a->trace + a->trace_len, line, n);
    a->trace_len += n;
    a->trace[a->trace_len++] = '\n';
    a->trace_records++;
    a->trace_seq++;
    return 1;
}

static void hex16(char out[17], uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    int i;
    for (i = 15; i >= 0; i--) {
        out[i] = digits[value & 0x0fU];
        value >>= 4;
    }
    out[16] = '\0';
}

static const char *outcome_name(dmp_tx_outcome outcome)
{
    switch (outcome) {
    case DMP_TX_TRANSMITTED:
        return "transmitted";
    case DMP_TX_CANCELLED_UNSENT:
        return "cancelled_unsent";
    case DMP_TX_FAILED_UNSENT:
        return "failed_unsent";
    case DMP_TX_POSSIBLY_TRANSMITTED:
        return "possibly_transmitted";
    default:
        return "failed_unsent";
    }
}

static int emit_submit(harness_adapter *a, uint32_t id, uint8_t link, size_t bytes, dmp_status status,
                       uint32_t slot, uint64_t generation)
{
    char line[512];
    char gen[17];
    hex16(gen, status == DMP_OK ? generation : 0U);
    snprintf(line, sizeof line,
             "{\"seq\":%u,\"time_ms\":%llu,\"event\":\"submit\",\"id\":%u,\"link\":%u,\"bytes\":%u,"
             "\"status\":\"%s\",\"slot\":%u,\"generation\":\"%s\"}",
             a->trace_seq, (unsigned long long)a->now, id, (unsigned)link, (unsigned)bytes,
             dmp_status_name(status), status == DMP_OK ? slot : 0U, gen);
    return trace_write(a, line, 0);
}

static int emit_terminal(harness_adapter *a, const hsub *sub, dmp_tx_outcome outcome)
{
    char line[512];
    char gen[17];
    hex16(gen, sub->generation);
    snprintf(line, sizeof line,
             "{\"seq\":%u,\"time_ms\":%llu,\"event\":\"terminal\",\"id\":%u,\"slot\":%u,"
             "\"generation\":\"%s\",\"outcome\":\"%s\"}",
             a->trace_seq, (unsigned long long)a->now, sub->id, sub->slot, gen, outcome_name(outcome));
    return trace_write(a, line, 0);
}

static int emit_cancel(harness_adapter *a, uint32_t id, dmp_status status)
{
    char line[256];
    snprintf(line, sizeof line,
             "{\"seq\":%u,\"time_ms\":%llu,\"event\":\"cancel\",\"id\":%u,\"status\":\"%s\"}",
             a->trace_seq, (unsigned long long)a->now, id, dmp_status_name(status));
    return trace_write(a, line, 0);
}

static int emit_arrival(harness_adapter *a, const hsub *sub, uint8_t copy)
{
    char line[256];
    snprintf(line, sizeof line,
             "{\"seq\":%u,\"time_ms\":%llu,\"event\":\"arrival\",\"id\":%u,\"link\":%u,\"bytes\":%u,\"copy\":%u}",
             a->trace_seq, (unsigned long long)a->now, sub->id, (unsigned)sub->link,
             (unsigned)sub->stored_len, (unsigned)copy);
    return trace_write(a, line, 0);
}

int harness_trace_budget_self_check(void)
{
    harness_adapter probe;
    memset(&probe, 0, sizeof probe);
    probe.trace = (char *)&probe;
    probe.trace_cap = HARNESS_MAX_TRACE_BYTES;
    probe.trace_records = HARNESS_MAX_TRACE_RECORDS - 2U;
    probe.trace_len = 0;
    if (!trace_room(&probe, 8U, 0)) {
        return 0;
    }
    probe.trace_records = HARNESS_MAX_TRACE_RECORDS - 1U;
    if (trace_room(&probe, 8U, 0)) {
        return 0;
    }
    probe.trace_records = 0;
    probe.trace_len = HARNESS_MAX_TRACE_BYTES - HARNESS_TRACE_RESERVE_BYTES - 8U;
    if (!trace_room(&probe, 8U, 0)) {
        return 0;
    }
    probe.trace_len = HARNESS_MAX_TRACE_BYTES - HARNESS_TRACE_RESERVE_BYTES - 7U;
    if (trace_room(&probe, 8U, 0)) {
        return 0;
    }
    return 1;
}

static void free_slot(harness_adapter *a, hsub *sub)
{
    if (sub->slot != 0U && sub->slot <= MAX_SLOTS && a->slot_used[sub->slot]) {
        a->slot_used[sub->slot] = 0;
        if (a->live_slots > 0U) {
            a->live_slots--;
        }
    }
    sub->slot = 0U;
}

static void kill_events(harness_adapter *a, uint32_t index, uint8_t kind)
{
    uint32_t i;
    for (i = 0; i < a->nevents; i++) {
        if (a->events[i].live && a->events[i].index == index &&
            (kind == 0U || a->events[i].kind == kind)) {
            a->events[i].live = 0;
        }
    }
}

static int queue_event(harness_adapter *a, uint64_t time, uint8_t phase, uint8_t kind, uint32_t index,
                       uint8_t copy)
{
    hevent *event;
    if (a->nevents >= HARNESS_MAX_EVENTS) {
        a->budget = 1;
        return 0;
    }
    event = &a->events[a->nevents++];
    event->time_ms = time;
    event->phase = phase;
    event->seq = a->next_seq++;
    event->kind = kind;
    event->index = index;
    event->copy = copy;
    event->live = 1;
    return 1;
}

static uint8_t *arena_copy(harness_adapter *a, const uint8_t *data, size_t len)
{
    uint8_t *dest;
    if (len > a->arena_cap - a->arena_used) {
        a->budget = 1;
        return NULL;
    }
    dest = a->arena + a->arena_used;
    if (len != 0U) {
        memcpy(dest, data, len);
    }
    a->arena_used += len;
    return dest;
}

static void finish_sub(harness_adapter *a, hsub *sub, dmp_tx_outcome outcome)
{
    dmp_tx_complete_fn complete;
    void *owner;
    dmp_tx_token token;
    if (!sub->accepted || sub->finished) {
        return;
    }
    sub->finished = 1;
    a->terminal_count++;
    a->executed++;
    complete = sub->complete;
    owner = sub->owner;
    token = sub->token;
    if (!emit_terminal(a, sub, outcome)) {
        sub->borrow = NULL;
        free_slot(a, sub);
        return;
    }
    free_slot(a, sub);
    if (complete != NULL) {
        complete(owner, token, outcome, a->now);
    }
    sub->borrow = NULL;
}

static int alloc_slot(harness_adapter *a, uint32_t *slot)
{
    uint32_t limit = a->binding.adapter_slots;
    uint32_t i;
    if (a->live_slots >= a->binding.adapter_slots || limit == 0U) {
        return 0;
    }
    if (limit > MAX_SLOTS) {
        limit = MAX_SLOTS;
    }
    for (i = 1; i <= limit; i++) {
        if (!a->slot_used[i]) {
            a->slot_used[i] = 1;
            a->live_slots++;
            *slot = i;
            return 1;
        }
    }
    return 0;
}

static int period_free(const harness_adapter *a, uint64_t start)
{
    uint32_t i;
    for (i = 0; i < a->nperiods; i++) {
        if (a->periods[i] == start) {
            return 0;
        }
    }
    return 1;
}

static int earliest_period(const harness_adapter *a, uint64_t at, uint64_t *start)
{
    uint64_t period = a->binding.period_ms;
    uint64_t k;
    uint32_t guard = 0;
    if (period == 0U) {
        return 0;
    }
    k = at / period;
    if (at % period != 0U) {
        if (k == UINT64_MAX) {
            return 0;
        }
        k++;
    }
    while (guard < HARNESS_MAX_ACTIONS + 2U) {
        uint64_t candidate;
        if (k > HARNESS_MAX_VIRTUAL_MS / period) {
            return 0;
        }
        candidate = k * period;
        if (candidate > HARNESS_MAX_VIRTUAL_MS) {
            return 0;
        }
        if (period_free(a, candidate)) {
            *start = candidate;
            return 1;
        }
        if (k == UINT64_MAX) {
            return 0;
        }
        k++;
        guard++;
    }
    return 0;
}

static int find_sub(const harness_adapter *a, uint32_t id, uint32_t *index)
{
    uint32_t i;
    for (i = 0; i < a->nsubs; i++) {
        if (a->subs[i].present && a->subs[i].id == id) {
            *index = i;
            return 1;
        }
    }
    return 0;
}

static void take_fault(harness_adapter *a, uint8_t link, int *drop, uint8_t *duplicates,
                       uint32_t *delivery, uint32_t *completion)
{
    uint32_t ordinal = ++a->accept_count[link];
    uint32_t i;
    *drop = 0;
    *duplicates = 0;
    *delivery = 0;
    *completion = 0;
    for (i = 0; i < a->nfaults; i++) {
        if (a->faults[i].link == link && a->faults[i].ordinal == ordinal) {
            a->faults[i].used = 1;
            *drop = a->faults[i].drop;
            *duplicates = a->faults[i].duplicates;
            *delivery = a->faults[i].delivery_delay_ms;
            *completion = a->faults[i].completion_delay_ms;
            return;
        }
    }
}

static dmp_status port_submit(void *context, const dmp_tx_submission *submission)
{
    harness_adapter *a = context;
    hsub *sub;
    uint64_t start = 0;
    uint64_t terminal_at = 0;
    uint64_t arrival_at = 0;
    uint32_t slot = 0;
    uint64_t generation = 0;
    int drop = 0;
    uint8_t duplicates = 0;
    uint32_t delivery = 0;
    uint32_t completion = 0;
    uint32_t source_index = 0;
    int is_source = 1;
    if (a == NULL || submission == NULL || submission->complete == NULL || !a->arm.active) {
        return DMP_INVALID_ARGUMENT;
    }
    a->in_submit++;
    if (submission->frame.data == NULL || submission->frame.size == 0U ||
        submission->frame.size > a->binding.encoded_mtu) {
        a->rejected++;
        emit_submit(a, a->arm.id, a->arm.link, submission->frame.size, DMP_INVALID_ARGUMENT, 0, 0);
        a->arm.active = 0;
        a->in_submit--;
        return DMP_INVALID_ARGUMENT;
    }
    if (a->nsubs >= HARNESS_MAX_ACTIONS) {
        a->budget = 1;
        a->arm.active = 0;
        a->in_submit--;
        return DMP_LIMIT_EXHAUSTED;
    }
    sub = &a->subs[a->nsubs];
    memset(sub, 0, sizeof *sub);
    sub->present = 1;
    sub->id = a->arm.id;
    sub->link = a->arm.link;
    sub->not_after_ms = submission->not_after;
    sub->complete = submission->complete;
    sub->owner = submission->owner;
    if (a->arm.is_return) {
        is_source = 0;
        if (!find_sub(a, a->arm.reply_to, &source_index) || !a->subs[source_index].accepted ||
            !a->subs[source_index].is_source || a->subs[source_index].link == a->arm.link ||
            (a->arm.return_slot != 1U && a->arm.return_slot != 2U)) {
            sub->accepted = 0;
            a->nsubs++;
            a->rejected++;
            emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_INVALID_ARGUMENT, 0, 0);
            a->arm.active = 0;
            a->in_submit--;
            return DMP_INVALID_ARGUMENT;
        }
        {
            uint64_t width = a->binding.width_ms;
            uint64_t period = a->binding.period_ms;
            uint64_t traversal = a->binding.frame_tx_ms;
            uint64_t delay = a->binding.delay_ms[0] > a->binding.delay_ms[1] ? a->binding.delay_ms[0]
                                                                              : a->binding.delay_ms[1];
            uint64_t slot_time;
            hsub *source = &a->subs[source_index];
            if (!add_u64(traversal, delay, &traversal) || period < width ||
                source->start_ms + period < width) {
                a->nsubs++;
                a->rejected++;
                emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_BUSY, 0, 0);
                a->arm.active = 0;
                a->in_submit--;
                return DMP_BUSY;
            }
            slot_time = source->start_ms + period - width;
            if (a->arm.return_slot == 2U && !add_u64(slot_time, traversal, &slot_time)) {
                a->nsubs++;
                a->rejected++;
                emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_BUSY, 0, 0);
                a->arm.active = 0;
                a->in_submit--;
                return DMP_BUSY;
            }
            if (source->reverse_used[a->arm.return_slot] || a->now > slot_time ||
                slot_time - a->now > a->binding.queue_ms) {
                a->nsubs++;
                a->rejected++;
                emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_BUSY, 0, 0);
                a->arm.active = 0;
                a->in_submit--;
                return DMP_BUSY;
            }
            if (slot_time >= submission->not_after) {
                a->nsubs++;
                a->rejected++;
                emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_DEADLINE_EXPIRED, 0, 0);
                a->arm.active = 0;
                a->in_submit--;
                return DMP_DEADLINE_EXPIRED;
            }
            start = slot_time;
        }
    } else {
        uint64_t wait;
        if (!earliest_period(a, a->now, &start)) {
            a->nsubs++;
            a->rejected++;
            emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_BUSY, 0, 0);
            a->arm.active = 0;
            a->in_submit--;
            return DMP_BUSY;
        }
        wait = start - a->now;
        if (wait > a->binding.queue_ms || a->live_slots >= a->binding.adapter_slots) {
            a->nsubs++;
            a->rejected++;
            emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_BUSY, 0, 0);
            a->arm.active = 0;
            a->in_submit--;
            return DMP_BUSY;
        }
        if (start >= submission->not_after) {
            a->nsubs++;
            a->rejected++;
            emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_DEADLINE_EXPIRED, 0, 0);
            a->arm.active = 0;
            a->in_submit--;
            return DMP_DEADLINE_EXPIRED;
        }
    }
    if (a->live_slots >= a->binding.adapter_slots || !alloc_slot(a, &slot)) {
        a->nsubs++;
        a->rejected++;
        emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_BUSY, 0, 0);
        a->arm.active = 0;
        a->in_submit--;
        return DMP_BUSY;
    }
    if (dmp_generation_next(a->generation, &generation) != DMP_OK) {
        free_slot(a, sub);
        sub->slot = 0;
        a->nsubs++;
        a->rejected++;
        emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_LIMIT_EXHAUSTED, 0, 0);
        a->arm.active = 0;
        a->in_submit--;
        return DMP_LIMIT_EXHAUSTED;
    }
    a->generation = generation;
    a->rng = harness_xorshift32(a->rng);
    take_fault(a, a->arm.link, &drop, &duplicates, &delivery, &completion);
    if (a->arm.drop) {
        drop = 1;
    }
    if (a->arm.duplicates > duplicates) {
        duplicates = a->arm.duplicates;
    }
    if (a->arm.delivery_delay_ms > delivery) {
        delivery = a->arm.delivery_delay_ms;
    }
    if (a->arm.completion_delay_ms > completion) {
        completion = a->arm.completion_delay_ms;
    }
    if ((uint64_t)a->rng < a->binding.loss_threshold) {
        drop = 1;
    }
    if (!add_u64(start, a->binding.frame_tx_ms, &terminal_at) ||
        !add_u64(terminal_at, completion, &terminal_at) ||
        !add_u64(start, a->binding.frame_tx_ms, &arrival_at) ||
        !add_u64(arrival_at, a->binding.delay_ms[a->arm.link], &arrival_at) ||
        !add_u64(arrival_at, delivery, &arrival_at)) {
        free_slot(a, sub);
        a->nsubs++;
        a->rejected++;
        emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_BUSY, 0, 0);
        a->arm.active = 0;
        a->in_submit--;
        return DMP_BUSY;
    }
    sub->accepted = 1;
    sub->is_source = is_source;
    sub->slot = slot;
    sub->generation = generation;
    sub->token.slot = slot;
    sub->token.generation = generation;
    sub->start_ms = start;
    sub->terminal_ms = terminal_at;
    sub->arrival_ms = arrival_at;
    sub->dropped = drop;
    sub->copies = (uint8_t)(drop ? 0U : (duplicates ? 2U : 1U));
    sub->source_index = (int)source_index;
    if (!a->binding.borrow) {
        sub->stored = arena_copy(a, submission->frame.data, submission->frame.size);
        if (sub->stored == NULL) {
            free_slot(a, sub);
            sub->accepted = 0;
            a->budget = 1;
            a->nsubs++;
            a->arm.active = 0;
            a->in_submit--;
            return DMP_LIMIT_EXHAUSTED;
        }
        sub->stored_len = submission->frame.size;
    } else {
        sub->borrow = submission->frame.data;
        sub->stored_len = submission->frame.size;
    }
    if (is_source) {
        if (a->nperiods >= HARNESS_MAX_ACTIONS) {
            free_slot(a, sub);
            sub->accepted = 0;
            a->budget = 1;
            a->nsubs++;
            a->arm.active = 0;
            a->in_submit--;
            return DMP_LIMIT_EXHAUSTED;
        }
        a->periods[a->nperiods++] = start;
        sub->period_held = 1;
        sub->period_start = start;
    } else {
        a->subs[source_index].reverse_used[a->arm.return_slot] = 1;
    }
    a->nsubs++;
    a->accepted++;
    if (!emit_submit(a, sub->id, sub->link, submission->frame.size, DMP_OK, slot, generation)) {
        a->arm.active = 0;
        a->in_submit--;
        return DMP_OK;
    }
    {
        int inline_now = !a->binding.borrow && a->binding.synchronous_completion && completion == 0U &&
                         a->binding.frame_tx_ms == 0U && start == a->now;
        if (!queue_event(a, start, 3, EV_START, a->nsubs - 1U, 0)) {
            a->arm.active = 0;
            a->in_submit--;
            return DMP_OK;
        }
        if (!drop) {
            uint8_t copy;
            uint8_t ncopies = duplicates ? 2U : 1U;
            for (copy = 0; copy < ncopies; copy++) {
                if (!queue_event(a, arrival_at, 1, EV_ARRIVAL, a->nsubs - 1U, copy)) {
                    a->arm.active = 0;
                    a->in_submit--;
                    return DMP_OK;
                }
            }
        }
        if (!inline_now && !queue_event(a, terminal_at, 1, EV_TERMINAL, a->nsubs - 1U, 0)) {
            a->arm.active = 0;
            a->in_submit--;
            return DMP_OK;
        }
        if (inline_now) {
            sub->started = 1;
            kill_events(a, a->nsubs - 1U, EV_START);
            finish_sub(a, sub, DMP_TX_TRANSMITTED);
        }
    }
    a->arm.active = 0;
    a->in_submit--;
    return DMP_OK;
}

static dmp_status port_cancel(void *context, dmp_tx_token token)
{
    harness_adapter *a = context;
    uint32_t i;
    hsub *sub = NULL;
    for (i = 0; i < a->nsubs; i++) {
        if (a->subs[i].present && a->subs[i].accepted && a->subs[i].token.slot == token.slot &&
            a->subs[i].token.generation == token.generation) {
            sub = &a->subs[i];
            break;
        }
    }
    if (sub == NULL || sub->finished || !sub->accepted) {
        return DMP_STALE_HANDLE;
    }
    if (!sub->started) {
        kill_events(a, (uint32_t)(sub - a->subs), EV_START);
        kill_events(a, (uint32_t)(sub - a->subs), EV_ARRIVAL);
        kill_events(a, (uint32_t)(sub - a->subs), EV_TERMINAL);
        finish_sub(a, sub, DMP_TX_CANCELLED_UNSENT);
        return DMP_OK;
    }
    kill_events(a, (uint32_t)(sub - a->subs), EV_TERMINAL);
    finish_sub(a, sub, DMP_TX_POSSIBLY_TRANSMITTED);
    return DMP_OK;
}

static void on_start(harness_adapter *a, uint32_t index)
{
    hsub *sub = &a->subs[index];
    a->executed++;
    if (!sub->accepted || sub->finished || sub->started) {
        return;
    }
    if (a->now >= sub->not_after_ms) {
        kill_events(a, index, EV_ARRIVAL);
        kill_events(a, index, EV_TERMINAL);
        finish_sub(a, sub, DMP_TX_FAILED_UNSENT);
        return;
    }
    sub->started = 1;
    if (sub->borrow != NULL) {
        sub->stored = arena_copy(a, sub->borrow, sub->stored_len);
        if (sub->stored == NULL) {
            a->budget = 1;
            return;
        }
    }
}

static void on_arrival(harness_adapter *a, uint32_t index, uint8_t copy)
{
    hsub *sub = &a->subs[index];
    a->executed++;
    if (!sub->accepted || sub->dropped) {
        return;
    }
    if (sub->stored == NULL && sub->borrow != NULL) {
        sub->stored = arena_copy(a, sub->borrow, sub->stored_len);
        if (sub->stored == NULL) {
            a->budget = 1;
            return;
        }
    }
    a->delivered++;
    emit_arrival(a, sub, copy);
}

static int live_kind(const harness_adapter *a, uint32_t index, uint8_t kind)
{
    uint32_t i;
    for (i = 0; i < a->nevents; i++) {
        if (a->events[i].live && a->events[i].index == index && a->events[i].kind == kind) {
            return 1;
        }
    }
    return 0;
}

static void on_terminal(harness_adapter *a, uint32_t index, uint32_t event_slot)
{
    hsub *sub = &a->subs[index];
    hevent *ev;
    if (!sub->accepted || sub->finished) {
        return;
    }
    /* A zero-duration terminal shares the start timestamp but is queued in
     * phase 1, so it would otherwise run before phase-3 start and be dropped.
     * Keep it until after that start without rewinding ahead of a same-time
     * phase-2 cancel. */
    ev = &a->events[event_slot];
    if (!sub->started) {
        if (ev->phase < 3U && live_kind(a, index, EV_START)) {
            ev->phase = 3;
            ev->seq = a->next_seq++;
            ev->live = 1;
        }
        return;
    }
    finish_sub(a, sub, DMP_TX_TRANSMITTED);
}

static void owned_complete(void *owner, dmp_tx_token token, dmp_tx_outcome outcome, dmp_time_ms when)
{
    (void)owner;
    (void)token;
    (void)outcome;
    (void)when;
}

static void perform_action(harness_adapter *a, uint32_t index)
{
    harness_action *action = &a->actions[index];
    dmp_tx_submission submission;
    uint32_t existing = 0;
    dmp_status status;
    a->executed++;
    if (a->budget) {
        return;
    }
    if (action->cancel) {
        dmp_tx_token token;
        hsub *sub = NULL;
        memset(&token, 0, sizeof token);
        if (find_sub(a, action->id, &existing)) {
            sub = &a->subs[existing];
            token = sub->token;
        }
        if (sub == NULL || !sub->accepted || sub->finished) {
            emit_cancel(a, action->id, DMP_STALE_HANDLE);
            return;
        }
        emit_cancel(a, action->id, DMP_OK);
        if (!sub->started) {
            kill_events(a, existing, EV_START);
            kill_events(a, existing, EV_ARRIVAL);
            kill_events(a, existing, EV_TERMINAL);
            finish_sub(a, sub, DMP_TX_CANCELLED_UNSENT);
        } else {
            kill_events(a, existing, EV_TERMINAL);
            finish_sub(a, sub, DMP_TX_POSSIBLY_TRANSMITTED);
        }
        return;
    }
    memset(&a->arm, 0, sizeof a->arm);
    a->arm.active = 1;
    a->arm.link = action->link;
    a->arm.id = action->id;
    a->arm.is_return = action->reply_to != 0U;
    a->arm.reply_to = action->reply_to;
    a->arm.return_slot = action->return_slot;
    memset(&submission, 0, sizeof submission);
    submission.frame.data = action->data;
    submission.frame.size = action->data_len;
    submission.not_after = action->not_after_ms;
    submission.complete = owned_complete;
    submission.owner = a;
    status = a->transport.submit(a, &submission);
    (void)status;
}

static int event_less(const hevent *a, const hevent *b)
{
    if (a->time_ms != b->time_ms) {
        return a->time_ms < b->time_ms;
    }
    if (a->phase != b->phase) {
        return a->phase < b->phase;
    }
    return a->seq < b->seq;
}

static int next_event(const harness_adapter *a)
{
    uint32_t i;
    int best = -1;
    for (i = 0; i < a->nevents; i++) {
        const hevent *event = &a->events[i];
        if (!event->live || event->time_ms > a->binding.until_ms) {
            continue;
        }
        if (best < 0 || event_less(event, &a->events[best])) {
            best = (int)i;
        }
    }
    return best;
}

static void horizon(harness_adapter *a)
{
    uint32_t i;
    if (a->ran_horizon) {
        return;
    }
    a->ran_horizon = 1;
    if (a->now < a->binding.until_ms) {
        a->now = a->binding.until_ms;
    }
    a->pending_local = 0;
    a->pending_delivery = 0;
    for (i = 0; i < a->nsubs; i++) {
        if (a->subs[i].accepted && !a->subs[i].finished) {
            a->pending_local++;
        }
    }
    for (i = 0; i < a->nevents; i++) {
        if (a->events[i].live && a->events[i].kind == EV_ARRIVAL) {
            a->pending_delivery++;
        }
    }
    for (i = 0; i < a->nsubs; i++) {
        hsub *sub = &a->subs[i];
        if (!sub->accepted || sub->finished) {
            continue;
        }
        if (!sub->started) {
            kill_events(a, i, 0);
            finish_sub(a, sub, DMP_TX_CANCELLED_UNSENT);
        } else {
            kill_events(a, i, EV_TERMINAL);
            finish_sub(a, sub, DMP_TX_POSSIBLY_TRANSMITTED);
        }
    }
    for (i = 0; i < a->nevents; i++) {
        if (a->events[i].kind == EV_ARRIVAL) {
            a->events[i].live = 0;
        }
    }
}

void harness_adapter_run(harness_adapter *a)
{
    if (a == NULL) {
        return;
    }
    while (!a->budget && !a->fatal) {
        int index = next_event(a);
        hevent event;
        if (index < 0) {
            break;
        }
        event = a->events[index];
        a->events[index].live = 0;
        a->now = event.time_ms;
        if (event.kind == EV_ACTION) {
            perform_action(a, event.index);
        } else if (event.kind == EV_START) {
            on_start(a, event.index);
        } else if (event.kind == EV_ARRIVAL) {
            on_arrival(a, event.index, event.copy);
        } else if (event.kind == EV_TERMINAL) {
            on_terminal(a, event.index, (uint32_t)index);
        }
    }
    if (!a->budget) {
        horizon(a);
    }
}

static int cmp_action(const void *left, const void *right)
{
    const harness_action *a = left;
    const harness_action *b = right;
    if (a->at_ms < b->at_ms) {
        return -1;
    }
    if (a->at_ms > b->at_ms) {
        return 1;
    }
    if (a->order < b->order) {
        return -1;
    }
    if (a->order > b->order) {
        return 1;
    }
    return 0;
}

harness_adapter *harness_adapter_create(const harness_binding *binding)
{
    harness_adapter *a = calloc(1, sizeof *a);
    if (a == NULL || binding == NULL) {
        free(a);
        return NULL;
    }
    a->binding = *binding;
    a->subs = calloc(HARNESS_MAX_ACTIONS, sizeof *a->subs);
    a->events = calloc(HARNESS_MAX_EVENTS, sizeof *a->events);
    a->arena_cap = 2U * 1024U * 1024U;
    a->arena = malloc(a->arena_cap);
    if (a->subs == NULL || a->events == NULL || a->arena == NULL) {
        harness_adapter_destroy(a);
        return NULL;
    }
    a->rng = binding->seed;
    a->transport.context = a;
    a->transport.caps.max_frame_bytes = binding->encoded_mtu;
    a->transport.caps.ownership = binding->borrow ? DMP_TX_BORROW : DMP_TX_COPY;
    a->transport.caps.synchronous_completion = binding->synchronous_completion ? true : false;
    a->transport.submit = port_submit;
    a->transport.cancel = port_cancel;
    return a;
}

void harness_adapter_destroy(harness_adapter *adapter)
{
    if (adapter == NULL) {
        return;
    }
    free(adapter->subs);
    free(adapter->events);
    free(adapter->actions);
    free(adapter->arena);
    free(adapter);
}

dmp_transport *harness_adapter_transport(harness_adapter *adapter)
{
    return adapter == NULL ? NULL : &adapter->transport;
}

void harness_adapter_set_now(harness_adapter *adapter, uint64_t now)
{
    if (adapter != NULL) {
        adapter->now = now;
    }
}

void harness_adapter_arm(harness_adapter *adapter, uint8_t link, uint32_t id, int is_return,
                         uint32_t reply_to, uint8_t return_slot, uint32_t completion_delay_ms,
                         uint32_t delivery_delay_ms, int drop, uint8_t duplicates)
{
    if (adapter == NULL) {
        return;
    }
    memset(&adapter->arm, 0, sizeof adapter->arm);
    adapter->arm.active = 1;
    adapter->arm.link = link;
    adapter->arm.id = id;
    adapter->arm.is_return = is_return;
    adapter->arm.reply_to = reply_to;
    adapter->arm.return_slot = return_slot;
    adapter->arm.completion_delay_ms = completion_delay_ms;
    adapter->arm.delivery_delay_ms = delivery_delay_ms;
    adapter->arm.drop = drop;
    adapter->arm.duplicates = duplicates;
}

int harness_adapter_in_submit(const harness_adapter *adapter)
{
    return adapter != NULL && adapter->in_submit > 0;
}

const uint8_t *harness_adapter_borrowed(const harness_adapter *adapter, uint32_t id)
{
    uint32_t index;
    if (adapter == NULL || !find_sub(adapter, id, &index)) {
        return NULL;
    }
    return adapter->subs[index].borrow;
}

int harness_adapter_stored_byte(const harness_adapter *adapter, uint32_t id, uint8_t *byte)
{
    uint32_t index;
    if (adapter == NULL || byte == NULL || !find_sub(adapter, id, &index) ||
        adapter->subs[index].stored == NULL || adapter->subs[index].stored_len == 0U) {
        return 0;
    }
    *byte = adapter->subs[index].stored[0];
    return 1;
}

uint32_t harness_adapter_pending_local(const harness_adapter *adapter)
{
    return adapter == NULL ? 0U : adapter->pending_local;
}

uint32_t harness_adapter_pending_delivery(const harness_adapter *adapter)
{
    return adapter == NULL ? 0U : adapter->pending_delivery;
}

static int emit_run_start(harness_adapter *a)
{
    char line[256];
    snprintf(line, sizeof line,
             "{\"seq\":%u,\"time_ms\":0,\"event\":\"run_start\",\"interface_version\":1,"
             "\"manifest_sha256\":\"%s\",\"seed\":\"%s\",\"mode\":\"transport-selftest\",\"stress\":%s}",
             a->trace_seq, a->binding.sha256, a->binding.seed_text, a->binding.stress ? "true" : "false");
    return trace_write(a, line, 0);
}

static int emit_run_end(harness_adapter *a, const char *outcome, int exit_code, int stress)
{
    char line[640];
    snprintf(line, sizeof line,
             "{\"seq\":%u,\"time_ms\":%llu,\"event\":\"run_end\",\"outcome\":\"%s\",\"exit_code\":%d,"
             "\"stress\":%s,\"accepted\":%u,\"rejected\":%u,\"delivered\":%u,\"terminal\":%u,"
             "\"pending_local_at_horizon\":%u,\"pending_delivery_at_horizon\":%u,\"events\":%u}",
             a->trace_seq, (unsigned long long)a->now, outcome, exit_code, stress ? "true" : "false",
             a->accepted, a->rejected, a->delivered, a->terminal_count, a->pending_local,
             a->pending_delivery, a->executed);
    return trace_write(a, line, 1);
}

int harness_execute(const harness_binding *binding, harness_action *actions, size_t nactions,
                    harness_fault *faults, size_t nfaults, char *trace, size_t trace_cap,
                    harness_result *result)
{
    harness_adapter *a;
    uint32_t i;
    int unused = 0;
    const char *outcome = "completed";
    int exit_code = 0;
    int stress;
    if (result == NULL || binding == NULL || trace == NULL) {
        return -1;
    }
    memset(result, 0, sizeof *result);
    a = harness_adapter_create(binding);
    if (a == NULL) {
        result->exit_code = 4;
        snprintf(result->outcome, sizeof result->outcome, "internal_error");
        return -1;
    }
    a->trace = trace;
    a->trace_cap = trace_cap;
    a->faults = faults;
    a->nfaults = (uint32_t)nfaults;
    for (i = 0; i < a->nfaults; i++) {
        a->faults[i].used = 0;
    }
    if (nactions > 0U) {
        a->actions = malloc(nactions * sizeof *a->actions);
        if (a->actions == NULL) {
            harness_adapter_destroy(a);
            result->exit_code = 4;
            return -1;
        }
        memcpy(a->actions, actions, nactions * sizeof *a->actions);
        a->nactions = (uint32_t)nactions;
        qsort(a->actions, nactions, sizeof *a->actions, cmp_action);
    }
    if (!emit_run_start(a)) {
        outcome = "budget_exhausted";
        exit_code = 3;
    }
    for (i = 0; i < a->nactions && exit_code == 0; i++) {
        if (!queue_event(a, a->actions[i].at_ms, 2, EV_ACTION, i, 0)) {
            outcome = "budget_exhausted";
            exit_code = 3;
        }
    }
    if (exit_code == 0) {
        harness_adapter_run(a);
        if (a->budget) {
            outcome = "budget_exhausted";
            exit_code = 3;
        }
    }
    if (exit_code == 0) {
        for (i = 0; i < a->nfaults; i++) {
            if (!a->faults[i].used) {
                unused = 1;
            }
        }
        if (unused) {
            outcome = "invalid_input";
            exit_code = 2;
        }
    }
    stress = a->binding.stress;
    (void)unused;
    if (a->now < a->binding.until_ms && exit_code != 3) {
        a->now = a->binding.until_ms;
    }
    if (!emit_run_end(a, outcome, exit_code, stress)) {
        result->exit_code = 4;
        snprintf(result->outcome, sizeof result->outcome, "internal_error");
        harness_adapter_destroy(a);
        return -1;
    }
    result->exit_code = exit_code;
    snprintf(result->outcome, sizeof result->outcome, "%s", outcome);
    result->trace_len = a->trace_len;
    result->accepted = a->accepted;
    result->rejected = a->rejected;
    result->delivered = a->delivered;
    result->terminal = a->terminal_count;
    result->pending_local = a->pending_local;
    result->pending_delivery = a->pending_delivery;
    result->events = a->executed;
    if (a->trace_len < trace_cap) {
        trace[a->trace_len] = '\0';
    }
    harness_adapter_destroy(a);
    return 0;
}
