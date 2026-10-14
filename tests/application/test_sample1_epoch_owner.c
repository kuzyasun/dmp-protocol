#include "sample1_epoch_owner.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                                            \
    do {                                                                                       \
        if (!(expr)) {                                                                         \
            (void)fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #expr);    \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

typedef struct {
    bool entered;
    bool has_previous;
    bool borrowed_tx_pending;
    uint64_t previous;
    uint64_t next;
    dmp_sample1_port_result reserve_result;
    dmp_sample1_port_result fence_result;
    dmp_sample1_port_result activate_result;
    dmp_sample1_port_result association_result;
    dmp_sample1_port_result read_result;
    dmp_sample1_port_result publish_result;
    unsigned reserve_calls;
    unsigned fence_calls;
    unsigned activate_calls;
    unsigned association_calls;
    unsigned read_calls;
    unsigned publish_calls;
    uint64_t fenced_epoch;
    uint64_t activated_epoch;
    uint64_t association_epoch;
    uint64_t published_epoch;
    uint32_t published_index;
    uint32_t published_value;
    uint32_t read_status;
    size_t read_len;
    uint8_t read_payload[DMP_SAMPLE1_READ_BYTES];
    dmp_identity_handle read_association;
    dmp_message_key read_request;
    char events[32];
    size_t event_count;
} test_ports;

static void record(test_ports *test, char event)
{
    if (test->event_count < sizeof(test->events)) {
        test->events[test->event_count++] = event;
    }
}

static bool try_enter(void *user)
{
    test_ports *test = user;
    if (test->entered) {
        return false;
    }
    test->entered = true;
    return true;
}

static void leave(void *user)
{
    test_ports *test = user;
    test->entered = false;
}

static dmp_sample1_port_result reserve_next(void *user, dmp_sample1_principal principal,
                                             bool *has_previous, uint64_t *previous_epoch,
                                             uint64_t *reserved_epoch)
{
    test_ports *test = user;
    (void)principal;
    if (!test->entered || has_previous == NULL || previous_epoch == NULL ||
        reserved_epoch == NULL) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    test->reserve_calls++;
    record(test, 'R');
    if (test->reserve_result != DMP_SAMPLE1_PORT_ACCEPTED) {
        return test->reserve_result;
    }
    *has_previous = test->has_previous;
    *previous_epoch = test->has_previous ? test->previous : 0U;
    *reserved_epoch = test->next;
    test->has_previous = true;
    test->previous = test->next;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result fence_epoch(void *user, dmp_sample1_principal principal,
                                            uint64_t old_epoch)
{
    test_ports *test = user;
    (void)principal;
    if (!test->entered) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    test->fence_calls++;
    test->fenced_epoch = old_epoch;
    record(test, 'F');
    if (test->borrowed_tx_pending) {
        return DMP_SAMPLE1_PORT_BUSY;
    }
    return test->fence_result;
}

static dmp_sample1_port_result activate_epoch(void *user, dmp_sample1_principal principal,
                                                uint64_t new_epoch)
{
    test_ports *test = user;
    (void)principal;
    if (!test->entered) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    test->activate_calls++;
    test->activated_epoch = new_epoch;
    record(test, 'A');
    return test->activate_result;
}

static dmp_sample1_port_result activate_association(void *user,
                                                      dmp_sample1_principal principal,
                                                      dmp_identity_handle association,
                                                      uint64_t sample_epoch)
{
    test_ports *test = user;
    (void)principal;
    (void)association;
    if (!test->entered) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    test->association_calls++;
    test->association_epoch = sample_epoch;
    record(test, 'a');
    return test->association_result;
}

static dmp_sample1_port_result queue_read_result(void *user,
                                                  dmp_sample1_principal principal,
                                                  dmp_identity_handle association,
                                                  dmp_reliability_handle request_handle,
                                                  dmp_message_key request,
                                                  uint32_t wire_status,
                                                  const uint8_t *payload,
                                                  size_t payload_len)
{
    test_ports *test = user;
    (void)principal;
    (void)request_handle;
    if (!test->entered || payload_len > sizeof(test->read_payload) ||
        (payload_len != 0U && payload == NULL)) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    test->read_calls++;
    test->read_status = wire_status;
    test->read_len = payload_len;
    test->read_association = association;
    test->read_request = request;
    if (payload_len != 0U) {
        (void)memcpy(test->read_payload, payload, payload_len);
    }
    record(test, 'r');
    return test->read_result;
}

static dmp_sample1_port_result publish_telem(void *user,
                                              dmp_sample1_principal principal,
                                              uint64_t sample_epoch,
                                              uint32_t sample_index,
                                              const uint8_t payload[DMP_SAMPLE1_TELEM_BYTES])
{
    test_ports *test = user;
    (void)principal;
    if (!test->entered || payload == NULL) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    test->publish_calls++;
    test->published_epoch = sample_epoch;
    test->published_index = sample_index;
    test->published_value = (uint32_t)payload[12] | ((uint32_t)payload[13] << 8U) |
                            ((uint32_t)payload[14] << 16U) |
                            ((uint32_t)payload[15] << 24U);
    record(test, 'p');
    return test->publish_result;
}

static dmp_sample1_epoch_owner_ports make_ports(test_ports *test)
{
    dmp_sample1_epoch_owner_ports ports;
    (void)memset(&ports, 0, sizeof(ports));
    ports.user = test;
    ports.try_enter = try_enter;
    ports.leave = leave;
    ports.reserve_next = reserve_next;
    ports.fence_epoch = fence_epoch;
    ports.activate_epoch = activate_epoch;
    ports.activate_association = activate_association;
    ports.queue_read_result = queue_read_result;
    ports.publish_telem = publish_telem;
    return ports;
}

static void initialize_test(test_ports *test)
{
    (void)memset(test, 0, sizeof(*test));
    test->reserve_result = DMP_SAMPLE1_PORT_ACCEPTED;
    test->fence_result = DMP_SAMPLE1_PORT_ACCEPTED;
    test->activate_result = DMP_SAMPLE1_PORT_ACCEPTED;
    test->association_result = DMP_SAMPLE1_PORT_ACCEPTED;
    test->read_result = DMP_SAMPLE1_PORT_ACCEPTED;
    test->publish_result = DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_principal principal(void)
{
    dmp_sample1_principal value = {7U, 10U};
    return value;
}

static int test_restart_fence_snapshot_and_publication_order(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    dmp_identity_handle association = {2U, 9U};
    dmp_message_key request = {{1U, 10U, 3U}, 41U};
    test_ports test;

    initialize_test(&test);
    test.has_previous = true;
    test.previous = 7U;
    test.next = 8U;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_OK);
    CHECK(test.event_count == 3U && memcmp(test.events, "RFA", 3U) == 0);
    CHECK(test.fenced_epoch == 7U && test.activated_epoch == 8U);
    CHECK(owner.active && owner.epoch == 8U && !owner.have_sample);

    CHECK(dmp_sample1_epoch_owner_activate_association(&owner, association) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(test.association_epoch == 8U);
    CHECK(dmp_sample1_epoch_owner_publish(&owner, UINT32_C(0x01020304), 0U) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(owner.sample_index == 1U && owner.sample_value == UINT32_C(0x01020304));
    CHECK(test.published_epoch == 8U && test.published_index == 1U);
    CHECK(test.published_value == UINT32_C(0x01020304));

    CHECK(dmp_sample1_epoch_owner_accept_read(&owner, association,
                                              (dmp_reliability_handle){0}, request, 0U) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(test.read_status == 0U && test.read_len == DMP_SAMPLE1_READ_BYTES);
    CHECK(test.read_association.slot == association.slot &&
          test.read_association.generation == association.generation);
    CHECK(test.read_request.seq == request.seq &&
          test.read_request.origin.origin_id == request.origin.origin_id);
    CHECK(test.read_payload[0] == DMP_SAMPLE1_READ_OPCODE);
    CHECK(test.read_payload[1] == 8U && test.read_payload[9] == 1U);
    CHECK(test.read_payload[13] == 4U && test.read_payload[14] == 3U &&
          test.read_payload[15] == 2U && test.read_payload[16] == 1U);
    CHECK(!test.entered);
    CHECK(test.event_count == 6U && memcmp(test.events, "RFAapr", 6U) == 0);
    return 0;
}

static int test_first_boot_no_sample_read(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    dmp_identity_handle association = {0U, 1U};
    dmp_message_key request = {{1U, 22U, 4U}, 2U};
    test_ports test;

    initialize_test(&test);
    test.next = 1U;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_OK);
    CHECK(test.event_count == 2U && memcmp(test.events, "RA", 2U) == 0);
    CHECK(test.fence_calls == 0U && owner.epoch == 1U);
    test.entered = true;
    CHECK(dmp_sample1_epoch_owner_publish(&owner, 123U, 0U) == DMP_SAMPLE1_OWNER_BUSY);
    CHECK(test.publish_calls == 0U && test.event_count == 2U);
    test.entered = false;
    CHECK(dmp_sample1_epoch_owner_accept_read(&owner, association,
                                              (dmp_reliability_handle){0}, request, 0U) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(test.read_status == DMP_SAMPLE1_NO_SAMPLE_STATUS && test.read_len == 0U);
    CHECK(test.event_count == 3U && test.events[2] == 'r');
    CHECK(!test.entered);
    return 0;
}

static int test_fence_failure_stops_before_activation(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    test_ports test;

    initialize_test(&test);
    test.has_previous = true;
    test.previous = 12U;
    test.next = 13U;
    test.fence_result = DMP_SAMPLE1_PORT_UNKNOWN;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(owner.stopped && !owner.active && owner.epoch == 0U);
    CHECK(test.event_count == 2U && memcmp(test.events, "RF", 2U) == 0);
    CHECK(test.activate_calls == 0U);
    CHECK(dmp_sample1_epoch_owner_publish(&owner, 99U, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(test.publish_calls == 0U && !test.entered);
    return 0;
}

static int test_retryable_fence_busy_reserves_once(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    test_ports test;

    initialize_test(&test);
    test.has_previous = true;
    test.previous = 12U;
    test.next = 13U;
    test.fence_result = DMP_SAMPLE1_PORT_BUSY;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 1U) == DMP_SAMPLE1_OWNER_BUSY);
    CHECK(!owner.stopped && !owner.active &&
          owner.transition_state == DMP_SAMPLE1_TRANSITION_RESERVED);
    CHECK(owner.epoch == 0U && owner.transition_reserved_epoch == 13U);
    CHECK(test.reserve_calls == 1U && test.fence_calls == 1U &&
          test.activate_calls == 0U);

    test.fence_result = DMP_SAMPLE1_PORT_ACCEPTED;
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 2U) == DMP_SAMPLE1_OWNER_OK);
    CHECK(owner.active && owner.epoch == 13U &&
          owner.transition_state == DMP_SAMPLE1_TRANSITION_IDLE);
    CHECK(test.reserve_calls == 1U && test.fence_calls == 2U &&
          test.activate_calls == 1U);
    CHECK(test.event_count == 4U && memcmp(test.events, "RFFA", 4U) == 0);
    CHECK(!test.entered);
    return 0;
}

static int test_read_during_epoch_transition_is_retried_after_activation(void)
{
    const dmp_sample1_transition_state transition_states[] = {
        DMP_SAMPLE1_TRANSITION_RESERVED,
        DMP_SAMPLE1_TRANSITION_FENCED,
    };
    dmp_identity_handle association = {1U, 2U};
    dmp_reliability_handle request_handle = {3U, 4U, {0U, 1U}};
    dmp_message_key request = {{7U, 10U, 3U}, 41U};
    size_t i;

    for (i = 0U; i < sizeof transition_states / sizeof transition_states[0]; ++i) {
        dmp_sample1_epoch_owner owner;
        dmp_sample1_epoch_owner_ports ports;
        test_ports test;

        initialize_test(&test);
        test.has_previous = true;
        test.previous = 12U;
        test.next = 13U;
        test.fence_result = transition_states[i] == DMP_SAMPLE1_TRANSITION_RESERVED
                                ? DMP_SAMPLE1_PORT_BUSY
                                : DMP_SAMPLE1_PORT_ACCEPTED;
        test.activate_result = transition_states[i] == DMP_SAMPLE1_TRANSITION_FENCED
                                   ? DMP_SAMPLE1_PORT_BUSY
                                   : DMP_SAMPLE1_PORT_ACCEPTED;
        ports = make_ports(&test);
        CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
              DMP_SAMPLE1_OWNER_OK);

        CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 1U) == DMP_SAMPLE1_OWNER_BUSY);
        CHECK(!owner.stopped && !owner.active && owner.epoch == 0U &&
              owner.transition_state == transition_states[i] &&
              owner.transition_reserved_epoch == 13U);
        CHECK(test.read_calls == 0U && !test.entered);

        CHECK(dmp_sample1_epoch_owner_accept_read(&owner, association, request_handle,
                                                  request, 2U) ==
              DMP_SAMPLE1_OWNER_NOT_READY);
        CHECK(dmp_sample1_epoch_owner_activate_association(&owner, association) ==
              DMP_SAMPLE1_OWNER_NOT_READY);
        CHECK(!owner.stopped && !owner.active && owner.epoch == 0U &&
              owner.transition_state == transition_states[i] &&
              owner.transition_reserved_epoch == 13U);
        CHECK(test.read_calls == 0U && test.association_calls == 0U && !test.entered);

        test.fence_result = DMP_SAMPLE1_PORT_ACCEPTED;
        test.activate_result = DMP_SAMPLE1_PORT_ACCEPTED;
        CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 3U) == DMP_SAMPLE1_OWNER_OK);
        CHECK(owner.active && !owner.stopped && owner.epoch == 13U &&
              owner.transition_state == DMP_SAMPLE1_TRANSITION_IDLE);
        CHECK(dmp_sample1_epoch_owner_activate_association(&owner, association) ==
              DMP_SAMPLE1_OWNER_OK);
        CHECK(test.association_calls == 1U && test.association_epoch == 13U);
        CHECK(dmp_sample1_epoch_owner_publish(&owner, UINT32_C(0xAABBCCDD), 4U) ==
              DMP_SAMPLE1_OWNER_OK);
        CHECK(dmp_sample1_epoch_owner_accept_read(&owner, association, request_handle,
                                                  request, 5U) == DMP_SAMPLE1_OWNER_OK);
        CHECK(test.read_calls == 1U && test.read_status == 0U &&
              test.read_len == DMP_SAMPLE1_READ_BYTES);
        CHECK(test.read_payload[0] == DMP_SAMPLE1_READ_OPCODE &&
              test.read_payload[1] == 13U && test.read_payload[9] == 1U &&
              test.read_payload[13] == 0xDDU && test.read_payload[14] == 0xCCU &&
              test.read_payload[15] == 0xBBU && test.read_payload[16] == 0xAAU);
        CHECK(!test.entered);
    }
    return 0;
}

static int test_retryable_read_results_do_not_stop_owner(void)
{
    const dmp_sample1_port_result outcomes[] = {
        DMP_SAMPLE1_PORT_BUSY,
        DMP_SAMPLE1_PORT_REJECTED,
    };
    const dmp_sample1_owner_result expected[] = {
        DMP_SAMPLE1_OWNER_BUSY,
        DMP_SAMPLE1_OWNER_NOT_READY,
    };
    dmp_identity_handle association = {1U, 2U};
    dmp_reliability_handle request_handle = {3U, 4U, {0U, 1U}};
    dmp_message_key request = {{7U, 10U, 3U}, 41U};
    size_t i;

    for (i = 0U; i < sizeof outcomes / sizeof outcomes[0]; ++i) {
        dmp_sample1_epoch_owner owner;
        dmp_sample1_epoch_owner_ports ports;
        test_ports test;

        initialize_test(&test);
        test.next = 8U;
        ports = make_ports(&test);
        CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
              DMP_SAMPLE1_OWNER_OK);
        CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) ==
              DMP_SAMPLE1_OWNER_OK);
        CHECK(dmp_sample1_epoch_owner_publish(&owner, 99U, 1U) ==
              DMP_SAMPLE1_OWNER_OK);

        test.read_result = outcomes[i];
        CHECK(dmp_sample1_epoch_owner_accept_read(
                  &owner, association, request_handle, request, 2U) == expected[i]);
        CHECK(owner.active && !owner.stopped && owner.epoch == 8U &&
              owner.sample_index == 1U && test.read_calls == 1U && !test.entered);

        /* A transient queue condition or stale binding must not poison a
         * usable epoch; publication can resume after the caller retries. */
        CHECK(dmp_sample1_epoch_owner_publish(&owner, 100U, 3U) ==
              DMP_SAMPLE1_OWNER_OK);
        CHECK(owner.active && !owner.stopped && owner.sample_index == 2U &&
              owner.sample_value == 100U && test.publish_calls == 2U &&
              !test.entered);
    }
    return 0;
}

static int test_rollback_and_exhaustion_fail_closed(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    test_ports test;

    initialize_test(&test);
    test.has_previous = true;
    test.previous = 50U;
    test.next = 49U;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(owner.stopped && test.fence_calls == 0U && test.activate_calls == 0U);

    initialize_test(&test);
    test.next = UINT64_MAX;
    test.reserve_result = DMP_SAMPLE1_PORT_FAILED;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(owner.stopped && test.fence_calls == 0U && test.activate_calls == 0U);
    CHECK(!test.entered);
    return 0;
}

static int test_uncertain_reserve_activation_read_and_publish_stop(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    dmp_identity_handle association = {1U, 2U};
    dmp_message_key request = {{1U, 10U, 2U}, 5U};
    test_ports test;

    initialize_test(&test);
    test.next = 1U;
    test.reserve_result = DMP_SAMPLE1_PORT_UNKNOWN;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(owner.stopped && test.activate_calls == 0U);

    initialize_test(&test);
    test.next = 4U;
    test.activate_result = DMP_SAMPLE1_PORT_UNKNOWN;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(owner.stopped && !owner.active);
    CHECK(dmp_sample1_epoch_owner_activate_association(&owner, association) ==
          DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(test.association_calls == 0U);

    initialize_test(&test);
    test.next = 4U;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_OK);
    test.read_result = DMP_SAMPLE1_PORT_UNKNOWN;
    CHECK(dmp_sample1_epoch_owner_accept_read(&owner, association,
                                              (dmp_reliability_handle){0}, request, 0U) ==
          DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(owner.stopped && !owner.active);
    CHECK(dmp_sample1_epoch_owner_publish(&owner, 1U, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(test.publish_calls == 0U && !test.entered);

    initialize_test(&test);
    test.next = 4U;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_OK);
    test.publish_result = DMP_SAMPLE1_PORT_UNKNOWN;
    CHECK(dmp_sample1_epoch_owner_publish(&owner, 1U, 0U) == DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(owner.stopped && !owner.active && owner.sample_index == 0U);
    CHECK(dmp_sample1_epoch_owner_activate_association(&owner, association) ==
          DMP_SAMPLE1_OWNER_STOPPED);
    CHECK(test.association_calls == 0U && !test.entered);
    return 0;
}

static int test_index_exhaustion_rotates_before_publication(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    test_ports test;

    initialize_test(&test);
    test.next = 40U;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_OK);
    owner.sample_index = UINT32_MAX;
    test.next = 41U;
    CHECK(dmp_sample1_epoch_owner_publish(&owner, 7U, 0U) == DMP_SAMPLE1_OWNER_OK);
    CHECK(owner.epoch == 41U && owner.sample_index == 1U && owner.sample_value == 7U);
    CHECK(test.fence_calls == 1U && test.fenced_epoch == 40U);
    CHECK(test.activated_epoch == 41U && test.published_epoch == 41U);
    CHECK(test.published_index == 1U);
    if (test.event_count != 6U || memcmp(test.events, "RARFAp", 6U) != 0) {
        (void)fprintf(stderr, "epoch rollover event order: count=%zu events=%.*s\n",
                      test.event_count, (int)test.event_count, test.events);
        return 1;
    }
    CHECK(!test.entered);
    return 0;
}

static int test_rollover_fence_busy_retries_publish_without_reserving_again(void)
{
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    test_ports test;
    unsigned rollover_reservations;

    initialize_test(&test);
    test.next = 40U;
    ports = make_ports(&test);
    CHECK(dmp_sample1_epoch_owner_init(&owner, principal(), &ports) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_epoch_owner_begin_epoch(&owner, 0U) == DMP_SAMPLE1_OWNER_OK);
    owner.sample_index = UINT32_MAX;
    test.next = 41U;
    test.borrowed_tx_pending = true;

    CHECK(dmp_sample1_epoch_owner_publish(&owner, 99U, 1U) == DMP_SAMPLE1_OWNER_BUSY);
    rollover_reservations = test.reserve_calls;
    CHECK(rollover_reservations == 2U);
    CHECK(!owner.stopped && !owner.active &&
          owner.transition_state == DMP_SAMPLE1_TRANSITION_RESERVED);
    CHECK(owner.transition_reserved_epoch == 41U);
    CHECK(test.fence_calls == 1U && test.activate_calls == 1U &&
          test.publish_calls == 0U);

    /* The borrowed TX reaches its terminal callback, so fencing can complete. */
    test.borrowed_tx_pending = false;
    CHECK(dmp_sample1_epoch_owner_publish(&owner, 7U, 2U) == DMP_SAMPLE1_OWNER_OK);
    CHECK(test.reserve_calls == rollover_reservations);
    CHECK(owner.active && owner.epoch == 41U && owner.sample_index == 1U &&
          owner.sample_value == 7U);
    CHECK(test.fence_calls == 2U && test.activated_epoch == 41U);
    CHECK(test.publish_calls == 1U && test.published_epoch == 41U &&
          test.published_index == 1U && test.published_value == 7U);
    CHECK(!test.entered);
    return 0;
}

int main(void)
{
    if (test_restart_fence_snapshot_and_publication_order() != 0 ||
        test_first_boot_no_sample_read() != 0 ||
        test_fence_failure_stops_before_activation() != 0 ||
        test_retryable_fence_busy_reserves_once() != 0 ||
        test_read_during_epoch_transition_is_retried_after_activation() != 0 ||
        test_retryable_read_results_do_not_stop_owner() != 0 ||
        test_rollback_and_exhaustion_fail_closed() != 0 ||
        test_uncertain_reserve_activation_read_and_publish_stop() != 0 ||
        test_index_exhaustion_rotates_before_publication() != 0 ||
        test_rollover_fence_busy_retries_publish_without_reserving_again() != 0) {
        return 1;
    }
    (void)puts("SAMPLE-1 epoch owner tests passed");
    return 0;
}
