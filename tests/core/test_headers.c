#include "dmp/base.h"
#include "dmp/core.h"
#include "dmp/integrity.h"
#include "dmp/stream.h"
#include "dmp/transport.h"

static dmp_status test_submit(void *context,
                              const dmp_tx_submission *submission)
{
    (void)context;
    (void)submission;
    return DMP_OK;
}

static dmp_status test_cancel(void *context, dmp_tx_token token)
{
    (void)context;
    (void)token;
    return DMP_OK;
}

static void test_complete(void *owner, dmp_tx_token token,
                          dmp_tx_outcome outcome, dmp_time_ms when)
{
    (void)owner;
    (void)token;
    (void)outcome;
    (void)when;
}

int main(void)
{
    dmp_transport transport = {
        .context = NULL,
        .caps = { 256U, DMP_TX_BORROW, false },
        .submit = test_submit,
        .cancel = test_cancel,
    };
    dmp_tx_complete_fn callback = test_complete;

    return (transport.submit == test_submit && transport.cancel == test_cancel &&
            callback == test_complete)
               ? 0
               : 1;
}
