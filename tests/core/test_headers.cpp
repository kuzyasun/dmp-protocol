#include "dmp/base.h"
#include "dmp/core.h"
#include "dmp/integrity.h"
#include "dmp/stream.h"
#include "dmp/transport.h"

int main()
{
    dmp_time_ms deadline = UINT64_C(99);
    uint64_t generation = 0U;

    if (dmp_deadline_after(UINT64_C(7), UINT64_C(0), &deadline) != DMP_OK ||
        deadline != UINT64_C(7)) {
        return 1;
    }
    if (dmp_generation_next(UINT64_C(0), &generation) != DMP_OK ||
        generation != UINT64_C(1)) {
        return 1;
    }
    return dmp_status_name(DMP_OK)[0] == 'o' ? 0 : 1;
}
