#include "dmp/stream.h"

#include <stdio.h>
#include <string.h>

/* These bytes are the structural core fixture also used by the core and stream
 * tests. Framing is produced by libdmp so the seed generator has no duplicate
 * Stream L/R encoder. */
static const uint8_t CORE[] = { 0x45U, 0x02U, 0xAAU, 0xBBU };

static int write_file(const char *path, const uint8_t *bytes, size_t size)
{
    FILE *file = fopen(path, "wb");
    int ok;
    if (file == NULL) {
        return 0;
    }
    ok = fwrite(bytes, 1U, size, file) == size;
    if (fclose(file) != 0) {
        ok = 0;
    }
    return ok;
}

int main(int argc, char **argv)
{
    uint8_t stream_l[32];
    uint8_t stream_r[32];
    size_t written_l = 0U;
    size_t written_r = 0U;
    static const uint8_t r_sync = 0U;
    uint8_t stream_r_seed[33];

    if (argc != 4) {
        (void)fprintf(stderr,
                      "usage: dmp_fuzz_seed_corpus <core-seed> <stream-l-seed> <stream-r-seed>\n");
        return 2;
    }
    if (dmp_stream_encode(DMP_STREAM_L, (dmp_bytes){ CORE, sizeof CORE },
                          (dmp_buffer){ stream_l, sizeof stream_l },
                          &written_l) != DMP_OK ||
        dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ CORE, sizeof CORE },
                          (dmp_buffer){ stream_r, sizeof stream_r },
                          &written_r) != DMP_OK ||
        written_r + 1U > sizeof stream_r_seed) {
        return 1;
    }
    memcpy(stream_r_seed, &r_sync, 1U);
    memcpy(stream_r_seed + 1U, stream_r, written_r);
    if (!write_file(argv[1], CORE, sizeof CORE) ||
        !write_file(argv[2], stream_l, written_l) ||
        !write_file(argv[3], stream_r_seed, written_r + 1U)) {
        (void)fprintf(stderr, "failed to write one or more fuzz corpus seeds\n");
        return 1;
    }
    return 0;
}
