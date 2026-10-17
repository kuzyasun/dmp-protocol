#include "qual_console_line.h"

#include <stdio.h>
#include <string.h>

static int test_fragmented_peer_line(void)
{
    static const uint8_t first[] = "PEER 94:a9:90:7b:ef:00 20";
    static const uint8_t second[] = "\n";
    dmp_qual_console_line_reader reader;
    char output[DMP_QUAL_CONSOLE_LINE_CAPACITY] = {0};

    dmp_qual_console_line_reader_init(&reader);
    for (size_t index = 0U; index < sizeof(first) - 1U; ++index) {
        if (dmp_qual_console_line_reader_feed(&reader, first[index], output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING) {
            return 0;
        }
    }
    if (dmp_qual_console_line_reader_feed(&reader, second[0], output) !=
            DMP_QUAL_CONSOLE_LINE_READY ||
        strcmp(output, "PEER 94:a9:90:7b:ef:00 20") != 0) {
        return 0;
    }
    return 1;
}

static int test_crlf_and_empty_line(void)
{
    dmp_qual_console_line_reader reader;
    char output[DMP_QUAL_CONSOLE_LINE_CAPACITY] = {0};

    dmp_qual_console_line_reader_init(&reader);
    if (dmp_qual_console_line_reader_feed(&reader, (uint8_t)'I', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'N', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'F', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'O', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'\r', output) !=
            DMP_QUAL_CONSOLE_LINE_READY ||
        strcmp(output, "INFO") != 0 ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'\n', output) !=
            DMP_QUAL_CONSOLE_LINE_EMPTY) {
        return 0;
    }
    return 1;
}

static int test_overlong_line_is_discarded_until_terminator(void)
{
    dmp_qual_console_line_reader reader;
    char output[DMP_QUAL_CONSOLE_LINE_CAPACITY] = {0};

    dmp_qual_console_line_reader_init(&reader);
    for (size_t index = 0U; index < DMP_QUAL_CONSOLE_LINE_CAPACITY; ++index) {
        if (dmp_qual_console_line_reader_feed(&reader, (uint8_t)'A', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING) {
            return 0;
        }
    }
    if (dmp_qual_console_line_reader_feed(&reader, (uint8_t)'\n', output) !=
        DMP_QUAL_CONSOLE_LINE_TOO_LONG) {
        return 0;
    }
    if (dmp_qual_console_line_reader_feed(&reader, (uint8_t)'I', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'N', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'F', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'O', output) !=
            DMP_QUAL_CONSOLE_LINE_PENDING ||
        dmp_qual_console_line_reader_feed(&reader, (uint8_t)'\n', output) !=
            DMP_QUAL_CONSOLE_LINE_READY ||
        strcmp(output, "INFO") != 0) {
        return 0;
    }
    return 1;
}

int main(void)
{
    if (!test_fragmented_peer_line() || !test_crlf_and_empty_line() ||
        !test_overlong_line_is_discarded_until_terminator()) {
        (void)fprintf(stderr, "qualification console line test failed\n");
        return 1;
    }
    (void)puts("qualification console line tests passed");
    return 0;
}
