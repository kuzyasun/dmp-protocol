#ifndef DMP_QUAL_CONSOLE_LINE_H
#define DMP_QUAL_CONSOLE_LINE_H

#include <stddef.h>
#include <stdint.h>

#define DMP_QUAL_CONSOLE_LINE_CAPACITY 128U

typedef struct dmp_qual_console_line_reader {
    char pending[DMP_QUAL_CONSOLE_LINE_CAPACITY];
    size_t pending_length;
    uint8_t discarding;
} dmp_qual_console_line_reader;

typedef enum dmp_qual_console_line_result {
    DMP_QUAL_CONSOLE_LINE_PENDING = 0,
    DMP_QUAL_CONSOLE_LINE_READY,
    DMP_QUAL_CONSOLE_LINE_EMPTY,
    DMP_QUAL_CONSOLE_LINE_TOO_LONG,
    DMP_QUAL_CONSOLE_LINE_INVALID
} dmp_qual_console_line_result;

void dmp_qual_console_line_reader_init(dmp_qual_console_line_reader *reader);
dmp_qual_console_line_result dmp_qual_console_line_reader_feed(
    dmp_qual_console_line_reader *reader, uint8_t byte,
    char output[DMP_QUAL_CONSOLE_LINE_CAPACITY]);

#endif
