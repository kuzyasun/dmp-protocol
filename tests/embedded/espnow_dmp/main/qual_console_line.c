#include "qual_console_line.h"

#include <string.h>

void dmp_qual_console_line_reader_init(dmp_qual_console_line_reader *reader)
{
    if (reader != NULL) {
        memset(reader, 0, sizeof(*reader));
    }
}

dmp_qual_console_line_result dmp_qual_console_line_reader_feed(
    dmp_qual_console_line_reader *reader, uint8_t byte,
    char output[DMP_QUAL_CONSOLE_LINE_CAPACITY])
{
    if (reader == NULL || output == NULL) {
        return DMP_QUAL_CONSOLE_LINE_INVALID;
    }

    if (byte == (uint8_t)'\r' || byte == (uint8_t)'\n') {
        dmp_qual_console_line_result result;
        if (reader->discarding != 0U) {
            result = DMP_QUAL_CONSOLE_LINE_TOO_LONG;
        } else if (reader->pending_length == 0U) {
            result = DMP_QUAL_CONSOLE_LINE_EMPTY;
        } else {
            reader->pending[reader->pending_length] = '\0';
            memcpy(output, reader->pending, reader->pending_length + 1U);
            result = DMP_QUAL_CONSOLE_LINE_READY;
        }
        reader->pending_length = 0U;
        reader->discarding = 0U;
        reader->pending[0] = '\0';
        return result;
    }

    if (reader->discarding != 0U) {
        return DMP_QUAL_CONSOLE_LINE_PENDING;
    }
    if (reader->pending_length + 1U >= sizeof(reader->pending)) {
        reader->pending_length = 0U;
        reader->pending[0] = '\0';
        reader->discarding = 1U;
        return DMP_QUAL_CONSOLE_LINE_PENDING;
    }

    reader->pending[reader->pending_length++] = (char)byte;
    reader->pending[reader->pending_length] = '\0';
    return DMP_QUAL_CONSOLE_LINE_PENDING;
}
