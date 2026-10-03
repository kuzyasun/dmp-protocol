#ifndef DMP_HARNESS_JSON_H
#define DMP_HARNESS_JSON_H

#include <stddef.h>
#include <stdint.h>

/* Bounded JSON DOM for manifest and scenario documents.
 * Integers are decimal JSON numbers with at most 20 digits. Floats, exponents,
 * NaN and Infinity are rejected. Object keys are decoded before duplicate checks.
 */

typedef struct json_arena json_arena;

typedef enum json_type {
    JSON_NULL = 0,
    JSON_BOOL,
    JSON_INT,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct json_value json_value;

struct json_value {
    json_type type;
    int boolean;
    int negative;
    int u64_ok;
    uint64_t u64;
    const char *text;
    size_t text_len;
    size_t codepoints;
    json_value **items;
    char **keys;
    size_t *key_lens;
    size_t count;
    size_t cap;
};

typedef struct json_error {
    const char *code;
    const char *path;
    const char *message;
} json_error;

json_arena *json_arena_create(size_t bytes);
void json_arena_destroy(json_arena *arena);

json_value *json_parse(json_arena *arena, const uint8_t *data, size_t length,
                       size_t max_depth, json_error *error);

const json_value *json_object_get(const json_value *object, const char *key);
const json_value *json_object_get_n(const json_value *object, const char *key, size_t key_len);
int json_text_eq(const char *text, size_t text_len, const char *literal);

#endif
