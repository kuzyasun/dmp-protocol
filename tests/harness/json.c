#include "json.h"

#include <stdlib.h>
#include <string.h>

struct json_arena {
    char *base;
    size_t used;
    size_t cap;
    int failed;
};

json_arena *json_arena_create(size_t bytes)
{
    json_arena *arena = calloc(1, sizeof *arena);
    if (arena == NULL) {
        return NULL;
    }
    arena->base = calloc(1, bytes);
    if (arena->base == NULL) {
        free(arena);
        return NULL;
    }
    arena->cap = bytes;
    return arena;
}

void json_arena_destroy(json_arena *arena)
{
    if (arena == NULL) {
        return;
    }
    free(arena->base);
    free(arena);
}

static void *arena_alloc(json_arena *arena, size_t bytes, size_t align)
{
    size_t used;
    void *ptr;
    if (arena == NULL || arena->failed || align == 0U || bytes > arena->cap) {
        if (arena != NULL) {
            arena->failed = 1;
        }
        return NULL;
    }
    used = (arena->used + (align - 1U)) & ~(align - 1U);
    if (used > arena->cap || bytes > arena->cap - used) {
        arena->failed = 1;
        return NULL;
    }
    ptr = arena->base + used;
    arena->used = used + bytes;
    return ptr;
}

static char *arena_str(json_arena *arena, const char *text, size_t length)
{
    char *copy = arena_alloc(arena, length + 1U, 1U);
    if (copy == NULL) {
        return NULL;
    }
    if (length != 0U) {
        memcpy(copy, text, length);
    }
    copy[length] = '\0';
    return copy;
}

const json_value *json_object_get_n(const json_value *object, const char *key, size_t key_len)
{
    size_t i;
    if (object == NULL || object->type != JSON_OBJECT || key == NULL ||
        (object->count != 0U && object->key_lens == NULL)) {
        return NULL;
    }
    for (i = 0; i < object->count; i++) {
        if (object->key_lens[i] == key_len &&
            (key_len == 0U || memcmp(object->keys[i], key, key_len) == 0)) {
            return object->items[i];
        }
    }
    return NULL;
}

const json_value *json_object_get(const json_value *object, const char *key)
{
    if (key == NULL) {
        return NULL;
    }
    return json_object_get_n(object, key, strlen(key));
}

int json_text_eq(const char *text, size_t text_len, const char *literal)
{
    size_t literal_len;
    if (text == NULL || literal == NULL) {
        return 0;
    }
    literal_len = strlen(literal);
    return text_len == literal_len &&
           (literal_len == 0U || memcmp(text, literal, literal_len) == 0);
}

typedef struct parser {
    json_arena *arena;
    const uint8_t *data;
    size_t length;
    size_t index;
    size_t depth;
    size_t max_depth;
    json_error error;
    int failed;
} parser;

static void fail(parser *parser, const char *code, const char *message)
{
    if (parser->failed) {
        return;
    }
    parser->failed = 1;
    parser->error.code = code;
    parser->error.path = "$";
    parser->error.message = message;
}

static int utf8_document(const uint8_t *data, size_t length)
{
    size_t i = 0;
    while (i < length) {
        uint8_t c = data[i];
        size_t need = 0;
        uint32_t cp = 0;
        size_t j;
        if (c <= 0x7fU) {
            i++;
            continue;
        }
        if ((c & 0xe0U) == 0xc0U) {
            need = 2;
            cp = c & 0x1fU;
            if (c < 0xc2U) {
                return 0;
            }
        } else if ((c & 0xf0U) == 0xe0U) {
            need = 3;
            cp = c & 0x0fU;
        } else if ((c & 0xf8U) == 0xf0U) {
            need = 4;
            cp = c & 0x07U;
            if (c > 0xf4U) {
                return 0;
            }
        } else {
            return 0;
        }
        if (i + need > length) {
            return 0;
        }
        for (j = 1; j < need; j++) {
            if ((data[i + j] & 0xc0U) != 0x80U) {
                return 0;
            }
            cp = (cp << 6) | (data[i + j] & 0x3fU);
        }
        if ((need == 3U && cp < 0x800U) || (need == 4U && cp < 0x10000U) ||
            cp > 0x10ffffU || (cp >= 0xd800U && cp <= 0xdfffU)) {
            return 0;
        }
        if (need == 3U && data[i] == 0xe0U && data[i + 1] < 0xa0U) {
            return 0;
        }
        if (need == 4U && data[i] == 0xf0U && data[i + 1] < 0x90U) {
            return 0;
        }
        if (need == 4U && data[i] == 0xf4U && data[i + 1] > 0x8fU) {
            return 0;
        }
        i += need;
    }
    return 1;
}

static void skip_ws(parser *parser)
{
    while (parser->index < parser->length) {
        uint8_t c = parser->data[parser->index];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            break;
        }
        parser->index++;
    }
}

static int append_byte(parser *parser, char **buf, size_t *len, size_t *cap, char byte)
{
    if (*len + 1U >= *cap) {
        size_t next = *cap == 0U ? 32U : *cap * 2U;
        char *grown;
        while (next < *len + 2U) {
            if (next > (SIZE_MAX / 2U)) {
                fail(parser, "json", "string exceeds parser memory");
                return 0;
            }
            next *= 2U;
        }
        grown = arena_alloc(parser->arena, next, 1U);
        if (grown == NULL) {
            fail(parser, "json", "string exceeds parser memory");
            return 0;
        }
        if (*len != 0U) {
            memcpy(grown, *buf, *len);
        }
        *buf = grown;
        *cap = next;
    }
    (*buf)[(*len)++] = byte;
    return 1;
}

static int append_utf8(parser *parser, char **buf, size_t *len, size_t *cap, uint32_t cp)
{
    char tmp[4];
    size_t n = 0;
    size_t i;
    if (cp > 0x10ffffU || (cp >= 0xd800U && cp <= 0xdfffU)) {
        fail(parser, "encoding", "unpaired Unicode surrogate");
        return 0;
    }
    if (cp <= 0x7fU) {
        tmp[0] = (char)cp;
        n = 1;
    } else if (cp <= 0x7ffU) {
        tmp[0] = (char)(0xc0U | (cp >> 6));
        tmp[1] = (char)(0x80U | (cp & 0x3fU));
        n = 2;
    } else if (cp <= 0xffffU) {
        tmp[0] = (char)(0xe0U | (cp >> 12));
        tmp[1] = (char)(0x80U | ((cp >> 6) & 0x3fU));
        tmp[2] = (char)(0x80U | (cp & 0x3fU));
        n = 3;
    } else {
        tmp[0] = (char)(0xf0U | (cp >> 18));
        tmp[1] = (char)(0x80U | ((cp >> 12) & 0x3fU));
        tmp[2] = (char)(0x80U | ((cp >> 6) & 0x3fU));
        tmp[3] = (char)(0x80U | (cp & 0x3fU));
        n = 4;
    }
    for (i = 0; i < n; i++) {
        if (!append_byte(parser, buf, len, cap, tmp[i])) {
            return 0;
        }
    }
    return 1;
}

static int hex_value(int c)
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

static int parse_hex4(parser *parser, uint32_t *out)
{
    uint32_t value = 0;
    int i;
    for (i = 0; i < 4; i++) {
        int digit;
        if (parser->index >= parser->length) {
            fail(parser, "json", "truncated unicode escape");
            return 0;
        }
        digit = hex_value(parser->data[parser->index++]);
        if (digit < 0) {
            fail(parser, "json", "invalid unicode escape");
            return 0;
        }
        value = (value << 4) | (uint32_t)digit;
    }
    *out = value;
    return 1;
}

static json_value *parse_value(parser *parser);

static int grow_items(parser *parser, json_value *value)
{
    size_t next = value->cap == 0U ? 4U : value->cap * 2U;
    json_value **items = arena_alloc(parser->arena, next * sizeof *items, sizeof(void *));
    char **keys = NULL;
    if (items == NULL) {
        fail(parser, "json", "container exceeds parser memory");
        return 0;
    }
    if (value->count != 0U) {
        memcpy(items, value->items, value->count * sizeof *items);
    }
    if (value->type == JSON_OBJECT) {
        size_t *key_lens = arena_alloc(parser->arena, next * sizeof *key_lens, sizeof(size_t));
        keys = arena_alloc(parser->arena, next * sizeof *keys, sizeof(void *));
        if (keys == NULL || key_lens == NULL) {
            fail(parser, "json", "container exceeds parser memory");
            return 0;
        }
        if (value->count != 0U) {
            memcpy(keys, value->keys, value->count * sizeof *keys);
            memcpy(key_lens, value->key_lens, value->count * sizeof *key_lens);
        }
        value->keys = keys;
        value->key_lens = key_lens;
    }
    value->items = items;
    value->cap = next;
    return 1;
}

static json_value *parse_string(parser *parser)
{
    json_value *value;
    char *text = NULL;
    size_t len = 0;
    size_t cap = 0;
    size_t points = 0;
    parser->index++;
    while (parser->index < parser->length) {
        uint8_t c = parser->data[parser->index++];
        uint32_t cp;
        if (c == '"') {
            char *owned;
            if (text == NULL) {
                text = arena_str(parser->arena, "", 0);
                len = 0;
            } else {
                text[len] = '\0';
            }
            owned = text == NULL ? NULL : text;
            value = arena_alloc(parser->arena, sizeof *value, sizeof(void *));
            if (value == NULL || owned == NULL) {
                fail(parser, "json", "string exceeds parser memory");
                return NULL;
            }
            memset(value, 0, sizeof *value);
            value->type = JSON_STRING;
            value->text = owned;
            value->text_len = len;
            value->codepoints = points;
            return value;
        }
        if (c < 0x20U) {
            fail(parser, "json", "raw control character in string");
            return NULL;
        }
        if (c != '\\') {
            if (!append_byte(parser, &text, &len, &cap, (char)c)) {
                return NULL;
            }
            if ((c & 0xc0U) != 0x80U) {
                points++;
            }
            continue;
        }
        if (parser->index >= parser->length) {
            fail(parser, "json", "truncated escape");
            return NULL;
        }
        c = parser->data[parser->index++];
        if (c == '"' || c == '\\' || c == '/') {
            cp = c;
        } else if (c == 'b') {
            cp = '\b';
        } else if (c == 'f') {
            cp = '\f';
        } else if (c == 'n') {
            cp = '\n';
        } else if (c == 'r') {
            cp = '\r';
        } else if (c == 't') {
            cp = '\t';
        } else if (c == 'u') {
            if (!parse_hex4(parser, &cp)) {
                return NULL;
            }
            if (cp >= 0xd800U && cp <= 0xdbffU) {
                uint32_t low;
                if (parser->index + 1U >= parser->length ||
                    parser->data[parser->index] != '\\' ||
                    parser->data[parser->index + 1U] != 'u') {
                    fail(parser, "encoding", "unpaired Unicode surrogate");
                    return NULL;
                }
                parser->index += 2U;
                if (!parse_hex4(parser, &low)) {
                    return NULL;
                }
                if (low < 0xdc00U || low > 0xdfffU) {
                    fail(parser, "encoding", "unpaired Unicode surrogate");
                    return NULL;
                }
                cp = 0x10000U + (((cp - 0xd800U) << 10) | (low - 0xdc00U));
            } else if (cp >= 0xdc00U && cp <= 0xdfffU) {
                fail(parser, "encoding", "unpaired Unicode surrogate");
                return NULL;
            }
        } else {
            fail(parser, "json", "invalid escape");
            return NULL;
        }
        if (!append_utf8(parser, &text, &len, &cap, cp)) {
            return NULL;
        }
        points++;
    }
    fail(parser, "json", "unterminated string");
    return NULL;
}

static json_value *parse_number(parser *parser)
{
    size_t start = parser->index;
    size_t digits = 0;
    int negative = 0;
    json_value *value;
    uint64_t acc = 0;
    int overflow = 0;
    size_t i;
    if (parser->data[parser->index] == '-') {
        negative = 1;
        parser->index++;
        if (parser->index >= parser->length) {
            fail(parser, "json", "truncated number");
            return NULL;
        }
    }
    if (parser->data[parser->index] == '0') {
        digits = 1;
        parser->index++;
    } else if (parser->data[parser->index] >= '1' && parser->data[parser->index] <= '9') {
        while (parser->index < parser->length &&
               parser->data[parser->index] >= '0' && parser->data[parser->index] <= '9') {
            digits++;
            parser->index++;
        }
    } else {
        fail(parser, "json", "invalid number");
        return NULL;
    }
    if (parser->index < parser->length) {
        uint8_t c = parser->data[parser->index];
        if (c == '.' || c == 'e' || c == 'E') {
            fail(parser, "json", "only JSON integer numbers are allowed");
            return NULL;
        }
    }
    if (digits == 0U || digits > 20U) {
        fail(parser, "json", digits == 0U ? "invalid number" : "integer exceeds 20 digits");
        return NULL;
    }
    for (i = start + (size_t)negative; i < parser->index; i++) {
        uint64_t digit = (uint64_t)(parser->data[i] - '0');
        if (acc > (UINT64_MAX - digit) / 10U) {
            overflow = 1;
        } else {
            acc = acc * 10U + digit;
        }
    }
    value = arena_alloc(parser->arena, sizeof *value, sizeof(void *));
    if (value == NULL) {
        fail(parser, "json", "number exceeds parser memory");
        return NULL;
    }
    memset(value, 0, sizeof *value);
    value->type = JSON_INT;
    value->negative = negative && acc != 0U;
    value->u64_ok = !overflow;
    value->u64 = overflow ? 0U : acc;
    value->text = arena_str(parser->arena, (const char *)parser->data + start,
                            parser->index - start);
    value->text_len = parser->index - start;
    if (value->text == NULL) {
        fail(parser, "json", "number exceeds parser memory");
        return NULL;
    }
    return value;
}

static json_value *parse_literal(parser *parser, const char *literal, json_type type, int boolean)
{
    size_t n = strlen(literal);
    json_value *value;
    if (parser->index + n > parser->length ||
        memcmp(parser->data + parser->index, literal, n) != 0) {
        fail(parser, "json", "invalid literal");
        return NULL;
    }
    parser->index += n;
    value = arena_alloc(parser->arena, sizeof *value, sizeof(void *));
    if (value == NULL) {
        fail(parser, "json", "literal exceeds parser memory");
        return NULL;
    }
    memset(value, 0, sizeof *value);
    value->type = type;
    value->boolean = boolean;
    return value;
}

static int push_item(parser *parser, json_value *container, char *key, size_t key_len, json_value *item)
{
    size_t i;
    if (container->type == JSON_OBJECT) {
        for (i = 0; i < container->count; i++) {
            if (container->key_lens[i] == key_len &&
                (key_len == 0U || memcmp(container->keys[i], key, key_len) == 0)) {
                fail(parser, "json", "duplicate member");
                return 0;
            }
        }
    }
    if (container->count == container->cap && !grow_items(parser, container)) {
        return 0;
    }
    if (container->type == JSON_OBJECT) {
        container->keys[container->count] = key;
        container->key_lens[container->count] = key_len;
    }
    container->items[container->count++] = item;
    return 1;
}

static json_value *parse_container(parser *parser, int object)
{
    json_value *value = arena_alloc(parser->arena, sizeof *value, sizeof(void *));
    uint8_t end = object ? '}' : ']';
    if (value == NULL) {
        fail(parser, "json", "container exceeds parser memory");
        return NULL;
    }
    memset(value, 0, sizeof *value);
    value->type = object ? JSON_OBJECT : JSON_ARRAY;
    parser->index++;
    skip_ws(parser);
    if (parser->index < parser->length && parser->data[parser->index] == end) {
        parser->index++;
        return value;
    }
    while (!parser->failed) {
        char *key = NULL;
        size_t key_len = 0;
        json_value *item;
        if (parser->depth > parser->max_depth) {
            fail(parser, "json", "nesting exceeds 24 containers");
            return NULL;
        }
        if (object) {
            json_value *key_value;
            skip_ws(parser);
            if (parser->index >= parser->length || parser->data[parser->index] != '"') {
                fail(parser, "json", "object key must be a string");
                return NULL;
            }
            key_value = parse_string(parser);
            if (key_value == NULL) {
                return NULL;
            }
            key = arena_str(parser->arena, key_value->text, key_value->text_len);
            key_len = key_value->text_len;
            if (key == NULL) {
                fail(parser, "json", "object key exceeds parser memory");
                return NULL;
            }
            skip_ws(parser);
            if (parser->index >= parser->length || parser->data[parser->index] != ':') {
                fail(parser, "json", "missing colon");
                return NULL;
            }
            parser->index++;
        }
        item = parse_value(parser);
        if (item == NULL || !push_item(parser, value, key, key_len, item)) {
            return NULL;
        }
        skip_ws(parser);
        if (parser->index >= parser->length) {
            fail(parser, "json", "unterminated container");
            return NULL;
        }
        if (parser->data[parser->index] == ',') {
            parser->index++;
            continue;
        }
        if (parser->data[parser->index] == end) {
            parser->index++;
            return value;
        }
        fail(parser, "json", "malformed container");
        return NULL;
    }
    return NULL;
}

static json_value *parse_value(parser *parser)
{
    uint8_t c;
    skip_ws(parser);
    if (parser->index >= parser->length) {
        fail(parser, "json", "unexpected end");
        return NULL;
    }
    c = parser->data[parser->index];
    if (c == '{') {
        if (parser->depth >= parser->max_depth) {
            fail(parser, "json", "nesting exceeds 24 containers");
            return NULL;
        }
        parser->depth++;
        {
            json_value *value = parse_container(parser, 1);
            parser->depth--;
            return value;
        }
    }
    if (c == '[') {
        if (parser->depth >= parser->max_depth) {
            fail(parser, "json", "nesting exceeds 24 containers");
            return NULL;
        }
        parser->depth++;
        {
            json_value *value = parse_container(parser, 0);
            parser->depth--;
            return value;
        }
    }
    if (c == '"') {
        return parse_string(parser);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        return parse_number(parser);
    }
    if (c == 't') {
        return parse_literal(parser, "true", JSON_BOOL, 1);
    }
    if (c == 'f') {
        return parse_literal(parser, "false", JSON_BOOL, 0);
    }
    if (c == 'n') {
        return parse_literal(parser, "null", JSON_NULL, 0);
    }
    fail(parser, "json", "invalid JSON");
    return NULL;
}

json_value *json_parse(json_arena *arena, const uint8_t *data, size_t length,
                       size_t max_depth, json_error *error)
{
    parser parser;
    json_value *value;
    memset(&parser, 0, sizeof parser);
    parser.arena = arena;
    parser.data = data;
    parser.length = length;
    parser.max_depth = max_depth;
    if (arena == NULL || data == NULL) {
        if (error != NULL) {
            error->code = "json";
            error->path = "$";
            error->message = "missing input";
        }
        return NULL;
    }
    if (!utf8_document(data, length)) {
        if (error != NULL) {
            error->code = "encoding";
            error->path = "$";
            error->message = "invalid UTF-8";
        }
        return NULL;
    }
    value = parse_value(&parser);
    if (parser.failed || value == NULL) {
        if (error != NULL) {
            *error = parser.error;
            if (error->code == NULL) {
                error->code = "json";
                error->path = "$";
                error->message = "invalid JSON";
            }
        }
        return NULL;
    }
    skip_ws(&parser);
    if (parser.index != parser.length) {
        if (error != NULL) {
            error->code = "json";
            error->path = "$";
            error->message = "trailing JSON value";
        }
        return NULL;
    }
    if (arena->failed) {
        if (error != NULL) {
            error->code = "json";
            error->path = "$";
            error->message = "parser memory exhausted";
        }
        return NULL;
    }
    return value;
}
