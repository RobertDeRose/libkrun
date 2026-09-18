#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef struct fake_xpc *xpc_object_t;
xpc_object_t xpc_dictionary_create(const char *const *keys, const xpc_object_t *values, size_t count);
void xpc_dictionary_set_bool(xpc_object_t object, const char *key, bool value);
void xpc_dictionary_set_uint64(xpc_object_t object, const char *key, uint64_t value);
void xpc_dictionary_set_string(xpc_object_t object, const char *key, const char *value);
uint64_t xpc_dictionary_get_uint64(xpc_object_t object, const char *key);
void xpc_release(xpc_object_t object);
