/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_BYTE_ARRAY_INTERNAL_H
#define CRYPTONITE_BYTE_ARRAY_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ByteArray_st {
	uint8_t *buf;
	size_t len;
};

ByteArray *ba_alloc_from_uint8_be(const uint8_t *buf, size_t buf_len);

ByteArray *ba_alloc_from_uint64(const uint64_t *buf, size_t buf_len);

int ba_to_uint64_with_alloc(const ByteArray *ba, uint64_t **buf, size_t *buf_len);

int ba_to_uint32(const ByteArray *ba, uint32_t *buf, size_t buf_len);
int ba_from_uint32(const uint32_t *buf, size_t buf_len, ByteArray *ba);
ByteArray *ba_alloc_from_uint32(const uint32_t *buf, size_t buf_len);
int ba_to_uint64(const ByteArray *ba, uint64_t *buf, size_t buf_len);
int ba_from_uint64(const uint64_t *buf, size_t buf_len, ByteArray *ba);
int ba_to_uint64(const ByteArray *ba, uint64_t *buf, size_t buf_len);
int ba_trim_leading_zeros(ByteArray *ba);
int ba_truncate(ByteArray *a, size_t bit_len);
bool ba_is_zero(const ByteArray *a);

#ifdef  __cplusplus
}
#endif

#endif
