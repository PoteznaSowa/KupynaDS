/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_BYTE_ARRAY_H
#define CRYPTONITE_BYTE_ARRAY_H

#include <stdint.h>
#include <stdio.h>

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст масиву байт.
 */
typedef struct ByteArray_st ByteArray;

/**
 * Створює контекст масиву байт.
 *
 * @return контекст масиву байт
 */
ByteArray *ba_alloc(void);

/**
 * Створює контекст масиву байт.
 *
 * @param len розмір масиву байт
 * @return контекст масиву байт
 */
ByteArray *ba_alloc_by_len(size_t len);

/**
 * Створює контекст масиву байт.
 *
 * @param buf массив байт
 * @param buf_len розмір масиву байт
 * @return контекст масиву байт
 */
ByteArray *ba_alloc_from_uint8(const uint8_t *buf, size_t buf_len);

/**
 * Створює контекст масиву байт з файлу.
 *
 * @param path шлях до файлу
 * @param out  контекст масиву байт
 * @return код помилки
 */
int ba_alloc_from_file(const char *path, ByteArray **out);

/**
 * Створює контекст масиву байт з файлу.
 *
 * @param path шлях до файлу
 * @return контекст масиву байт
 */
ByteArray *ba_alloc_from_stream(FILE *path);


ByteArray *ba_alloc_from_str(const char *buf);
ByteArray *ba_copy_with_alloc(const ByteArray *in, size_t off, size_t len);

int ba_swap(const ByteArray *a);
int ba_xor(const ByteArray *a, const ByteArray *b);
int ba_print(FILE *stream, const ByteArray *ba);

int ba_set(ByteArray *a, uint8_t value);

ByteArray *ba_alloc_from_le_hex_string(const char *data);
/**
 * Створює контекст масиву байт за двома іншими.
 *
 * @param a контекст масиву байт
 * @param b контекст масиву байт
 * @return контекст масиву байт
 */
ByteArray *ba_join(const ByteArray *a, const ByteArray *b);

int ba_cmp(const ByteArray *a, const ByteArray *b);

/**
 * Повертає розмір даних, які зберігають контекст масиву байт.
 *
 * @param ba контекст масиву байт
 * @return розмір даних, які зберігають контекст масиву байт.
 */
size_t ba_get_len(const ByteArray *ba);

/**
 * Повертає вказівник на дані, які зберігають контекст масиву байт.
 *
 * @param ba контекст масиву байт
 * @return вказівник на дані, які зберігають контекст масиву байт
 */
const uint8_t *ba_get_buf(const ByteArray *ba);

/**
 * Зберігає дані у існуючий контекст масиву байт.
 *
 * @param buf массив байт
 * @param buf_len розмір масиву байт
 * @param ba контекст масиву байт
 * @return код помилки
 */
int ba_from_uint8(const uint8_t *buf, size_t buf_len, ByteArray *ba);

/**
 * Повертає дані, які зберігають контекст масиву байт.
 * Виділяє пам'ять.
 *
 * @param ba контекст масиву байт
 * @param buf массив байт
 * @param buf_len розмір масиву байт
 * @return код помилки
 */
int ba_to_uint8_with_alloc(const ByteArray *ba, uint8_t **buf, size_t *buf_len);

/**
 * Повертає дані, які зберігають контекст масиву байт.
 * Не виділяє пам'ять.
 *
 * @param ba контекст масиву байт
 * @param buf массив байт
 * @param buf_len розмір масиву байт
 * @return код помилки
 */
int ba_to_uint8(const ByteArray *ba, uint8_t *buf, size_t buf_len);

/**
 * Записує дані у файл, які зберігають контекст масиву байт.
 * Не виділяє пам'ять.
 *
 * @param ba   контекст масиву байт
 * @param path шлях до файлу
 * @return код помилки
 */
int ba_to_file(const ByteArray *ba, const char *path);

int ba_copy(const ByteArray *in, size_t in_off, size_t len, ByteArray *out, size_t out_off);

int ba_append(const ByteArray *in, size_t in_off, size_t len, ByteArray *out);

int ba_change_len(ByteArray *ba, size_t len);

/**
 * Звільняє контекст масиву байт.
 *
 * @param ba контекст масиву байт
 */
void ba_free(ByteArray *ba);

void ba_free_private(ByteArray *ba);

#ifdef  __cplusplus
}
#endif

#endif
