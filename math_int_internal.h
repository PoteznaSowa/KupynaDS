/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_INT_H
#define CRYPTONITE_MATH_INT_H

#include <stdbool.h>

#include "word_internal.h"
#include "prng.h"

#define WORD_MASK (word_t)(-1)
#define MAX_WORD (dword_t)((dword_t)WORD_MASK + 1)

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Dword_st {
	word_t lo;
	word_t hi;
} Dword;

bool int_is_zero(const WordArray *a);

bool int_is_one(const WordArray *a);

bool int_equals(const WordArray *a, const WordArray *b);

int int_cmp(const WordArray *a, const WordArray *b);

word_t int_add(const WordArray *a, const WordArray *b, WordArray *out);

int int_sub(const WordArray *a, const WordArray *b, WordArray *out);

size_t int_word_len(const WordArray *a);

size_t int_bit_len(const WordArray *a);

void int_truncate(WordArray *a, size_t bit_len);

int int_get_bit(const WordArray *a, size_t bit_num);

void int_lshift(const WordArray *a, size_t shift, WordArray *out);

void int_rshift(word_t a_hi, const WordArray *a, size_t shift, WordArray *out);

void int_mul(const WordArray *a, const WordArray *b, WordArray *out);

void int_sqr(const WordArray *a, WordArray *out);

void int_div(const WordArray *a, const WordArray *b, WordArray *q, WordArray *r);

void int_sqrt(const WordArray *in, WordArray *out);

int int_rand(PrngCtx *prng, const WordArray *in, WordArray *out);
int int_prand(const WordArray *in, WordArray *out);

int int_is_prime(WordArray *a, bool *is_prime);

int int_rabin_miller_primary_test(WordArray *num, bool *is_prime);

int int_fermat_primary_test(WordArray *num, bool *is_prime);

void factorial(int n, WordArray *fac);

int int_mult_and_div(const WordArray *a, word_t b, word_t c, int n, WordArray *abc);

int int_get_naf(const WordArray *in, int width, int **out);

int int_get_naf_extra_add(const WordArray *in, const int *naf, int width, int *extra_addition);

int int_gen_prime(const size_t bits, PrngCtx *prng, WordArray **out);

#ifdef  __cplusplus
}
#endif

#endif
