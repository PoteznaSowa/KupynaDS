/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_GF2M_H
#define CRYPTONITE_MATH_GF2M_H

#include <stdbool.h>
#include "word_internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct Gf2mCtx_st {
	int *f;
	WordArray *f_ext;
	size_t len;
} Gf2mCtx;

Gf2mCtx *gf2m_alloc(const int *f, size_t f_len);

void gf2m_mod_add(const WordArray *a, const WordArray *b, WordArray *out);

void gf2m_mod_sqr(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

void gf2m_mod_mul(const Gf2mCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);

void gf2m_mod_inv(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

void gf2m_mod_gcd(const WordArray *a, const WordArray *b, WordArray *gcd, WordArray *ka, WordArray *kb);

int gf2m_mod_trace(const Gf2mCtx *ctx, const WordArray *a);

bool gf2m_mod_solve_quad(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

void gf2m_mod_sqrt(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Створює копію контексту параметрів GF(2^m).
 *
 * @param ctx параметри GF(2^m)
 * @return копія контексту
 */
Gf2mCtx *gf2m_copy_with_alloc(const Gf2mCtx *ctx);

void gf2m_free(Gf2mCtx *ctx);


#ifdef  __cplusplus
}
#endif

#endif
