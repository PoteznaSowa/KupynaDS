/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_EC2M_H
#define CRYPTONITE_MATH_EC2M_H

#include <stdbool.h>

#include "math_ec_point_internal.h"
#include "math_ec_precomp_internal.h"
#include "math_gf2m_internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct EC2m_st {
	Gf2mCtx *gf2m;          /* Контекст поля GF(2m). */
	int a;                  /* коефіцієнт еліптичної кривої a. */
	WordArray *b;           /* коефіцієнт еліптичної кривої b. */
	size_t len;
} EcGf2mCtx;

EcGf2mCtx *ec2m_alloc(const int *f, size_t f_len, int a, const WordArray *b);

void ec2m_init(EcGf2mCtx *ctx, const int *f, size_t f_len, int a, const WordArray *b);

bool ec2m_is_on_curve(const EcGf2mCtx *ctx, const WordArray *px, const WordArray *py);

void ec2m_mul(EcGf2mCtx *ctx, const ECPoint *p, const WordArray *k, ECPoint *r);

int ec2m_dual_mul_opt(const EcGf2mCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m,
		const EcPrecomp *q_precomp, const WordArray *n, ECPoint *r);

void ec2m_dual_mul(const EcGf2mCtx *ctx, const ECPoint *p, const WordArray *k,
		const ECPoint *q, const WordArray *n, ECPoint *r);

void ec2m_dual_mul_by_precomp(EcGf2mCtx *ctx, const EcPrecomp *precomp_p, const WordArray *k,
		const EcPrecomp *precomp_q, const WordArray *n, ECPoint *r);

void ec2m_point_to_affine(const EcGf2mCtx *ctx, ECPoint *p);

/**
 * Створює копію контексту еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @return копія контексту
 */
EcGf2mCtx *ec2m_copy_with_alloc(EcGf2mCtx *ctx);

int ec2m_calc_win_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

int ec2m_calc_comb_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

void ec2m_free(EcGf2mCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
