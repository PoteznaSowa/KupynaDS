/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_STACKTRACE_H
#define CRYPTONITE_STACKTRACE_H

#include <stddef.h>
#include <stdbool.h>

#ifdef EDEBUG
#undef ASSERT
#include <assert.h>

#define ASSERT(condition) assert(condition)
#else
#undef ASSERT
#define ASSERT(...)
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#undef FILE_MARKER
#define FILE_MARKER "unknown_file"

typedef struct ErrorCtx_st {
	char *file;
	size_t line;
	int error_code;
	struct ErrorCtx_st *next;
} ErrorCtx;

#define ERROR_CREATE(error_code) stacktrace_create(FILE_MARKER, __LINE__, error_code, NULL)
#define ERROR_ADD(error_code) stacktrace_add(FILE_MARKER, __LINE__, error_code)

const ErrorCtx *stacktrace_get_last(void);
void stacktrace_create(const char *file, const size_t line, const int error_code, const char *msg);
void stacktrace_add(const char *file, const size_t line, const int error_code);
ErrorCtx *stacktrace_get_last_with_alloc(void);
void error_ctx_free(ErrorCtx *err);
void stacktrace_free_current(void);
void stacktrace_finalize(void);

#ifdef  __cplusplus
}
#endif

#endif
