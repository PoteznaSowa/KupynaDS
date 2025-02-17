/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "prng.h"

#ifdef _WIN32
	#include <Windows.h>
	#include <winioctl.h>
	#include <winternl.h>
	#pragma comment(lib, "NTDLL.Lib")
	#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), s }

	#ifndef IOCTL_KSEC_RNG	// ntddksec.h, 0x390004
	#define IOCTL_KSEC_RNG	CTL_CODE(FILE_DEVICE_KSEC, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
	#endif

	#ifndef IOCTL_KSEC_RNG_REKEY	// ntddksec.h, 0x390008
	#define IOCTL_KSEC_RNG_REKEY	CTL_CODE(FILE_DEVICE_KSEC, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
	#endif
#else   // _WIN32
	#include <sys/random.h> // Linux
#endif

#include "macros_internal.h"
#include "byte_array_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/prng.c"

struct PrngCtx_st {
#ifdef _WIN32
	HANDLE dev;
#else
	void* dummy;
#endif
};

PrngCtx *prng_alloc(PrngMode mode, const ByteArray *seed)
{
	PrngCtx* ctx = NULL;
	int ret = RET_OK;
	CALLOC_CHECKED(ctx, sizeof(PrngCtx));

#ifdef _WIN32
	UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\Device\\CNG");
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;

	InitializeObjectAttributes(&oa, &path, 0, NULL, NULL);
	NTSTATUS status = NtOpenFile(
		&(ctx->dev),
		FILE_READ_DATA,
		&oa,
		&iosb,
		FILE_SHARE_READ,
		0
	);
	if (NT_ERROR(status)) {
		SET_ERROR(RET_FILE_OPEN_ERROR);
	}
#endif

cleanup:

	if (ret != RET_OK) {
		prng_free(ctx);
		ctx = NULL;
	}

	return ctx;
}

int prng_get_mode(PrngCtx *prng, PrngMode *mode)
{
	int ret = RET_OK;

	CHECK_PARAM(prng != NULL);
	CHECK_PARAM(mode != NULL);

	*mode = PRNG_MODE_DEFAULT;

cleanup:

	return ret;
}

int prng_seed(PrngCtx *prng, const ByteArray *seed)
{
	int ret = RET_OK;

	CHECK_PARAM(prng != NULL);
	CHECK_PARAM(seed != NULL);

cleanup:

	return ret;
}

int prng_next_bytes(PrngCtx *prng, ByteArray *buf)
{
	int ret = RET_OK;

	CHECK_PARAM(prng != NULL);
	CHECK_PARAM(buf != NULL);

	// Зчитати випадкові байти з ГВЧ операційної системи
#ifdef _WIN32
	ULONG length = buf->len;
	ULONG ioctl = length < 16384 ? IOCTL_KSEC_RNG : IOCTL_KSEC_RNG_REKEY;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtDeviceIoControlFile(
		prng->dev,
		NULL,
		NULL,
		NULL,
		&iosb,
		ioctl,
		NULL,
		length,
		buf->buf,
		length
	);
	if (NT_ERROR(status)) {
		SET_ERROR(RET_FILE_READ_ERROR);
	}
#else   // Linux
	if (getrandom(buf->buf, buf->len, GRND_RANDOM) == -1) {
		SET_ERROR(RET_FILE_READ_ERROR);
	}
#endif

cleanup:

	return ret;
}

void prng_free(PrngCtx *prng)
{
	if (prng != NULL) {
#ifdef _WIN32
		NtClose(prng->dev);
#endif
		free(prng);
	}
}
