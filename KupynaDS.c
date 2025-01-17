#include "byte_array_internal.h"
#include "cryptonite_errors.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include <Windows.h>
#include <wchar.h>

#define FreeIfNotNull(x, y)	\
	if (x) {	\
		y(x);	\
		x = NULL;	\
	}

ByteArray* CalculateHash(uint8_t* buf, size_t size) {
	Dstu7564Ctx* ctx = NULL;
	ByteArray* r = NULL;

	ctx = dstu7564_alloc(DSTU7564_SBOX_1);
	dstu7564_init(ctx, 64);	// Купина-512

	int dummy;
	ByteArray block = {
		size ? buf : &dummy,
		size
	};

	dstu7564_update(ctx, &block);

	dstu7564_final(ctx, &r);
	FreeIfNotNull(ctx, dstu7564_free);
	return r;
}

typedef struct {
	wchar_t* path;
	ByteArray* ba;
} FileHashWork;

DWORD FileHash(FileHashWork* fhw) {
	HANDLE f = NULL;
	HANDLE fmap = NULL;
	uint8_t* fview = NULL;
	DWORD ret = 0;

	f = CreateFileW(
		fhw->path,
		FILE_READ_ACCESS,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL
	);
	if (f == INVALID_HANDLE_VALUE) {
		ret = GetLastError();
		f = NULL;
		goto exit;
	}

	LARGE_INTEGER fsize;
	GetFileSizeEx(f, &fsize);

	// Відобразити файл у пам’ять.
	fmap = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!fmap) {
		ret = GetLastError();
		goto exit;
	}
	fview = MapViewOfFile(fmap, FILE_MAP_READ, 0, 0, 0);
	if (!fview) {
		ret = GetLastError();
		goto exit;
	}

	fhw->ba = CalculateHash(fview, fsize.QuadPart);

exit:
	FreeIfNotNull(fview, UnmapViewOfFile);
	FreeIfNotNull(fmap, CloseHandle);
	FreeIfNotNull(f, CloseHandle);

	return ret;
}

int GenerateSecret(wchar_t* path) {
	HANDLE f = NULL;
	Dstu4145Ctx* ctx = NULL;
	PrngCtx* rng = NULL;
	ByteArray* sk = NULL;
	wchar_t* path2 = NULL;

	DWORD r;

	const wchar_t ext[] = L".sk4145";

	ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_ONB);
	rng = prng_alloc(PRNG_MODE_DEFAULT, NULL);

	dstu4145_generate_privkey(ctx, rng, &sk);

	size_t path2_l = wcslen(path) + sizeof(ext) / sizeof(wchar_t);
	path2 = malloc(path2_l * sizeof(wchar_t));
	if (!path2) {
		printf("Cannot allocate heap.\n");
		goto exit;
	}

	swprintf(path2, path2_l, L"%s.sk4145", path);
	f = CreateFileW(
		path2,
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		0,
		NULL,
		CREATE_NEW,
		0,
		NULL
	);
	if (f == INVALID_HANDLE_VALUE) {
		printf("Cannot create file: 0x%08X\n", GetLastError());
		f = NULL;
		goto exit;
	}

	WriteFile(f, ba_get_buf(sk), ba_get_len(sk), &r, NULL);

exit:
	FreeIfNotNull(f, CloseHandle);
	FreeIfNotNull(path2, free);
	FreeIfNotNull(sk, ba_free);
	FreeIfNotNull(rng, prng_free);
	FreeIfNotNull(ctx, dstu4145_free);

	return 0;
}


int SignFile(wchar_t* file, wchar_t* skfile) {
	HANDLE f = NULL;
	HANDLE thr = NULL;
	wchar_t* path2 = NULL;
	ByteArray* sk = NULL;
	uint8_t* _sk = NULL;
	ByteArray* pk = NULL;
	Dstu4145Ctx* ctx = NULL;
	PrngCtx* rng = NULL;
	ByteArray* sign_r = NULL;
	ByteArray* sign_s = NULL;
	ByteArray* pk_x = NULL;
	ByteArray* pk_y = NULL;

	int keysize;
	DWORD r;
	uint8_t _keysize;

	// Обчислення гешу можна виконувати окремим потоком.
	FileHashWork fhw;
	fhw.path = file;
	fhw.ba = NULL;
	thr = CreateThread(NULL, 0, FileHash, &fhw, 0, 0);
	if (!thr) {
		printf("Cannot create thread: 0x%08X\n", GetLastError());
		goto exit2;
	}

	f = CreateFileW(
		skfile,
		FILE_READ_ACCESS,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (f == INVALID_HANDLE_VALUE) {
		printf("Cannot open file: 0x%08X\n", GetLastError());
		f = NULL;
		goto exit;
	}

	keysize = GetFileSize(f, NULL);
	_sk = malloc(keysize);
	if (!_sk) {
		printf("Cannot allocate heap.\n");
		goto exit;
	}

	if (!ReadFile(f, _sk, keysize, &r, NULL)) {
		printf("Cannot read file: 0x%08X\n", GetLastError());
		goto exit;
	}
	FreeIfNotNull(f, CloseHandle);

	sk = ba_alloc_from_uint8(_sk, keysize);

	const wchar_t ext[] = L".sign4145";

	size_t path2_l = wcslen(file) + sizeof(ext) / sizeof(wchar_t);
	path2 = malloc(path2_l * sizeof(wchar_t));
	if (!path2) {
		printf("Cannot allocate heap.\n");
		goto exit;
	}

	swprintf(path2, path2_l, L"%s.sign4145", file);

	ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_ONB);
	rng = prng_alloc(PRNG_MODE_DEFAULT, NULL);

	dstu4145_init_sign(ctx, sk, rng);

	WaitForSingleObject(thr, INFINITE);
	GetExitCodeThread(thr, &r);
	if (r) {
		printf("Cannot calculate file hash: 0x%08X\n", r);
		goto exit;
	}

	dstu4145_sign(ctx, fhw.ba, &sign_r, &sign_s);

	dstu4145_get_pubkey(ctx, sk, &pk_x, &pk_y);
	dstu4145_compress_pubkey(ctx, pk_x, pk_y, &pk);

	f = CreateFileW(
		path2,
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		0,
		NULL,
		CREATE_NEW,
		0,
		NULL
	);
	if (f == INVALID_HANDLE_VALUE) {
		printf("Cannot create file: 0x%08X\n", GetLastError());
		f = NULL;
		goto exit;
	}

	_keysize = ba_get_len(sign_r);
	WriteFile(f, &_keysize, sizeof(_keysize), &r, NULL);
	WriteFile(f, ba_get_buf(sign_r), ba_get_len(sign_r), &r, NULL);

	_keysize = ba_get_len(sign_s);
	WriteFile(f, &_keysize, sizeof(_keysize), &r, NULL);
	WriteFile(f, ba_get_buf(sign_s), ba_get_len(sign_s), &r, NULL);

	// Записати відкритий ключ
	_keysize = ba_get_len(pk);
	WriteFile(f, &_keysize, sizeof(_keysize), &r, NULL);
	WriteFile(f, ba_get_buf(pk), ba_get_len(pk), &r, NULL);

exit:
	WaitForSingleObject(thr, INFINITE);
exit2:
	FreeIfNotNull(path2, free);
	FreeIfNotNull(sk, ba_free);
	FreeIfNotNull(_sk, free);
	FreeIfNotNull(ctx, dstu4145_free);
	FreeIfNotNull(rng, prng_free);
	FreeIfNotNull(sign_r, ba_free);
	FreeIfNotNull(sign_s, ba_free);
	FreeIfNotNull(pk_x, ba_free);
	FreeIfNotNull(pk_y, ba_free);
	FreeIfNotNull(pk, ba_free);
	FreeIfNotNull(f, CloseHandle);
	FreeIfNotNull(fhw.ba, ba_free);
	FreeIfNotNull(thr, CloseHandle);

	return 0;
}

int VerifyFile(wchar_t* file) {
	HANDLE f = NULL;
	HANDLE fmap = NULL;
	uint8_t* fview = NULL;
	HANDLE thr = NULL;
	wchar_t* path2 = NULL;
	Dstu4145Ctx* ctx = NULL;
	ByteArray* pk_x = NULL;
	ByteArray* pk_y = NULL;

	ByteArray sign_r;
	ByteArray sign_s;
	ByteArray pk;
	DWORD r;

	// Обчислення гешу можна виконувати окремим потоком.
	FileHashWork fhw;
	fhw.path = file;
	fhw.ba = NULL;
	thr = CreateThread(NULL, 0, FileHash, &fhw, 0, 0);
	if (!thr) {
		printf("Cannot create thread: 0x%08X\n", GetLastError());
		goto exit2;
	}

	const wchar_t ext[] = L".sign4145";

	size_t path2_l = wcslen(file) + sizeof(ext) / sizeof(wchar_t);
	path2 = malloc(path2_l * sizeof(wchar_t));
	if (!path2) {
		printf("Cannot allocate heap.\n");
		goto exit;
	}

	swprintf(path2, path2_l, L"%s.sign4145", file);

	f = CreateFileW(
		path2,
		FILE_READ_ACCESS,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (f == INVALID_HANDLE_VALUE) {
		printf("Cannot open file: 0x%08X\n", GetLastError());
		f = NULL;
		goto exit;
	}

	// Відобразити підпис і відкритий ключ у пам’ять.
	fmap = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!fmap) {
		printf("Cannot create file mapping: 0x%08X\n", GetLastError());
		goto exit;
	}
	fview = MapViewOfFile(fmap, FILE_MAP_READ, 0, 0, 0);
	if (!fview) {
		printf("Cannot map view of file: 0x%08X\n", GetLastError());
		goto exit;
	}

	uint8_t* fview2 = fview;

	sign_r.len = *fview2;
	sign_r.buf = fview2 + 1;

	fview2 += *fview2 + 1;

	sign_s.len = *fview2;
	sign_s.buf = fview2 + 1;

	fview2 += *fview2 + 1;

	pk.len = *fview2;
	pk.buf = fview2 + 1;

	ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_ONB);
	dstu4145_decompress_pubkey(ctx, &pk, &pk_x, &pk_y);
	dstu4145_init_verify(ctx, pk_x, pk_y);

	WaitForSingleObject(thr, INFINITE);
	GetExitCodeThread(thr, &r);
	if (r) {
		printf("Cannot calculate file hash: 0x%08X\n", r);
		goto exit;
	}

	switch (dstu4145_verify(ctx, fhw.ba, &sign_r, &sign_s)) {
	case RET_VERIFY_FAILED:
		puts("Signature incorrect.");
		break;
	case RET_OK:
		puts("Signature OK.");
		break;
	default:
		puts("Cannot verify signature.");
	}

exit:
	WaitForSingleObject(thr, INFINITE);
exit2:
	FreeIfNotNull(ctx, dstu4145_free);
	FreeIfNotNull(fview, UnmapViewOfFile);
	FreeIfNotNull(fmap, CloseHandle);
	FreeIfNotNull(f, CloseHandle);
	FreeIfNotNull(path2, free);
	FreeIfNotNull(thr, CloseHandle);
	FreeIfNotNull(fhw.ba, ba_free);

	return 0;
}

/*
* Аргументи:
* /g <шлях> — згенерувати пару ключів як <шлях>.sk4145 та <шлях>.pk4145
* /s <шлях_1> <шлях_2> — підписати файл <шлях_1> особистим ключем <шлях_2>
* /v <шлях_1> — перевірити підпис, що знаходиться в <шлях_1>
*/

int wmain(int argc, wchar_t** argv) {
	if (argc > 1 && wcslen(argv[1]) == 2 && argv[1][0] == L'/') {
		switch (towlower(argv[1][1])) {
		case L'g':
			if (argc == 3) {
				return GenerateSecret(argv[2]);
			}
			break;
		case L's':
			if (argc == 4) {
				return SignFile(argv[2], argv[3]);
			}
			break;
		case L'v':
			if (argc == 3) {
				return VerifyFile(argv[2]);
			}
			break;
		}
	}

	puts("Command line options:");
	puts("/g <path> -- Generate private and public keys at <path>.sk4145 and");
	puts("<path>.pk4145 respectively");
	puts("/s <path1> <path2> -- Sign a file at <path1> with a private key at");
	puts("<path2> and store a signature as <path1>.sign4145");
	puts("/v <path1> -- Verify a signature for <path1>.");

	return 0;
}
