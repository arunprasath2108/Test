#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_EcallSealData_t {
	uint8_t* ms_ciphertext;
	size_t ms_cipher_len;
	uint8_t* ms_iv;
	size_t ms_iv_len;
	uint8_t* ms_tag;
	size_t ms_tag_len;
} ms_EcallSealData_t;

typedef struct ms_EcallGetUserPasswords_t {
	uint8_t* ms_passwords;
	size_t ms_password_len;
	uint8_t* ms_iv;
	size_t ms_iv_len;
	uint8_t* ms_tag;
	size_t ms_tag_len;
} ms_EcallGetUserPasswords_t;

typedef struct ms_EcallGetBreachedPasswords_t {
	const char** ms_breached_arr;
	size_t ms_arr_len;
} ms_EcallGetBreachedPasswords_t;

typedef struct ms_EcallComparePasswords_t {
	long long ms_user_id;
} ms_EcallComparePasswords_t;

typedef struct ms_OcallIsFileExist_t {
	int ms_retval;
	const char* ms_file_name;
} ms_OcallIsFileExist_t;

typedef struct ms_OcallSaveFile_t {
	uint8_t* ms_sealed_data;
	size_t ms_data_len;
} ms_OcallSaveFile_t;

typedef struct ms_OcallGetFileSize_t {
	size_t ms_retval;
	const char* ms_file_name;
} ms_OcallGetFileSize_t;

typedef struct ms_LoadFile_t {
	const char* ms_file_name;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_LoadFile_t;

typedef struct ms_OcallSendResult_t {
	uint8_t* ms_ciphertext;
	size_t ms_cipher_len;
} ms_OcallSendResult_t;

typedef struct ms_OcallPrintError_t {
	const char* ms_error_message;
} ms_OcallPrintError_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL sgx_EcallSealData(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_EcallSealData_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_EcallSealData_t* ms = SGX_CAST(ms_EcallSealData_t*, pms);
	ms_EcallSealData_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_EcallSealData_t), ms, sizeof(ms_EcallSealData_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_ciphertext = __in_ms.ms_ciphertext;
	size_t _tmp_cipher_len = __in_ms.ms_cipher_len;
	size_t _len_ciphertext = _tmp_cipher_len;
	uint8_t* _in_ciphertext = NULL;
	uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _tmp_iv_len = __in_ms.ms_iv_len;
	size_t _len_iv = _tmp_iv_len;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_tag = __in_ms.ms_tag;
	size_t _tmp_tag_len = __in_ms.ms_tag_len;
	size_t _len_tag = _tmp_tag_len;
	uint8_t* _in_tag = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_tag, _len_tag);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ciphertext = (uint8_t*)malloc(_len_ciphertext);
		if (_in_ciphertext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ciphertext, _len_ciphertext, _tmp_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag != NULL && _len_tag != 0) {
		if ( _len_tag % sizeof(*_tmp_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag = (uint8_t*)malloc(_len_tag);
		if (_in_tag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag, _len_tag, _tmp_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	EcallSealData(_in_ciphertext, _tmp_cipher_len, _in_iv, _tmp_iv_len, _in_tag, _tmp_tag_len);

err:
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_iv) free(_in_iv);
	if (_in_tag) free(_in_tag);
	return status;
}

static sgx_status_t SGX_CDECL sgx_EcallGetUserPasswords(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_EcallGetUserPasswords_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_EcallGetUserPasswords_t* ms = SGX_CAST(ms_EcallGetUserPasswords_t*, pms);
	ms_EcallGetUserPasswords_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_EcallGetUserPasswords_t), ms, sizeof(ms_EcallGetUserPasswords_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_passwords = __in_ms.ms_passwords;
	size_t _tmp_password_len = __in_ms.ms_password_len;
	size_t _len_passwords = _tmp_password_len;
	uint8_t* _in_passwords = NULL;
	uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _tmp_iv_len = __in_ms.ms_iv_len;
	size_t _len_iv = _tmp_iv_len;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_tag = __in_ms.ms_tag;
	size_t _tmp_tag_len = __in_ms.ms_tag_len;
	size_t _len_tag = _tmp_tag_len;
	uint8_t* _in_tag = NULL;

	CHECK_UNIQUE_POINTER(_tmp_passwords, _len_passwords);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_tag, _len_tag);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_passwords != NULL && _len_passwords != 0) {
		if ( _len_passwords % sizeof(*_tmp_passwords) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_passwords = (uint8_t*)malloc(_len_passwords);
		if (_in_passwords == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_passwords, _len_passwords, _tmp_passwords, _len_passwords)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag != NULL && _len_tag != 0) {
		if ( _len_tag % sizeof(*_tmp_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tag = (uint8_t*)malloc(_len_tag);
		if (_in_tag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag, _len_tag, _tmp_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	EcallGetUserPasswords(_in_passwords, _tmp_password_len, _in_iv, _tmp_iv_len, _in_tag, _tmp_tag_len);

err:
	if (_in_passwords) free(_in_passwords);
	if (_in_iv) free(_in_iv);
	if (_in_tag) free(_in_tag);
	return status;
}

static sgx_status_t SGX_CDECL sgx_EcallGetBreachedPasswords(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_EcallGetBreachedPasswords_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_EcallGetBreachedPasswords_t* ms = SGX_CAST(ms_EcallGetBreachedPasswords_t*, pms);
	ms_EcallGetBreachedPasswords_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_EcallGetBreachedPasswords_t), ms, sizeof(ms_EcallGetBreachedPasswords_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char** _tmp_breached_arr = __in_ms.ms_breached_arr;
	size_t _tmp_arr_len = __in_ms.ms_arr_len;
	size_t _len_breached_arr = _tmp_arr_len * sizeof(char*);
	char** _in_breached_arr = NULL;

	if (sizeof(*_tmp_breached_arr) != 0 &&
		(size_t)_tmp_arr_len > (SIZE_MAX / sizeof(*_tmp_breached_arr))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_breached_arr, _len_breached_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_breached_arr != NULL && _len_breached_arr != 0) {
		if ( _len_breached_arr % sizeof(*_tmp_breached_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_breached_arr = (char**)malloc(_len_breached_arr);
		if (_in_breached_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_breached_arr, _len_breached_arr, _tmp_breached_arr, _len_breached_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	EcallGetBreachedPasswords((const char**)_in_breached_arr, _tmp_arr_len);

err:
	if (_in_breached_arr) free(_in_breached_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_EcallComparePasswords(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_EcallComparePasswords_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_EcallComparePasswords_t* ms = SGX_CAST(ms_EcallComparePasswords_t*, pms);
	ms_EcallComparePasswords_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_EcallComparePasswords_t), ms, sizeof(ms_EcallComparePasswords_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	EcallComparePasswords(__in_ms.ms_user_id);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_EcallSealData, 0, 0},
		{(void*)(uintptr_t)sgx_EcallGetUserPasswords, 0, 0},
		{(void*)(uintptr_t)sgx_EcallGetBreachedPasswords, 0, 0},
		{(void*)(uintptr_t)sgx_EcallComparePasswords, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[15][4];
} g_dyn_entry_table = {
	15,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL OcallIsFileExist(int* retval, const char* file_name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_name = file_name ? strlen(file_name) + 1 : 0;

	ms_OcallIsFileExist_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OcallIsFileExist_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(file_name, _len_file_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_name != NULL) ? _len_file_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OcallIsFileExist_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OcallIsFileExist_t));
	ocalloc_size -= sizeof(ms_OcallIsFileExist_t);

	if (file_name != NULL) {
		if (memcpy_verw_s(&ms->ms_file_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_file_name % sizeof(*file_name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, file_name, _len_file_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_name);
		ocalloc_size -= _len_file_name;
	} else {
		ms->ms_file_name = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OcallSaveFile(uint8_t* sealed_data, size_t data_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_data = data_len;

	ms_OcallSaveFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OcallSaveFile_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OcallSaveFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OcallSaveFile_t));
	ocalloc_size -= sizeof(ms_OcallSaveFile_t);

	if (sealed_data != NULL) {
		if (memcpy_verw_s(&ms->ms_sealed_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, sealed_data, _len_sealed_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_data_len, sizeof(ms->ms_data_len), &data_len, sizeof(data_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OcallGetFileSize(size_t* retval, const char* file_name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_name = file_name ? strlen(file_name) + 1 : 0;

	ms_OcallGetFileSize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OcallGetFileSize_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(file_name, _len_file_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_name != NULL) ? _len_file_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OcallGetFileSize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OcallGetFileSize_t));
	ocalloc_size -= sizeof(ms_OcallGetFileSize_t);

	if (file_name != NULL) {
		if (memcpy_verw_s(&ms->ms_file_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_file_name % sizeof(*file_name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, file_name, _len_file_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_name);
		ocalloc_size -= _len_file_name;
	} else {
		ms->ms_file_name = NULL;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL LoadFile(const char* file_name, uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_name = file_name ? strlen(file_name) + 1 : 0;
	size_t _len_sealed_data = sealed_size;

	ms_LoadFile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_LoadFile_t);
	void *__tmp = NULL;

	void *__tmp_sealed_data = NULL;

	CHECK_ENCLAVE_POINTER(file_name, _len_file_name);
	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_name != NULL) ? _len_file_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_LoadFile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_LoadFile_t));
	ocalloc_size -= sizeof(ms_LoadFile_t);

	if (file_name != NULL) {
		if (memcpy_verw_s(&ms->ms_file_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_file_name % sizeof(*file_name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, file_name, _len_file_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_name);
		ocalloc_size -= _len_file_name;
	} else {
		ms->ms_file_name = NULL;
	}

	if (sealed_data != NULL) {
		if (memcpy_verw_s(&ms->ms_sealed_data, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_sealed_data = __tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_sealed_data, 0, _len_sealed_data);
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}

	if (memcpy_verw_s(&ms->ms_sealed_size, sizeof(ms->ms_sealed_size), &sealed_size, sizeof(sealed_size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (sealed_data) {
			if (memcpy_s((void*)sealed_data, _len_sealed_data, __tmp_sealed_data, _len_sealed_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OcallSendResult(uint8_t* ciphertext, size_t cipher_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ciphertext = cipher_len;

	ms_OcallSendResult_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OcallSendResult_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(ciphertext, _len_ciphertext);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ciphertext != NULL) ? _len_ciphertext : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OcallSendResult_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OcallSendResult_t));
	ocalloc_size -= sizeof(ms_OcallSendResult_t);

	if (ciphertext != NULL) {
		if (memcpy_verw_s(&ms->ms_ciphertext, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_ciphertext % sizeof(*ciphertext) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, ciphertext, _len_ciphertext)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ciphertext);
		ocalloc_size -= _len_ciphertext;
	} else {
		ms->ms_ciphertext = NULL;
	}

	if (memcpy_verw_s(&ms->ms_cipher_len, sizeof(ms->ms_cipher_len), &cipher_len, sizeof(cipher_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OcallPrintError(const char* error_message)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error_message = error_message ? strlen(error_message) + 1 : 0;

	ms_OcallPrintError_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OcallPrintError_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(error_message, _len_error_message);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error_message != NULL) ? _len_error_message : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OcallPrintError_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OcallPrintError_t));
	ocalloc_size -= sizeof(ms_OcallPrintError_t);

	if (error_message != NULL) {
		if (memcpy_verw_s(&ms->ms_error_message, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_error_message % sizeof(*error_message) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, error_message, _len_error_message)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_error_message);
		ocalloc_size -= _len_error_message;
	} else {
		ms->ms_error_message = NULL;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		if (memcpy_verw_s(&ms->ms_timeptr, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_timeptr = __tmp;
		memset_verw(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_timeb_len, sizeof(ms->ms_timeb_len), &timeb_len, sizeof(timeb_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

