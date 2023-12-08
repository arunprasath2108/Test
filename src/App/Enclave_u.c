#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_OcallIsFileExist(void* pms)
{
	ms_OcallIsFileExist_t* ms = SGX_CAST(ms_OcallIsFileExist_t*, pms);
	ms->ms_retval = OcallIsFileExist(ms->ms_file_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_OcallSaveFile(void* pms)
{
	ms_OcallSaveFile_t* ms = SGX_CAST(ms_OcallSaveFile_t*, pms);
	OcallSaveFile(ms->ms_sealed_data, ms->ms_data_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_OcallGetFileSize(void* pms)
{
	ms_OcallGetFileSize_t* ms = SGX_CAST(ms_OcallGetFileSize_t*, pms);
	ms->ms_retval = OcallGetFileSize(ms->ms_file_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_LoadFile(void* pms)
{
	ms_LoadFile_t* ms = SGX_CAST(ms_LoadFile_t*, pms);
	LoadFile(ms->ms_file_name, ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_OcallSendResult(void* pms)
{
	ms_OcallSendResult_t* ms = SGX_CAST(ms_OcallSendResult_t*, pms);
	OcallSendResult(ms->ms_ciphertext, ms->ms_cipher_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_OcallPrintError(void* pms)
{
	ms_OcallPrintError_t* ms = SGX_CAST(ms_OcallPrintError_t*, pms);
	OcallPrintError(ms->ms_error_message);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[15];
} ocall_table_Enclave = {
	15,
	{
		(void*)Enclave_OcallIsFileExist,
		(void*)Enclave_OcallSaveFile,
		(void*)Enclave_OcallGetFileSize,
		(void*)Enclave_LoadFile,
		(void*)Enclave_OcallSendResult,
		(void*)Enclave_OcallPrintError,
		(void*)Enclave_u_sgxssl_ftime,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_pthread_wait_timeout_ocall,
		(void*)Enclave_pthread_create_ocall,
		(void*)Enclave_pthread_wakeup_ocall,
	}
};
sgx_status_t EcallSealData(sgx_enclave_id_t eid, uint8_t* ciphertext, size_t cipher_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len)
{
	sgx_status_t status;
	ms_EcallSealData_t ms;
	ms.ms_ciphertext = ciphertext;
	ms.ms_cipher_len = cipher_len;
	ms.ms_iv = iv;
	ms.ms_iv_len = iv_len;
	ms.ms_tag = tag;
	ms.ms_tag_len = tag_len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t EcallGetUserPasswords(sgx_enclave_id_t eid, uint8_t* passwords, size_t password_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len)
{
	sgx_status_t status;
	ms_EcallGetUserPasswords_t ms;
	ms.ms_passwords = passwords;
	ms.ms_password_len = password_len;
	ms.ms_iv = iv;
	ms.ms_iv_len = iv_len;
	ms.ms_tag = tag;
	ms.ms_tag_len = tag_len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t EcallGetBreachedPasswords(sgx_enclave_id_t eid, const char** breached_arr, size_t arr_len)
{
	sgx_status_t status;
	ms_EcallGetBreachedPasswords_t ms;
	ms.ms_breached_arr = breached_arr;
	ms.ms_arr_len = arr_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t EcallComparePasswords(sgx_enclave_id_t eid, long long user_id)
{
	sgx_status_t status;
	ms_EcallComparePasswords_t ms;
	ms.ms_user_id = user_id;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

