#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void EcallSealData(uint8_t* ciphertext, size_t cipher_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len);
void EcallGetUserPasswords(uint8_t* passwords, size_t password_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len);
void EcallGetBreachedPasswords(const char** breached_arr, size_t arr_len);
void EcallComparePasswords(long long user_id);

sgx_status_t SGX_CDECL OcallIsFileExist(int* retval, const char* file_name);
sgx_status_t SGX_CDECL OcallSaveFile(uint8_t* sealed_data, size_t data_len);
sgx_status_t SGX_CDECL OcallGetFileSize(size_t* retval, const char* file_name);
sgx_status_t SGX_CDECL LoadFile(const char* file_name, uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL OcallSendResult(uint8_t* ciphertext, size_t cipher_len);
sgx_status_t SGX_CDECL OcallPrintError(const char* error_message);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
