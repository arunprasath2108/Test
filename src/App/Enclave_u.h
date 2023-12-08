#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALLISFILEEXIST_DEFINED__
#define OCALLISFILEEXIST_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, OcallIsFileExist, (const char* file_name));
#endif
#ifndef OCALLSAVEFILE_DEFINED__
#define OCALLSAVEFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, OcallSaveFile, (uint8_t* sealed_data, size_t data_len));
#endif
#ifndef OCALLGETFILESIZE_DEFINED__
#define OCALLGETFILESIZE_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, OcallGetFileSize, (const char* file_name));
#endif
#ifndef LOADFILE_DEFINED__
#define LOADFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, LoadFile, (const char* file_name, uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALLSENDRESULT_DEFINED__
#define OCALLSENDRESULT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, OcallSendResult, (uint8_t* ciphertext, size_t cipher_len));
#endif
#ifndef OCALLPRINTERROR_DEFINED__
#define OCALLPRINTERROR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, OcallPrintError, (const char* error_message));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif

sgx_status_t EcallSealData(sgx_enclave_id_t eid, uint8_t* ciphertext, size_t cipher_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len);
sgx_status_t EcallGetUserPasswords(sgx_enclave_id_t eid, uint8_t* passwords, size_t password_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len);
sgx_status_t EcallGetBreachedPasswords(sgx_enclave_id_t eid, const char** breached_arr, size_t arr_len);
sgx_status_t EcallComparePasswords(sgx_enclave_id_t eid, long long user_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
