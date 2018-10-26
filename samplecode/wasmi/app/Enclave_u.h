#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef U_STDIN_OCALL_DEFINED__
#define U_STDIN_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_stdin_ocall, (void* buf, size_t nbytes));
#endif
#ifndef U_STDOUT_OCALL_DEFINED__
#define U_STDOUT_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_stdout_ocall, (const void* buf, size_t nbytes));
#endif
#ifndef U_STDERR_OCALL_DEFINED__
#define U_STDERR_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_stderr_ocall, (const void* buf, size_t nbytes));
#endif
#ifndef U_BACKTRACE_OPEN_OCALL_DEFINED__
#define U_BACKTRACE_OPEN_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_open_ocall, (int* error, const char* pathname, int flags));
#endif
#ifndef U_BACKTRACE_CLOSE_OCALL_DEFINED__
#define U_BACKTRACE_CLOSE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_close_ocall, (int* error, int fd));
#endif
#ifndef U_BACKTRACE_FCNTL_OCALL_DEFINED__
#define U_BACKTRACE_FCNTL_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_fcntl_ocall, (int* error, int fd, int cmd, int arg));
#endif
#ifndef U_BACKTRACE_MMAP_OCALL_DEFINED__
#define U_BACKTRACE_MMAP_OCALL_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_mmap_ocall, (int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset));
#endif
#ifndef U_BACKTRACE_MUNMAP_OCALL_DEFINED__
#define U_BACKTRACE_MUNMAP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_munmap_ocall, (int* error, void* start, size_t length));
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

sgx_status_t sgxwasm_init(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t sgxwasm_run_action(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* req_bin, size_t req_len, uint8_t* output_bin, size_t out_max_len);
sgx_status_t t_global_init_ecall(sgx_enclave_id_t eid, uint64_t id, const uint8_t* path, size_t len);
sgx_status_t t_global_exit_ecall(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
