#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_quote.h"
#include "inc/stat.h"
#include "time.h"
#include "sys/types.h"
#include "merkle.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sockaddr_t {
	uint16_t sa_family;
	char sa_data[14];
} sockaddr_t;

sgx_status_t merkletreeflow(MerkleTree* tree, HASHTYPE roothash, int codeid, int dataid, char* report, char* wasmfunc, int wasmargs);
void t_global_init_ecall(uint64_t id, const uint8_t* path, size_t len);
void t_global_exit_ecall(void);

sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_status_t* retval, sgx_target_info_t* ret_ti, sgx_epid_group_id_t* ret_gid);
sgx_status_t SGX_CDECL ocall_get_ias_socket(sgx_status_t* retval, int* ret_fd);
sgx_status_t SGX_CDECL ocall_get_quote(sgx_status_t* retval, uint8_t* p_sigrl, uint32_t sigrl_len, sgx_report_t* report, sgx_quote_sign_type_t quote_type, sgx_spid_t* p_spid, sgx_quote_nonce_t* p_nonce, sgx_report_t* p_qe_report, sgx_quote_t* p_quote, uint32_t maxlen, uint32_t* p_quote_len);
sgx_status_t SGX_CDECL ocall_get_update_info(sgx_status_t* retval, sgx_platform_info_t* platformBlob, int32_t enclaveTrusted, sgx_update_info_bit_t* update_info);
sgx_status_t SGX_CDECL u_backtrace_open_ocall(int* retval, int* error, const char* pathname, int flags);
sgx_status_t SGX_CDECL u_backtrace_close_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_backtrace_fcntl_ocall(int* retval, int* error, int fd, int cmd, int arg);
sgx_status_t SGX_CDECL u_backtrace_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset);
sgx_status_t SGX_CDECL u_backtrace_munmap_ocall(int* retval, int* error, void* start, size_t length);
sgx_status_t SGX_CDECL u_stdin_ocall(size_t* retval, void* buf, size_t nbytes);
sgx_status_t SGX_CDECL u_stdout_ocall(size_t* retval, const void* buf, size_t nbytes);
sgx_status_t SGX_CDECL u_stderr_ocall(size_t* retval, const void* buf, size_t nbytes);
sgx_status_t SGX_CDECL u_net_bind_ocall(int* retval, int* error, int sockfd, const struct sockaddr_t* addr, uint32_t addrlen);
sgx_status_t SGX_CDECL u_net_connect_ocall(int* retval, int* error, int sockfd, const struct sockaddr_t* addr, uint32_t addrlen);
sgx_status_t SGX_CDECL u_net_recv_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL u_net_recvfrom_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags, struct sockaddr_t* src_addr, uint32_t _in_addrlen, uint32_t* addrlen);
sgx_status_t SGX_CDECL u_net_send_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL u_net_sendto_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr_t* dest_addr, uint32_t addrlen);
sgx_status_t SGX_CDECL u_net_getsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, void* optval, uint32_t _in_optlen, uint32_t* optlen);
sgx_status_t SGX_CDECL u_net_setsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, const void* optval, uint32_t optlen);
sgx_status_t SGX_CDECL u_net_getsockname_ocall(int* retval, int* error, int sockfd, struct sockaddr_t* addr, uint32_t _in_addrlen, uint32_t* addrlen);
sgx_status_t SGX_CDECL u_net_getpeername_ocall(int* retval, int* error, int sockfd, struct sockaddr_t* addr, uint32_t _in_addrlen, uint32_t* addrlen);
sgx_status_t SGX_CDECL u_net_shutdown_ocall(int* retval, int* error, int sockfd, int how);
sgx_status_t SGX_CDECL u_net_ioctl_ocall(int* retval, int* error, int fd, int request, int* arg);
sgx_status_t SGX_CDECL u_fs_open64_ocall(int* retval, int* error, const char* path, int oflag, int mode);
sgx_status_t SGX_CDECL u_fs_read_ocall(size_t* retval, int* error, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL u_fs_pread64_ocall(size_t* retval, int* error, int fd, void* buf, size_t count, int64_t offset);
sgx_status_t SGX_CDECL u_fs_write_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL u_fs_pwrite64_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count, int64_t offset);
sgx_status_t SGX_CDECL u_fs_close_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fs_fcntl_arg0_ocall(int* retval, int* error, int fd, int cmd);
sgx_status_t SGX_CDECL u_fs_fcntl_arg1_ocall(int* retval, int* error, int fd, int cmd, int arg);
sgx_status_t SGX_CDECL u_fs_ioctl_arg0_ocall(int* retval, int* error, int fd, int request);
sgx_status_t SGX_CDECL u_fs_ioctl_arg1_ocall(int* retval, int* error, int fd, int request, int* arg);
sgx_status_t SGX_CDECL u_fs_fstat64_ocall(int* retval, int* error, int fd, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_fs_fsync_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fs_fdatasync_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fs_ftruncate64_ocall(int* retval, int* error, int fd, int64_t length);
sgx_status_t SGX_CDECL u_fs_lseek64_ocall(int64_t* retval, int* error, int fd, int64_t offset, int whence);
sgx_status_t SGX_CDECL u_fs_fchmod_ocall(int* retval, int* error, int fd, uint32_t mode);
sgx_status_t SGX_CDECL u_fs_unlink_ocall(int* retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_fs_link_ocall(int* retval, int* error, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_fs_rename_ocall(int* retval, int* error, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_fs_chmod_ocall(int* retval, int* error, const char* path, uint32_t mode);
sgx_status_t SGX_CDECL u_fs_readlink_ocall(size_t* retval, int* error, const char* path, char* buf, size_t bufsz);
sgx_status_t SGX_CDECL u_fs_symlink_ocall(int* retval, int* error, const char* path1, const char* path2);
sgx_status_t SGX_CDECL u_fs_stat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_fs_lstat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_fs_realpath_ocall(char** retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_fs_free_ocall(void* p);
sgx_status_t SGX_CDECL u_clock_gettime_ocall(int* retval, int* error, int clk_id, struct timespec* tp);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_write_ocall(ssize_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL buildmerkletree(int* retval, struct MerkleTree* tree);
sgx_status_t SGX_CDECL writemerkletree(int* retval, struct MerkleTree* tree);
sgx_status_t SGX_CDECL MTPrintNodeByIndex(struct MerkleTree* treeptr, int idx);
sgx_status_t SGX_CDECL MTUpdateNode(struct MerkleTree* treeptr, int idx);
sgx_status_t SGX_CDECL MTGetMerkleProof(MerkleProof** retval, struct MerkleTree* treeptr, int nodeidx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
