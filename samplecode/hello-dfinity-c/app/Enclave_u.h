#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

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
#ifndef U_NET_BIND_OCALL_DEFINED__
#define U_NET_BIND_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_bind_ocall, (int* error, int sockfd, const struct sockaddr_t* addr, uint32_t addrlen));
#endif
#ifndef U_NET_CONNECT_OCALL_DEFINED__
#define U_NET_CONNECT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_connect_ocall, (int* error, int sockfd, const struct sockaddr_t* addr, uint32_t addrlen));
#endif
#ifndef U_NET_RECV_OCALL_DEFINED__
#define U_NET_RECV_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_net_recv_ocall, (int* error, int sockfd, void* buf, size_t len, int flags));
#endif
#ifndef U_NET_RECVFROM_OCALL_DEFINED__
#define U_NET_RECVFROM_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_net_recvfrom_ocall, (int* error, int sockfd, void* buf, size_t len, int flags, struct sockaddr_t* src_addr, uint32_t _in_addrlen, uint32_t* addrlen));
#endif
#ifndef U_NET_SEND_OCALL_DEFINED__
#define U_NET_SEND_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_net_send_ocall, (int* error, int sockfd, const void* buf, size_t len, int flags));
#endif
#ifndef U_NET_SENDTO_OCALL_DEFINED__
#define U_NET_SENDTO_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_net_sendto_ocall, (int* error, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr_t* dest_addr, uint32_t addrlen));
#endif
#ifndef U_NET_GETSOCKOPT_OCALL_DEFINED__
#define U_NET_GETSOCKOPT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_getsockopt_ocall, (int* error, int sockfd, int level, int optname, void* optval, uint32_t _in_optlen, uint32_t* optlen));
#endif
#ifndef U_NET_SETSOCKOPT_OCALL_DEFINED__
#define U_NET_SETSOCKOPT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_setsockopt_ocall, (int* error, int sockfd, int level, int optname, const void* optval, uint32_t optlen));
#endif
#ifndef U_NET_GETSOCKNAME_OCALL_DEFINED__
#define U_NET_GETSOCKNAME_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_getsockname_ocall, (int* error, int sockfd, struct sockaddr_t* addr, uint32_t _in_addrlen, uint32_t* addrlen));
#endif
#ifndef U_NET_GETPEERNAME_OCALL_DEFINED__
#define U_NET_GETPEERNAME_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_getpeername_ocall, (int* error, int sockfd, struct sockaddr_t* addr, uint32_t _in_addrlen, uint32_t* addrlen));
#endif
#ifndef U_NET_SHUTDOWN_OCALL_DEFINED__
#define U_NET_SHUTDOWN_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_shutdown_ocall, (int* error, int sockfd, int how));
#endif
#ifndef U_NET_IOCTL_OCALL_DEFINED__
#define U_NET_IOCTL_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_net_ioctl_ocall, (int* error, int fd, int request, int* arg));
#endif
#ifndef U_FS_OPEN64_OCALL_DEFINED__
#define U_FS_OPEN64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_open64_ocall, (int* error, const char* path, int oflag, int mode));
#endif
#ifndef U_FS_READ_OCALL_DEFINED__
#define U_FS_READ_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_read_ocall, (int* error, int fd, void* buf, size_t count));
#endif
#ifndef U_FS_PREAD64_OCALL_DEFINED__
#define U_FS_PREAD64_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_pread64_ocall, (int* error, int fd, void* buf, size_t count, int64_t offset));
#endif
#ifndef U_FS_WRITE_OCALL_DEFINED__
#define U_FS_WRITE_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_write_ocall, (int* error, int fd, const void* buf, size_t count));
#endif
#ifndef U_FS_PWRITE64_OCALL_DEFINED__
#define U_FS_PWRITE64_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_pwrite64_ocall, (int* error, int fd, const void* buf, size_t count, int64_t offset));
#endif
#ifndef U_FS_CLOSE_OCALL_DEFINED__
#define U_FS_CLOSE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_close_ocall, (int* error, int fd));
#endif
#ifndef U_FS_FCNTL_ARG0_OCALL_DEFINED__
#define U_FS_FCNTL_ARG0_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fcntl_arg0_ocall, (int* error, int fd, int cmd));
#endif
#ifndef U_FS_FCNTL_ARG1_OCALL_DEFINED__
#define U_FS_FCNTL_ARG1_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fcntl_arg1_ocall, (int* error, int fd, int cmd, int arg));
#endif
#ifndef U_FS_IOCTL_ARG0_OCALL_DEFINED__
#define U_FS_IOCTL_ARG0_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_ioctl_arg0_ocall, (int* error, int fd, int request));
#endif
#ifndef U_FS_IOCTL_ARG1_OCALL_DEFINED__
#define U_FS_IOCTL_ARG1_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_ioctl_arg1_ocall, (int* error, int fd, int request, int* arg));
#endif
#ifndef U_FS_FSTAT64_OCALL_DEFINED__
#define U_FS_FSTAT64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fstat64_ocall, (int* error, int fd, struct stat64_t* buf));
#endif
#ifndef U_FS_FSYNC_OCALL_DEFINED__
#define U_FS_FSYNC_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fsync_ocall, (int* error, int fd));
#endif
#ifndef U_FS_FDATASYNC_OCALL_DEFINED__
#define U_FS_FDATASYNC_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fdatasync_ocall, (int* error, int fd));
#endif
#ifndef U_FS_FTRUNCATE64_OCALL_DEFINED__
#define U_FS_FTRUNCATE64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_ftruncate64_ocall, (int* error, int fd, int64_t length));
#endif
#ifndef U_FS_LSEEK64_OCALL_DEFINED__
#define U_FS_LSEEK64_OCALL_DEFINED__
int64_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_lseek64_ocall, (int* error, int fd, int64_t offset, int whence));
#endif
#ifndef U_FS_FCHMOD_OCALL_DEFINED__
#define U_FS_FCHMOD_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fchmod_ocall, (int* error, int fd, uint32_t mode));
#endif
#ifndef U_FS_UNLINK_OCALL_DEFINED__
#define U_FS_UNLINK_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_unlink_ocall, (int* error, const char* pathname));
#endif
#ifndef U_FS_LINK_OCALL_DEFINED__
#define U_FS_LINK_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_link_ocall, (int* error, const char* oldpath, const char* newpath));
#endif
#ifndef U_FS_RENAME_OCALL_DEFINED__
#define U_FS_RENAME_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_rename_ocall, (int* error, const char* oldpath, const char* newpath));
#endif
#ifndef U_FS_CHMOD_OCALL_DEFINED__
#define U_FS_CHMOD_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_chmod_ocall, (int* error, const char* path, uint32_t mode));
#endif
#ifndef U_FS_READLINK_OCALL_DEFINED__
#define U_FS_READLINK_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_readlink_ocall, (int* error, const char* path, char* buf, size_t bufsz));
#endif
#ifndef U_FS_SYMLINK_OCALL_DEFINED__
#define U_FS_SYMLINK_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_symlink_ocall, (int* error, const char* path1, const char* path2));
#endif
#ifndef U_FS_STAT64_OCALL_DEFINED__
#define U_FS_STAT64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_stat64_ocall, (int* error, const char* path, struct stat64_t* buf));
#endif
#ifndef U_FS_LSTAT64_OCALL_DEFINED__
#define U_FS_LSTAT64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_lstat64_ocall, (int* error, const char* path, struct stat64_t* buf));
#endif
#ifndef U_FS_REALPATH_OCALL_DEFINED__
#define U_FS_REALPATH_OCALL_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_realpath_ocall, (int* error, const char* pathname));
#endif
#ifndef U_FS_FREE_OCALL_DEFINED__
#define U_FS_FREE_OCALL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_free_ocall, (void* p));
#endif
#ifndef U_CLOCK_GETTIME_OCALL_DEFINED__
#define U_CLOCK_GETTIME_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_clock_gettime_ocall, (int* error, int clk_id, struct timespec* tp));
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
#ifndef U_WRITE_OCALL_DEFINED__
#define U_WRITE_OCALL_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_write_ocall, (int fd, const void* buf, size_t count));
#endif
#ifndef BUILDMERKLETREE_DEFINED__
#define BUILDMERKLETREE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, buildmerkletree, (struct MerkleTree* tree));
#endif
#ifndef WRITEMERKLETREE_DEFINED__
#define WRITEMERKLETREE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, writemerkletree, (struct MerkleTree* tree));
#endif
#ifndef MTPRINTNODEBYINDEX_DEFINED__
#define MTPRINTNODEBYINDEX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, MTPrintNodeByIndex, (struct MerkleTree* treeptr, int idx));
#endif
#ifndef MTUPDATENODE_DEFINED__
#define MTUPDATENODE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, MTUpdateNode, (struct MerkleTree* treeptr, int idx));
#endif
#ifndef MTGETMERKLEPROOF_DEFINED__
#define MTGETMERKLEPROOF_DEFINED__
MerkleProof* SGX_UBRIDGE(SGX_NOCONVENTION, MTGetMerkleProof, (struct MerkleTree* treeptr, int nodeidx));
#endif

sgx_status_t merkletreeflow(sgx_enclave_id_t eid, sgx_status_t* retval, MerkleTree* tree, HASHTYPE roothash, int codeid, int dataid, char* report, char* wasmfunc, int wasmargs);
sgx_status_t t_global_init_ecall(sgx_enclave_id_t eid, uint64_t id, const uint8_t* path, size_t len);
sgx_status_t t_global_exit_ecall(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
