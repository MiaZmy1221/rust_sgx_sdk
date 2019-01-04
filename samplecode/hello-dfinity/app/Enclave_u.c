#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_merkletreeflow_t {
	sgx_status_t ms_retval;
	MerkleTree* ms_tree;
	HASHTYPE ms_roothash;
	int ms_codeid;
	int ms_dataid;
	char* ms_report;
	char* ms_wasmfunc;
	int ms_wasmargs;
} ms_merkletreeflow_t;

typedef struct ms_t_global_init_ecall_t {
	uint64_t ms_id;
	const uint8_t* ms_path;
	size_t ms_len;
} ms_t_global_init_ecall_t;

typedef struct ms_ocall_sgx_init_quote_t {
	sgx_status_t ms_retval;
	sgx_target_info_t* ms_ret_ti;
	sgx_epid_group_id_t* ms_ret_gid;
} ms_ocall_sgx_init_quote_t;

typedef struct ms_ocall_get_ias_socket_t {
	sgx_status_t ms_retval;
	int* ms_ret_fd;
} ms_ocall_get_ias_socket_t;

typedef struct ms_ocall_get_quote_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_sigrl;
	uint32_t ms_sigrl_len;
	sgx_report_t* ms_report;
	sgx_quote_sign_type_t ms_quote_type;
	sgx_spid_t* ms_p_spid;
	sgx_quote_nonce_t* ms_p_nonce;
	sgx_report_t* ms_p_qe_report;
	sgx_quote_t* ms_p_quote;
	uint32_t ms_maxlen;
	uint32_t* ms_p_quote_len;
} ms_ocall_get_quote_t;

typedef struct ms_ocall_get_update_info_t {
	sgx_status_t ms_retval;
	sgx_platform_info_t* ms_platformBlob;
	int32_t ms_enclaveTrusted;
	sgx_update_info_bit_t* ms_update_info;
} ms_ocall_get_update_info_t;

typedef struct ms_u_backtrace_open_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_pathname;
	int ms_flags;
} ms_u_backtrace_open_ocall_t;

typedef struct ms_u_backtrace_close_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_backtrace_close_ocall_t;

typedef struct ms_u_backtrace_fcntl_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
} ms_u_backtrace_fcntl_ocall_t;

typedef struct ms_u_backtrace_mmap_ocall_t {
	void* ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
	int ms_prot;
	int ms_flags;
	int ms_fd;
	int64_t ms_offset;
} ms_u_backtrace_mmap_ocall_t;

typedef struct ms_u_backtrace_munmap_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
} ms_u_backtrace_munmap_ocall_t;

typedef struct ms_u_stdin_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdin_ocall_t;

typedef struct ms_u_stdout_ocall_t {
	size_t ms_retval;
	const void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdout_ocall_t;

typedef struct ms_u_stderr_ocall_t {
	size_t ms_retval;
	const void* ms_buf;
	size_t ms_nbytes;
} ms_u_stderr_ocall_t;

typedef struct ms_u_net_bind_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	const struct sockaddr_t* ms_addr;
	uint32_t ms_addrlen;
} ms_u_net_bind_ocall_t;

typedef struct ms_u_net_connect_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	const struct sockaddr_t* ms_addr;
	uint32_t ms_addrlen;
} ms_u_net_connect_ocall_t;

typedef struct ms_u_net_recv_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_u_net_recv_ocall_t;

typedef struct ms_u_net_recvfrom_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
	struct sockaddr_t* ms_src_addr;
	uint32_t ms__in_addrlen;
	uint32_t* ms_addrlen;
} ms_u_net_recvfrom_ocall_t;

typedef struct ms_u_net_send_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_u_net_send_ocall_t;

typedef struct ms_u_net_sendto_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
	const struct sockaddr_t* ms_dest_addr;
	uint32_t ms_addrlen;
} ms_u_net_sendto_ocall_t;

typedef struct ms_u_net_getsockopt_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	void* ms_optval;
	uint32_t ms__in_optlen;
	uint32_t* ms_optlen;
} ms_u_net_getsockopt_ocall_t;

typedef struct ms_u_net_setsockopt_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	const void* ms_optval;
	uint32_t ms_optlen;
} ms_u_net_setsockopt_ocall_t;

typedef struct ms_u_net_getsockname_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	struct sockaddr_t* ms_addr;
	uint32_t ms__in_addrlen;
	uint32_t* ms_addrlen;
} ms_u_net_getsockname_ocall_t;

typedef struct ms_u_net_getpeername_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	struct sockaddr_t* ms_addr;
	uint32_t ms__in_addrlen;
	uint32_t* ms_addrlen;
} ms_u_net_getpeername_ocall_t;

typedef struct ms_u_net_shutdown_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_sockfd;
	int ms_how;
} ms_u_net_shutdown_ocall_t;

typedef struct ms_u_net_ioctl_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_request;
	int* ms_arg;
} ms_u_net_ioctl_ocall_t;

typedef struct ms_u_fs_open64_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	int ms_oflag;
	int ms_mode;
} ms_u_fs_open64_ocall_t;

typedef struct ms_u_fs_read_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_fs_read_ocall_t;

typedef struct ms_u_fs_pread64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	int64_t ms_offset;
} ms_u_fs_pread64_ocall_t;

typedef struct ms_u_fs_write_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
} ms_u_fs_write_ocall_t;

typedef struct ms_u_fs_pwrite64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
	int64_t ms_offset;
} ms_u_fs_pwrite64_ocall_t;

typedef struct ms_u_fs_close_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fs_close_ocall_t;

typedef struct ms_u_fs_fcntl_arg0_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
} ms_u_fs_fcntl_arg0_ocall_t;

typedef struct ms_u_fs_fcntl_arg1_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
} ms_u_fs_fcntl_arg1_ocall_t;

typedef struct ms_u_fs_ioctl_arg0_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_request;
} ms_u_fs_ioctl_arg0_ocall_t;

typedef struct ms_u_fs_ioctl_arg1_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_request;
	int* ms_arg;
} ms_u_fs_ioctl_arg1_ocall_t;

typedef struct ms_u_fs_fstat64_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	struct stat64_t* ms_buf;
} ms_u_fs_fstat64_ocall_t;

typedef struct ms_u_fs_fsync_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fs_fsync_ocall_t;

typedef struct ms_u_fs_fdatasync_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fs_fdatasync_ocall_t;

typedef struct ms_u_fs_ftruncate64_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_length;
} ms_u_fs_ftruncate64_ocall_t;

typedef struct ms_u_fs_lseek64_ocall_t {
	int64_t ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_offset;
	int ms_whence;
} ms_u_fs_lseek64_ocall_t;

typedef struct ms_u_fs_fchmod_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	uint32_t ms_mode;
} ms_u_fs_fchmod_ocall_t;

typedef struct ms_u_fs_unlink_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_pathname;
} ms_u_fs_unlink_ocall_t;

typedef struct ms_u_fs_link_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_u_fs_link_ocall_t;

typedef struct ms_u_fs_rename_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_u_fs_rename_ocall_t;

typedef struct ms_u_fs_chmod_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	uint32_t ms_mode;
} ms_u_fs_chmod_ocall_t;

typedef struct ms_u_fs_readlink_ocall_t {
	size_t ms_retval;
	int* ms_error;
	const char* ms_path;
	char* ms_buf;
	size_t ms_bufsz;
} ms_u_fs_readlink_ocall_t;

typedef struct ms_u_fs_symlink_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path1;
	const char* ms_path2;
} ms_u_fs_symlink_ocall_t;

typedef struct ms_u_fs_stat64_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	struct stat64_t* ms_buf;
} ms_u_fs_stat64_ocall_t;

typedef struct ms_u_fs_lstat64_ocall_t {
	int ms_retval;
	int* ms_error;
	const char* ms_path;
	struct stat64_t* ms_buf;
} ms_u_fs_lstat64_ocall_t;

typedef struct ms_u_fs_realpath_ocall_t {
	char* ms_retval;
	int* ms_error;
	const char* ms_pathname;
} ms_u_fs_realpath_ocall_t;

typedef struct ms_u_fs_free_ocall_t {
	void* ms_p;
} ms_u_fs_free_ocall_t;

typedef struct ms_u_clock_gettime_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_clk_id;
	struct timespec* ms_tp;
} ms_u_clock_gettime_ocall_t;

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

typedef struct ms_u_write_ocall_t {
	ssize_t ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
} ms_u_write_ocall_t;

typedef struct ms_buildmerkletree_t {
	int ms_retval;
	struct MerkleTree* ms_tree;
} ms_buildmerkletree_t;

typedef struct ms_writemerkletree_t {
	int ms_retval;
	struct MerkleTree* ms_tree;
} ms_writemerkletree_t;

typedef struct ms_MTPrintNodeByIndex_t {
	struct MerkleTree* ms_treeptr;
	int ms_idx;
} ms_MTPrintNodeByIndex_t;

typedef struct ms_MTUpdateNode_t {
	struct MerkleTree* ms_treeptr;
	int ms_idx;
} ms_MTUpdateNode_t;

typedef struct ms_MTGetMerkleProof_t {
	MerkleProof* ms_retval;
	struct MerkleTree* ms_treeptr;
	int ms_nodeidx;
} ms_MTGetMerkleProof_t;

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_init_quote(void* pms)
{
	ms_ocall_sgx_init_quote_t* ms = SGX_CAST(ms_ocall_sgx_init_quote_t*, pms);
	ms->ms_retval = ocall_sgx_init_quote(ms->ms_ret_ti, ms->ms_ret_gid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_ias_socket(void* pms)
{
	ms_ocall_get_ias_socket_t* ms = SGX_CAST(ms_ocall_get_ias_socket_t*, pms);
	ms->ms_retval = ocall_get_ias_socket(ms->ms_ret_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_quote(void* pms)
{
	ms_ocall_get_quote_t* ms = SGX_CAST(ms_ocall_get_quote_t*, pms);
	ms->ms_retval = ocall_get_quote(ms->ms_p_sigrl, ms->ms_sigrl_len, ms->ms_report, ms->ms_quote_type, ms->ms_p_spid, ms->ms_p_nonce, ms->ms_p_qe_report, ms->ms_p_quote, ms->ms_maxlen, ms->ms_p_quote_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_update_info(void* pms)
{
	ms_ocall_get_update_info_t* ms = SGX_CAST(ms_ocall_get_update_info_t*, pms);
	ms->ms_retval = ocall_get_update_info(ms->ms_platformBlob, ms->ms_enclaveTrusted, ms->ms_update_info);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_open_ocall(void* pms)
{
	ms_u_backtrace_open_ocall_t* ms = SGX_CAST(ms_u_backtrace_open_ocall_t*, pms);
	ms->ms_retval = u_backtrace_open_ocall(ms->ms_error, ms->ms_pathname, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_close_ocall(void* pms)
{
	ms_u_backtrace_close_ocall_t* ms = SGX_CAST(ms_u_backtrace_close_ocall_t*, pms);
	ms->ms_retval = u_backtrace_close_ocall(ms->ms_error, ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_fcntl_ocall(void* pms)
{
	ms_u_backtrace_fcntl_ocall_t* ms = SGX_CAST(ms_u_backtrace_fcntl_ocall_t*, pms);
	ms->ms_retval = u_backtrace_fcntl_ocall(ms->ms_error, ms->ms_fd, ms->ms_cmd, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_mmap_ocall(void* pms)
{
	ms_u_backtrace_mmap_ocall_t* ms = SGX_CAST(ms_u_backtrace_mmap_ocall_t*, pms);
	ms->ms_retval = u_backtrace_mmap_ocall(ms->ms_error, ms->ms_start, ms->ms_length, ms->ms_prot, ms->ms_flags, ms->ms_fd, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_munmap_ocall(void* pms)
{
	ms_u_backtrace_munmap_ocall_t* ms = SGX_CAST(ms_u_backtrace_munmap_ocall_t*, pms);
	ms->ms_retval = u_backtrace_munmap_ocall(ms->ms_error, ms->ms_start, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_stdin_ocall(void* pms)
{
	ms_u_stdin_ocall_t* ms = SGX_CAST(ms_u_stdin_ocall_t*, pms);
	ms->ms_retval = u_stdin_ocall(ms->ms_buf, ms->ms_nbytes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_stdout_ocall(void* pms)
{
	ms_u_stdout_ocall_t* ms = SGX_CAST(ms_u_stdout_ocall_t*, pms);
	ms->ms_retval = u_stdout_ocall(ms->ms_buf, ms->ms_nbytes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_stderr_ocall(void* pms)
{
	ms_u_stderr_ocall_t* ms = SGX_CAST(ms_u_stderr_ocall_t*, pms);
	ms->ms_retval = u_stderr_ocall(ms->ms_buf, ms->ms_nbytes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_bind_ocall(void* pms)
{
	ms_u_net_bind_ocall_t* ms = SGX_CAST(ms_u_net_bind_ocall_t*, pms);
	ms->ms_retval = u_net_bind_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_connect_ocall(void* pms)
{
	ms_u_net_connect_ocall_t* ms = SGX_CAST(ms_u_net_connect_ocall_t*, pms);
	ms->ms_retval = u_net_connect_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_recv_ocall(void* pms)
{
	ms_u_net_recv_ocall_t* ms = SGX_CAST(ms_u_net_recv_ocall_t*, pms);
	ms->ms_retval = u_net_recv_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_recvfrom_ocall(void* pms)
{
	ms_u_net_recvfrom_ocall_t* ms = SGX_CAST(ms_u_net_recvfrom_ocall_t*, pms);
	ms->ms_retval = u_net_recvfrom_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_src_addr, ms->ms__in_addrlen, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_send_ocall(void* pms)
{
	ms_u_net_send_ocall_t* ms = SGX_CAST(ms_u_net_send_ocall_t*, pms);
	ms->ms_retval = u_net_send_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_sendto_ocall(void* pms)
{
	ms_u_net_sendto_ocall_t* ms = SGX_CAST(ms_u_net_sendto_ocall_t*, pms);
	ms->ms_retval = u_net_sendto_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_dest_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_getsockopt_ocall(void* pms)
{
	ms_u_net_getsockopt_ocall_t* ms = SGX_CAST(ms_u_net_getsockopt_ocall_t*, pms);
	ms->ms_retval = u_net_getsockopt_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms__in_optlen, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_setsockopt_ocall(void* pms)
{
	ms_u_net_setsockopt_ocall_t* ms = SGX_CAST(ms_u_net_setsockopt_ocall_t*, pms);
	ms->ms_retval = u_net_setsockopt_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_getsockname_ocall(void* pms)
{
	ms_u_net_getsockname_ocall_t* ms = SGX_CAST(ms_u_net_getsockname_ocall_t*, pms);
	ms->ms_retval = u_net_getsockname_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_addr, ms->ms__in_addrlen, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_getpeername_ocall(void* pms)
{
	ms_u_net_getpeername_ocall_t* ms = SGX_CAST(ms_u_net_getpeername_ocall_t*, pms);
	ms->ms_retval = u_net_getpeername_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_addr, ms->ms__in_addrlen, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_shutdown_ocall(void* pms)
{
	ms_u_net_shutdown_ocall_t* ms = SGX_CAST(ms_u_net_shutdown_ocall_t*, pms);
	ms->ms_retval = u_net_shutdown_ocall(ms->ms_error, ms->ms_sockfd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_net_ioctl_ocall(void* pms)
{
	ms_u_net_ioctl_ocall_t* ms = SGX_CAST(ms_u_net_ioctl_ocall_t*, pms);
	ms->ms_retval = u_net_ioctl_ocall(ms->ms_error, ms->ms_fd, ms->ms_request, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_open64_ocall(void* pms)
{
	ms_u_fs_open64_ocall_t* ms = SGX_CAST(ms_u_fs_open64_ocall_t*, pms);
	ms->ms_retval = u_fs_open64_ocall(ms->ms_error, ms->ms_path, ms->ms_oflag, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_read_ocall(void* pms)
{
	ms_u_fs_read_ocall_t* ms = SGX_CAST(ms_u_fs_read_ocall_t*, pms);
	ms->ms_retval = u_fs_read_ocall(ms->ms_error, ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_pread64_ocall(void* pms)
{
	ms_u_fs_pread64_ocall_t* ms = SGX_CAST(ms_u_fs_pread64_ocall_t*, pms);
	ms->ms_retval = u_fs_pread64_ocall(ms->ms_error, ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_write_ocall(void* pms)
{
	ms_u_fs_write_ocall_t* ms = SGX_CAST(ms_u_fs_write_ocall_t*, pms);
	ms->ms_retval = u_fs_write_ocall(ms->ms_error, ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_pwrite64_ocall(void* pms)
{
	ms_u_fs_pwrite64_ocall_t* ms = SGX_CAST(ms_u_fs_pwrite64_ocall_t*, pms);
	ms->ms_retval = u_fs_pwrite64_ocall(ms->ms_error, ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_close_ocall(void* pms)
{
	ms_u_fs_close_ocall_t* ms = SGX_CAST(ms_u_fs_close_ocall_t*, pms);
	ms->ms_retval = u_fs_close_ocall(ms->ms_error, ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_fcntl_arg0_ocall(void* pms)
{
	ms_u_fs_fcntl_arg0_ocall_t* ms = SGX_CAST(ms_u_fs_fcntl_arg0_ocall_t*, pms);
	ms->ms_retval = u_fs_fcntl_arg0_ocall(ms->ms_error, ms->ms_fd, ms->ms_cmd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_fcntl_arg1_ocall(void* pms)
{
	ms_u_fs_fcntl_arg1_ocall_t* ms = SGX_CAST(ms_u_fs_fcntl_arg1_ocall_t*, pms);
	ms->ms_retval = u_fs_fcntl_arg1_ocall(ms->ms_error, ms->ms_fd, ms->ms_cmd, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_ioctl_arg0_ocall(void* pms)
{
	ms_u_fs_ioctl_arg0_ocall_t* ms = SGX_CAST(ms_u_fs_ioctl_arg0_ocall_t*, pms);
	ms->ms_retval = u_fs_ioctl_arg0_ocall(ms->ms_error, ms->ms_fd, ms->ms_request);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_ioctl_arg1_ocall(void* pms)
{
	ms_u_fs_ioctl_arg1_ocall_t* ms = SGX_CAST(ms_u_fs_ioctl_arg1_ocall_t*, pms);
	ms->ms_retval = u_fs_ioctl_arg1_ocall(ms->ms_error, ms->ms_fd, ms->ms_request, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_fstat64_ocall(void* pms)
{
	ms_u_fs_fstat64_ocall_t* ms = SGX_CAST(ms_u_fs_fstat64_ocall_t*, pms);
	ms->ms_retval = u_fs_fstat64_ocall(ms->ms_error, ms->ms_fd, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_fsync_ocall(void* pms)
{
	ms_u_fs_fsync_ocall_t* ms = SGX_CAST(ms_u_fs_fsync_ocall_t*, pms);
	ms->ms_retval = u_fs_fsync_ocall(ms->ms_error, ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_fdatasync_ocall(void* pms)
{
	ms_u_fs_fdatasync_ocall_t* ms = SGX_CAST(ms_u_fs_fdatasync_ocall_t*, pms);
	ms->ms_retval = u_fs_fdatasync_ocall(ms->ms_error, ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_ftruncate64_ocall(void* pms)
{
	ms_u_fs_ftruncate64_ocall_t* ms = SGX_CAST(ms_u_fs_ftruncate64_ocall_t*, pms);
	ms->ms_retval = u_fs_ftruncate64_ocall(ms->ms_error, ms->ms_fd, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_lseek64_ocall(void* pms)
{
	ms_u_fs_lseek64_ocall_t* ms = SGX_CAST(ms_u_fs_lseek64_ocall_t*, pms);
	ms->ms_retval = u_fs_lseek64_ocall(ms->ms_error, ms->ms_fd, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_fchmod_ocall(void* pms)
{
	ms_u_fs_fchmod_ocall_t* ms = SGX_CAST(ms_u_fs_fchmod_ocall_t*, pms);
	ms->ms_retval = u_fs_fchmod_ocall(ms->ms_error, ms->ms_fd, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_unlink_ocall(void* pms)
{
	ms_u_fs_unlink_ocall_t* ms = SGX_CAST(ms_u_fs_unlink_ocall_t*, pms);
	ms->ms_retval = u_fs_unlink_ocall(ms->ms_error, ms->ms_pathname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_link_ocall(void* pms)
{
	ms_u_fs_link_ocall_t* ms = SGX_CAST(ms_u_fs_link_ocall_t*, pms);
	ms->ms_retval = u_fs_link_ocall(ms->ms_error, ms->ms_oldpath, ms->ms_newpath);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_rename_ocall(void* pms)
{
	ms_u_fs_rename_ocall_t* ms = SGX_CAST(ms_u_fs_rename_ocall_t*, pms);
	ms->ms_retval = u_fs_rename_ocall(ms->ms_error, ms->ms_oldpath, ms->ms_newpath);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_chmod_ocall(void* pms)
{
	ms_u_fs_chmod_ocall_t* ms = SGX_CAST(ms_u_fs_chmod_ocall_t*, pms);
	ms->ms_retval = u_fs_chmod_ocall(ms->ms_error, ms->ms_path, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_readlink_ocall(void* pms)
{
	ms_u_fs_readlink_ocall_t* ms = SGX_CAST(ms_u_fs_readlink_ocall_t*, pms);
	ms->ms_retval = u_fs_readlink_ocall(ms->ms_error, ms->ms_path, ms->ms_buf, ms->ms_bufsz);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_symlink_ocall(void* pms)
{
	ms_u_fs_symlink_ocall_t* ms = SGX_CAST(ms_u_fs_symlink_ocall_t*, pms);
	ms->ms_retval = u_fs_symlink_ocall(ms->ms_error, ms->ms_path1, ms->ms_path2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_stat64_ocall(void* pms)
{
	ms_u_fs_stat64_ocall_t* ms = SGX_CAST(ms_u_fs_stat64_ocall_t*, pms);
	ms->ms_retval = u_fs_stat64_ocall(ms->ms_error, ms->ms_path, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_lstat64_ocall(void* pms)
{
	ms_u_fs_lstat64_ocall_t* ms = SGX_CAST(ms_u_fs_lstat64_ocall_t*, pms);
	ms->ms_retval = u_fs_lstat64_ocall(ms->ms_error, ms->ms_path, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_realpath_ocall(void* pms)
{
	ms_u_fs_realpath_ocall_t* ms = SGX_CAST(ms_u_fs_realpath_ocall_t*, pms);
	ms->ms_retval = u_fs_realpath_ocall(ms->ms_error, ms->ms_pathname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fs_free_ocall(void* pms)
{
	ms_u_fs_free_ocall_t* ms = SGX_CAST(ms_u_fs_free_ocall_t*, pms);
	u_fs_free_ocall(ms->ms_p);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_clock_gettime_ocall(void* pms)
{
	ms_u_clock_gettime_ocall_t* ms = SGX_CAST(ms_u_clock_gettime_ocall_t*, pms);
	ms->ms_retval = u_clock_gettime_ocall(ms->ms_error, ms->ms_clk_id, ms->ms_tp);

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

static sgx_status_t SGX_CDECL Enclave_u_write_ocall(void* pms)
{
	ms_u_write_ocall_t* ms = SGX_CAST(ms_u_write_ocall_t*, pms);
	ms->ms_retval = u_write_ocall(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_buildmerkletree(void* pms)
{
	ms_buildmerkletree_t* ms = SGX_CAST(ms_buildmerkletree_t*, pms);
	ms->ms_retval = buildmerkletree(ms->ms_tree);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_writemerkletree(void* pms)
{
	ms_writemerkletree_t* ms = SGX_CAST(ms_writemerkletree_t*, pms);
	ms->ms_retval = writemerkletree(ms->ms_tree);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MTPrintNodeByIndex(void* pms)
{
	ms_MTPrintNodeByIndex_t* ms = SGX_CAST(ms_MTPrintNodeByIndex_t*, pms);
	MTPrintNodeByIndex(ms->ms_treeptr, ms->ms_idx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MTUpdateNode(void* pms)
{
	ms_MTUpdateNode_t* ms = SGX_CAST(ms_MTUpdateNode_t*, pms);
	MTUpdateNode(ms->ms_treeptr, ms->ms_idx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_MTGetMerkleProof(void* pms)
{
	ms_MTGetMerkleProof_t* ms = SGX_CAST(ms_MTGetMerkleProof_t*, pms);
	ms->ms_retval = MTGetMerkleProof(ms->ms_treeptr, ms->ms_nodeidx);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[62];
} ocall_table_Enclave = {
	62,
	{
		(void*)Enclave_ocall_sgx_init_quote,
		(void*)Enclave_ocall_get_ias_socket,
		(void*)Enclave_ocall_get_quote,
		(void*)Enclave_ocall_get_update_info,
		(void*)Enclave_u_backtrace_open_ocall,
		(void*)Enclave_u_backtrace_close_ocall,
		(void*)Enclave_u_backtrace_fcntl_ocall,
		(void*)Enclave_u_backtrace_mmap_ocall,
		(void*)Enclave_u_backtrace_munmap_ocall,
		(void*)Enclave_u_stdin_ocall,
		(void*)Enclave_u_stdout_ocall,
		(void*)Enclave_u_stderr_ocall,
		(void*)Enclave_u_net_bind_ocall,
		(void*)Enclave_u_net_connect_ocall,
		(void*)Enclave_u_net_recv_ocall,
		(void*)Enclave_u_net_recvfrom_ocall,
		(void*)Enclave_u_net_send_ocall,
		(void*)Enclave_u_net_sendto_ocall,
		(void*)Enclave_u_net_getsockopt_ocall,
		(void*)Enclave_u_net_setsockopt_ocall,
		(void*)Enclave_u_net_getsockname_ocall,
		(void*)Enclave_u_net_getpeername_ocall,
		(void*)Enclave_u_net_shutdown_ocall,
		(void*)Enclave_u_net_ioctl_ocall,
		(void*)Enclave_u_fs_open64_ocall,
		(void*)Enclave_u_fs_read_ocall,
		(void*)Enclave_u_fs_pread64_ocall,
		(void*)Enclave_u_fs_write_ocall,
		(void*)Enclave_u_fs_pwrite64_ocall,
		(void*)Enclave_u_fs_close_ocall,
		(void*)Enclave_u_fs_fcntl_arg0_ocall,
		(void*)Enclave_u_fs_fcntl_arg1_ocall,
		(void*)Enclave_u_fs_ioctl_arg0_ocall,
		(void*)Enclave_u_fs_ioctl_arg1_ocall,
		(void*)Enclave_u_fs_fstat64_ocall,
		(void*)Enclave_u_fs_fsync_ocall,
		(void*)Enclave_u_fs_fdatasync_ocall,
		(void*)Enclave_u_fs_ftruncate64_ocall,
		(void*)Enclave_u_fs_lseek64_ocall,
		(void*)Enclave_u_fs_fchmod_ocall,
		(void*)Enclave_u_fs_unlink_ocall,
		(void*)Enclave_u_fs_link_ocall,
		(void*)Enclave_u_fs_rename_ocall,
		(void*)Enclave_u_fs_chmod_ocall,
		(void*)Enclave_u_fs_readlink_ocall,
		(void*)Enclave_u_fs_symlink_ocall,
		(void*)Enclave_u_fs_stat64_ocall,
		(void*)Enclave_u_fs_lstat64_ocall,
		(void*)Enclave_u_fs_realpath_ocall,
		(void*)Enclave_u_fs_free_ocall,
		(void*)Enclave_u_clock_gettime_ocall,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_u_write_ocall,
		(void*)Enclave_buildmerkletree,
		(void*)Enclave_writemerkletree,
		(void*)Enclave_MTPrintNodeByIndex,
		(void*)Enclave_MTUpdateNode,
		(void*)Enclave_MTGetMerkleProof,
	}
};
sgx_status_t merkletreeflow(sgx_enclave_id_t eid, sgx_status_t* retval, MerkleTree* tree, HASHTYPE roothash, int codeid, int dataid, char* report, char* wasmfunc, int wasmargs)
{
	sgx_status_t status;
	ms_merkletreeflow_t ms;
	ms.ms_tree = tree;
	ms.ms_roothash = roothash;
	ms.ms_codeid = codeid;
	ms.ms_dataid = dataid;
	ms.ms_report = report;
	ms.ms_wasmfunc = wasmfunc;
	ms.ms_wasmargs = wasmargs;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t t_global_init_ecall(sgx_enclave_id_t eid, uint64_t id, const uint8_t* path, size_t len)
{
	sgx_status_t status;
	ms_t_global_init_ecall_t ms;
	ms.ms_id = id;
	ms.ms_path = path;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t t_global_exit_ecall(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

