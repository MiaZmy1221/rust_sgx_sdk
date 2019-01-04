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

static sgx_status_t SGX_CDECL sgx_merkletreeflow(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_merkletreeflow_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_merkletreeflow_t* ms = SGX_CAST(ms_merkletreeflow_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	MerkleTree* _tmp_tree = ms->ms_tree;
	char* _tmp_report = ms->ms_report;
	char* _tmp_wasmfunc = ms->ms_wasmfunc;



	ms->ms_retval = merkletreeflow(_tmp_tree, ms->ms_roothash, ms->ms_codeid, ms->ms_dataid, _tmp_report, _tmp_wasmfunc, ms->ms_wasmargs);


	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_init_ecall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_global_init_ecall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_global_init_ecall_t* ms = SGX_CAST(ms_t_global_init_ecall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_path = ms->ms_path;
	size_t _tmp_len = ms->ms_len;
	size_t _len_path = _tmp_len;
	uint8_t* _in_path = NULL;

	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_path != NULL && _len_path != 0) {
		_in_path = (uint8_t*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s((void*)_in_path, _len_path, _tmp_path, _len_path)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	t_global_init_ecall(ms->ms_id, (const uint8_t*)_in_path, _tmp_len);
err:
	if (_in_path) free((void*)_in_path);

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_exit_ecall(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	t_global_exit_ecall();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_merkletreeflow, 0},
		{(void*)(uintptr_t)sgx_t_global_init_ecall, 0},
		{(void*)(uintptr_t)sgx_t_global_exit_ecall, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[62][3];
} g_dyn_entry_table = {
	62,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_sgx_init_quote(sgx_status_t* retval, sgx_target_info_t* ret_ti, sgx_epid_group_id_t* ret_gid)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ret_ti = sizeof(sgx_target_info_t);
	size_t _len_ret_gid = sizeof(sgx_epid_group_id_t);

	ms_ocall_sgx_init_quote_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_init_quote_t);
	void *__tmp = NULL;

	void *__tmp_ret_ti = NULL;
	void *__tmp_ret_gid = NULL;

	CHECK_ENCLAVE_POINTER(ret_ti, _len_ret_ti);
	CHECK_ENCLAVE_POINTER(ret_gid, _len_ret_gid);

	ocalloc_size += (ret_ti != NULL) ? _len_ret_ti : 0;
	ocalloc_size += (ret_gid != NULL) ? _len_ret_gid : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_init_quote_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_init_quote_t));
	ocalloc_size -= sizeof(ms_ocall_sgx_init_quote_t);

	if (ret_ti != NULL) {
		ms->ms_ret_ti = (sgx_target_info_t*)__tmp;
		__tmp_ret_ti = __tmp;
		memset(__tmp_ret_ti, 0, _len_ret_ti);
		__tmp = (void *)((size_t)__tmp + _len_ret_ti);
		ocalloc_size -= _len_ret_ti;
	} else {
		ms->ms_ret_ti = NULL;
	}
	
	if (ret_gid != NULL) {
		ms->ms_ret_gid = (sgx_epid_group_id_t*)__tmp;
		__tmp_ret_gid = __tmp;
		memset(__tmp_ret_gid, 0, _len_ret_gid);
		__tmp = (void *)((size_t)__tmp + _len_ret_gid);
		ocalloc_size -= _len_ret_gid;
	} else {
		ms->ms_ret_gid = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ret_ti) {
			if (memcpy_s((void*)ret_ti, _len_ret_ti, __tmp_ret_ti, _len_ret_ti)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ret_gid) {
			if (memcpy_s((void*)ret_gid, _len_ret_gid, __tmp_ret_gid, _len_ret_gid)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_ias_socket(sgx_status_t* retval, int* ret_fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ret_fd = sizeof(int);

	ms_ocall_get_ias_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_ias_socket_t);
	void *__tmp = NULL;

	void *__tmp_ret_fd = NULL;

	CHECK_ENCLAVE_POINTER(ret_fd, _len_ret_fd);

	ocalloc_size += (ret_fd != NULL) ? _len_ret_fd : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_ias_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_ias_socket_t));
	ocalloc_size -= sizeof(ms_ocall_get_ias_socket_t);

	if (ret_fd != NULL) {
		ms->ms_ret_fd = (int*)__tmp;
		__tmp_ret_fd = __tmp;
		memset(__tmp_ret_fd, 0, _len_ret_fd);
		__tmp = (void *)((size_t)__tmp + _len_ret_fd);
		ocalloc_size -= _len_ret_fd;
	} else {
		ms->ms_ret_fd = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ret_fd) {
			if (memcpy_s((void*)ret_fd, _len_ret_fd, __tmp_ret_fd, _len_ret_fd)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_quote(sgx_status_t* retval, uint8_t* p_sigrl, uint32_t sigrl_len, sgx_report_t* report, sgx_quote_sign_type_t quote_type, sgx_spid_t* p_spid, sgx_quote_nonce_t* p_nonce, sgx_report_t* p_qe_report, sgx_quote_t* p_quote, uint32_t maxlen, uint32_t* p_quote_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_sigrl = sigrl_len;
	size_t _len_report = sizeof(sgx_report_t);
	size_t _len_p_spid = sizeof(sgx_spid_t);
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	size_t _len_p_qe_report = sizeof(sgx_report_t);
	size_t _len_p_quote = maxlen;
	size_t _len_p_quote_len = sizeof(uint32_t);

	ms_ocall_get_quote_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_quote_t);
	void *__tmp = NULL;

	void *__tmp_p_qe_report = NULL;
	void *__tmp_p_quote = NULL;
	void *__tmp_p_quote_len = NULL;

	CHECK_ENCLAVE_POINTER(p_sigrl, _len_p_sigrl);
	CHECK_ENCLAVE_POINTER(report, _len_report);
	CHECK_ENCLAVE_POINTER(p_spid, _len_p_spid);
	CHECK_ENCLAVE_POINTER(p_nonce, _len_p_nonce);
	CHECK_ENCLAVE_POINTER(p_qe_report, _len_p_qe_report);
	CHECK_ENCLAVE_POINTER(p_quote, _len_p_quote);
	CHECK_ENCLAVE_POINTER(p_quote_len, _len_p_quote_len);

	ocalloc_size += (p_sigrl != NULL) ? _len_p_sigrl : 0;
	ocalloc_size += (report != NULL) ? _len_report : 0;
	ocalloc_size += (p_spid != NULL) ? _len_p_spid : 0;
	ocalloc_size += (p_nonce != NULL) ? _len_p_nonce : 0;
	ocalloc_size += (p_qe_report != NULL) ? _len_p_qe_report : 0;
	ocalloc_size += (p_quote != NULL) ? _len_p_quote : 0;
	ocalloc_size += (p_quote_len != NULL) ? _len_p_quote_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_quote_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_quote_t));
	ocalloc_size -= sizeof(ms_ocall_get_quote_t);

	if (p_sigrl != NULL) {
		ms->ms_p_sigrl = (uint8_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, p_sigrl, _len_p_sigrl)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_sigrl);
		ocalloc_size -= _len_p_sigrl;
	} else {
		ms->ms_p_sigrl = NULL;
	}
	
	ms->ms_sigrl_len = sigrl_len;
	if (report != NULL) {
		ms->ms_report = (sgx_report_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, report, _len_report)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_report);
		ocalloc_size -= _len_report;
	} else {
		ms->ms_report = NULL;
	}
	
	ms->ms_quote_type = quote_type;
	if (p_spid != NULL) {
		ms->ms_p_spid = (sgx_spid_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, p_spid, _len_p_spid)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_spid);
		ocalloc_size -= _len_p_spid;
	} else {
		ms->ms_p_spid = NULL;
	}
	
	if (p_nonce != NULL) {
		ms->ms_p_nonce = (sgx_quote_nonce_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, p_nonce, _len_p_nonce)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_nonce);
		ocalloc_size -= _len_p_nonce;
	} else {
		ms->ms_p_nonce = NULL;
	}
	
	if (p_qe_report != NULL) {
		ms->ms_p_qe_report = (sgx_report_t*)__tmp;
		__tmp_p_qe_report = __tmp;
		memset(__tmp_p_qe_report, 0, _len_p_qe_report);
		__tmp = (void *)((size_t)__tmp + _len_p_qe_report);
		ocalloc_size -= _len_p_qe_report;
	} else {
		ms->ms_p_qe_report = NULL;
	}
	
	if (p_quote != NULL) {
		ms->ms_p_quote = (sgx_quote_t*)__tmp;
		__tmp_p_quote = __tmp;
		memset(__tmp_p_quote, 0, _len_p_quote);
		__tmp = (void *)((size_t)__tmp + _len_p_quote);
		ocalloc_size -= _len_p_quote;
	} else {
		ms->ms_p_quote = NULL;
	}
	
	ms->ms_maxlen = maxlen;
	if (p_quote_len != NULL) {
		ms->ms_p_quote_len = (uint32_t*)__tmp;
		__tmp_p_quote_len = __tmp;
		memset(__tmp_p_quote_len, 0, _len_p_quote_len);
		__tmp = (void *)((size_t)__tmp + _len_p_quote_len);
		ocalloc_size -= _len_p_quote_len;
	} else {
		ms->ms_p_quote_len = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_qe_report) {
			if (memcpy_s((void*)p_qe_report, _len_p_qe_report, __tmp_p_qe_report, _len_p_qe_report)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_quote) {
			if (memcpy_s((void*)p_quote, _len_p_quote, __tmp_p_quote, _len_p_quote)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (p_quote_len) {
			if (memcpy_s((void*)p_quote_len, _len_p_quote_len, __tmp_p_quote_len, _len_p_quote_len)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_update_info(sgx_status_t* retval, sgx_platform_info_t* platformBlob, int32_t enclaveTrusted, sgx_update_info_bit_t* update_info)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_platformBlob = sizeof(sgx_platform_info_t);
	size_t _len_update_info = sizeof(sgx_update_info_bit_t);

	ms_ocall_get_update_info_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_update_info_t);
	void *__tmp = NULL;

	void *__tmp_update_info = NULL;

	CHECK_ENCLAVE_POINTER(platformBlob, _len_platformBlob);
	CHECK_ENCLAVE_POINTER(update_info, _len_update_info);

	ocalloc_size += (platformBlob != NULL) ? _len_platformBlob : 0;
	ocalloc_size += (update_info != NULL) ? _len_update_info : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_update_info_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_update_info_t));
	ocalloc_size -= sizeof(ms_ocall_get_update_info_t);

	if (platformBlob != NULL) {
		ms->ms_platformBlob = (sgx_platform_info_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, platformBlob, _len_platformBlob)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_platformBlob);
		ocalloc_size -= _len_platformBlob;
	} else {
		ms->ms_platformBlob = NULL;
	}
	
	ms->ms_enclaveTrusted = enclaveTrusted;
	if (update_info != NULL) {
		ms->ms_update_info = (sgx_update_info_bit_t*)__tmp;
		__tmp_update_info = __tmp;
		memset(__tmp_update_info, 0, _len_update_info);
		__tmp = (void *)((size_t)__tmp + _len_update_info);
		ocalloc_size -= _len_update_info;
	} else {
		ms->ms_update_info = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (update_info) {
			if (memcpy_s((void*)update_info, _len_update_info, __tmp_update_info, _len_update_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_open_ocall(int* retval, int* error, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_backtrace_open_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_open_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (pathname != NULL) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_open_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_open_ocall_t));
	ocalloc_size -= sizeof(ms_u_backtrace_open_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_close_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_close_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_close_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_close_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_close_ocall_t));
	ocalloc_size -= sizeof(ms_u_backtrace_close_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_fcntl_ocall(int* retval, int* error, int fd, int cmd, int arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_fcntl_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_fcntl_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_fcntl_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_fcntl_ocall_t));
	ocalloc_size -= sizeof(ms_u_backtrace_fcntl_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_mmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_mmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_mmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_mmap_ocall_t));
	ocalloc_size -= sizeof(ms_u_backtrace_mmap_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_start = start;
	ms->ms_length = length;
	ms->ms_prot = prot;
	ms->ms_flags = flags;
	ms->ms_fd = fd;
	ms->ms_offset = offset;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_munmap_ocall(int* retval, int* error, void* start, size_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_backtrace_munmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_munmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_munmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_munmap_ocall_t));
	ocalloc_size -= sizeof(ms_u_backtrace_munmap_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_start = start;
	ms->ms_length = length;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stdin_ocall(size_t* retval, void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdin_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdin_ocall_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdin_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdin_ocall_t));
	ocalloc_size -= sizeof(ms_u_stdin_ocall_t);

	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stdout_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdout_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdout_ocall_t));
	ocalloc_size -= sizeof(ms_u_stdout_ocall_t);

	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stderr_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stderr_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stderr_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stderr_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stderr_ocall_t));
	ocalloc_size -= sizeof(ms_u_stderr_ocall_t);

	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_bind_ocall(int* retval, int* error, int sockfd, const struct sockaddr_t* addr, uint32_t addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen;

	ms_u_net_bind_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_bind_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (addr != NULL) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_bind_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_bind_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_bind_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (addr != NULL) {
		ms->ms_addr = (const struct sockaddr_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}
	
	ms->ms_addrlen = addrlen;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_connect_ocall(int* retval, int* error, int sockfd, const struct sockaddr_t* addr, uint32_t addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = addrlen;

	ms_u_net_connect_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_connect_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (addr != NULL) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_connect_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_connect_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_connect_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (addr != NULL) {
		ms->ms_addr = (const struct sockaddr_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}
	
	ms->ms_addrlen = addrlen;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_recv_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = len;

	ms_u_net_recv_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_recv_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_recv_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_recv_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_recv_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_recvfrom_ocall(size_t* retval, int* error, int sockfd, void* buf, size_t len, int flags, struct sockaddr_t* src_addr, uint32_t _in_addrlen, uint32_t* addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = len;
	size_t _len_src_addr = _in_addrlen;
	size_t _len_addrlen = sizeof(uint32_t);

	ms_u_net_recvfrom_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_recvfrom_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;
	void *__tmp_src_addr = NULL;
	void *__tmp_addrlen = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(src_addr, _len_src_addr);
	CHECK_ENCLAVE_POINTER(addrlen, _len_addrlen);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;
	ocalloc_size += (src_addr != NULL) ? _len_src_addr : 0;
	ocalloc_size += (addrlen != NULL) ? _len_addrlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_recvfrom_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_recvfrom_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_recvfrom_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	if (src_addr != NULL) {
		ms->ms_src_addr = (struct sockaddr_t*)__tmp;
		__tmp_src_addr = __tmp;
		memset(__tmp_src_addr, 0, _len_src_addr);
		__tmp = (void *)((size_t)__tmp + _len_src_addr);
		ocalloc_size -= _len_src_addr;
	} else {
		ms->ms_src_addr = NULL;
	}
	
	ms->ms__in_addrlen = _in_addrlen;
	if (addrlen != NULL) {
		ms->ms_addrlen = (uint32_t*)__tmp;
		__tmp_addrlen = __tmp;
		if (memcpy_s(__tmp_addrlen, ocalloc_size, addrlen, _len_addrlen)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addrlen);
		ocalloc_size -= _len_addrlen;
	} else {
		ms->ms_addrlen = NULL;
	}
	
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (src_addr) {
			if (memcpy_s((void*)src_addr, _len_src_addr, __tmp_src_addr, _len_src_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen) {
			if (memcpy_s((void*)addrlen, _len_addrlen, __tmp_addrlen, _len_addrlen)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_send_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = len;

	ms_u_net_send_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_send_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_send_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_send_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_send_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_sendto_ocall(size_t* retval, int* error, int sockfd, const void* buf, size_t len, int flags, const struct sockaddr_t* dest_addr, uint32_t addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = len;
	size_t _len_dest_addr = addrlen;

	ms_u_net_sendto_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_sendto_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(dest_addr, _len_dest_addr);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;
	ocalloc_size += (dest_addr != NULL) ? _len_dest_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_sendto_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_sendto_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_sendto_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	if (dest_addr != NULL) {
		ms->ms_dest_addr = (const struct sockaddr_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, dest_addr, _len_dest_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dest_addr);
		ocalloc_size -= _len_dest_addr;
	} else {
		ms->ms_dest_addr = NULL;
	}
	
	ms->ms_addrlen = addrlen;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_getsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, void* optval, uint32_t _in_optlen, uint32_t* optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_optval = _in_optlen;
	size_t _len_optlen = sizeof(uint32_t);

	ms_u_net_getsockopt_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_getsockopt_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_optval = NULL;
	void *__tmp_optlen = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(optval, _len_optval);
	CHECK_ENCLAVE_POINTER(optlen, _len_optlen);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (optval != NULL) ? _len_optval : 0;
	ocalloc_size += (optlen != NULL) ? _len_optlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_getsockopt_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_getsockopt_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_getsockopt_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL) {
		ms->ms_optval = (void*)__tmp;
		__tmp_optval = __tmp;
		memset(__tmp_optval, 0, _len_optval);
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}
	
	ms->ms__in_optlen = _in_optlen;
	if (optlen != NULL) {
		ms->ms_optlen = (uint32_t*)__tmp;
		__tmp_optlen = __tmp;
		if (memcpy_s(__tmp_optlen, ocalloc_size, optlen, _len_optlen)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optlen);
		ocalloc_size -= _len_optlen;
	} else {
		ms->ms_optlen = NULL;
	}
	
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (optval) {
			if (memcpy_s((void*)optval, _len_optval, __tmp_optval, _len_optval)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (optlen) {
			if (memcpy_s((void*)optlen, _len_optlen, __tmp_optlen, _len_optlen)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_setsockopt_ocall(int* retval, int* error, int sockfd, int level, int optname, const void* optval, uint32_t optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_optval = optlen;

	ms_u_net_setsockopt_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_setsockopt_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(optval, _len_optval);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (optval != NULL) ? _len_optval : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_setsockopt_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_setsockopt_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_setsockopt_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL) {
		ms->ms_optval = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, optval, _len_optval)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}
	
	ms->ms_optlen = optlen;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_getsockname_ocall(int* retval, int* error, int sockfd, struct sockaddr_t* addr, uint32_t _in_addrlen, uint32_t* addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = _in_addrlen;
	size_t _len_addrlen = sizeof(uint32_t);

	ms_u_net_getsockname_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_getsockname_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_addr = NULL;
	void *__tmp_addrlen = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen, _len_addrlen);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (addr != NULL) ? _len_addr : 0;
	ocalloc_size += (addrlen != NULL) ? _len_addrlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_getsockname_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_getsockname_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_getsockname_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (addr != NULL) {
		ms->ms_addr = (struct sockaddr_t*)__tmp;
		__tmp_addr = __tmp;
		memset(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}
	
	ms->ms__in_addrlen = _in_addrlen;
	if (addrlen != NULL) {
		ms->ms_addrlen = (uint32_t*)__tmp;
		__tmp_addrlen = __tmp;
		if (memcpy_s(__tmp_addrlen, ocalloc_size, addrlen, _len_addrlen)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addrlen);
		ocalloc_size -= _len_addrlen;
	} else {
		ms->ms_addrlen = NULL;
	}
	
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen) {
			if (memcpy_s((void*)addrlen, _len_addrlen, __tmp_addrlen, _len_addrlen)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_getpeername_ocall(int* retval, int* error, int sockfd, struct sockaddr_t* addr, uint32_t _in_addrlen, uint32_t* addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_addr = _in_addrlen;
	size_t _len_addrlen = sizeof(uint32_t);

	ms_u_net_getpeername_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_getpeername_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_addr = NULL;
	void *__tmp_addrlen = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen, _len_addrlen);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (addr != NULL) ? _len_addr : 0;
	ocalloc_size += (addrlen != NULL) ? _len_addrlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_getpeername_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_getpeername_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_getpeername_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	if (addr != NULL) {
		ms->ms_addr = (struct sockaddr_t*)__tmp;
		__tmp_addr = __tmp;
		memset(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}
	
	ms->ms__in_addrlen = _in_addrlen;
	if (addrlen != NULL) {
		ms->ms_addrlen = (uint32_t*)__tmp;
		__tmp_addrlen = __tmp;
		if (memcpy_s(__tmp_addrlen, ocalloc_size, addrlen, _len_addrlen)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addrlen);
		ocalloc_size -= _len_addrlen;
	} else {
		ms->ms_addrlen = NULL;
	}
	
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen) {
			if (memcpy_s((void*)addrlen, _len_addrlen, __tmp_addrlen, _len_addrlen)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_shutdown_ocall(int* retval, int* error, int sockfd, int how)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_net_shutdown_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_shutdown_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_shutdown_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_shutdown_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_shutdown_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_sockfd = sockfd;
	ms->ms_how = how;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_net_ioctl_ocall(int* retval, int* error, int fd, int request, int* arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_arg = sizeof(int);

	ms_u_net_ioctl_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_net_ioctl_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_arg = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(arg, _len_arg);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (arg != NULL) ? _len_arg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_net_ioctl_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_net_ioctl_ocall_t));
	ocalloc_size -= sizeof(ms_u_net_ioctl_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_request = request;
	if (arg != NULL) {
		ms->ms_arg = (int*)__tmp;
		__tmp_arg = __tmp;
		if (memcpy_s(__tmp_arg, ocalloc_size, arg, _len_arg)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_arg);
		ocalloc_size -= _len_arg;
	} else {
		ms->ms_arg = NULL;
	}
	
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (arg) {
			if (memcpy_s((void*)arg, _len_arg, __tmp_arg, _len_arg)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_open64_ocall(int* retval, int* error, const char* path, int oflag, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_fs_open64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_open64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (path != NULL) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_open64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_open64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_open64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	ms->ms_oflag = oflag;
	ms->ms_mode = mode;
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_read_ocall(size_t* retval, int* error, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = count;

	ms_u_fs_read_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_read_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_read_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_read_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_read_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_pread64_ocall(size_t* retval, int* error, int fd, void* buf, size_t count, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = count;

	ms_u_fs_pread64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_pread64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_pread64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_pread64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_pread64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_write_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = count;

	ms_u_fs_write_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_write_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_write_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_write_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_write_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_pwrite64_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = count;

	ms_u_fs_pwrite64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_pwrite64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_pwrite64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_pwrite64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_pwrite64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_close_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_close_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_close_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_close_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_close_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_close_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fcntl_arg0_ocall(int* retval, int* error, int fd, int cmd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_fcntl_arg0_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fcntl_arg0_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fcntl_arg0_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fcntl_arg0_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_fcntl_arg0_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fcntl_arg1_ocall(int* retval, int* error, int fd, int cmd, int arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_fcntl_arg1_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fcntl_arg1_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fcntl_arg1_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fcntl_arg1_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_fcntl_arg1_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_ioctl_arg0_ocall(int* retval, int* error, int fd, int request)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_ioctl_arg0_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_ioctl_arg0_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_ioctl_arg0_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_ioctl_arg0_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_ioctl_arg0_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_request = request;
	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_ioctl_arg1_ocall(int* retval, int* error, int fd, int request, int* arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_arg = sizeof(int);

	ms_u_fs_ioctl_arg1_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_ioctl_arg1_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(arg, _len_arg);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (arg != NULL) ? _len_arg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_ioctl_arg1_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_ioctl_arg1_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_ioctl_arg1_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_request = request;
	if (arg != NULL) {
		ms->ms_arg = (int*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, arg, _len_arg)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_arg);
		ocalloc_size -= _len_arg;
	} else {
		ms->ms_arg = NULL;
	}
	
	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fstat64_ocall(int* retval, int* error, int fd, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_buf = sizeof(struct stat64_t);

	ms_u_fs_fstat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fstat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fstat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fstat64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_fstat64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (struct stat64_t*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	status = sgx_ocall(34, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fsync_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_fsync_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fsync_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fsync_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fsync_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_fsync_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fdatasync_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_fdatasync_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fdatasync_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fdatasync_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fdatasync_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_fdatasync_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(36, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_ftruncate64_ocall(int* retval, int* error, int fd, int64_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_ftruncate64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_ftruncate64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_ftruncate64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_ftruncate64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_ftruncate64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_length = length;
	status = sgx_ocall(37, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_lseek64_ocall(int64_t* retval, int* error, int fd, int64_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_lseek64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_lseek64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_lseek64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_lseek64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_lseek64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fchmod_ocall(int* retval, int* error, int fd, uint32_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);

	ms_u_fs_fchmod_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fchmod_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);

	ocalloc_size += (error != NULL) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fchmod_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fchmod_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_fchmod_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_fd = fd;
	ms->ms_mode = mode;
	status = sgx_ocall(39, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_unlink_ocall(int* retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_fs_unlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_unlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (pathname != NULL) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_unlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_unlink_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_unlink_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	status = sgx_ocall(40, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_link_ocall(int* retval, int* error, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_fs_link_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_link_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (oldpath != NULL) ? _len_oldpath : 0;
	ocalloc_size += (newpath != NULL) ? _len_newpath : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_link_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_link_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_link_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (oldpath != NULL) {
		ms->ms_oldpath = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}
	
	if (newpath != NULL) {
		ms->ms_newpath = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}
	
	status = sgx_ocall(41, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_rename_ocall(int* retval, int* error, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_fs_rename_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_rename_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (oldpath != NULL) ? _len_oldpath : 0;
	ocalloc_size += (newpath != NULL) ? _len_newpath : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_rename_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_rename_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_rename_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (oldpath != NULL) {
		ms->ms_oldpath = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}
	
	if (newpath != NULL) {
		ms->ms_newpath = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}
	
	status = sgx_ocall(42, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_chmod_ocall(int* retval, int* error, const char* path, uint32_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_fs_chmod_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_chmod_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (path != NULL) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_chmod_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_chmod_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_chmod_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(43, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_readlink_ocall(size_t* retval, int* error, const char* path, char* buf, size_t bufsz)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = bufsz;

	ms_u_fs_readlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_readlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (path != NULL) ? _len_path : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_readlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_readlink_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_readlink_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (char*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_bufsz = bufsz;
	status = sgx_ocall(44, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_symlink_ocall(int* retval, int* error, const char* path1, const char* path2)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path1 = path1 ? strlen(path1) + 1 : 0;
	size_t _len_path2 = path2 ? strlen(path2) + 1 : 0;

	ms_u_fs_symlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_symlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path1, _len_path1);
	CHECK_ENCLAVE_POINTER(path2, _len_path2);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (path1 != NULL) ? _len_path1 : 0;
	ocalloc_size += (path2 != NULL) ? _len_path2 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_symlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_symlink_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_symlink_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (path1 != NULL) {
		ms->ms_path1 = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, path1, _len_path1)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path1);
		ocalloc_size -= _len_path1;
	} else {
		ms->ms_path1 = NULL;
	}
	
	if (path2 != NULL) {
		ms->ms_path2 = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, path2, _len_path2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path2);
		ocalloc_size -= _len_path2;
	} else {
		ms->ms_path2 = NULL;
	}
	
	status = sgx_ocall(45, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_stat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(struct stat64_t);

	ms_u_fs_stat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_stat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (path != NULL) ? _len_path : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_stat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_stat64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_stat64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (struct stat64_t*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	status = sgx_ocall(46, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_lstat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(struct stat64_t);

	ms_u_fs_lstat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_lstat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (path != NULL) ? _len_path : 0;
	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_lstat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_lstat64_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_lstat64_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (struct stat64_t*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	status = sgx_ocall(47, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_realpath_ocall(char** retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_fs_realpath_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_realpath_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (pathname != NULL) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_realpath_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_realpath_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_realpath_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	status = sgx_ocall(48, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_free_ocall(void* p)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fs_free_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_free_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_free_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_free_ocall_t));
	ocalloc_size -= sizeof(ms_u_fs_free_ocall_t);

	ms->ms_p = p;
	status = sgx_ocall(49, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_clock_gettime_ocall(int* retval, int* error, int clk_id, struct timespec* tp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(int);
	size_t _len_tp = sizeof(struct timespec);

	ms_u_clock_gettime_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_clock_gettime_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_tp = NULL;

	CHECK_ENCLAVE_POINTER(error, _len_error);
	CHECK_ENCLAVE_POINTER(tp, _len_tp);

	ocalloc_size += (error != NULL) ? _len_error : 0;
	ocalloc_size += (tp != NULL) ? _len_tp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_clock_gettime_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_clock_gettime_ocall_t));
	ocalloc_size -= sizeof(ms_u_clock_gettime_ocall_t);

	if (error != NULL) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
		ocalloc_size -= _len_error;
	} else {
		ms->ms_error = NULL;
	}
	
	ms->ms_clk_id = clk_id;
	if (tp != NULL) {
		ms->ms_tp = (struct timespec*)__tmp;
		__tmp_tp = __tmp;
		memset(__tmp_tp, 0, _len_tp);
		__tmp = (void *)((size_t)__tmp + _len_tp);
		ocalloc_size -= _len_tp;
	} else {
		ms->ms_tp = NULL;
	}
	
	status = sgx_ocall(50, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) {
			if (memcpy_s((void*)error, _len_error, __tmp_error, _len_error)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (tp) {
			if (memcpy_s((void*)tp, _len_tp, __tmp_tp, _len_tp)) {
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

	ocalloc_size += (cpuinfo != NULL) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(51, ms);

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

	ms->ms_self = self;
	status = sgx_ocall(52, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
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

	ms->ms_waiter = waiter;
	status = sgx_ocall(53, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
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

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(54, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
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

	ocalloc_size += (waiters != NULL) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(55, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_write_ocall(ssize_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_write_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_write_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	ocalloc_size += (buf != NULL) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_write_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_write_ocall_t));
	ocalloc_size -= sizeof(ms_u_write_ocall_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(56, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL buildmerkletree(int* retval, struct MerkleTree* tree)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_buildmerkletree_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_buildmerkletree_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_buildmerkletree_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_buildmerkletree_t));
	ocalloc_size -= sizeof(ms_buildmerkletree_t);

	ms->ms_tree = tree;
	status = sgx_ocall(57, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL writemerkletree(int* retval, struct MerkleTree* tree)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_writemerkletree_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_writemerkletree_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_writemerkletree_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_writemerkletree_t));
	ocalloc_size -= sizeof(ms_writemerkletree_t);

	ms->ms_tree = tree;
	status = sgx_ocall(58, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL MTPrintNodeByIndex(struct MerkleTree* treeptr, int idx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_treeptr = sizeof(struct MerkleTree);

	ms_MTPrintNodeByIndex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_MTPrintNodeByIndex_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(treeptr, _len_treeptr);

	ocalloc_size += (treeptr != NULL) ? _len_treeptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_MTPrintNodeByIndex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_MTPrintNodeByIndex_t));
	ocalloc_size -= sizeof(ms_MTPrintNodeByIndex_t);

	if (treeptr != NULL) {
		ms->ms_treeptr = (struct MerkleTree*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, treeptr, _len_treeptr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_treeptr);
		ocalloc_size -= _len_treeptr;
	} else {
		ms->ms_treeptr = NULL;
	}
	
	ms->ms_idx = idx;
	status = sgx_ocall(59, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL MTUpdateNode(struct MerkleTree* treeptr, int idx)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_MTUpdateNode_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_MTUpdateNode_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_MTUpdateNode_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_MTUpdateNode_t));
	ocalloc_size -= sizeof(ms_MTUpdateNode_t);

	ms->ms_treeptr = treeptr;
	ms->ms_idx = idx;
	status = sgx_ocall(60, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL MTGetMerkleProof(MerkleProof** retval, struct MerkleTree* treeptr, int nodeidx)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_MTGetMerkleProof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_MTGetMerkleProof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_MTGetMerkleProof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_MTGetMerkleProof_t));
	ocalloc_size -= sizeof(ms_MTGetMerkleProof_t);

	ms->ms_treeptr = treeptr;
	ms->ms_nodeidx = nodeidx;
	status = sgx_ocall(61, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

