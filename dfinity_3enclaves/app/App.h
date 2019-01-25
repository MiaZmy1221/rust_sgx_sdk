#include <stdio.h>
#include <map>
#include "Enclave1_u.h"
#include "Enclave2_u.h"
#include "Enclave3_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "sgx_uae_service.h"

#include "sgx_quote.h"
#include "merkle.h"
#include <openssl/sha.h>

// function signatures

void testDHKE();
void record_transaction(Transaction tx_out);
void print_transaction(Transaction tx);
bool check_transaction(Transaction tx);
void print_message_params(int idx, Message array[MAX_MSG]);
void get_args_from_message(int idx, int* codeid, int* dataid, char* wasmfunc, int* func_len, int* wasmargs, int* args_len);
void empty_message_array(MerkleTree *tree, sgx_target_info_t vali_ti);
void append_message(int count, Message* array);
void execute(MerkleTree *tree, int codeid, int dataid, char* wasmfunc, int func_len, 
            int* wasmargs, int args_len, sgx_target_info_t vali_ti);