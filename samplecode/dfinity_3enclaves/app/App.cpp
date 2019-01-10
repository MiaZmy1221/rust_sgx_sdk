// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// App.cpp : Defines the entry point for the console application.
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


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;


sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;
sgx_enclave_id_t e3_enclave_id = 0;

#define ENCLAVE1_PATH "enclave1.signed.so"
#define ENCLAVE2_PATH "enclave2.signed.so"
#define ENCLAVE3_PATH "enclave3.signed.so"

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


// Attestation

sgx_status_t ocall_sgx_init_quote(sgx_target_info_t* ret_ti, sgx_epid_group_id_t* ret_gid)
{
    printf("[App]Entering ocall_sgx_init_quote\n");
    sgx_init_quote(ret_ti, ret_gid);


}

sgx_status_t ocall_get_quote(uint8_t * p_sigrl,
                             uint32_t sigrl_len,
                             sgx_report_t *p_report,
                             sgx_quote_sign_type_t quote_type,
                             sgx_spid_t *p_spid,
                             sgx_quote_nonce_t *p_nonce,
                             sgx_report_t *p_qe_report,
                             sgx_quote_t *p_quote,
                             uint32_t maxlen,
                             uint32_t* p_quote_len)
{
    printf("[App]Entering ocall_get_quote\n");
    uint32_t real_quote_len = 0;
    sgx_status_t ret = sgx_calc_quote_size(p_sigrl, sigrl_len, &real_quote_len);
    if (ret != SGX_SUCCESS)
        {
            print_error_message(ret);
            return ret;
        }
    printf("[App]quote size = %u\n", real_quote_len);
    *p_quote_len = real_quote_len;
    ret = sgx_get_quote(p_report,
                      quote_type,
                      p_spid,
                      p_nonce,
                      p_sigrl,
                      sigrl_len,
                      p_qe_report,
                      p_quote,
                      real_quote_len);
    if (ret != SGX_SUCCESS)
        {   
           print_error_message(ret);
           return ret;
        }

    printf("[App]get_quote returned\n");
    return ret;
}

sgx_status_t ocall_get_update_info(sgx_platform_info_t * platformblob,
                       int32_t enclave_trusted,
                       sgx_update_info_bit_t * update_info)
{

    sgx_report_attestation_status(platformblob, enclave_trusted, update_info);

}

sgx_status_t ocall_get_ias_socket(int* ret_fd)
{
    int port = 443;
    char * hostname = "test-as.sgx.trustedservices.intel.com";
    struct hostent *he;
    struct sockaddr_in server;
    int sockfd;
    char* ip;
        if ((he = gethostbyname(hostname)) == NULL)
    {   
            printf("failed at gethostbyname\n");    
    }
        memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(connect(sockfd, (struct sockaddr *)&server, sizeof(server)))
    {
        printf("failed to connect\n");  
    
    }


/*  addr_list = (struct in_addr **) hei->h_addr_list;

    for (i = 0; addr_list[i] != NULL; i++)
    {
        strcpy(ip, inet_ntoa(*addr_list[i]));
        
    }
*/  
    *ret_fd = sockfd;
        
    return SGX_SUCCESS;

}


uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE3_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e3_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e3_enclave_id, enclave_temp_no));



    return SGX_SUCCESS;
}


// Transaction Records. App should send the record array to Validation Enclave when it is full.
//////////////////////////////////////////////////////////////////////////////////////////

#define RECORD_NUM 100
Transaction tx_array[RECORD_NUM];
int tx_count = 0;

void record_transaction(HASHTYPE oldhash, char* tx_str_out, HASHTYPE newhash, sgx_report_t report_out)
{
    Transaction* ptr = &tx_array[tx_count];
    ptr->oldhash = oldhash;
    ptr->newhash = newhash;
    strncpy(ptr->tx_str, tx_str_out, strlen(tx_str_out));
    memcpy(&(ptr->report), &report_out, sizeof(sgx_report_t));
    ++tx_count;
}

void print_transaction(int idx)
{
    printf("recorded idx %i: oldhash: %u tx_str: %s newhash: %u\n", 
    idx, tx_array[idx].oldhash, tx_array[idx].tx_str, tx_array[idx].newhash);
    printf("recorded report data: ");
    for (int i=0; i<64; i++)
        printf("%d ", tx_array[idx].report.body.report_data.d[i]);
    printf("\n");
}
//////////////////////////////////////////////////////////////////////////////////////////

int _tmain(int argc, _TCHAR* argv[])
{
    uint32_t ret_status;
    sgx_status_t status;

    UNUSED(argc);
    UNUSED(argv);

    if(load_enclaves() != SGX_SUCCESS)
    {
        printf("\nLoad Enclave Failure");
    }

    do
    {
        Enclave1_test_enclave_init(e1_enclave_id);
        Enclave2_test_enclave_init(e2_enclave_id);
        Enclave3_test_enclave_init(e3_enclave_id);


#pragma warning (push)
#pragma warning (disable : 4127)
    }while(0);
#pragma warning (pop)


    // 1: get target info (ti) of the validation enclave
    sgx_target_info_t vali_ti;
    Enclave2_ecall_get_ti(e2_enclave_id, &vali_ti);

    // merkle tree init
    MerkleTree* tree = (MerkleTree*)malloc(sizeof(MerkleTree));
    MTBuildTreeHelper(tree);
    
    // code & data index
    int codeidx = 4 + MAX_LEAF_NODE;
    int dataidx = 5 + MAX_LEAF_NODE;

    // prepare args of ecall
    HASHTYPE oldhash = MTReadNode(tree,ROOT)->hash;
    char wasmfunc[64] = "init";
    int wasmargs[2] = {0,10};

    // get MerkleProofs
    MerkleProof* codeproof = (MerkleProof*)malloc(sizeof(MerkleProof));
    MTGetMerkleProof(tree, codeidx, codeproof);
    MerkleProof* dataproof = (MerkleProof*)malloc(sizeof(MerkleProof));
    MTGetMerkleProof(tree, dataidx, dataproof);

    // return values
    char data_out[MAX_LEN] = "";
    char tx_str_out[MAX_LEN]= "";
    HASHTYPE newhash = 0;
    sgx_report_t ret_report;

    Enclave1_ecall_merkle_tree_entry(e1_enclave_id, &status, codeproof, dataproof, oldhash, 
        &ret_report, wasmfunc, 4*sizeof(char), wasmargs, 2*sizeof(int), data_out, tx_str_out, &newhash, &vali_ti);
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        printf("[App]merkletreeflow failed...\n");
        return -1;
    }

    printf("\n\n[App]data_out after ecall: %s\n", data_out);
    printf("[App]report data after ecall: ");
    for (int i=0; i<64; i++)
        printf("%d ", ret_report.body.report_data.d[i]);
    printf("\n");
    printf("[App]tx_str_out after ecall: %s\n", tx_str_out);
    printf("[App]newhash after ecall: %u\n", newhash);

    // write node 
    MTWriteNode(tree, dataidx, data_out);
    printf("[App]new data node: ");
    MTPrintNodeByIndex(tree, dataidx);
    
    // print new ROOT
    printf("[App]new ROOT: ");
    MTPrintNodeByIndex(tree, ROOT);
    printf("\n");

    // update tree: Databuf -> DB
    // MTWriteTreeHelper(tree);
    // printf("[App]write tree finished\n");

    // record transaction
    record_transaction(oldhash, tx_str_out, newhash, ret_report);
    print_transaction(tx_count-1);

    // get ti of the execution enclave
    sgx_target_info_t exec_ti;
    Enclave1_ecall_get_ti(e1_enclave_id, &exec_ti);

    // read and verify report in validation enclave
    Enclave2_ecall_read_and_verify_report(e2_enclave_id, &status, tx_array, tx_count, sizeof(Transaction)*tx_count, &exec_ti); 
    
    if (status != SGX_SUCCESS)
    {
        printf("%s\n", "Report verification failed!");
    }

    // free pointers
    free(tree);
    free(codeproof);
    free(dataproof);

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);
    sgx_destroy_enclave(e3_enclave_id);

    return 0;
}
