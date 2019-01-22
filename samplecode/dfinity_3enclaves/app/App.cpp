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
#include <openssl/sha.h>

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

///////////////////////////////////////////////////////////////////////////////////////////

// Test DH key exchange between Enclave1 and Enclave3.

//////////////////////////////////////////////////////////////////////////////////////////
void testDHKE()
{
        uint32_t ret_status;
        sgx_status_t status;

        //Test Create session between Enclave1(Source) and Enclave3(Destination)
        status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_create_session Ecall failed: Error code is %x", status);
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nSecure Channel Establishment between Source (E1) and Destination (E3) Enclaves successful !!!");
            }
            else
            {
                printf("\n\nSession establishment and key exchange failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
            }
        }


        //Test DH Request & Response: Enclave1 is Exec Enclave, Enclave3 is KM Enclave
        char request[100];
        int node_idx = 12;
        Enclave1_test_generate_request(e1_enclave_id, &status, e1_enclave_id, e3_enclave_id, node_idx, request, 100);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_generate_request Ecall failed: Error code is %x", status);
        }

        printf("\nrequest: %s\n", request);

        char response[100];
        Enclave3_test_generate_response(e3_enclave_id, &status, e1_enclave_id, e3_enclave_id, 
                                        request, strlen(request), response, 100);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave3_test_generate_response Ecall failed: Error code is %x", status);
        }
        printf("\nresponse: %s\n", response);

        Enclave1_test_get_key_from_response(e1_enclave_id, &status, e1_enclave_id, e3_enclave_id, response, strlen(response));
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_get_key_from_response Ecall failed: Error code is %x", status);
        }

        //Test Closing Session between Enclave1(Source) and Enclave3(Destination)
        status = Enclave1_test_close_session(e1_enclave_id, &ret_status, e1_enclave_id, e3_enclave_id);
        if (status!=SGX_SUCCESS)
        {
            printf("Enclave1_test_close_session Ecall failed: Error code is %x", status);
        }
        else
        {
            if(ret_status==0)
            {
                printf("\n\nClose Session between Source (E1) and Destination (E3) Enclaves successful !!!\n");
            }
            else
            {
                printf("\n\nClose session failure between Source (E1) and Destination (E3): Error code is %x", ret_status);
            }
        }
}


///////////////////////////////////////////////////////////////////////////////////////////

// Transaction Records. App should send the record array to Validation Enclave when it is full.

//////////////////////////////////////////////////////////////////////////////////////////

#define RECORD_NUM 100
Transaction tx_array[RECORD_NUM];
int tx_count = 0;

void record_transaction(Transaction tx_out)
{
    Transaction* ptr = &tx_array[tx_count];
    memcpy(ptr, &tx_out, sizeof(Transaction));
    ++tx_count;
}

void print_transaction(Transaction tx)
{

    printf("Transaction: oldhash: %u tx_str: %s newhash: %u\n", tx.oldhash, tx.tx_str, tx.newhash);
    printf("recorded report data: ");
    for (int i=0; i<64; i++)
        printf("%d ", tx.report.body.report_data.d[i]);
    printf("\n");
}

// check local attestation data in the Transaction: data[0..32]: SHA256(oldroot;tx_str;newroot)
bool check_transaction(Transaction tx)
{
    // construct string to be hashed
    char s[MAX_LEN*2];
    snprintf(s, MAX_LEN*2, "%u;%s;%u", tx.oldhash, tx.tx_str, tx.newhash);

    // calculate hash
    uint8_t hash[SGX_REPORT_DATA_SIZE];
    memset(hash, 0, sizeof(uint8_t)*SGX_REPORT_DATA_SIZE);

    SHA256((const unsigned char*)s, strlen(s), hash);
    printf("check_transaction HASH:");
    for (int i = 0; i < SGX_REPORT_DATA_SIZE; i++)
        printf("%02X", hash[i]);
    printf("\n");

    printf("check_transaction REPORT_DATA:");
    for (int i = 0; i < SGX_REPORT_DATA_SIZE; i++)
        printf("%02X", tx.report.body.report_data.d[i]);
    printf("\n");

    for (int i = 0; i < SGX_REPORT_DATA_SIZE; i++)
    {
        if (hash[i] != tx.report.body.report_data.d[i])
        {
            printf("%d: not equal! %u vs. %u\n", i, hash[i], tx.report.body.report_data.d[i]);
            return false;
        }
    } 
    return true;
    
}

//////////////////////////////////////////////////////////////////////////////////////////

// Messages. App need to deal with these messages.

/////////////////////////////////////////////////////////////////////////////////////////

Message allMsgArray[MAX_MSG];
int msg_num = 0;

void print_message_params(int idx, Message array[MAX_MSG])
{
    printf("message %d params are: ", idx);
    for (int i=0; i<100; i++)
        printf("%d ", array[idx].params[i]);
    printf("\n");

    printf("message %d function is: %s\n", idx, array[idx].func);
}

void deal_with_message(int idx, int* codeid, int* dataid, char* funcname, int* func_len, int* args, int* args_len) {
    //get the codeid, dataid, name, name_legth, and args length of a function
    char delim[] = {"|"};
    int i = 0;
    char *p = strtok(allMsgArray[idx].func, delim);
    char *array[4]; // codeid dataid name and params_length

    while (p != NULL && i < 4)
    {
        array[i] = p;
        i = i + 1;
        p = strtok (NULL, delim);
    }

    for (i = 0; i < 3; ++i){
        printf("%s\n", array[i]);
        char delim1[] = {':', '}'};
        int j = 0;
        char *p1 = strtok(array[i], delim1);
        char *array1[3]; // might be 3 
        while (p1 != NULL && j < 3)
        {
            array1[j] = p1;
            j = j + 1;
            p1 = strtok (NULL, delim1);
        }

        for (j = 0; j < 3 ; ++j) {
            printf("%s\n", array1[j]);
        }
        array[i] = array1[1];
    } 
    
    for (i = 0; i < 4; ++i){
        printf("%s\n", array[i]);
    }

    sscanf(array[0], "%d", codeid);
    printf("codeid is %d\n", *codeid);

    sscanf(array[1], "%d", dataid);
    printf("dataid is %d\n", *dataid);

    sscanf(array[3], "%d", args_len);
    printf("arguments length is %d\n", *args_len);

    char delim2[] = {' ', '"'};
    int m = 0;
    char *p2 = strtok(array[2], delim2);
    char *array2[1]; // codeid dataid and name

    while (p2 != NULL && m < 1)
    {
        array2[m] = p2;
        m = m + 2;
        p2 = strtok (NULL, delim2);
    }

    *func_len = strlen(array2[0]);
    printf("funcname length is %d\n", *func_len);
    strncpy(funcname, array2[0], *func_len);
    printf("func name is %s\n", funcname);
    
    // get the parameters of a function
    for (int n = 0; n < *args_len; n++) {
        args[n] = allMsgArray[idx].params[n];
    }
    
}

void addMessage(int count, Message* array) {
    for(int i=0; i<count; i++){
        memcpy(&allMsgArray[msg_num], &array[i], sizeof(Message));
        msg_num++;
    }
}

/////////////////////////////////////////////////////////////////////////////////////////

// execute code in Enclave1. 

/////////////////////////////////////////////////////////////////////////////////////////

void execute(MerkleTree *tree, int codeidx, int dataidx, char* wasmfunc, int* wasmargs, sgx_target_info_t vali_ti)
{
    uint32_t ret_status;
    sgx_status_t status;

    HASHTYPE oldhash = MTReadNode(tree,ROOT)->hash;

    // get MerkleProofs
    MerkleProof* codeproof = (MerkleProof*)malloc(sizeof(MerkleProof));
    MTGetMerkleProof(tree, codeidx, codeproof);
    MerkleProof* dataproof = (MerkleProof*)malloc(sizeof(MerkleProof));
    MTGetMerkleProof(tree, dataidx, dataproof);

    // return values
    char data_out[MAX_LEN] = "";
    Transaction tx_out;
    int count = 0;
    Message tempArray[MAX_MSG];

    Enclave1_ecall_merkle_tree_entry(e1_enclave_id, &status, codeproof, dataproof, oldhash, 
                wasmfunc, 7*sizeof(char), wasmargs, 1*sizeof(int), data_out, &tx_out, &vali_ti,
                tempArray, &count, sizeof(Message)*100);
    
    if (status != SGX_SUCCESS) {
        print_error_message(status);
        printf("[App]merkletreeflow failed...\n");
        return;
    }

    printf("\n\n[App]data_out after ecall: %s\n", data_out);

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

    // add msg to global allMsgArray
    addMessage(count, tempArray);

    // record transaction
    record_transaction(tx_out);
    print_transaction(tx_array[tx_count-1]);
    if (!check_transaction(tx_array[tx_count-1]))
    {
        printf("[App]check_transaction failed!\n");
    }
    else
    {
        printf("[App]check_transaction success!\n");

        // // get ti of the execution enclave
        // sgx_target_info_t exec_ti;
        // Enclave1_ecall_get_ti(e1_enclave_id, &exec_ti);

        // //TESTING
        // // tx_out.oldhash = tx_out.newhash;
        // // record_transaction(tx_out);
        // // record_transaction(tx_out);
        // // record_transaction(tx_out);

        // // read and verify report in validation enclave; get remote attn Transaction
        // Transaction remote_attn_tx;
        // Enclave2_ecall_read_and_verify_report(e2_enclave_id, &status, tx_array, tx_count, sizeof(Transaction)*tx_count, 
        //                                       &exec_ti, &remote_attn_tx); 
        
        // if (status != SGX_SUCCESS)
        // {
        //     printf("%s\n", "Report verification failed!");
        // }
        // printf("[App]remote attestation response: %s\n", remote_attn_tx.remote_attn_response);
    }

    free(codeproof);
    free(dataproof);

}

/////////////////////////////////////////////////////////////////////////////////////////

int _tmain(int argc, _TCHAR* argv[])
{
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


    // get target info (ti) of the validation enclave
    sgx_target_info_t vali_ti;
    Enclave2_ecall_get_ti(e2_enclave_id, &vali_ti);

    // merkle tree init
    MerkleTree* tree = (MerkleTree*)malloc(sizeof(MerkleTree));
    MTBuildTreeHelper(tree);

    // prepare args of ecall
    char wasmfunc[64] = "callref";
    int wasmargs[1] = {1};

    execute(tree, 8 + MAX_LEAF_NODE, 9 + MAX_LEAF_NODE, wasmfunc, wasmargs, vali_ti);

    free(tree);

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);
    sgx_destroy_enclave(e3_enclave_id);

    return 0;
}
