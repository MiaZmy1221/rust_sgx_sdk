#include "merkle.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "sgx_error.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
//    ocall_print_string(buf);
}
       
// sgx_status_t checkreadnode(MerkleTree* tree){
//     int idx = 4+MAX_LEAF_NODE;
//     LinkedNode* lnptr = malloc(sizeof(LinkedNode));
//     LinkedNode* retptr;
//     MTGetNodePath(&retptr, tree, idx);
//     if(retptr != NULL){
//           memcpy(lnptr, retptr, sizeof(LinkedNode));
//     }
//     else{
// 	  printf("readnode path failed\n");
// 	  return SGX_ERROR_UNEXPECTED;
//     }
//     printf("LinkedNode: %d", lnptr->treeIdx);
//     while (lnptr->parent)
//     {
//              lnptr = lnptr->parent;
//              printf(" -> %d", lnptr->treeIdx);
//     }
//     printf("%s", "\n");

//     int ret = MTCheckNodePath(tree, lnptr);
//     printf("the return value is %d\n", ret);
//     if(ret == 1){
// 	    Node* nodeptr = malloc(sizeof(Node));
// 	    Node* retnode;
// 	    MTReadNode(&retnode, tree, idx);
//             if(retnode != NULL){
// 		memcpy(nodeptr, retnode, sizeof(Node));
//             }
// 	    else{
// 		printf("readnode failed\n");
// 		return SGX_ERROR_UNEXPECTED;
// 	    }
// 	    printf("print node: %s%u%s%u%s%u%s%d%s%s\n",
//                 "H", nodeptr->hash,
//                 "L", nodeptr->leftHash,
//                 "R", nodeptr->rightHash,
//                 "P", nodeptr->prefix,
//                 "V", nodeptr->value);

//     }
//     else{
// 	    printf("checknode path failed\n");
// 	    return SGX_ERROR_UNEXPECTED;
//     }
//     return SGX_SUCCESS;

// }

// sgx_status_t writenode(MerkleTree* tree){

//      strncpy(tree->nodes[68].value, "newvalsmart", strlen("newvalsmart"));
//      MTUpdateNode(tree, 4+MAX_LEAF_NODE);
//      return SGX_SUCCESS;

// }
