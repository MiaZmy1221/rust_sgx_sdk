#ifndef MERKLE_H
#define MERKLE_H

#define MAX_LEAF_NODE 64
#define MAX_NODE MAX_LEAF_NODE*2
#define MAX_TREE_LEVEL 7
#define MAX_LEN 2048
#define MAX_HASH_LEN 10 // used for printing the hash
#define ROOT 1	// the root idx is 1!

#define MAX_MSG 100
#define MAX_PARAMS 100 // maximum number of a function's params

/// Changes compared to the previous file:
///
/// 1) Define some static constants.
/// 2) Define a struct MessageInC used to tansfer message from enclave to app.

typedef unsigned int HASHTYPE;

typedef struct Node
{
	HASHTYPE hash, leftHash, rightHash;
	int prefix;
	char value[MAX_LEN];
} Node;

typedef struct MerkleTree
{
	Node nodes[MAX_LEAF_NODE*2];
	int totalLeafNode;
} MerkleTree;

typedef struct LinkedNode
{
	struct LinkedNode* parent;
	int treeIdx;
	Node node;
} LinkedNode;

typedef struct MerkleProof
{
	Node path[MAX_TREE_LEVEL];
} MerkleProof;

typedef struct Transaction {
    HASHTYPE oldhash;
    char tx_str[MAX_LEN];
    HASHTYPE newhash;
    sgx_report_t report;
} Transaction;

/// MessageInC struct is used to store the message in the execution enclave.
/// This struct equals to struct Message in file third_part/wasmi/src/message.rs actually.
typedef struct Message {
	char func[MAX_LEN];
	int params[MAX_PARAMS];
} Message;

#endif /* MERKLE_H */

