#ifndef MERKLE_H
#define MERKLE_H

#define MAX_LEAF_NODE 64
#define MAX_NODE MAX_LEAF_NODE*2
#define MAX_TREE_LEVEL 7
#define MAX_LEN 2048
#define MAX_HASH_LEN 10 // used for printing the hash
#define ROOT 1	// the root idx is 1!

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

#endif /* MERKLE_H */

