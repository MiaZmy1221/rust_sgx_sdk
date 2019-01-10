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

//helper
HASHTYPE djb_hash(char* str);
bool MTIsLeafNode(int idx);
int MTLeafIdxToTreeIdx(int leafidx);

// Node Operation
char* MTSerializeNode(MerkleTree* treeptr, int idx);
char* MTSerializeNodeWithOwnHash(MerkleTree* treeptr, int idx); // add hash value to string
char* MTSerializeNodeByPtr(Node* ptr);
void MTGenNodeHash(MerkleTree* treeptr, int idx);
void MTGenNodeHashByPtr(Node* ptr);
void MTUpdateNode(MerkleTree* treeptr, int idx);
void MTAddNewNode(MerkleTree* treeptr, char* newval);
void MTDeleteNode(MerkleTree* treeptr, int idx);
void MTChangeNodeHash(MerkleTree* treeptr, int idx, HASHTYPE newhash); // for test only!
Node* MTReadNode(MerkleTree* treeptr, int idx);
void MTCopyNode(Node* dest, Node* src);
void MTWriteNode(MerkleTree* treeptr, int idx, char* newval);
void MTPrintNodeByIndex(MerkleTree* treeptr, int idx);
void MTPrintNodeByPtr(Node* node);
bool MTCheckNodeHash(MerkleTree* treeptr, int idx);
bool MTCheckNodeHashByPtr(Node* ptr);

// LinkedNode Operation
LinkedNode* MTGetNodePath(MerkleTree* treeptr, int idx);
void MTPrintLinkedNode(LinkedNode* lnptr);
void MTFreeLinkedNode(LinkedNode* lnptr);
bool MTCheckNodePath(MerkleTree* treeptr, LinkedNode* lnptr);
bool MTCheckNodePathLinkedNodeOnly(LinkedNode* lnptr);

// Tree Operation
void MTUpdateTree(MerkleTree* treeptr);
void MTPrintTree(MerkleTree* treeptr);
void MTBuildTreeFromDB(MerkleTree* treeptr, const char* filename);
void MTWriteTreeToDB(MerkleTree* treeptr, const char* filename);
bool MTCmpTree(MerkleTree* oldTree, MerkleTree* newTree);
void MTBuildTreeHelper(MerkleTree* tree);
void MTWriteTreeHelper(MerkleTree* tree);

// MerkleProof Operation
void MTGetMerkleProof(MerkleTree* treeptr, int nodeidx, MerkleProof* result);
void MTPrintMerkleProof(MerkleProof* mp);
bool MTCheckMerkleProof(MerkleProof* mp);
void MTFreeMerkleProof(MerkleProof* mpptr);

#endif /* MERKLE_H */


