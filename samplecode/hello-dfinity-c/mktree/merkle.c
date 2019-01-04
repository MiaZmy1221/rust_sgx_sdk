#include <stdio.h> 
//#include <errno.h> 
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "merkle.h"
#include "db.h"

/* D. J. Bernstein hash function */
HASHTYPE djb_hash(char* str)
{
    HASHTYPE hash = 5381;
    int c;
    while (c = *str++)
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        // printf("hash: %u\n", hash);
    }
    return hash;
}

bool MTIsLeafNode(int idx)
{
	return (idx >= MAX_LEAF_NODE? true : false);
}

int MTLeafIdxToTreeIdx(int leafidx)
{
	return leafidx+MAX_LEAF_NODE;
}

char* MTSerializeNode(MerkleTree* treeptr, int idx) 
{
	char* out = (char*)malloc(sizeof(char)*MAX_LEN); // need to be freed by the caller
	snprintf(out, MAX_LEN, "%s%u%s%u%s%d%s%s", 
		"L", treeptr->nodes[idx].leftHash,
		"R", treeptr->nodes[idx].rightHash, 
		"P", treeptr->nodes[idx].prefix,
		"V", treeptr->nodes[idx].value);
	return out; 
}

char* MTSerializeNodeWithOwnHash(MerkleTree* treeptr, int idx) // add hash value to string
{
	char* out = (char*)malloc(sizeof(char)*MAX_LEN); // need to be freed by the caller
	snprintf(out, MAX_LEN, "%s%u%s%u%s%u%s%d%s%s", 
		"H", treeptr->nodes[idx].hash,
		"L", treeptr->nodes[idx].leftHash,
		"R", treeptr->nodes[idx].rightHash, 
		"P", treeptr->nodes[idx].prefix,
		"V", treeptr->nodes[idx].value);
	// printf("%s\n", out);
	return out; 
}

char* MTSerializeNodeByPtr(Node* ptr) 
{
	char* out = (char*)malloc(sizeof(char)*MAX_LEN); // need to be freed by the caller
	snprintf(out, MAX_LEN, "%s%u%s%u%s%d%s%s", 
		"L", ptr->leftHash,
		"R", ptr->rightHash, 
		"P", ptr->prefix,
		"V", ptr->value);
	return out; 
}

void MTGenNodeHash(MerkleTree* treeptr, int idx)
{
	char* s = MTSerializeNode(treeptr, idx);
	treeptr->nodes[idx].hash = djb_hash(s);
	// printf("HASH: %*u\n", MAX_HASH_LEN, treeptr->nodes[idx].hash);
	free(s);
	return;
}

void MTGenNodeHashByPtr(Node* ptr)
{
	char* s = MTSerializeNodeByPtr(ptr);
	ptr->hash = djb_hash(s);
	// printf("HASH: %*u\n", MAX_HASH_LEN, treeptr->nodes[idx].hash);
	free(s);
	return;
}

bool MTCheckNodeHash(MerkleTree* treeptr, int idx)
{
	HASHTYPE old = treeptr->nodes[idx].hash;
	MTGenNodeHash(treeptr, idx);
	if (old != treeptr->nodes[idx].hash)
	{
		printf("%s %d, old hash: %u, new hash: %u\n", 
			"ERROR checking node:", 
			idx, old, treeptr->nodes[idx].hash);
		return false;
	}
	return true;
}

bool MTCheckNodeHashByPtr(Node* ptr)
{
	HASHTYPE old = ptr->hash;
	MTGenNodeHashByPtr(ptr);
	if (old != ptr->hash)
	{
		printf("%s old hash: %u, new hash: %u\n", 
			"ERROR checking node:", old, ptr->hash);
		return false;
	}
	return true;
}

// for test purpose only!
void MTChangeNodeHash(MerkleTree* treeptr, int idx, HASHTYPE newhash)
{
	treeptr->nodes[idx].hash = newhash;
}

LinkedNode* MTGetNodePath(MerkleTree* treeptr, int idx)
{
	//TODO
	if (idx == ROOT) // reach ROOT
	{
		LinkedNode* lnptr = malloc(sizeof(LinkedNode));
		lnptr->treeIdx = ROOT;
		lnptr->node = treeptr->nodes[ROOT];
		lnptr->parent = NULL;
		return lnptr;
	}
	LinkedNode* lnparent = MTGetNodePath(treeptr, idx/2);
	LinkedNode* lnptr = malloc(sizeof(LinkedNode));
	lnptr->treeIdx = idx;
	MTCopyNode(&(lnptr->node), &(treeptr->nodes[idx]));
	lnptr->parent = lnparent;
	return lnptr;
}

bool MTCheckNodePath(MerkleTree* treeptr, LinkedNode* lnptr)
{
	if (!lnptr) 
	{
		printf("%s\n", "MTCheckNodePath finished!");
		return true;	// check ends
	}

	//TODO
	printf("Checking: %d\n", lnptr->treeIdx);
	if (MTCheckNodeHash(treeptr, lnptr->treeIdx))
		return MTCheckNodePath(treeptr, lnptr->parent);
	else
		return false;
}

void MTPrintLinkedNode(LinkedNode* lnptr)
{
	printf("%d (%s)", lnptr->treeIdx, (lnptr->node).value);
	while (lnptr->parent)
	{
		lnptr = lnptr->parent;
		printf(" -> %d (%s)", lnptr->treeIdx, (lnptr->node).value);
	}
	printf("%s", "\n");
}

void MTFreeLinkedNode(LinkedNode* lnptr)
{
	//TODO
	if (lnptr->parent)
		MTFreeLinkedNode(lnptr->parent);
	free(lnptr);
	return;
}

Node* MTReadNode(MerkleTree* treeptr, int idx)
{
	return &(treeptr->nodes[idx]);
}

void MTWriteNode(MerkleTree* treeptr, int idx, char* newval)
{
	strncpy(treeptr->nodes[idx].value, newval, strlen(newval));
	MTUpdateNode(treeptr, idx);
}

void MTCopyNode(Node* dest, Node* src)
{
	memcpy((void*)dest, (const void*)src, sizeof(Node));
}

bool MTCheckNodePathLinkedNodeOnly(LinkedNode* lnptr)
{
	if (!lnptr) 
	{
		printf("%s\n", "MTCheckNodePathLinkedNodeOnly finished!");
		return true;	// check ends
	}

	//TODO
	printf("Checking: %d\n", lnptr->treeIdx);
	if (MTCheckNodeHashByPtr(&(lnptr->node)))
		return MTCheckNodePathLinkedNodeOnly(lnptr->parent);
	else
		return false;
}

MerkleProof* MTGetMerkleProof(MerkleTree* treeptr, int nodeidx)	
{
	int arridx = 0;
	MerkleProof* mpptr = malloc(sizeof(MerkleProof));
	// get path
	while (nodeidx >= ROOT)
	{
		MTCopyNode(&((mpptr->path)[arridx]), &(treeptr->nodes[nodeidx]));
		nodeidx = nodeidx / 2;
		++arridx;
	}
	return mpptr;
}

bool MTCheckMerkleProof(MerkleProof* mp)
{
	for (int i = 0; i < MAX_TREE_LEVEL; ++i)
		if (!MTCheckNodeHashByPtr(& ((mp->path)[i])) )
		{
			printf("%s\n", "MTCheckMerkleProof failed");
			return false;
		}
	printf("%s\n", "MTCheckMerkleProof passed");
	return true;
}

void MTPrintMerkleProof(MerkleProof* mp)
{
	printf("%s\n", "MTPrintMerkleProof:");
	for (int i = 0; i < MAX_TREE_LEVEL; ++i)
	{
		MTPrintNodeByPtr( & ((mp->path)[i]) );
	}
}


void MTFreeMerkleProof(MerkleProof* mpptr)
{
	free(mpptr);
}

void MTPrintNodeByIndex(MerkleTree* treeptr, int idx)
{
	char* s = MTSerializeNodeWithOwnHash(treeptr, idx);
	printf("%s\n", s);
	free(s);
	return;
}

void MTPrintNodeByPtr(Node* node)
{
	printf("%s%u%s%u%s%u%s%d%s%s\n", 
		"H", node->hash,
		"L", node->leftHash,
		"R", node->rightHash, 
		"P", node->prefix,
		"V", node->value);
	return;
}

void MTUpdateNode(MerkleTree* treeptr, int idx)
{
	if (idx == 0) return; // 

	if (!MTIsLeafNode(idx)) // not leaf: get the hash of the children
	{
		treeptr->nodes[idx].leftHash = treeptr->nodes[idx*2].hash;
		treeptr->nodes[idx].rightHash = treeptr->nodes[idx*2+1].hash;
	}
	else
	{
		treeptr->nodes[idx].leftHash = 0;
		treeptr->nodes[idx].rightHash = 0;
	}
	treeptr->nodes[idx].prefix = idx;
	MTGenNodeHash(treeptr, idx);
	MTUpdateNode(treeptr, idx/2);	// update parent
}

void MTAddNewNode(MerkleTree* treeptr, char* newval)
{
	if (treeptr->totalLeafNode == MAX_LEAF_NODE) // tree is full
	{
		printf("%s\n", "ERROR adding node: tree is full!");
		return;
	}
	++(treeptr->totalLeafNode);
	int idx = MTLeafIdxToTreeIdx(treeptr->totalLeafNode - 1);
	strncpy(treeptr->nodes[idx].value, newval, strlen(newval));
	MTUpdateNode(treeptr, idx);
}

void MTDeleteNode(MerkleTree* treeptr, int idx)
{
	if (idx > MTLeafIdxToTreeIdx(treeptr->totalLeafNode-1)) //check range
	{
		printf("%s\n", "ERROR deleting node: idx out of range!");
		return;
	}

	int endIdx = MTLeafIdxToTreeIdx(treeptr->totalLeafNode-1);

	// move all node from idx to end
	for (int i = idx; i < endIdx; ++i)
	{
		treeptr->nodes[i] = treeptr->nodes[i+1];
	}
	
	// deal with last node
	strcpy(treeptr->nodes[endIdx].value, "");
	treeptr->nodes[endIdx].hash = 0; // left/right hashes are already 0
	--treeptr->totalLeafNode;
	MTUpdateTree(treeptr);
	return;
}

void MTUpdateTree(MerkleTree* treeptr)
{
	for (int i = 0; i < treeptr->totalLeafNode; ++i)
	{
		MTUpdateNode(treeptr, MTLeafIdxToTreeIdx(i));
	}
}

void MTPrintTree(MerkleTree* treeptr)
{

	for (int i = 0; i < MAX_NODE; ++i)
	{
		printf("%3d: \t hash: %u \t value: %s\n", i,
			treeptr->nodes[i].hash, treeptr->nodes[i].value);
	}
}

void MTBuildTreeFromDB(MerkleTree* treeptr, const char* filename)
{
	readDB(filename);
	// printDatabuf();
	
	// store leaf node in MerkleTree
	treeptr->totalLeafNode = totalNumDB;
	for (int i = 0; i < totalNumDB; ++i)
	{
		int arridx = i + MAX_LEAF_NODE; // leaf node index starts from MAX_LEAF_NODE

		char* remaining;
		treeptr->nodes[arridx].hash = strtoul(databuf[i], &remaining, 10); // return a pointer of the remaining part to `value`
		strncpy(treeptr->nodes[arridx].value, remaining+1, strlen(remaining));
	}

	MTUpdateTree(treeptr);

}


void MTWriteTreeToDB(MerkleTree* treeptr, const char* filename)
{
	int arridx;
	totalNumDB = treeptr->totalLeafNode;
	for (int i = 0; i < treeptr->totalLeafNode; ++i)
	{
		arridx = i + MAX_LEAF_NODE; // leaf node index starts from MAX_LEAF_NODE
		snprintf(databuf[i], MAX_LEN, "%u:%s", 
			treeptr->nodes[arridx].hash, treeptr->nodes[arridx].value);
	}
	writeDB(filename);
	return;
}

bool MTCmpTree(MerkleTree* oldTree, MerkleTree* newTree)
{
	// compare root
	if (oldTree->nodes[ROOT].hash == newTree->nodes[ROOT].hash)
		return true;

	// TODO: find difference

	return false;
}


int buildmerkletree(MerkleTree* tree){

//        MerkleTree* tree = malloc(sizeof(MerkleTree));
        MTBuildTreeFromDB(tree, DBFILE);
        MTPrintTree(tree);

}

int writemerkletree(MerkleTree* tree){
	    MTWriteTreeToDB(tree, DBFILE);
        MTPrintTree(tree);
}

int test()
{
	MerkleTree* tree = malloc(sizeof(MerkleTree));
	MTBuildTreeFromDB(tree, DBFILE);
	// MTPrintTree(tree);
	MTAddNewNode(tree, "val9");
	MTPrintTree(tree);
	MTDeleteNode(tree, MTLeafIdxToTreeIdx(4));
	MTPrintTree(tree);
	// MTWriteTreeToDB(tree, DBFILE);


	LinkedNode* path = MTGetNodePath(tree, MTLeafIdxToTreeIdx(4));
	MTPrintLinkedNode(path);

	MTCheckNodePath(tree, path);
	MTChangeNodeHash(tree, 4, 1234567);
	MTCheckNodePath(tree, path);
	MTFreeLinkedNode(path);

	Node* ptr = MTReadNode(tree, MTLeafIdxToTreeIdx(4));
	MTPrintNodeByIndex(tree, MTLeafIdxToTreeIdx(4));
	MTPrintNodeByPtr(ptr);

	MTWriteNode(tree, MTLeafIdxToTreeIdx(4), "newval");
	MTPrintNodeByIndex(tree, MTLeafIdxToTreeIdx(4));

	// MerkleTree* tree2 = malloc(sizeof(MerkleTree));
	// MTBuildTreeFromDB(tree2, DBFILE_BACKUP);
	// MTPrintTree(tree2);
	// if (MTCmpTree(tree, tree2))
	// 	printf("%s\n", "Same!");
	// else
	// 	printf("%s\n", "Different!");

	MerkleProof* mpptr = MTGetMerkleProof(tree, MTLeafIdxToTreeIdx(4));
	printf("%s\n", "\n\n\n");
	MTPrintMerkleProof(mpptr);

	MTCheckMerkleProof(mpptr);
	MTFreeMerkleProof(mpptr);

	free(tree);

	// free(tree2);
	return 0;
}












