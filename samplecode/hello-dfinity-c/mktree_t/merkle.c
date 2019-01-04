#include <stdio.h> 
//#include <errno.h> 
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "merkle.h"

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


char* MTSerializeNode(MerkleTree* treeptr, int idx) 
{
	char* out = (char*)malloc(sizeof(char)*MAX_LEN); // need to be freed by the caller
	snprintf(out, MAX_LEN, "%s%u%s%u%s%d%s%s", 
		"L", treeptr->nodes[idx].leftHash,
		"R", treeptr->nodes[idx].rightHash, 
		"P", treeptr->nodes[idx].prefix,
		"V", treeptr->nodes[idx].value);
	// printf("%s\n", out);
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

