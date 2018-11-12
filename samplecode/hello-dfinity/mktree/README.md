# Introduction

A PoC implementation of a merkle tree with database backend. 

# Merkle Tree

The merkle tree is implemented as an array of `Node` for easy indexing. Currently, the maximum number of leaf node is `64` (defined in `MAX_LEAF_NODE`). The leaf nodes are the data stored in the database. See `merkle.h` for details of the related structs and functions.

# Database

The database is a simple key-value database. It is implemented as a text file for simplicity. The format of the text file is `key:val` for each entry. To interact with the database, the contents need to be loaded in the memory through `readDB()`. See `db.h` for details.
