#ifndef DB_H
#define DB_H

#define DBFILE "testDB.txt"
#define DBFILE_BACKUP "testDB.bak"
#define MAX_NUM 64
#define LINE_SIZE 256
#define DELIMITER ":"

extern FILE* DBfptr;					// file pointer of DB
extern int totalNumDB;				// current number of entries
extern char databuf[MAX_NUM][LINE_SIZE];
extern bool databufInit;

// FILE* openDB(const char* file);
// void closeDB();
void readDB(const char* filename);
void writeDB(const char* filename);
void printDatabuf();
char* findKey(char* key);
bool deleteKey(char* key);
bool storeKey(char* key, char* val);
bool updateKey(char* key, char* newVal);

#endif /* DB_H */