// simple `key:val` database implementation
// For now, each line is a `key:val` string.
// For searching, it is linear time O(n). We might change to O(1) later.

#include <stdio.h> 
// #include <errno.h> 
#include <stdbool.h>
#include <string.h>

#include "db.h"

FILE* DBfptr;					// file pointer of DB
int totalNumDB = 0;				// current number of entries
char databuf[MAX_NUM][LINE_SIZE];
bool databufInit = false;


// FILE* openDB(const char* file)
// {
// 	return fopen(file, "r+"); 
// }

// void closeDB()
// { 
// 	fclose(DBfptr);
// }

// read the whole content in databuf (file -> memory)
void readDB(const char* filename)
{
	DBfptr = fopen(filename, "r+"); 
	if (!DBfptr) 
	{  
		printf("Error opening file\n");  
		return;
	} 

	//read line by line
	char line[LINE_SIZE];
	int count = 0;
	while (fgets(line, LINE_SIZE, DBfptr) != NULL)  
	{
		char* nl;
		nl = strrchr(line, '\n');	//rm newline
		if (nl) *nl = '\0';
		strncpy(databuf[count], line, strlen(line));
		++count;
	}
	if (count > totalNumDB) totalNumDB = count;
	databufInit = true;
	fclose(DBfptr);
}

// store the databuf to file (memory -> file)
void writeDB(const char* filename)
{
	DBfptr = fopen(filename, "w+"); 
	if (!DBfptr) 
	{  
		printf("Error opening file\n");  
		return;
	} 

	for (int i=0; i<totalNumDB; i++)
	{
		fprintf(DBfptr, "%s\n", databuf[i]);
	}
	fclose(DBfptr);
}

// print the databuf
void printDatabuf()
{
	if (!databufInit) readDB(DBFILE);
	for (int i=0; i<totalNumDB; i++)
	{
		printf("%s\n", databuf[i]);
	}
}

char* findKey(char* key)
{
	if (!databufInit) readDB(DBFILE);
	int keylen = strlen(key);
	for (int i=0; i<totalNumDB; i++)
	{
		if (strncmp(key, databuf[i], keylen) == 0)	// found key
		{
			char* pos = strstr(databuf[i], DELIMITER);
			return pos+1;
		}
	}
	return NULL;
}

bool updateKey(char* key, char* newVal)
{
	if (!databufInit) readDB(DBFILE);
	int keylen = strlen(key);
	char* valPtr = findKey(key);
	if (valPtr == NULL)
	{
		printf("Key does not exist!\n");
		return false;
	}
	strncpy(valPtr, newVal, strlen(newVal));
	return true;
}

bool deleteKey(char* key)
{
	if (!databufInit) readDB(DBFILE);
	int keylen = strlen(key);
	for (int i=0; i<totalNumDB; i++)
	{
		if (strncmp(key, databuf[i], keylen) == 0)	// found key
		{
			// move all following entries
			for (int j=i; j<totalNumDB-1; j++) 
			{
				strncpy(databuf[j], databuf[j+1], strlen(databuf[j+1]));
			}
			strcpy(databuf[totalNumDB-1], "");
			--totalNumDB;
			return true;
		}
	}
	return false;
}

bool storeKey(char* key, char* val)
{
	if (!databufInit) readDB(DBFILE);
	if (totalNumDB == MAX_NUM)
	{
		printf("Number of entries exceeds Maximum!\n");
		return false;
	}

	if (findKey(key))
	{
		printf("Key already exists! Use updateKey() instead\n");
		return false;
	}
	// add new entry (`key:val`)
	strncpy(databuf[totalNumDB], key, strlen(key));
	strncat(databuf[totalNumDB], DELIMITER, 1);
	strncat(databuf[totalNumDB], val, strlen(val));

	++totalNumDB;
	return true;
}

int testDB()
{

	readDB(DBFILE);
	printDatabuf();
	printf("findKey(key1): %s\n", findKey("key1"));
	printf("findKey(key6): %s\n", findKey("key6"));
	storeKey("key6", "val6");
	printf("findKey(key6): %s\n", findKey("key6"));
	deleteKey("key1");
	printf("findKey(key1): %s\n", findKey("key1"));
	printDatabuf();
	updateKey("key6", "val7");
	printDatabuf();
	writeDB(DBFILE);

	return 0;
}















