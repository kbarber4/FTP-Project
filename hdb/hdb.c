//Hooli Redis Library
//Student: Kyle Barber
//Student#: 250674178
//Course: CS3357
//Instructor: Jeff Shantz

#include "hdb.h"
#include <stdlib.h>
#include <stdio.h>
#include <hiredis/hiredis.h>
#include <string.h>

char* redisCS(hdb_connection* con, const char* username, const char* filename);
int redisFCount(hdb_connection* con, const char* username);
void redisFiles(hdb_connection* con, const char* username, char *list[]);
char* randgen();

//Creates a connection to the Redis server
hdb_connection* hdb_connect(const char* server) {
  // Connect to the Redis server.  
  // See https://github.com/redis/hiredis/blob/master/examples/example.c
  //
  // Cast the redisContext to an hdb_connection.
  // See the definition of hdb_connection in hdb.h -- notice that it's
  // just a typedef of void* (i.e. an alias of void*).
  //
  // Why are we doing this?  To hide our implementation details from
  // any users of the library.  We want to be able to change our 
  // implementation at any time without affecting external code.
  // We don't want external users of the code to know we're using
  // Redis, so that, if we decided to switch to another data store
  // in the future, we could make the change internally, and no
  // external code would break.
  //
  // To avoid a compiler warning when casting the redisContext to
  // an hdb_connection, you may find the following line helpful
  // (don't be scared):
  // return *(hdb_connection**)&context;

	redisContext *c; //stores the connection
	struct timeval timeout={1,500000}; //time dedicated to connecting

	//connect to Redis
	c=redisConnectWithTimeout(server, 6379, timeout);
	//check connection
	if(c==NULL || c->err){
		printf("Unable to connect");
		exit(1);
	}
	return *(hdb_connection**)&c;
}

//Closes the connection to the Redis server
void hdb_disconnect(hdb_connection* con) {
  // "Disconnect" from the Redis server (i.e. free the Redis context)
  // See https://github.com/redis/hiredis/blob/master/examples/example.c

	//diconnect from Redis and free context
	redisFree((redisContext*)con);
}

//Stores a record in the Redis server
void hdb_store_file(hdb_connection* con, hdb_record* record) {
  // Store the specified record in the Redis server.  There are many ways to
  // do this with Redis.  Whichever way you choose, the checksum should be 
  // associated with the file, and the file should be associated with the user.
  //
  // Hint: look up the HSET command. 
  //
  // See https://github.com/redis/hiredis/blob/master/examples/example.c for
  // an example of how to execute it on the Redis server.

	//call Redis to store a record in the database
	redisReply* reply=redisCommand((redisContext*)con,"HSET %s %s %s",record->username,record->filename,record->checksum);
	freeReplyObject(reply);
}

//Removes a file from the Redis server
int hdb_remove_file(hdb_connection* con, const char* username, const char* filename) {
  // Remove the specified file record from the Redis server.

	//call Redis to remove a file from the database
	redisReply* reply=redisCommand((redisContext*)con,"HDEL %s %s",username,filename);
	int num=reply->integer;
	freeReplyObject(reply);
	return num;
}

//Finds the checksum of a file
char* hdb_file_checksum(hdb_connection* con, const char* username, const char* filename) {
  // If the specified file exists in the Redis server, return its checksum.
  // Otherwise, return NULL.

	//call function to recieve checksum value
	char* csum=redisCS(con,username,filename);
	return csum;
}

//Finds the number of files a user has stored
int hdb_file_count(hdb_connection* con, const char* username) {
  // Return a count of the user's files stored in the Redis server.

	//call function to get number of files a user has on Redis
	return redisFCount(con,username);
}

//Checks if a user exists in the server
bool hdb_user_exists(hdb_connection* con, const char* username) {
  // Return a Boolean value indicating whether or not the user exists in
  // the Redis server (i.e. whether or not he/she has files stored).

	//call Redis to find if a user exists
	redisReply* reply=redisCommand((redisContext*)con,"EXISTS %s",username);
	int boolean=reply->integer;
	freeReplyObject(reply);
	return boolean;
}

//Checks if a file exists in the server
bool hdb_file_exists(hdb_connection* con, const char* username, const char* filename) {
  // Return a Boolean value indicating whether or not the file exists in
  // the Redis server.

	//call Redis to find if a file exists
	redisReply* reply=redisCommand((redisContext*)con,"HEXISTS %s %s",username,filename);
	int boolean=reply->integer;
	freeReplyObject(reply);
	return boolean;
}

//Creates a linked list of all of a user's files
hdb_record* hdb_user_files(hdb_connection* con, const char* username) {
  // Return a linked list of all the user's file records from the Redis
  // server.  See the hdb_record struct in hdb.h  -- notice that it 
  // already has a pointer 'next', allowing you to set up a linked list
  // quite easily.
  //
  // If the user has no files stored in the server, return NULL.

	int fnum=redisFCount(con,username); //number of user's files
	char *flist[fnum]; //list of user's files
	hdb_record *records[fnum]; //list of records to be filled and added
	hdb_record* head; //first record, will be returned
	int num=0; //for loop counter
	char* csum;

	//check if there are files
	if(fnum==0)
		return NULL;

	//fill flist with files
	redisFiles(con,username,flist);

	//fill out the list one record at a time
	records[num]=malloc(sizeof(hdb_record));
	records[num]->username=malloc(sizeof(char)*100);
	records[num]->filename=malloc(sizeof(char)*100);
	records[num]->checksum=malloc(sizeof(char)*100);
	for(num=0;num<fnum;num++){
		//fill out record
		strcpy(records[num]->username,username);
		strcpy(records[num]->filename,flist[num]);
		csum=redisCS(con,username,flist[num]);
		strcpy(records[num]->checksum,csum);
		free(csum);
		free(flist[num]);
		//check if there should be another record in the list
		if((num+1)<fnum){
			records[num+1]=malloc(sizeof(hdb_record));
			records[num+1]->username=malloc(sizeof(char)*100);
			records[num+1]->filename=malloc(sizeof(char)*100);
			records[num+1]->checksum=malloc(sizeof(char)*100);
			records[num]->next=records[num+1];
		}
		else{
			records[num]->next=NULL;
		}
	}
	//return the list
	head=records[0];
	return head;
}

//Frees the memory used in a linked list
void hdb_free_result(hdb_record* record) {
  // Free up the memory in a linked list allocated by hdb_user_files().

	hdb_record* next; //used for tracking the next record to free
	//free the first record
	next=record->next;
	free(record->username);
	free(record->filename);
	free(record->checksum);
	free(record);
	//free all remaining records
	while(next!=NULL){
		record=next;
		next=record->next;
		free(record->username);
		free(record->filename);
		free(record->checksum);
		free(record);
	}
}

//Deletes a user from the Redis server
int hdb_delete_user(hdb_connection* con, const char* username) {
  // Delete the user and all of his/her file records from the Redis server.

	//calls Redis to delete the key associated with a user
	redisReply* reply=redisCommand((redisContext*)con,"DEL %s",username);
	int num=reply->integer;
	freeReplyObject(reply);
	return num;
}

//Finds the checksum of a file
char* redisCS(hdb_connection* con, const char* username, const char* filename){
	//call Redis to get a crc value
	redisReply* reply=redisCommand((redisContext*)con,"HGET %s %s",username,filename);
	char* csum; //string to be returned
	if(reply->str!=NULL){
		csum=malloc(sizeof(char)*(strlen(reply->str)+1));
		strcpy(csum,reply->str);
	}
	else
		csum=NULL;
	freeReplyObject(reply);
	return csum;
}

//Finds the number of files a user has
int redisFCount(hdb_connection* con, const char* username){
	//call Redis to get the number of files a user has
	redisReply* reply=redisCommand((redisContext*)con,"HLEN %s",username);
	int num=reply->integer;
	//free memory used for reply
	freeReplyObject(reply);
	return num;
}

//Creates a linked list of a user's files
void redisFiles(hdb_connection* con, const char* username, char *list[]){
	int count=0; //increments so files are placed into list
	//call Redis to get a list of files belonging to the user
	redisReply* reply=redisCommand((redisContext*)con,"HKEYS %s",username);
	//add files to the list
	for(count=0;count < reply->elements;count++){
		list[count]=malloc(sizeof(char)*(strlen(reply->element[count]->str)+1));
		strcpy(list[count],reply->element[count]->str);
	}
	freeReplyObject(reply);
}

//Checks if a username/password combo is correct and returns a token
char* hdb_authenticate(hdb_connection* con, const char* username, const char* password){
	char* token=NULL; //token value to be returned
	char* cred=malloc(sizeof(char)*(strlen(username)+strlen("cred")+1)); //modified username for accessing password and token
	strcpy(cred,username);
	strcat(cred,"cred");
	//call Redis to get password associated with username
	redisReply* reply=redisCommand((redisContext*)con,"HGET %s password",cred);
	//check if username exists
	if(reply->str==NULL){
		//create user
		freeReplyObject(reply);
		reply=redisCommand((redisContext*)con,"HSET %s username %s",cred,username);
		freeReplyObject(reply);
		reply=redisCommand((redisContext*)con,"HSET %s password %s",cred,password);
		//create and store token
		token=randgen();
		freeReplyObject(reply);
		reply=redisCommand((redisContext*)con,"HSET %s token %s",cred,token);
	}
	//check if password matches actual password
	else if(strcmp(reply->str,password)==0){
		//create and store token
		token=randgen();
		freeReplyObject(reply);
		reply=redisCommand((redisContext*)con,"HSET %s token %s",cred,token);
	}
	//free memory and return token
	freeReplyObject(reply);
	free(cred);
	return token;
}

//Creates a token
char* randgen(){
	char characters[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; //list of possible characters to pick from
	char token[16]; //token to be returned
	int index; //position in token being assigned a value

	//randomly select 16 characters
	for(index=0;index<16;index++){
		//randomly select digit and add to token
		token[index]=characters[rand()%(sizeof(characters)-1)];
	}
	token[16]='\0';

	//malloc token value and return the token
	char* fulltoken=malloc(sizeof(char)*(strlen(token)+1));
	strcpy(fulltoken,token);
	return fulltoken;
}

//Finds the username associated with a token
char* hdb_verify_token(hdb_connection* con, const char* token){
	redisReply* keys=redisCommand((redisContext*)con,"KEYS *cred"); //List of user credential keys
	redisReply* reply; //Used for getting tokens from Redis
	int count=0; //Used for iterating through the keys
	//Compare the tokens of all users to the given token
	for(count=0;count < keys->elements;count++){
		reply=redisCommand((redisContext*)con,"HGET %s token",keys->element[count]->str);
		//If user token matches given token, then return the username
		if(reply->str!=NULL && strcmp(reply->str,token)==0){
			freeReplyObject(reply);
			reply=redisCommand((redisContext*)con,"HGET %s username",keys->element[count]->str);
			char* username=malloc(sizeof(char)*(strlen(reply->str)+1));
			strcpy(username,reply->str);
			freeReplyObject(reply);
			freeReplyObject(keys);
			return username;
		}
		freeReplyObject(reply);
	}
	freeReplyObject(keys);
	//Return NULL if no user tokens match
	return NULL;
}
