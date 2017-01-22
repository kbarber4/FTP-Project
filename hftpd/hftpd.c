//Hooli File Transfer Protocol
//Student: Kyle Barber
//Student#: 250674178
//Course: CS3357
//Instructor: Jeff Shantz

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>
#include <syslog.h>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include "hdb.h"

typedef struct{
	int length;
	uint8_t buffer[1472];
} message;

typedef struct{
	int length;
	uint8_t type;
	uint8_t seq;
	uint16_t namelength;
	uint32_t size;
	uint32_t checksum;
	char token[16];
	char file[1444];
} control_message;

typedef struct{
	int length;
	uint8_t type;
	uint8_t seq;
	uint16_t datalength;
	char data[1468];
} data_message;

typedef struct{
	int length;
	uint8_t type;
	uint8_t seq;
	uint16_t error;
} ack_message;

struct host{
	struct sockaddr_in addr;
	socklen_t addr_len;
	char friendly_ip[INET_ADDRSTRLEN];
};

data_message* dmsg; //message received from client with file data
control_message* msg; //message received from client
message* ack; //message to be sent to client
hdb_connection* con; //connection to the Redis server

//Use port to set up the creation of a UDP socket
struct addrinfo* get_udp_sockaddr(const char* node, const char* port, int flags){
	struct addrinfo hints;
	struct addrinfo* results;
	int retval;

	memset(&hints,0,sizeof(struct addrinfo));

	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_DGRAM;
	hints.ai_flags=flags;

	retval=getaddrinfo(node,port,&hints,&results);

	if(retval!=0){
		syslog(LOG_ERR,"getaddrinfo: %s",gai_strerror(retval));
		exit(EXIT_FAILURE);
	}

	return results;
}

//Create a socket and bind to it
int bind_socket(struct addrinfo* addr_list){
	struct addrinfo* addr;
	int sockfd;

	for(addr=addr_list; addr!=NULL; addr=addr->ai_next){
		sockfd=socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

		if(sockfd==-1)
			continue;

		if(bind(sockfd, addr->ai_addr, addr->ai_addrlen)==-1){
			close(sockfd);
			continue;
		}
		else
			break;
	}

	freeaddrinfo(addr_list);

	if(addr==NULL)
		err(EXIT_FAILURE, "%s", "Unable to bind");
	else
		return sockfd;
}

//Set up and create a socket
int create_server_socket(char* port){
	struct addrinfo* results=get_udp_sockaddr(NULL,port,AI_PASSIVE);
	int sockfd=bind_socket(results);

	return sockfd;
}

//Create and initialize message struct
message* create_message(){
	return (message*)malloc(sizeof(message));
}

//Receive UDP message
message* receive_message(int sockfd, struct host* source){
	message* msg=create_message();

	source->addr_len=sizeof(source->addr);

	msg->length=recvfrom(sockfd, msg->buffer, sizeof(msg->buffer), 0, (struct sockaddr*)&source->addr, &source->addr_len);

	if(msg->length>0){
		inet_ntop(source->addr.sin_family, &source->addr.sin_addr, source->friendly_ip, sizeof(source->friendly_ip));
		return msg;
	}
	else{
		free(msg);
		return NULL;
	}
}

//Send UDP message
int send_message(int sockfd, message* msg, struct host* dest){
	return sendto(sockfd, msg->buffer, msg->length, 0, (struct sockaddr*)&dest->addr, dest->addr_len);
}

//Create a response message to ACK a received message
message* create_response(uint8_t seq, uint16_t error){
	ack_message* msg=(ack_message*)create_message(); //message to be sent to client

	//build the message based on the hftp protocol
	msg->length=4;
	msg->type=255;
	msg->seq=seq;
	msg->error=error;

	return (message*)msg;
}

//Ends the loop so the program can exit
void ender(){
	syslog(LOG_DEBUG,"File server closing");
	free(msg);
	free(ack);
	hdb_disconnect(con);
	exit(1);
}

int main(int argc, char* argv[]){
	char* port="10000"; //port to listen for messages on
	char* rhost="localhost"; //hostname of the Redis server
	char* root="tmp/hftpd"; //root of storage file path
	int time=10; //time spent waiting before exit in seconds
	int c; //used to store returned values of getopt_long
	int index=0; //used for getopt_long

	//Initialize option object for getopt_long
	struct option long_options[]={
		{"verbose",no_argument,0,'v'},
		{"port",required_argument,0,'p'},
		{"redis",required_argument,0,'r'},
		{"dir",required_argument,0,'d'},
		{"timewait",required_argument,0,'t'},
		{0,0,0,0}
	};

	//Set up syslog
	openlog("hftpd",LOG_PERROR|LOG_PID|LOG_NDELAY,LOG_USER);
	setlogmask(LOG_UPTO(LOG_INFO));

	//Loop through arguments with getopt_long
	while(1){
		c=getopt_long(argc,argv,"vp:r:d:t:",long_options,&index);

		//End loop if no more arguments
		if(c==-1)
			break;

		//Perform action based on arguments sent
		switch(c){
			case 'v':
				setlogmask(LOG_UPTO(LOG_DEBUG));
				syslog(LOG_DEBUG,"Verbose enabled");
				break;
			case 'p':
				port=optarg;
				syslog(LOG_DEBUG,"Port set to %s",port);
				break;
			case 'r':
				rhost=optarg;
				syslog(LOG_DEBUG,"Redis host set to %s",rhost);
				break;
			case 'd':
				root=optarg;
				syslog(LOG_DEBUG,"Root set to %s",root);
				break;
			case 't':
				time=atoi(optarg);
				syslog(LOG_DEBUG,"Wait time set to %d",time);
				break;
			case '?':
				exit(EXIT_FAILURE);
				break;
		}
	}


	//Create socket to listen on
	int sockfd=create_server_socket(port);
	struct host server; //address of the client

	//Create connection to Redis
	con=hdb_connect(rhost);

	int type; //type of current message
	int prevtype; //type of previous message
	int seq; //keeps track of sequence number
	int rseq; //seqence number of received message
	int length=0; //length of the variable filed on the message
	int retval=0; //value returned from poll
	int error; //value sent in error field of ACK
	int size; //total size of file being transfered
	int bytesum; //total bytes transfered of current file
	unsigned long checksum=0; //checksum of file being transfered
	char token[17]; //token of user
	char file[1445]; //file path of file being transfered
	char data[1469]; //file data sent from client
	char* username=""; //name of current user
	char path[PATH_MAX]; //full path to file being transfered

	//Watch for ctrl+c
	signal(SIGINT,ender);

	//Constant loop so server stays on
	while(1){
		bytesum=0;
		type=0;
		prevtype=0;
		seq=0;
		error=0;
		FILE* fp=NULL; //file being writen to
		//Keep receiving messages until a termination message is received
		syslog(LOG_INFO,"Waiting for client message");
		while(type!=2){
			//Receive message and check type
			msg=(control_message*)receive_message(sockfd,&server);
			syslog(LOG_DEBUG,"Message received");
			prevtype=type;
			type=msg->type;
			rseq=msg->seq;
			length=msg->namelength;

			//Send ACK of previous message if wrong sequence number
			if(type==3 && seq!=rseq){
				ack=create_response(seq,error);
				send_message(sockfd,ack,&server);
			}

			//Process initialization message and send ACK
			else if(type==1 && prevtype!=1){
				syslog(LOG_DEBUG,"Type:Initialization, Seq#:%d",seq);

				//Close previous file and update Redis
				if(fp!=NULL){
					fclose(fp);
					hdb_record* record=malloc(sizeof(hdb_record));
					record->username=malloc((strlen(username)+1)*sizeof(char));
					strcpy(record->username,username);
					record->filename=malloc((strlen(file)+1)*sizeof(char));
					strcpy(record->filename,file);
					char tmpsum[PATH_MAX/3];
					snprintf(tmpsum,PATH_MAX,"%lX",checksum);
					record->checksum=malloc((strlen(tmpsum)+1)*sizeof(char));
					strcpy(record->checksum,tmpsum);
					record->next=NULL;
					hdb_store_file(con,record);
					hdb_free_result(record);
					bytesum=0;
					free(username);
					syslog(LOG_DEBUG,"Previous file closed");
				}

				//Parse message
				size=msg->size;
				checksum=msg->checksum;
				strncpy(token,msg->token,16);
				token[17]='\0';
				strcpy(file,msg->file);
				file[length]='\0';
				username=hdb_verify_token(con,token);
				syslog(LOG_INFO,"File: %s",file);
				if(username==NULL){
					error=1;
					syslog(LOG_ERR,"Invalid token");
					//Send ACK
					ack=create_response(seq,error);
					send_message(sockfd,ack,&server);
					break;
				}
				else{
					error=0;
					syslog(LOG_DEBUG,"Message parsed");

					//Create directory path for next file and open file
					snprintf(path,PATH_MAX,"mkdir -p %s/%s/%s",root,username,file);
					system(path);
					snprintf(path,PATH_MAX,"rmdir %s/%s/%s",root,username,file);
					system(path);
					snprintf(path,PATH_MAX,"./%s/%s/%s",root,username,file);
					fp=fopen(path,"w");
					if(fp==NULL){
						syslog(LOG_ERR,"File failed to open");
						error=1;
					}
					else
						syslog(LOG_DEBUG,"Next file opened");

					//Send ACK
					ack=create_response(seq,error);
					send_message(sockfd,ack,&server);

					//Update seq#
					seq=(seq+1)%2;
					rseq=(seq+1)%2;
				}
			}

			//Process data message and send ACK
			else if(type==3 && prevtype!=0){
				dmsg=(data_message*)msg;
				syslog(LOG_DEBUG,"Type:Data, Seq#:%d, Bytes:%d",seq,length);
				bytesum+=length;
				syslog(LOG_INFO,"Bytes: %d/%d, %f%%",bytesum,size,(double)(bytesum/size)*100);

				//Parse data
				strcpy(data,dmsg->data);
				data[length]='\0';

				//Write to file
				fputs(data,fp);

				//Create and send ACK
				ack=create_response(seq,error);
				send_message(sockfd,ack,&server);

				//Update seq#
				seq=(seq+1)%2;
				rseq=(seq+1)%2;
			}

			//Process termination message and send ACK
			else if(type==2 && prevtype==3){
				syslog(LOG_DEBUG,"Type:Termination, Seq#:%d",seq);

				//Close previous file and update Redis
				fclose(fp);
				hdb_record* record=malloc(sizeof(hdb_record));
				record->username=malloc((strlen(username)+1)*sizeof(char));
				strcpy(record->username,username);
				record->filename=malloc((strlen(file)+1)*sizeof(char));
				strcpy(record->filename,file);
				char tmpsum[PATH_MAX/3];
				snprintf(tmpsum,PATH_MAX,"%lX",checksum);
				record->checksum=malloc((strlen(tmpsum)+1)*sizeof(char));
				strcpy(record->checksum,tmpsum);
				record->next=NULL;
				hdb_store_file(con,record);
				hdb_free_result(record);
				free(username);
				syslog(LOG_DEBUG,"Previous file closed");

				//Create and send termination ACK
				ack=create_response(seq,error);
				send_message(sockfd,ack,&server);
			}

			if(type!=2){
				free(msg);
				free(ack);
			}
		}

		if(error==0){
			//Listen for repeat termination messages
			struct pollfd fd={.fd=sockfd,.events=POLLIN};
			retval=poll(&fd,1,time*1000);
			while(retval==1){
				syslog(LOG_DEBUG,"Resending termination ACK");
				send_message(sockfd,ack,&server);
				retval=poll(&fd,1,time*1000);
			}
		}
		syslog(LOG_DEBUG,"Files transfered");
	}

	//Free memory
	free(msg);
	free(ack);

	hdb_disconnect(con);
	return 0;
}
