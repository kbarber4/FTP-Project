//Hooli Client
//Student: Kyle Barber
//Student#: 250674178
//Course: CS3357
//Instructor: Jeff Shantz

#include <stdlib.h>
#include <zlib.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <err.h>
#include <arpa/inet.h>
#include <poll.h>

struct llist{
	char* file;
	char* checksum;
	struct llist* next;
};

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

message* create_data(uint8_t type, uint8_t seq, char* data);
message* create_control(uint8_t type, uint8_t seq, uint32_t size, uint32_t checksum, char* token, char* file);
message* create_message();
message* receive_message(int sockfd, struct host* source);
int send_message(int sockfd, message* msg, struct host* dest);
struct addrinfo* get_udp_sockaddr(const char* node, const char* port, int flags);
int create_client_socket(char* hostname, char* port, struct host* server);
int open_connection(struct addrinfo* addr_list);
struct addrinfo* get_sockaddr(const char* hostname, const char* port);
struct llist* filedata(char name[], uLong crc, char path[], struct llist* files);
uLong crcfinder(char item[]);
struct llist* trav(char dire[], char path[], struct llist* files);

int main(int argc, char* argv[]){
	DIR* d; //used for checking if argument directory exists
	char* directory="~/hooli"; //Stores Hooli root directory
	char* host="localhost"; //Stores server name
	char* port="9000"; //Stores port number
	char* fserver="localhost"; //Stores file server name
	char* fport="10000"; //Stores file server port number
	char msg[PATH_MAX]; //Message to be sent to server
	char response[PATH_MAX]; //Response received from server
	char listresponse[PATH_MAX]; //List response received from server
	char* token=""; //Stores token sent from server
	char list[PATH_MAX]; //List of files and checksums to send, used to make LIST request
	char entry[PATH_MAX]; //Individual files and checksums to send, used to make list
	char* parser; //Used to parse responses from the server
	int index=0; //Used for getopt_long
	int c; //Used to store returned values of getopt_long
	//Initialize the linked list used for storing files and checksums
	struct llist* files=malloc(sizeof(struct llist));
	files->file="";
	files->next=NULL;
	//Initialize the linked list used for storing reqested files
	struct llist* requests=malloc(sizeof(struct llist));
	requests->file="";
	requests->next=NULL;

	//Initialize option object for getopt_long
	struct option long_options[]={
		{"verbose",no_argument,0,'v'},
		{"server",required_argument,0,'s'},
		{"port",required_argument,0,'p'},
		{"dir",required_argument,0,'d'},
		{"fserver",required_argument,0,'f'},
		{"fport",required_argument,0,'o'},
		{0,0,0,0}
	};

	//Set up syslog
	openlog("client",LOG_PERROR|LOG_PID|LOG_NDELAY,LOG_USER);
	setlogmask(LOG_UPTO(LOG_INFO));

	//Loop through arguments with getopt_long
	while(1){
		c=getopt_long(argc,argv,"vs:p:d:f:o:",long_options,&index);

		//End loop if no more arguments
		if(c==-1)
			break;

		//Perform action based on arguments sent
		switch(c){
			case 'd':
				directory=optarg;
				syslog(LOG_DEBUG,"Directory set to %s",directory);
				break;
			case 'v':
				setlogmask(LOG_UPTO(LOG_DEBUG));
				syslog(LOG_DEBUG,"Verbose enabled");
				break;
			case 'p':
				port=optarg;
				syslog(LOG_DEBUG,"Port set to %s",port);
				break;
			case 's':
				host=optarg;
				syslog(LOG_DEBUG,"Host set to %s",host);
				break;
			case 'f':
				fserver=optarg;
				syslog(LOG_DEBUG,"File server set to %s",fserver);
				break;
			case 'o':
				fport=optarg;
				syslog(LOG_DEBUG,"File server port set to %s",fport);
				break;
			case '?':
				exit(EXIT_FAILURE);
				break;
		}
	}

	//Check if username and password were included
	if(optind>=argc || optind+1>=argc){
		syslog(LOG_ERR,"Must include username and password");
		exit(EXIT_FAILURE);
	}

	char* username=argv[optind];
	char* password=argv[optind+1];
	syslog(LOG_DEBUG,"Username: %s, Password: %s",username,password);


	//Open root directory
	d=opendir(directory);
	if(d==NULL){
		syslog(LOG_ERR,"Directory failed to open");
		closedir(d);
		exit(EXIT_FAILURE);
	}
	syslog(LOG_INFO,"Directory successfully opened");
	closedir(d);

	//Begin directory traversal
	syslog(LOG_DEBUG,"Finding Files");
	files=trav(directory, "", files);

	syslog(LOG_DEBUG,"Printing Files");
	struct llist* node=files;
	while(node->next!=NULL){
		node=node->next;
		syslog(LOG_DEBUG,"%s %s", node->file, node->checksum);
	}


	//Connect to the server
	struct addrinfo* results=get_sockaddr(host,port);
	int sockfd=open_connection(results);


	//Create AUTH request
	snprintf(msg,PATH_MAX,"AUTH\nUsername:%s\nPassword:%s\n\n",username,password);
	syslog(LOG_INFO,"Sending AUTH request");
	syslog(LOG_DEBUG,"Sending:%s",msg);

	//Send AUTH request
	if(send(sockfd,msg,strlen(msg),0)==-1){
		syslog(LOG_ERR,"Unable to send");
		exit(EXIT_FAILURE);
	}

	//Receive AUTH response
	int bytes=recv(sockfd,response,sizeof(response)-1,0);
	if(bytes==-1){
		syslog(LOG_ERR,"Unable to read");
		exit(EXIT_FAILURE);
	}
	response[bytes]='\0';
	syslog(LOG_DEBUG,"Received:%s",response);

	//Parse AUTH response
	parser=strtok(response,"\n");
	if(strcmp(parser,"401 Unauthorized")==0){
		syslog(LOG_INFO,"Response:Unauthorized");
		exit(EXIT_FAILURE);
	}
	syslog(LOG_INFO,"Response:Authorized");
	parser=strtok(NULL,":");
	token=strtok(NULL,"\n");


	//Create LIST request
	node=files;
	while(node->next!=NULL){
		node=node->next;
		snprintf(entry,PATH_MAX,"\n%s\n%s",node->file,node->checksum);
		strcat(list,entry);
	}
	snprintf(msg,PATH_MAX,"LIST\nToken:%s\nLength:%d\n%s",token,strlen(list)-1,list);
	syslog(LOG_DEBUG,"Sending:%s",msg);

	//Send LIST request
	if(send(sockfd,msg,strlen(msg),0)==-1){
		syslog(LOG_ERR,"Unable to send");
		exit(EXIT_FAILURE);
	}

	//Receive LIST response
	bytes=recv(sockfd,listresponse,sizeof(listresponse)-1,0);
	if(bytes==-1){
		syslog(LOG_ERR,"Unable to read");
		exit(EXIT_FAILURE);
	}
	listresponse[bytes]='\0';
	syslog(LOG_DEBUG,"Received:%s",listresponse);

	//Parse LIST response
	parser=strtok(listresponse,"\n");
	if(strcmp(parser,"204 No files requested")==0){
		syslog(LOG_INFO,"No files requested");
		exit(EXIT_FAILURE);
	}
	parser=strtok(NULL,"\n");
	parser=strtok(NULL,"\n");
	node=requests;
	//Display and store requested files
	int filecount=0; //counts number of files requested
	while(parser!=NULL){
		syslog(LOG_INFO,"Requested:%s",parser);
		node->next=malloc(sizeof(struct llist));
		node->next->file=parser;
		node->next->checksum=NULL;
		node->next->next=NULL;
		node=node->next;
		parser=strtok(NULL,"\n");
		filecount++;
	}


	//Connect to the file server
	struct host server; //address of the file server
	int sockfdudp=create_client_socket(fserver,fport,&server);
	syslog(LOG_DEBUG,"Connected to file server");


	//Transfer contents of files to file server
	node=requests;
	int seq=0; //used to keep track of the sequence number
	int rseq=1; //used to see if correct sequence number was received
	int error; //checks for errors in ACK messages
	int filenum=0; //counts number of files sent
	int retval; //value returned from poll
	int length; //length of the file being sent
	char path[PATH_MAX/2]; //used for opening files
	message* udpmsg; //message that will be sent to the file server
	ack_message* ack; //message received from file server

	//Iterate through requested files
	while(node->next!=NULL){
		snprintf(path,PATH_MAX/2,"./%s/%s",directory,node->next->file);
		FILE* fp=fopen(path,"r"); //file being sent
		fseek(fp,0,SEEK_END);
		length=ftell(fp);
		fseek(fp,0,SEEK_SET);
		//Create control message
		udpmsg=create_control(1,seq,length,crcfinder(path),token,node->next->file);
		filenum++;
		syslog(LOG_INFO,"File: %s, %d/%d",node->next->file,filenum,filecount);
		syslog(LOG_DEBUG,"Type:Initialization, Seq#:%d",seq);

		while(seq!=rseq){
			//Send control message and wait for ACK
			send_message(sockfdudp,udpmsg,&server);
			struct pollfd fd={.fd=sockfdudp,.events=POLLIN};
			retval=poll(&fd,1,10000);
			//Resend control message on timeout
			while(retval==0){
				syslog(LOG_DEBUG,"Resending Control");
				send_message(sockfdudp,udpmsg,&server);
				retval=poll(&fd,1,10000);
			}

			//Receive and parse control ACK
			ack=(ack_message*)receive_message(sockfdudp,&server);
			rseq=ack->seq;
			error=ack->error;
			syslog(LOG_DEBUG,"ACK Received, Seq#:%d, Error Code:%d",rseq,error);
			if(error==1){
				syslog(LOG_ERR,"ACK error received");
				exit(EXIT_FAILURE);
			}
		}
		seq=(seq+1)%2;
		rseq=(seq+1)%2;
		free(udpmsg);
		free(ack);

		size_t bytes; //number of bytes read from the file for current data message
		size_t bytesum=0; //total number of bytes read from the file
		char data[1468]; //data read from the file for current data message
		while(1){
			while(seq!=rseq){
				//Read data from file and make message
				bytes=fread(data,1,1468,fp);
				data[bytes]='\0';
				udpmsg=create_data(3,seq,data);
				bytesum+=bytes;
				syslog(LOG_INFO,"Bytes: %d/%d, %f%%",bytesum,length,(double)(bytesum/length)*100);
				syslog(LOG_DEBUG,"Type:Data, Seq#:%d, Bytes:%d",seq,bytes);
				//Send data message and wait for ACK
				send_message(sockfdudp,udpmsg,&server);
				struct pollfd fd={.fd=sockfdudp,.events=POLLIN};
				retval=poll(&fd,1,10000);
				//Resend data message on timeout
				while(retval==0){
					syslog(LOG_DEBUG,"Resending data");
					send_message(sockfdudp,udpmsg,&server);
					retval=poll(&fd,1,10000);
				}

				//Receive and parse data ACK
				ack=(ack_message*)receive_message(sockfdudp,&server);
				rseq=ack->seq;
				error=ack->error;
				syslog(LOG_DEBUG,"ACK Received, Seq#:%d, Error Code:%d",rseq,error);
				if(error==1){
					syslog(LOG_ERR,"ACK error received");
					exit(EXIT_FAILURE);
				}
			}
			seq=(seq+1)%2;
			rseq=(seq+1)%2;
			free(udpmsg);
			free(ack);
			if(bytes<1468)
				break;
		}

		fclose(fp);
		node=node->next;
	}

	udpmsg=create_control(2,seq,0,0,token,"");
	syslog(LOG_DEBUG,"Type:Termination, Seq#:%d",seq);
	while(seq!=rseq){
		//Send control message and wait for ACK
		send_message(sockfdudp,udpmsg,&server);
		struct pollfd fd={.fd=sockfdudp,.events=POLLIN};
		retval=poll(&fd,1,10000);
		//Resend control message on timeout
		while(retval==0){
			send_message(sockfdudp,udpmsg,&server);
			retval=poll(&fd,1,10000);
		}

		//Receive and parse control ACK
		ack=(ack_message*)receive_message(sockfdudp,&server);
		rseq=ack->seq;
		error=ack->error;
		syslog(LOG_DEBUG,"ACK Received, Seq#:%d, Error Code:%d",rseq,error);
		if(error==1){
			syslog(LOG_ERR,"ACK error received");
			exit(EXIT_FAILURE);
		}
	}


	//Free memory
	syslog(LOG_DEBUG,"Freeing memory");
	node=files;
	while(node->next!=NULL){
		files=files->next;
		free(node);
		node=files;
	}
	free(node);

	node=requests;
	while(node->next!=NULL){
		requests=requests->next;
		free(node);
		node=requests;
	}
	free(node);

	free(udpmsg);
	free(ack);

	close(sockfd);
	closelog();
	return 0;
}

//Traverses through the root directory
struct llist* trav(char dire[], char path[], struct llist* files){
	DIR* d=opendir(dire); //current directory
	//loop through all items in the directory
	while(1){
		struct dirent* entry=readdir(d); //next directory item
		char item[PATH_MAX]; //used to make path to item
		char newpath[PATH_MAX]; //used to update relative path
		uLong crc; //stores found crc value
		//break loop if there are no more items
		if(!entry){
			break;
		}
		//check if item is a file
		if(entry->d_type==DT_REG){
			//find checksum
			snprintf(item,PATH_MAX,"%s/%s",dire,entry->d_name);
			crc=crcfinder(item);
			//write to file
			files=filedata(entry->d_name, crc, path, files);
		}
		//check if item is a directory
		if(entry->d_type==DT_DIR && strcmp(entry->d_name,"..")!=0 && strcmp(entry->d_name,".")!=0){
			//call trav recursively with new directory
			snprintf(item,PATH_MAX,"%s/%s",dire,entry->d_name);
			snprintf(newpath,PATH_MAX,"%s/%s",path,entry->d_name);
			files=trav(item,newpath,files);
		}
	}
	//close directory when all items have been checked
	closedir(d);
	return files;
}

//Create checksum value from a file
uLong crcfinder(char item[]){
	uLong crc; //store the crc value
	FILE* fp; //file that is being read from
	char* line=NULL; //output from reading file
	unsigned char* crcline; //casted output for crc32 function
	size_t len=0; //for reading from file
	ssize_t read; //length of output
	uInt length; //casted length of output

	//setup crc
	crc=crc32(0L,Z_NULL,0);
	//setup file read
	fp=fopen(item,"r");

	//read through file line by line
	while((read=getline(&line,&len,fp))!=-1){
		//fine crc value
		length=read;
		crcline=(unsigned char*)line;
		crc=crc32(crc,crcline,length);
	}

	//free memory
	fclose(fp);
	free(line);
	return crc;
}

//Store file name and checksum in the linked list
struct llist* filedata(char name[], uLong crc, char path[], struct llist* files){
	//add file and checksum to linked list
	char newfile[PATH_MAX/3]; //Stores file and path
	char checksum[PATH_MAX/3]; //Stores checksum
	struct llist* node=files; //Used to traverse through linked list
	//Create file and checksum values to be added
	if(strlen(path)==0){
		snprintf(newfile,PATH_MAX,"%s", name);
	}
	else{
		snprintf(newfile,PATH_MAX,"%s/%s", path+1, name);
	}
	snprintf(checksum,PATH_MAX,"%lX",crc);
	syslog(LOG_DEBUG,"File:%s\nChecksum:%s",newfile,checksum);

	//Move to the end of the linked list
	while(node->next!=NULL){
		node=node->next;
	}
	//Create and fill new node in linked list
	node->next=malloc(sizeof(struct llist));
	node->next->file=malloc((strlen(newfile)+1)*sizeof(char));
	node->next->checksum=malloc((strlen(checksum)+1)*sizeof(char));
	strcpy(node->next->file,newfile);
	strcpy(node->next->checksum,checksum);
	node->next->next=NULL;
	syslog(LOG_DEBUG,"Added:%s\nChecksum:%s",node->next->file,node->next->checksum);

	//Return the linked list with new entry
	return files;
}

//Use hostname and port to set up the creation of a socket
struct addrinfo* get_sockaddr(const char* hostname, const char* port){
	struct addrinfo hints;
	struct addrinfo* results;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;

	int retval=getaddrinfo(NULL, port, &hints, &results);

	if(retval)
		errx(EXIT_FAILURE, "%s", gai_strerror(retval));

	return results;
}

//Create a socket and establish a connection
int open_connection(struct addrinfo* addr_list){
	struct addrinfo* addr;
	int sockfd;

	for(addr=addr_list; addr!=NULL; addr=addr->ai_next){
		sockfd=socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

		if(sockfd==-1)
			continue;

		if(connect(sockfd, addr->ai_addr, addr->ai_addrlen)!=-1)
			break;
	}

	freeaddrinfo(addr_list);

	if(addr==NULL)
		err(EXIT_FAILURE, "%s", "Unable to connect");
	else
		return sockfd;
}

//Create a UDP socket
int create_client_socket(char* hostname, char* port, struct host* server){
	int sockfd;
	struct addrinfo* addr;
	struct addrinfo* results=get_udp_sockaddr(hostname,port,0);

	for(addr=results; addr!=NULL; addr=addr->ai_next){
		sockfd=socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

		if(sockfd==-1)
			continue;

		memcpy(&server->addr, addr->ai_addr, addr->ai_addrlen);
		memcpy(&server->addr_len, &addr->ai_addrlen, sizeof(addr->ai_addrlen));

		break;
	}

	freeaddrinfo(results);

	if(addr==NULL){
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}
	else{
		return sockfd;
	}
}

//Set up the creation of a UDP socket
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
		fprintf(stderr,"getaddrinfo: %s\n",gai_strerror(retval));
		exit(EXIT_FAILURE);
	}

	return results;
}

//Send UDP message
int send_message(int sockfd, message* msg, struct host* dest){
	return sendto(sockfd, msg->buffer, msg->length, 0, (struct sockaddr*)&dest->addr, dest->addr_len);
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

//Create and initialize message struct
message* create_message(){
	return (message*)malloc(sizeof(message));
}

//Create a control message to begin or end a file transfer
message* create_control(uint8_t type, uint8_t seq, uint32_t size, uint32_t checksum, char* token, char* file){
	int length=strlen(file); //length of the filename
	control_message* msg=(control_message*)create_message(); //message that will be sent to server

	//build the message based on the hftp protocol
	msg->length=28+length;
	msg->type=type;
	msg->seq=seq;
	msg->namelength=length;
	msg->size=size;
	msg->checksum=checksum;
	strcpy(msg->token,token);
	strcpy(msg->file,file);

	return (message*)msg;
}

//Create a data message to send a portion of a file to the server
message* create_data(uint8_t type, uint8_t seq, char* data){
	int length=strlen(data); //length of data
	data_message* msg=(data_message*)create_message(); //message that will be sent to server

	//build the message based on the hftp protocol
	msg->length=4+length;
	msg->type=type;
	msg->seq=seq;
	msg->datalength=length;
	strcpy(msg->data,data);

	return (message*)msg;
}
