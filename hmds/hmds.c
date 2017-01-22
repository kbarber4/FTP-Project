//Hooli Metadata Server
//Student: Kyle Barber
//Student#: 250674178
//Course: CS3357
//Instructor: Jeff Shantz

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "hdb.h"

//Use port to set up the creation of a socket
struct addrinfo* get_server_sockaddr(const char* port){
	struct addrinfo hints;
	struct addrinfo* results;

	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	hints.ai_flags=AI_PASSIVE;

	int retval=getaddrinfo(NULL, port, &hints, &results);

	if(retval)
		errx(EXIT_FAILURE, "%s", gai_strerror(retval));

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

//Receive a connection at the socket
int wait_for_connection(int sockfd){
	struct sockaddr_in client_addr;
	unsigned int addr_len=sizeof(struct sockaddr_in);
	char ip_address[INET_ADDRSTRLEN];
	int connectionfd;

	connectionfd=accept(sockfd, (struct sockaddr*)&client_addr, &addr_len);

	if(connectionfd==-1)
		err(EXIT_FAILURE, "%s", "Unable to accept connection");

	inet_ntop(client_addr.sin_family, &client_addr.sin_addr, ip_address, sizeof(ip_address));
	syslog(LOG_INFO, "Connection accepted from %s", ip_address);

	return connectionfd;
}

int main(int argc, char* argv[]){
	char* port="9000"; //Stores port number
	char* host="localhost"; //Stores Redis server name
	int index=0; //Used for getopt_long
	int c; //Used to store returned values of getopt_long
	char request[PATH_MAX]; //AUTH request sent by client
	char lrequest[PATH_MAX]; //LIST request sent by client
	char response[PATH_MAX]; //Response sent to client
	char list[PATH_MAX]; //List of files to request, used to make LIST response
	char entry[PATH_MAX]; //Individual files to request, used to make list
	char* username; //Username received from client
	char* password; //Password received from client
	char* token; //Token generated and sent to client
	char* file; //Stores file names, used for parsing LIST request
	char* checksum; //Stores checksum values, used for parsing LIST request

	//Initialize option object for getopt_long
	struct option long_options[]={
		{"verbose",no_argument,0,'v'},
		{"redis",required_argument,0,'r'},
		{"port",required_argument,0,'p'},
		{0,0,0,0}
	};

	//Set up syslog
	openlog("hmds",LOG_PERROR|LOG_PID|LOG_NDELAY,LOG_USER);
	setlogmask(LOG_UPTO(LOG_INFO));

	//Loop through arguments with getopt_long
	while(1){
		c=getopt_long(argc,argv,"vr:p:",long_options,&index);

		//End loop if no more arguments
		if(c==-1)
			break;

		//Perform action base on arguments sent
		switch(c){
			case 'v':
				setlogmask(LOG_UPTO(LOG_DEBUG));
				syslog(LOG_DEBUG,"Verbose enabled");
				break;
			case 'r':
				host=optarg;
				syslog(LOG_DEBUG,"Host set to %s",host);
				break;
			case 'p':
				port=optarg;
				syslog(LOG_DEBUG,"Port set to %s",port);
				break;
			case '?':
				exit(EXIT_FAILURE);
				break;
		}
	}


	//Wait for connection
	syslog(LOG_INFO,"Waiting for connection");
	struct addrinfo* results=get_server_sockaddr(port);
	int sockfd=bind_socket(results);
	if(listen(sockfd, 25)==-1){
		syslog(LOG_ERR,"Unable to listen to socket");
		exit(EXIT_FAILURE);
	}
	int connectionfd=wait_for_connection(sockfd);


	//Connect to REDIS
	hdb_connection* con=hdb_connect(host);


	//Receive AUTH request
	int bytes=recv(connectionfd,request,sizeof(request)-1,0);
	if(bytes==-1){
		syslog(LOG_ERR,"Unable to read");
		syslog(LOG_ERR,"%s",strerror(errno));
		exit(EXIT_FAILURE);
	}
	request[bytes]='\0';
	syslog(LOG_INFO,"Received AUTH request");
	syslog(LOG_DEBUG,"Received:%s",request);

	//Parse AUTH request
	username=strtok(request,":");
	username=strtok(NULL,"\n");
	password=strtok(NULL,":");
	password=strtok(NULL,"\n");
	syslog(LOG_INFO,"Username:%s",username);

	//Create AUTH response
	token=hdb_authenticate(con,username,password);
	if(token==NULL){
		snprintf(response,PATH_MAX,"401 Unauthorized\n\n");
		syslog(LOG_INFO,"Unauthorized");
	}
	else{
		snprintf(response,PATH_MAX,"200 Authentication successful\nToken:%s\n\n",token);
		syslog(LOG_INFO,"Authorized");
	}
	syslog(LOG_DEBUG,"Sending:%s",response);

	//Send AUTH response
	if(send(connectionfd,response,strlen(response),0)==-1){
		syslog(LOG_ERR,"Unable to send");
		exit(EXIT_FAILURE);
	}
	if(strcmp(response,"401 Unauthorized\n\n")==0)
		exit(EXIT_FAILURE);


	//Receive LIST request
	bytes=recv(connectionfd,lrequest,sizeof(lrequest)-1,0);
	if(bytes==-1){
		syslog(LOG_ERR,"Unable to read");
		exit(EXIT_FAILURE);
	}
	lrequest[bytes]='\0';
	syslog(LOG_INFO,"Received file list");
	syslog(LOG_DEBUG,"Received:%s",lrequest);

	//Parse LIST request and create LIST response
	strtok(lrequest,":");
	char* recvtoken=strtok(NULL,"\n");
	syslog(LOG_DEBUG,"Verifying");
	char* verify_username;
	//Verify token received
	int verify=strcmp(verify_username=hdb_verify_token(con,recvtoken),username);
	syslog(LOG_DEBUG,"Verified");
	int reqfile=0;
	strtok(NULL,"\n");
	file=strtok(NULL,"\n");
	//Loop through received files and create list to request
	while(file!=NULL && verify==0){
		checksum=strtok(NULL,"\n");
		syslog(LOG_DEBUG,"Checking File:%s",file);
		//If file is needed add to list and print file name
		if(!hdb_file_exists(con,username,file) || strcmp(hdb_file_checksum(con,username,file),checksum)!=0){
			reqfile=1;
			snprintf(entry,PATH_MAX,"\n%s",file);
			strcat(list,entry);
			syslog(LOG_INFO,"Requesting:%s",file);
		}
		file=strtok(NULL,"\n");
	}
	//Send 401 if token is invalid
	if(verify!=0)
		snprintf(response,PATH_MAX,"401 Unauthorized\n\n");
	//Send 204 if no files requested
	else if(reqfile==0){
		snprintf(response,PATH_MAX,"204 No files requested\n\n");
		syslog(LOG_INFO,"No files requested");
	}
	//Send 302 if files requested
	else{
		snprintf(response,PATH_MAX,"302 Files requested\nLength:%d\n%s",strlen(list)-1,list);
	}
	syslog(LOG_DEBUG,"Sending:%s",response);

	//Send LIST response
	if(send(connectionfd,response,strlen(response),0)==-1){
		syslog(LOG_ERR,"Unable to send");
		exit(EXIT_FAILURE);
	}


	//Close connections and free memory
	free(token);
	free(verify_username);
	hdb_disconnect(con);
	close(connectionfd);
	close(sockfd);
	return 0;
}
