#include "libraries_include.h"

int OS_ConnectPort(unsigned int _port, char *serv_host)
{
  int sockfd = 0;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  int flag = 1;
  
  if(( sockfd = socket(PF_INET, SOCK_STREAM,0 )) < 0){
    return(int)(OS_SOCKTERR);
  }
  
  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) < 0){
    OS_CloseSocket(sockfd);
    return(OS_SOCKTERR);
  }
  
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons( _port );
  server = gethostbyname(serv_host);
  bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr,server->h_length);
  
  if( connect(sockfd,(struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
    OS_CloseSocket(sockfd);
    return(OS_SOCKTERR);
  }
  
  return(sockfd);  
}

int OS_CloseSocket(int socket)
{
  return(close(socket));  
}
