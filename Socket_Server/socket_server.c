/*
    C socket server example
*/
 
#include<stdio.h>
#include<string.h>    //strlen
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include<unistd.h>    //write
 
int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c , read_size;
    struct sockaddr_in server , client;
    char client_message[100000];
     
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
     
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 514 );
     
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");
    listen(socket_desc , 3);
conexion:
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }
    puts("Connection accepted");
    while( (read_size = recv(client_sock , client_message , 2000 , 0)) > 0 ){
        if(fputs(client_message, stdout) == EOF)
        {
            printf("\n Error : Fputs error\n");
        }
        bzero(client_message,100000);
}
     
    if(read_size == 0)
    {
        puts("Client disconnected......");
        fflush(stdout);
        goto conexion;
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }
    return 0;
}

