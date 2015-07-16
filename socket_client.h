#ifndef __OS_NET_H

#define __OS_NET_H

#define OS_SOCKTERR	-6	/* Socket error */

/**
 * OS_ConnectPort
 * @Connect a specific @port and a @ip.
 * @Return the socket.
 */
int OS_ConnectPort(unsigned int _port, char *serv_host);

/**
 * Close a network socket.
 * @param socket the socket to close
 * @return 0 on success, else -1 or SOCKET_ERROR
 */
int OS_CloseSocket(int socket);

#endif

