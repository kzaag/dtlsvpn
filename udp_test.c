#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

/*
 * send udp packet to given destination
 */

int main(int argc, char ** argv) 
{
	if(argc < 3) {
		return 1;
	}

	int sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sfd < 0)
		return 1;

	char msg[] = "it's not a tumor";
	struct sockaddr_in saddr;
	inet_aton(argv[1], &saddr.sin_addr);
	saddr.sin_port = htons(atoi(argv[2]));
	saddr.sin_family = AF_INET;
	int w = sendto(sfd, msg, sizeof(msg), 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if(w != sizeof(msg)) {
		return 1;
	}
	printf("sent it\n");
}
