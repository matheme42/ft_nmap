#include "../../includes/ft_nmap.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

void send_dummy_bytes(int sockFd, struct sockaddr *addr) {
  // 216.58.214.174: ip google
  t_packet dummy_packet;

  lookup_host("google.com", &addr);
  ((struct sockaddr_in *)addr)->sin_family = AF_INET;
  ((struct sockaddr_in *)addr)->sin_port = htons(33434);

  dprintf(1, "[0]\n");
  fill_UDP_Header(&dummy_packet.udphdr, 33434); // test port
  fill_IP_Header(&dummy_packet.iphdr,
                 (uint32_t)((struct sockaddr_in *)addr)->sin_addr.s_addr,
                 IPPROTO_UDP);

  dprintf(1, "[1]\n");

  sendto(sockFd, &dummy_packet, sizeof(struct packet), 0,
         (struct sockaddr *)addr, sizeof(struct sockaddr_in));
  dprintf(1, "[2]\n");
  dprintf(1, "dummy bytes sent?\n");
}

char *recieve_data(int sockFd, struct sockaddr *addr) {
  char recieve[100];
  struct iovec retMsgData;
  struct msghdr messageHdr;

  ft_memset(&recieve, 0, 100);
  ft_memset(&retMsgData, 0, sizeof(struct iovec));
  ft_memset(&messageHdr, 0, sizeof(struct msghdr));

  retMsgData.iov_base = &recieve;
  retMsgData.iov_len = 0;

  messageHdr.msg_iovlen = 1;
  messageHdr.msg_iov = &retMsgData;

  socklen_t addrlen = sizeof(struct sockaddr);

  ssize_t bytesRecieved = recvfrom(sockFd, recieve, 100, 0, addr, &addrlen);

  if (bytesRecieved < 0) {
    dprintf(1, "cant recieve bytes");
    perror("no bytes recievefrom : ");
  } else {
    dprintf(1, "we got %lu bytes\n", bytesRecieved);
    for (int i = 0; i < bytesRecieved; i++) {
      if (i % 8 == 0 && i != 0)
        dprintf(1, "\n");
      dprintf(1, "%02hhx ", recieve[i]);
    }
  }

  t_packet *retPack = (t_packet *)recieve;
  char buff[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &retPack->iphdr.daddr, buff, INET_ADDRSTRLEN);

  // dprintf(1, "inet ntoa res = %s\n", buff);
  return ft_strsub(buff, 0, INET_ADDRSTRLEN);
}

char *get_public_ip() {
  int sockFd = create_socket(IPPROTO_UDP);
  struct sockaddr *addr;

  send_dummy_bytes(sockFd, addr);
  char *publicIp = recieve_data(sockFd, addr);
  // read_public_ip(sockFd);
  //  char *wait = "wait";
  return publicIp;
}
