#include "../../includes/ft_nmap.h"
#include <string.h>

static void send_dummy_bytes(int sockFd, struct sockaddr *addr, const char *host) {
  // 216.58.214.174: ip google
  t_packet dummy_packet;

  ft_bzero(&dummy_packet, sizeof(t_packet));
  lookup_host(host, &addr);
  ((struct sockaddr_in *)addr)->sin_family = AF_INET;
  ((struct sockaddr_in *)addr)->sin_port = htons(33434);
  fill_ICMP_Header(&dummy_packet);
  fill_IP_Header(&dummy_packet.iphdr, (uint32_t)((struct sockaddr_in *)addr)->sin_addr.s_addr, IPPROTO_ICMP);
  sendto(sockFd, &dummy_packet, sizeof(struct packet), 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
}

u_int32_t recieve_data(int sockFd, struct sockaddr *addr) {
  t_packet recieve;
  struct iovec retMsgData;
  struct msghdr messageHdr;

  ft_bzero(&recieve, sizeof(t_packet));
  ft_bzero(&retMsgData, sizeof(struct iovec));
  ft_bzero(&messageHdr, sizeof(struct msghdr));

  retMsgData.iov_base = &recieve;
  retMsgData.iov_len = 0;

  messageHdr.msg_iovlen = 1;
  messageHdr.msg_iov = &retMsgData;

  socklen_t addrlen = sizeof(struct sockaddr);
  int ret = recvfrom(sockFd, &recieve, sizeof(recieve), 0, addr, &addrlen);
  if (ret <= 0) return 0;
  return recieve.iphdr.daddr;
}

u_int32_t get_public_ip(const char *host) {
  int sockFd;
  struct sockaddr addr;
  u_int32_t publicIp;

  sockFd = create_socket(IPPROTO_ICMP);
  send_dummy_bytes(sockFd, &addr, host);
  publicIp = recieve_data(sockFd, &addr);
  close(sockFd);
  return publicIp;
}
