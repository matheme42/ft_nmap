#include "../../includes/ft_nmap.h"

int create_socket(int protoType) {
  int sockId;
  int option;

  if ((sockId = socket(PF_INET, SOCK_RAW, protoType)) < 0) {
    dprintf(2, "ft_nmap: Socket creation failed\n");
    return 0;
  }

  // set custom header to true
  option = 1;
  if (setsockopt(sockId, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option))) {
    dprintf(2, "ft_nmap: Failed to set socket option\n");
    return 0;
  }
  dprintf(1, "gimme socketFd %d\n", sockId);
  return (sockId);
}
