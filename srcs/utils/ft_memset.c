#include "../../includes/ft_nmap.h"

void *ft_memset(void *b, int c, size_t len) {
  void *ret;

  ret = b;
  while (len) {
    *(unsigned char *)b = c;
    b++;
    len--;
  }
  return (ret);
}
