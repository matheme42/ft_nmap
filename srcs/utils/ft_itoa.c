#include "../../includes/ft_nmap.h"

int ft_count_integer(int n) {
  int cpt;

  cpt = 0;
  if (n == 0)
    cpt = 1;
  while (n != 0) {
    n = n / 10;
    cpt++;
  }
  return (cpt);
}

char *ft_strnew(size_t size) {
  char *ret;
  char *s;

  if (!(s = (char *)malloc(sizeof(char) * size + 1)))
    return (NULL);
  ret = s;
  while (size + 1) {
    *s = '\0';
    s++;
    size--;
  }
  return (ret);
}

char *ft_itoa(int n) {
  int cpt;
  char *ret;
  long nb;
  int neg;

  neg = 0;
  cpt = ft_count_integer(n);
  nb = (long)n;
  if (nb < 0) {
    neg = 1;
    cpt++;
    nb = -nb;
  }
  if (!(ret = ft_strnew(cpt)))
    return (NULL);
  while (cpt) {
    ret[cpt - 1] = nb % 10 + 48;
    nb /= 10;
    cpt--;
  }
  if (neg == 1)
    ret[0] = '-';
  return (ret);
}
