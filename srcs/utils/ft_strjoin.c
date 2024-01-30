#include "../../includes/ft_nmap.h"

char *ft_strjoin(char const *s1, char const *s2) {
  size_t len;
  char *ret;
  char *tmp;

  if (!(s1) || !(s2))
    return (0);
  len = ft_strlen(s1) + ft_strlen(s2);
  if (!(ret = (char *)malloc(sizeof(char) * len + 1)))
    return (NULL);
  tmp = ret;
  while (len) {
    while (*s1) {
      *ret++ = *s1++;
      len--;
    }
    while (*s2) {
      *ret++ = *s2++;
      len--;
    }
  }
  *ret = '\0';
  return (tmp);
}
