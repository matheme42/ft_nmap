#include "../../includes/ft_nmap.h"

char *ft_strsub(char const *s, unsigned int start, size_t len) {
  char *str;
  size_t i;
  size_t j;
  size_t k;

  i = start;
  j = 0;
  k = 0;
  if (s == NULL)
    return (NULL);
  if (!(str = ft_malloc(sizeof(*str) * (len + 1))))
    return (NULL);
  while (s[i] && k++ < len)
    str[j++] = s[i++];
  str[j] = '\0';
  return (str);
}
