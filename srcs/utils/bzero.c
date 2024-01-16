#include "ft_nmap.h"

void	ft_bzero(void *s, size_t n)
{
    for (size_t i = 0; i < n; i++) ((unsigned char *)s)[i] = 0;
}