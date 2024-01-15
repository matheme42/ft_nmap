#include "ft_nmap.h"

int	ft_strlen(const char *str)
{
	const char *s;

	if (str == NULL)
		return (0);
	s = str;
	while (*s != '\0')
		s++;
	return (s - str);
}