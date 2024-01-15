#include "ft_nmap.h"

void			*ft_malloc(size_t size)
{
	void	*ret;

	ret = malloc(size);
	if (ret == NULL)
	{
		dprintf(1, "memory allocation failed\n");
		dprintf(1, "program stops\n");
		exit(126);
	}
	ft_bzero(ret, size);
	return (ret);
}