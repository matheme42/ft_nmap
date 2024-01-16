int	ft_strcmp(const char *s1, const char *s2)
{
	int n;

	n = 0;
	while (s1[n] == s2[n] && (s1[n] != '\0' || s2[n] != '\0'))
		n++;
	return ((unsigned char)s1[n] - (unsigned char)s2[n]);
}
