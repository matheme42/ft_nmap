int		ft_atoi(const char *str)
{
	int i;
	int neg;
	int result;

	neg = 1;
	result = 0;
	i = 0;
    if (!str)
		return (0);
	while (str[i] && ((str[i] >= 9 && str[i] <= 13) || str[i] == 32))
		i++;
	if (str[i] == '+' || str[i] == '-')
	{
		if (str[i] == '-')
			neg = -1;
		i++;
	}
	str = &str[i];
	i = -1;
	while (str[++i] >= '0' && str[i] <= '9')
		result = result * 10 + str[i] - '0';
	return (result * neg);
}