
BLUE=\033[0;38;5;123m
LIGHT_PINK = \033[0;38;5;200m
PINK = \033[0;38;5;198m
DARK_BLUE = \033[1;38;5;110m
GREEN = \033[1;32;111m
LIGHT_GREEN = \033[1;38;5;121m
LIGHT_RED = \033[0;38;5;110m
FLASH_GREEN = \033[33;32m
WHITE_BOLD = \033[37m

# nom de l'executable
NAME = ft_nmap

# paths
SRC_PATH= srcs
OBJ_PATH= .objs
INC_PATH= includes


INC= $(INC_PATH)/*


NAME_SRC= main.c get_available_port.c

NAME_SRC_PARSING= parsing.c parsing_set.c parsing_debug.c parsing_file.c \
			parsing_scan.c parsing_usage.c

NAME_SRC_UTILS = atoi.c bzero.c ft_split.c ft_strsub.c free_tab.c \
				ft_malloc.c ft_strchr.c ft_strlen.c trim.c ft_strcpy.c \
				ft_strcmp.c

NAME_SRC_LEN	= $(shell echo -n $(NAME_SRC) $(NAME_SRC_UTILS) $(NAME_SRC_PARSING) | wc -w)
I				= 

OBJ_NAME		= $(NAME_SRC:.c=.o)
OBJ_NAME_UTILS	= $(NAME_SRC_UTILS:.c=.o)
OBJ_NAME_PARSING= $(NAME_SRC_PARSING:.c=.o)


OBJS = $(addprefix $(OBJ_PATH)/,$(OBJ_NAME)) $(addprefix $(OBJ_PATH)/utils/,$(OBJ_NAME_UTILS)) $(addprefix $(OBJ_PATH)/parsing/,$(OBJ_NAME_PARSING))

DEBUG_FLAG = -Wall -Wextra # -fsanitize=address



all: $(NAME)

$(NAME) : $(OBJS)
	@$(CC) $(DEBUG_FLAG) $^ -o $@ -lpcap
	@echo "	\033[2K\r$(DARK_BLUE)$(NAME):\t\t$(GREEN)loaded\033[0m"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c $(INC) Makefile
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	@mkdir $(OBJ_PATH)/utils 2> /dev/null || true
	@mkdir $(OBJ_PATH)/parsing 2> /dev/null || true
	@$(CC) $(DEBUG_FLAG) -I $(INC_PATH) -c $< -o $@
	@$(eval I=$(shell echo $$(($(I)+1))))
	@printf "\033[2K\r${G}$(DARK_BLUE)>>\t\t\t\t$(I)/$(shell echo $(NAME_SRC_LEN)) ${N}$(BLUE)$<\033[36m \033[0m"

clean:
ifeq ("$(wildcard $(OBJ_PATH))", "")
else
	@rm -f $(OBJS)
	@rmdir $(OBJ_PATH)/utils 2> /dev/null || true
	@rmdir $(OBJ_PATH)/parsing 2> /dev/null || true
	@rmdir $(OBJ_PATH) 2> /dev/null || true
	@printf "\033[2K\r$(DARK_BLUE)$(NAME) objects:\t$(LIGHT_PINK)removing\033[36m \033[0m\n"
endif


fclean: clean
ifeq ("$(wildcard $(NAME))", "")
else
	@rm -f $(NAME)
	@printf "\033[2K\r$(DARK_BLUE)$(NAME):\t\t$(PINK)removing\033[36m \033[0m\n"
endif

re: fclean all

.PHONY: all re clean fclean lib silent