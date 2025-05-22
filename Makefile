NAME = ft_strace

CC = gcc

CCFLAGS = -Wall -Wextra -Werror -g -fsanitize=address,undefined,leak

SRC_PATH = ./src

INCLUDE_PATH = ./includes

OBJ_PATH = ./obj

SRC_INCLUDE = $(SRC_PATH)

INC = $(addprefix -I,  $(INCLUDE_PATH))

SRC = $(addprefix $(SRC_PATH)/, main.c cli_args.c strace.c syscall.c format_sys_result.c)

INCLUDE_FILES = $(wildcard $(INCLUDE_PATH)/*.h)

OBJ = $(SRC:$(SRC_PATH)/%.c=$(OBJ_PATH)/%.o)

all : creat_obj_dir $(NAME)

$(NAME): $(LIBFT) $(OBJ)
	@$(CC) $(CCFLAGS) -o $@ $(OBJ)

$(OBJ_PATH)/%.o : $(SRC_PATH)/%.c $(INCLUDE_FILES)
	$(CC) $(CCFLAGS) $(INC) -c $< -o $@

creat_obj_dir:
	@if [ ! -d $(OBJ_PATH) ]; then mkdir $(OBJ_PATH); fi

clean:
	@rm -rf $(OBJ)

fclean: clean
	@rm -f $(NAME)

re : fclean all

.PHONY: all clean fclean re
