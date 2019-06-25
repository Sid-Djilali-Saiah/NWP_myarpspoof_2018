NAME	= myARPspoof

CC	= gcc

RM	= rm -f

SRCS	=   ./src/main.c \
	        ./src/myarpspoof.c \
	        ./src/find_victim_mac.c \
	        ./src/send_spoofed_packets.c \
	        ./src/tools.c \
	        ./src/get_params.c

OBJS	= $(SRCS:.c=.o)

CFLAGS = -I./inc/
CFLAGS += -W -Wall -Wextra -Werror -O3

all: $(NAME)

$(NAME): $(OBJS)
	 $(CC) $(OBJS) -o $(NAME)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re
