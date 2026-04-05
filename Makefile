CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c99 -pedantic
TARGET  = des
SRCS    = main.c des.c utils.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

main.o:  main.c des.h
des.o:   des.c des.h tables.h
utils.o: utils.c des.h

clean:
	rm -f $(OBJS) $(TARGET)
