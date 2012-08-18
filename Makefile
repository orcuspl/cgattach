CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -Wno-unused -pedantic
LDFLAGS=-lcgroup -lm
SOURCES=main.c funcs.c cgroups.c llist.c
OBJS=$(SOURCES:.c=.o)
EXEC=cgattach

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm $(OBJS)

.PHONY: all clean

