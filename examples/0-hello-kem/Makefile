CFLAGS=-std=c11 -W -Wall -Wextra -Wpedantic -O3 -march=native -mtune=native
APP=./hello
OBJS=fips203ipd.o hello.o sha3.o

.PHONY=all test clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) -o $(APP) $(CFLAGS) $(OBJS)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

clean:
	$(RM) -f $(APP) $(OBJS)
