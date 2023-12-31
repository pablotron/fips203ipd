CFLAGS=-std=c11 -W -Wall -Wextra -Wpedantic -O3 -march=native -mtune=native
APP=./example-fips203ipd
APP_OBJS=fips203ipd.o main.o sha3.o

# test app (test suite and sanitizers)
TEST_CFLAGS=-g -fsanitize=address,pointer-compare,pointer-subtract,undefined,leak -W -Wall -Wextra -Werror -pedantic -std=c11
TEST_APP=./test-fips203ipd

.PHONY=all test clean

all: $(APP)

$(APP): $(APP_OBJS)
	$(CC) -o $(APP) $(CFLAGS) $(APP_OBJS)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

# build and run test suite with sanitizers
test:
	$(CC) -o $(TEST_APP) $(TEST_CFLAGS) -DTEST_FIPS203IPD sha3.c fips203ipd.c && $(TEST_APP)

# build api documentation
doc:
	doxygen

clean:
	$(RM) -f $(APP) $(APP_OBJS) $(TEST_APP)
