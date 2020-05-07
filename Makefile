# The compiler being used
CC = gcc

CFLAGS = -g -Wall -Wextra -pedantic

LDLIBS = -lnsl

INCLUDES = $(shell echo *.h)

# sed command finds first period ('.') of each word in a line and removes the
# rest of the word
C_TEST_FILES = $(shell echo test* | sed -E "s/([^\.]*)(\.*)([^\ ]*)\b/\1/g") 

EXECUTABLES = proxy

all: $(EXECUTABLES) $(C_TEST_FILES)

# Called target-specific variable values. Only assigns to CFLAGS when building
# target 'debug', as well as debug's (recursive) dependencies (a1.o/.c as well)
debug: CFLAGS += -DDEBUG
debug: proxy

trace: CFLAGS += -DDEBUG -DTRACE
trace: proxy

# $< is first dependency, $@ is target
%.o: %.c $(INCLUDES)
	$(CC) $(CFLAGS) -c $< -o $@ $(LDLIBS)

proxy: main.o utils.o cache.o http.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# $^ is a space-separated list of the prerequisites (names after the colon),
# with duplicates removed
test_%: test_%.o %.o $(INCLUDES)
	$(CC) $(CFLAGS) -o $@ $^

clean: 
	rm -f *.o .*.swp $(EXECUTABLES) $(C_TEST_FILES)
