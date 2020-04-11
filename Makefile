# The compiler being used
CC = gcc

INCLUDES = $(shell echo *.h)

# sed command finds first period ('.') of each word in a line and removes the
# rest of the word
C_TEST_FILES = $(shell echo test* | sed -E "s/([^\.]*)(\.*)([^\ ]*)\b/\1/g") 

EXECUTABLES = proxy tcpserver tcpclient 

all: $(EXECUTABLES) $(C_TEST_FILES)

# $< is first dependency, $@ is target
%.o: %.c $(INCLUDES)
	$(CC) -g -c $< -lnsl -o $@

proxy: a1.o
	$(CC) -g $< -lnsl -o $@

tcpserver: tcpserver.o
	$(CC) -g $< -lnsl -o $@

tcpclient: tcpclient.o
	$(CC) -g $< -lnsl -o $@

# $^ is a space-separated list of the prerequisites (names after the colon),
# with duplicates removed
test_%: test_%.o %.o $(INCLUDES)
	$(CC) -g $^ -o $@

clean: 
	rm -f *.o .*.swp $(EXECUTABLES) $(C_TEST_FILES)
