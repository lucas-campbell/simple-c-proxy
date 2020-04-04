CC = gcc # The compiler being used

INCLUDES = $(shell echo *.h)

all: $(shell echo test* | sed -E "s/([^\.]*)(\.*)([^\ ]*)\b/\1/g")

# $< is first dependency, $@ is target
%.o: %.c $(INCLUDES)
	$(CC) -g -c $< -o $@

# $^ is a space-separated list of the prerequisites (names after the colon),
# with duplicates removed
test_%: test_%.o %.o $(INCLUDES)
	$(CC) -g $^ -o $@
clean: 
	rm -f *.o .*.swp

