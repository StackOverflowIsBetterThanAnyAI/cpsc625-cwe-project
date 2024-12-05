# Compiler settings
CC = gcc
CFLAGS = -Wall -O2
INCLUDES = -I/opt/saltstack/salt/include
LDFLAGS = -L/opt/saltstack/salt/lib
LIBS = -lsqlite3

# Target executable
TARGET = uofcLogin

# Source files
SRC = uofcLogin.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) $(LDFLAGS) $(LIBS) -o $(TARGET)

clean:
	/bin/rm -f $(TARGET)
	/bin/rm -f *~