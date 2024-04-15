# Project: IPK 2. projekt
# File: MakeFile
# Author: Dominik Sajko (xsajko01)
# Date: 04.04.2024

CC = g++
CFLAGS = -std=c++20 -Wall -Wextra -Werror -pedantic
SRCS = $(wildcard *.cpp)
OBJS := $(SRCS:%.cpp=%.o)

.PHONY: clean zip

# Main target
ipk-sniffer: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpcap

# Utils
zip:
	zip xsajko01.zip *.cpp *.h Makefile CHANGELOG.md LICENSE README.md test.py

clean:
	rm -f *.o ipk-sniffer
