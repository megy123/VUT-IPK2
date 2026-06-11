# Project: IPK 2. projekt
# File: MakeFile
# Author: Dominik Sajko (xsajko01)
# Date: 04.04.2024

CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -pedantic
LDLIBS = -lpcap
SRCS = $(wildcard *.cpp)
OBJS := $(SRCS:%.cpp=%.o)

.PHONY: all clean zip

all: ipk-sniffer

# Main target
ipk-sniffer: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Utils
zip:
	zip xsajko01.zip *.cpp *.h docs/assets/*.png Makefile CHANGELOG.md LICENSE README.md test.py

clean:
	rm -f *.o ipk-sniffer
