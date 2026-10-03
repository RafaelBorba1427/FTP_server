CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread

.PHONY: all

all: Server Client

Server: FTPServer.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) FTPServer.cpp -o Server -lsodium -lpam $(LDLIBS)

Client: FTPClient.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) FTPClient.cpp -o Client $(LDLIBS)
