all: proxy_server

proxy_server: proxy_main.o
	g++ -Wall -o $@ $^ -lpcap

proxy_main.o: proxy_main.cpp
	g++ -Wall -c -o $@ $^
