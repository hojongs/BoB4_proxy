all: proxy_server

proxy_server: proxy_main.o
	g++ -Wall -o $@ $^ -lpcap -lpthread

proxy_main.o: proxy_main.cpp
	g++ -Wall -c -o $@ $^

proxy_arp.o: proxy_arp.cpp
	g++ -Wall -c -o $@ $^ 

clean: 
	rm -rf proxy_server *.o