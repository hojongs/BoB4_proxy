all: proxy_server

proxy_server: proxy_main.o
	cc -Wall -o $@ $^ -lpcap -lpthread

proxy_main.o: proxy_main.cpp
	cc -Wall -c -o $@ $^

#proxy_server: proxy_main.o proxy_req.o proxy_res.o
#	cc -Wall -o $@ $^ -lpcap -lpthread

#proxy_req.o: proxy_req.cpp
#	cc -Wall -c -o $@ $^ 

#proxy_res.o: proxy_res.c
#	cc -Wall -c -o $@ $^ 

#proxy_main.o: proxy_main.c
#	cc -Wall -c -o $@ $^

clean: 
	rm -rf proxy_server *.o