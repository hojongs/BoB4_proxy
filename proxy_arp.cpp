#include <stdlib.h>
#include <string.h>

#include <unistd.h> //sleep
#include <pthread.h>
#include <stdint.h> //uintxx_t
#include <pcap.h>
#include <sys/socket.h> //ethhdr -> ifru_addr
#include <linux/if_ether.h> //ethhdr
#include <netinet/ether.h> //ether_ntoa
#include <netinet/ip.h> //iphdr
#include <netinet/tcp.h> //iphdr
#include <netinet/udp.h> //iphdr

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define ICMPHDR_LEN 8
#define DST_IP "192.168.230.130"

struct handlezip
{
	pcap_t* req_handle;
	pcap_t* res_handle;
};

void req_handling(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{

}

void req_handling(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	pcap_t* r_handle = (pcap_t*)args;

	char*ethptr=(char*)buffer;
	char*ipptr;
	ipptr=ptr+sizeof(struct ethhdr);
	char*trpptr=ptr+sizeof(struct ethhdr)+ipptr->version<<2;;
	char*data;

	switch(ipptr->protocol)
	{
		case PROTO_TCP:
			data=ptr+sizeof(struct ethhdr)+ipptr->version<<2+tcpptr->th_off<<2;
			break;
		case PROTO_UDP:	
			data=ptr+sizeof(struct ethhdr)+ipptr->version<<2+udpptr->len;
			break;
		case PROTO_ICMP:
			data=ptr+sizeof(struct ethhdr)+ipptr->version<<2+ICMPHDR_LEN;
		default:
			printf("what is this?\n");
	}

	//todo
	//filtering
	
	//todo
	//srcMAC/IP change(MY MAC/IP)

	return; //temp
    /* Send down the packet */
    if (pcap_sendpacket(r_handle, buffer, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(r_handle));
        return;
    }
}

void* caller_thread(void *args)
{
	struct handlezip* hdzip=(struct handlezip*)args;
	pcap_loop(hdzip->res_handle , -1 , req_handling , (u_char*)hdzip->req_handle);

	return NULL;
}

int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *req_handle, *res_handle;
	
	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;

	pthread_t thread;
	int iret;
	
	//First get the list of available devices
	printf("Finding available devices ... ");
	if(pcap_findalldevs( &alldevsp , errbuf))
	{
		printf("Error finding devices : %s\n" , errbuf);
		exit(1);
	}
	if(alldevsp == NULL)
	{
		printf("\n*** devices are not exist. ***\n");
		exit(1);
	}
	printf("Done\n");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s" , count , device->name);
		if(device->description != NULL)
			printf(" - %s", device->description);
		printf("\n");
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//			sub network NIC
	printf("\nEnter the number of the device(in)\n");
	printf("-> ");
	scanf("%d" , &n);
	devname = devs[n];
	
	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	req_handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (req_handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	//			relay NIC
	printf("\nEnter the number of the device(out)\n");
	printf("-> ");
	scanf("%d" , &n);
	devname = devs[n];
	
	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	res_handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (res_handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	struct handlezip* hdzip;

	if(iret = pthread_create( &thread, NULL, caller_thread, (void*)hdzip))
	     perror("pthread_create");
	
	pcap_loop(req_handle , -1 , req_handling , (u_char*)res_handle);

	return 0;
}