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
#include <arpa/inet.h> //inet_addr

#include "handlezip.h"

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1
#define ICMPHDR_LEN 8
#define MIDDLE_MAC {0x00, 0x0c, 0x29, 0x77, 0xe5, 0x7e} //(SRC)AP_IP/MAC -> MIDDLE_IP/MAC
#define MIDDLE_IP "192.168.230.255"
#define AP_MAC {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}									//(DST)MIDDLE_IP/MAC -> AP_IP/MAC
#define AP_IP "192.168.230.164"

void req_handling(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	pcap_t* res_handle = (pcap_t*)args;

	char*ptr=(char*)buffer;
	struct ethhdr*ethptr=(struct ethhdr*)ptr;
	struct iphdr*ipptr;
	struct tcphdr*tcpptr;
	struct udphdr*udpptr;
	char*data;

	if(ethptr->h_proto==htons(ETH_P_IP))
	{
		ipptr=(struct iphdr*)(ptr+sizeof(struct ethhdr));
	}
	else
	{
		printf("IPv6\n");
		return;
	}

	switch(ipptr->protocol)
	{
		case PROTO_TCP:
		tcpptr=(struct tcphdr*)(ptr+sizeof(struct ethhdr)+ipptr->version*4);
		data=ptr+sizeof(struct ethhdr)+ipptr->version*4+tcpptr->th_off*4;
		break;
		case PROTO_UDP:
		udpptr=(struct udphdr*)(ptr+sizeof(struct ethhdr)+ipptr->version*4);
		data=ptr+sizeof(struct ethhdr)+ipptr->version*4+udpptr->len;
		break;
		case PROTO_ICMP:
		data=ptr+sizeof(struct ethhdr)+ipptr->version*4+ICMPHDR_LEN;
		break;
		default:
		printf("exception\n");
		printf("type : 0x%x\n", ipptr->protocol);
	}

	printf("len : %d bytes\n", header->len);

	fwrite(data, 1, header->len, stdout);
	//todo
	//filtering
	
	if(ipptr->saddr == inet_addr(AP_IP))
	{ //request packet
		u_char* temp=(u_char*)ethptr->h_source;
		printf ("mac before : ");
		for(int i=0;i<ETH_ALEN;i++)
		{
			printf("%02x", temp[i]);
			if(i<ETH_ALEN-1)
				printf(":");
		}
		printf("\n");
		u_char mac_array[6]=MIDDLE_MAC;
		printf ("mac after  : ");
		for(int i=0;i<ETH_ALEN;i++)
		{
			temp[i]=mac_array[i];
			printf("%02x", temp[i]);
			if(i<ETH_ALEN-1)
				printf(":");
		}
		printf("\n");

		printf("0x%08x\n", ipptr->saddr);
		ipptr->saddr=inet_addr(MIDDLE_IP);
		printf("0x%08x\n", ipptr->saddr);
	}

	return; //stop

	/* Send down the packet */
	if (pcap_sendpacket(res_handle, buffer, header->len /* size */) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(res_handle));
		return;
	}
}

void res_handling(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	pcap_t* req_handle = (pcap_t*)args;

	char*ptr=(char*)buffer;
	struct ethhdr*ethptr=(struct ethhdr*)ptr;
	struct iphdr*ipptr;
	struct tcphdr*tcpptr;
	struct udphdr*udpptr;
	char*data;

	if(ethptr->h_proto==htons(ETH_P_IP))
	{
		ipptr=(struct iphdr*)(ptr+sizeof(struct ethhdr));
	}
	else
	{
		printf("IPv6\n");
		return;
	}

	switch(ipptr->protocol)
	{
		case PROTO_TCP:
		tcpptr=(struct tcphdr*)(ptr+sizeof(struct ethhdr)+ipptr->version*4);
		data=ptr+sizeof(struct ethhdr)+ipptr->version*4+tcpptr->th_off*4;
		break;
		case PROTO_UDP:
		udpptr=(struct udphdr*)(ptr+sizeof(struct ethhdr)+ipptr->version*4);
		data=ptr+sizeof(struct ethhdr)+ipptr->version*4+udpptr->len;
		break;
		case PROTO_ICMP:
		data=ptr+sizeof(struct ethhdr)+ipptr->version*4+ICMPHDR_LEN;
		break;
		default:
		printf("exception\n");
		printf("type : 0x%x\n", ipptr->protocol);
	}

	printf("len : %d bytes\n", header->len);

	fwrite(data, 1, header->len, stdout);
	//todo
	//filtering
	
	if(ipptr->daddr == inet_addr(AP_IP))
	{ //request packet
		u_char* temp=(u_char*)ethptr->h_dest;
		printf ("mac before : ");
		for(int i=0;i<ETH_ALEN;i++)
		{
			printf("%02x", temp[i]);
			if(i<ETH_ALEN-1)
				printf(":");
		}
		printf("\n");
		u_char mac_array[6]=AP_MAC;
		printf ("mac after  : ");
		for(int i=0;i<ETH_ALEN;i++)
		{
			temp[i]=mac_array[i];
			printf("%02x", temp[i]);
			if(i<ETH_ALEN-1)
				printf(":");
		}
		printf("\n");

		printf("0x%08x\n", ipptr->daddr);
		ipptr->saddr=inet_addr(AP_IP);
		printf("0x%08x\n", ipptr->daddr);
	}

	return; //stop

	/* Send down the packet */
	if (pcap_sendpacket(req_handle, buffer, header->len /* size */) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(req_handle));
		return;
	}
}


void* caller_thread(void *args)
{ //res_handling func caller
	struct handlezip* hdzip=(struct handlezip*)args;
	pcap_loop(hdzip->res_handle , -1 , res_handling , (u_char*)hdzip->req_handle);

	return NULL;
}


int main(int argc,char **argv)
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
		printf("*** Use 'sudo' ***\n");
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
	
	//          sub network NIC
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

	//          relay NIC
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

	struct handlezip hdzip;
	hdzip.req_handle=req_handle;
	hdzip.res_handle=res_handle;

    if(iret = pthread_create( &thread, NULL, caller_thread, (void*)&hdzip))
         perror("pthread_create");
	
	pcap_loop(req_handle , -1 , req_handling , (u_char*)res_handle);

	return 0;
}
