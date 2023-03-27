#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP
#include <signal.h>
#include <stdbool.h>

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

unsigned char buffer[BUFFSIZE]; 

int sockd;
int on;
struct ifreq ifr;

struct port
{
	int name;
	int count;
};

struct port udp_ports[5000];
int udp_index = 0;
struct port tcp_ports[5000];
int tcp_index = 0;

bool stop = false;



int packages_sum=0;
int amount_packages=0;
int average_length=0;
int min_length=2000;
int max_length=0;

int arp;
int arp_reply=0;
int arp_request=0;

int ipv4=0;
int icmp=0;
int icmp_request=0;
int icmp_reply=0;
int ipv6=0;
int icmpv6=0;
int icmpv6_request=0;
int icmpv6_reply=0;

int tcp=0;
int udp=0;

int https=0;
int http=0;
int dns=0;
int dhcp=0;
int any=0;

bool run = true;

void transporte(unsigned char buffer[],bool is_ipv4, int package_length);
void dump(int type);
void sort();
bool insert_port(int port_name, int type);
void filter(unsigned char buffer[], int package_length);
void rede(unsigned char buffer[], int package_length);
void increase(int port_name, int type);

void signal_handler(int signo){
	if(signo == SIGINT){
		run = false;
	}
}

void print_data(){

	int total_arp = arp_reply + arp_request;

	int total_rede = ipv4 + ipv6 + icmp+ icmpv6;

	int total_transporte = udp + tcp;

	int total_aplicacao = https + http + dns + dhcp + any;


	printf("-----------------------------------------\n");
	printf("PACOTES:\n");
	printf("min: %d\n",min_length);
	printf("max: %d\n",max_length);
	printf("media: %d\n\n",average_length);

	printf("ENLACE:\nARP:\n");
	printf("quantidade: %d\n",arp);
	printf("	request: %d  %.2f%c\n",arp_request,(float)(arp_request*100)/total_arp,37);
	printf("	reply: %d  %.2f%c\n\n",arp_reply,(float)(arp_reply*100)/total_arp,37);

	printf("REDE:\n");
	printf("ipv4: %d  %.2f%c\n",ipv4,(float)(ipv4*100)/total_rede,37);
	printf("ipv6: %d  %.2f%c\n",ipv6,(float)(ipv6*100)/total_rede,37);
	printf("icmp: %d  %.2f%c\n",icmp,(float)(icmp*100)/total_rede,37);
	printf("	request: %d  %.2f%c\n",icmp_request,(float)(icmp_request*100)/total_rede,37);
	printf("	reply: %d  %.2f%c\n\n",icmp_reply,(float)(icmp_reply*100)/total_rede,37);
	printf("icmpv6: %d  %.2f%c\n",icmpv6,(float)(icmpv6*100)/total_rede,37);
	printf("	request: %d  %.2f%c\n",icmpv6_request,(float)(icmpv6_request*100)/total_rede,37);
	printf("	reply: %d  %.2f%c\n\n",icmpv6_reply,(float)(icmpv6_reply*100)/total_rede,37);
	printf("TRANSPORTE:\n");
	printf("\ntcp:%d  %.2f%c\n",tcp,(float)(tcp*100)/total_transporte,37);
	dump(1);
	printf("\nudp:%d  %.2f%c\n",udp,(float)(udp*100)/total_transporte,37);
	dump(2);
	printf("\nAPLICAÇÃO:\n");
	printf("https:%d  %.2f%c\n",https,(float)(https*100)/total_aplicacao,37);
	printf("http:%d  %.2f%c\n",http,(float)(http*100)/total_aplicacao,37);
	printf("dns:%d  %.2f%c\n",dns,(float)(dns*100)/total_aplicacao,37);
	printf("dhcp:%d  %.2f%c\n",dhcp,(float)(dhcp*100)/total_aplicacao,37);
	printf("outro:%d  %.2f%c\n",any,(float)(any*100)/total_aplicacao,37);
	printf("-----------------------------------------\n");

}

void filter(unsigned char buffer[], int package_length){
	//printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
	//printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buffer[6],buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);

	rede(buffer,package_length);
}

void rede(unsigned char buffer[], int package_length){
	size_t type_protocol = (buffer[12] << 8) | buffer[13];

	
	if(type_protocol == 0x0800){
		printf("IPv4  ");
		ipv4++;
		transporte(buffer,true,package_length);
	}
	if(type_protocol == 0x86dd){
		printf("IPv6  ");
		ipv6++;
		transporte(buffer,false,package_length);
	}
	if(type_protocol == 0x0806){
		printf("ARP  ");
		arp++;
		size_t arp_type = (buffer[20] << 8) | buffer[21];
		
		if(arp_type == 2){
			printf("reply\n");
			arp_reply++;
		}else if(arp_type == 1){
			arp_request++;
			printf("request\n");
		}
	}


	if(package_length < min_length){
		min_length = package_length;
	}
	if(package_length > max_length){
		max_length = package_length;
	}

	packages_sum += package_length;
	amount_packages++;

	average_length = packages_sum / amount_packages;
}


void transporte(unsigned char buffer[],bool is_ipv4, int package_length){
	int index = 20;

	if(is_ipv4){
		index = 23;
	}

	bool app = false;
	int type_transport_port = 0;

	switch (buffer[index])
	{
	case 6:
		printf("TCP  ");
		tcp++;
		app = true;
		type_transport_port = 1;
		break;
	case 17:
		printf("UDP  ");
		udp++;
		app = true;
		type_transport_port = 2;
		break;
	case 1:
		printf("ICMP  ");
		icmp++;
		if(buffer[34] == 8){
			icmp_reply++;
			printf("reply  ");
		}
		if(buffer[34] == 0){
			icmp_request++;
			printf("request  ");
		}
		break;
	case 58:
		printf("ICMPv6  ");
		icmpv6++;
		if(buffer[54] == 129){
			icmpv6_reply++;
			printf("reply ");
		}
		if(buffer[54] == 128){
			icmpv6_request++;
			printf("request ");
		}
		break;
	
	default:
		printf("[%x] -> unknown transport ",buffer[34]);
		break;
	}

	if(app){
		int source = 0;
		int destination = 0;
		if(is_ipv4){
			int ipv4_size = (buffer[14] & 0x0F) * 4;
			int type_app = ipv4_size + 14;

			source = (buffer[type_app] << 8) | buffer[type_app+1];
			destination = (buffer[type_app+2] << 8) | buffer[type_app+3];
		}else{
			source = (buffer[54] << 8) | buffer[55];
			destination = (buffer[56] << 8) | buffer[57];
		}

		if (type_transport_port == 1){
			increase(source,1);
			increase(destination,1);
		}
		if (type_transport_port == 2){
			increase(source,2);
			increase(destination,2);
		}

		printf(" [%d -> ",source);
		printf("%d] ",destination);

		if(source == 80 || destination == 80){
			http++;
			printf(" HTTP ");
		}else
		if((source == 68 || destination == 68)){
			dhcp++;
			printf(" DHCP ");
		}else
		if(source == 53 || destination == 53){
			dns++;
			printf(" DNS ");
		}if(source == 443 || destination == 443){
			https++;
			printf(" HTTPS ");
		}else{
			any++;
			printf(" UNKOWN PORT ");
		}

		
	}

	printf("len: %d \n",package_length);
}

bool insert_port(int port_name, int type){
	switch (type)
	{
	case 1:
		tcp_ports[tcp_index].name = port_name;
		tcp_ports[tcp_index].count = 1;
		tcp_index++;
		break;
	
	case 2:
		udp_ports[udp_index].name = port_name;
		udp_ports[udp_index].count = 1;
		udp_index++;
		break;
	
	default:
		return false;
	}
	
	return true;
}

void increase(int port_name, int type){
	bool exist = false;

	switch (type)
	{
	case 1:
		for (int i = 0; i < tcp_index; i++)
		{
			if(tcp_ports[i].name == port_name){
				tcp_ports[i].count++;
				exist = true;
			}
		}

		if(!exist){
			if(!insert_port(port_name,1)){
				printf("lista de portas tcp cheia!");
			}
		}
		
		break;

	case 2:
		for (int i = 0; i < udp_index; i++)
		{
			if(udp_ports[i].name == port_name){
				udp_ports[i].count++;
				exist = true;
			}
		}

		if(!exist){
			if(!insert_port(port_name,2)){
				printf("lista de portas udp cheia!");
			}
		}
		
		break;
	
	default:
		break;
	}
}

void dump(int type){
	switch (type)
	{
	case 1:
		for (int i = 0; i < 5; i++){
			printf("%d - port: %d  -  count: %d\n",i,tcp_ports[i].name,tcp_ports[i].count);
		}
		break;
	
	case 2:
		for (int i = 0; i < 5; i++){
			printf("%d - port: %d  -  count: %d\n",i,udp_ports[i].name,udp_ports[i].count);
		}
		break;

	default:
		break;
	}
}

void sort(){
	for (size_t i = 0; i < tcp_index; i++){
		struct port biggest;
		biggest.name = 0;
		biggest.count = 0;

		int index_changed = 0;

		for (size_t j = i; j < tcp_index; j++){
			if(tcp_ports[j].count > biggest.count){
				biggest = tcp_ports[j];
				index_changed = j;
			}
		}

		struct port aux;
		
		aux = tcp_ports[i];
		tcp_ports[i] = biggest;
		tcp_ports[index_changed] = aux;
	}

	for (size_t i = 0; i < udp_index; i++){
		struct port biggest;
		biggest.name = 0;
		biggest.count = 0;

		int index_changed = 0;

		for (size_t j = i; j < udp_index; j++){
			if(udp_ports[j].count > biggest.count){
				biggest = udp_ports[j];
				index_changed = j;
			}
		}

		struct port aux;
		
		aux = udp_ports[i];
		udp_ports[i] = biggest;
		udp_ports[index_changed] = aux;
	}
}


int main(int argc,char *argv[])
{
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	signal(SIGINT,&signal_handler);

	strcpy(ifr.ifr_name, "eth0");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	while (run) {
   		size_t package_length = recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);
		filter(buffer,package_length);
	}

	sort();
	print_data();

	
}