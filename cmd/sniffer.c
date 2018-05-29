#include "./sniffer.h"

int main(int argc, char *argv[]) {

    // 参数校验
    if (argc < 2) {
        printf("Usage: ./sniffer interfaceName\n");
        exit(0);
    }

    // 设置网卡混杂模式
    set_promiscuous_mode(argv[1]);

    // 开始嗅探
    sniffer();

    return 0;
}

// 设置网卡混杂模式
void set_promiscuous_mode(char *interface_name) {
    int fd;
    
    // 建立特殊 socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        printf("Can't create socket! Please try run the program in the root mode?\n");
        exit(0);
    }

    // ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, strlen(interface_name) + 1);

    // 接受网卡的信息
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        printf("Can't get info from the interface!\n");
        exit(0);
    }

    // 更改flags为混杂模式
    ifr.ifr_flags |= IFF_PROMISC;
    
    // 设置混杂模式
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
        printf("Can't set the promisc flag to interface!\n");
        exit(0);
    }

    printf("The interface has been set to promiscuous mode.\n");
}

// 嗅探
void sniffer() {
    int fd, bytes, i;
    socklen_t len;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in addr;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // 打开socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd == -1) {
        printf("Can't open socket! Please try to run the program in the root mode!\n");
        exit(0);
    }

    // 开始嗅探
    while (1) {
        // 清空结构体
        memset(buffer, 0, sizeof(buffer));

        // 接收数据
        bytes = recvfrom(fd, (char *) buffer, sizeof(buffer), 0, NULL, NULL);

        printf("\n");

        for (i = 0; i < bytes; i++) {
            printf("%02x ", (unsigned char) buffer[i]);

            if ((i + 1) % 12 == 0) {
                printf("\n");
            }
        }

        printf("\n");

        printf("\nBytes receiverd %5d\n", bytes);

        ip = (struct iphdr *) buffer;
        printf("IP header length %d\n", ip->tot_len);
        printf("Protocol %d\n",ip->protocol);

        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        printf("Src address: ");

        for (i = 0; i < 4; i++) {
            printf("%03d ", (unsigned char) *((char *) (&ip->saddr) + i));
        }

        printf("(");

        for (i = 0; i < 4; i++) {
            printf("%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
        }

        printf(")\nDest address: ");

        for (i = 0; i < 4; i++) {
            printf("%03d.",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        printf("(");

        for (i = 0; i < 4; i++) {
            printf("%02x ",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        printf(")\n");

        printf("Source port %d\n", ntohs(tcp->source)); 
		printf("Dest port %d \n", ntohs(tcp->dest)); 
		printf("FIN:%d SYN:%d RST:%d PSH:%d ACK:%d URG:%d \n", ntohs(tcp->fin) && 1, ntohs(tcp->syn) && 1, ntohs(tcp->rst) && 1, ntohs(tcp->psh) && 1, ntohs(tcp->ack) && 1, ntohs(tcp->urg) && 1);
		printf("--------------------------------------------------\n");
    }
}