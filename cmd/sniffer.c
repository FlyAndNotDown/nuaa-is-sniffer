#include "./sniffer.h"

int main(int argc, char *argv[]) {

    // 打开日志文件
    FILE *log = NULL;
    log = fopen(LOG_FILE_PATH, "w");
    if (log == NULL) {
        printf("Can't open log file!\n");
        exit(0);
    }

    // 参数校验
    if (argc < 2) {
        fprintf(log, "Usage: ./sniffer interfaceName\n");
        printf("Usage: ./sniffer interfaceName\n");
        fclose(log);
        exit(0);
    }

    // 设置网卡混杂模式
    set_promiscuous_mode(argv[1], log);

    // 开始嗅探
    sniffer(log);

    // 关闭日志文件
    fclose(log);
    return 0;
}

// 设置网卡混杂模式
void set_promiscuous_mode(char *interface_name, FILE *log) {
    int fd;
    
    // 建立特殊 socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        fprintf(log, "Can't create socket! Please try run the program in the root mode?\n");
        printf("Can't create socket! Please try run the program in the root mode?\n");
        fclose(log);
        exit(0);
    }

    // ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, strlen(interface_name) + 1);

    // 接受网卡的信息
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        fprintf(log, "Can't get info from the interface!\n");
        printf("Can't get info from the interface!\n");
        fclose(log);        
        exit(0);
    }

    // 更改flags为混杂模式
    ifr.ifr_flags |= IFF_PROMISC;
    
    // 设置混杂模式
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
        fprintf(log, "Can't set the promisc flag to interface!\n");
        printf("Can't set the promisc flag to interface!\n");
        fclose(log);
        exit(0);
    }

    fprintf(log, "The interface has been set to promiscuous mode.\n");
    printf("The interface has been set to promiscuous mode.\n");
}

// 嗅探
void sniffer(FILE *log) {
    int fd, bytes, i;
    socklen_t len;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in addr;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // 打开socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd == -1) {
        fprintf(log, "Can't open socket! Please try to run the program in the root mode!\n");
        printf("Can't open socket! Please try to run the program in the root mode!\n");
        fclose(log);
        exit(0);
    }

    // 开始嗅探
    while (1) {
        // 清空结构体
        memset(buffer, 0, sizeof(buffer));

        // 接收数据
        bytes = recvfrom(fd, (char *) buffer, sizeof(buffer), 0, NULL, NULL);

        fprintf(log, ">>>");
        printf(">>>");

        for (i = 0; i < bytes; i++) {
            fprintf(log, "%c", (unsigned char) buffer[i]);
            printf("%c ", (unsigned char) buffer[i]);

            if ((i + 1) % 12 == 0) {
                fprintf(log, "\n>>>");
                printf("\n>>>");
            }
        }

        fprintf(log, "\nBytes receiverd %5d\n", bytes);
        printf("\nBytes receiverd %5d\n", bytes);

        ip = (struct iphdr *) buffer;
        fprintf(log, "IP header length %d\n", ip->tot_len);
        printf("IP header length %d\n", ip->tot_len);
        fprintf(log, "Protocol %d\n",ip->protocol);
        printf("Protocol %d\n",ip->protocol);

        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        fprintf(log, "Src address: ");
        printf("Src address: ");

        for (i = 0; i < 4; i++) {
            fprintf(log, "%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
            printf("%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
        }

        fprintf(log, "(");
        printf("(");

        for (i = 0; i < 4; i++) {
            fprintf(log, "%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
            printf("%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
        }

        fprintf(log, ")\nDest address: ");
        printf(")\nDest address: ");

        for (i = 0; i < 4; i++) {
            fprintf(log, "%02d.",(unsigned char) *((char *) (&ip->daddr) + i));
            printf("%02d.",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        fprintf(log, "(");
        printf("(");

        for (i = 0; i < 4; i++) {
            fprintf(log, "%02x ",(unsigned char) *((char *) (&ip->daddr) + i));
            printf("%02x ",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        fprintf(log, ")\n");
        printf(")\n");

        printf("Source port %d\n",ntohs(tcp->source)); 
		printf("Dest port %d \n",ntohs(tcp->dest)); 
		printf("FIN:%d SYN:%d RST:%d PSH:%d ACK:%d URG:%d \n",ntohs(tcp->fin)&&1,ntohs(tcp->syn)&&1,ntohs(tcp->rst)&&1,ntohs(tcp->psh)&&1,ntohs(tcp->ack)&&1,ntohs(tcp->urg)&&1);
		printf("-------------------------\n");
		fprintf(f,"Source port %d\n",ntohs(tcp->source)); 
		fprintf(f,"Dest port %d \n",ntohs(tcp->dest)); 
		fprintf(f,"FIN:%d SYN:%d RST:%d PSH:%d ACK:%d URG:%d \n",ntohs(tcp->fin)&&1,ntohs(tcp->syn)&&1,ntohs(tcp->rst)&&1,ntohs(tcp->psh)&&1,ntohs(tcp->ack)&&1,ntohs(tcp->urg)&&1);
		fprintf(f,"-------------------------\n");
    }
}