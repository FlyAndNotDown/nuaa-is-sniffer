// 头文件
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#define LOG_FILE_PATH "./log.txt"
#define BUFFER_SIZE 65535

// TODO
// 那三个结构体

// 设置混杂模式
void set_promiscuous_mode(char *);
// 嗅探
void sniffer();
