#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    stop = 0;
}

MainWindow::~MainWindow()
{
    delete ui;
}

// 设置网卡混杂模式
void MainWindow::set_promiscuous_mode(char *interface_name) {
    int fd;

    // 建立特殊 socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        ui->log->appendPlainText("Can't create socket! Please try run the program in the root mode?");
        printf("Can't create socket! Please try run the program in the root mode?\n");
        exit(0);
    }

    // ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, strlen(interface_name) + 1);

    // 接受网卡的信息
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        ui->log->appendPlainText("Can't get info from the interface!");
        printf("Can't get info from the interface!\n");
        exit(0);
    }

    // 更改flags为混杂模式
    ifr.ifr_flags |= IFF_PROMISC;

    // 设置混杂模式
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
        ui->log->appendPlainText("Can't set the promisc flag to interface!");
        printf("Can't set the promisc flag to interface!\n");
        exit(0);
    }

    ui->log->appendPlainText("The interface has been set to promiscuous mode.");
    printf("The interface has been set to promiscuous mode.\n");
}

void MainWindow::sniffer() {
    ui->log->clear();

    int fd, bytes, i;
    socklen_t len;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in addr;
    struct iphdr *ip;
    struct tcphdr *tcp;

    char temp1[BUFFER_SIZE * 10];
    char temp2[BUFFER_SIZE];

    // 打开socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd == -1) {
        ui->log->appendPlainText("Can't open socket! Please try to run the program in the root mode!");
        printf("Can't open socket! Please try to run the program in the root mode!\n");
        exit(0);
    }

    // 开始嗅探
    while (1) {
        if (stop == 1) {
            stop = 0;
            break;
        }

        // 清空结构体
        memset(buffer, 0, sizeof(buffer));

        // 接收数据
        bytes = recvfrom(fd, (char *) buffer, sizeof(buffer), 0, NULL, NULL);

        temp1[0] = '\0';
        temp2[0] = '\0';
        sprintf(temp2, "\n");
        strcat(temp1, temp2);
        printf("\n");

        for (i = 0; i < bytes; i++) {
            sprintf(temp2, "%02x ", (unsigned char) buffer[i]);
            strcat(temp1, temp2);
            printf("%02x ", (unsigned char) buffer[i]);

            if ((i + 1) % 12 == 0) {
                sprintf(temp2, "\n");
                strcat(temp1, temp2);
                printf("\n");
            }
        }

        sprintf(temp2, "\n");
        strcat(temp1, temp2);
        printf("\n");

        sprintf(temp2, "\nBytes receiverd %5d\n", bytes);
        strcat(temp1, temp2);
        printf("\nBytes receiverd %5d\n", bytes);

        ip = (struct iphdr *) buffer;
        sprintf(temp2, "IP header length %d\n", ip->tot_len);
        strcat(temp1, temp2);
        printf("IP header length %d\n", ip->tot_len);
        sprintf(temp2, "Protocol %d\n",ip->protocol);
        strcat(temp1, temp2);
        printf("Protocol %d\n",ip->protocol);

        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        sprintf(temp2, "Src address: ");
        strcat(temp1, temp2);
        printf("Src address: ");

        for (i = 0; i < 4; i++) {
            sprintf(temp2, "%03d ", (unsigned char) *((char *) (&ip->saddr) + i));
            strcat(temp1, temp2);
            printf("%03d ", (unsigned char) *((char *) (&ip->saddr) + i));
        }

        sprintf(temp2, "(");
        strcat(temp1, temp2);
        printf("(");

        for (i = 0; i < 4; i++) {
            sprintf(temp2, "%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
            strcat(temp1, temp2);
            printf("%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
        }

        sprintf(temp2, ")\nDest address: ");
        strcat(temp1, temp2);
        printf(")\nDest address: ");

        for (i = 0; i < 4; i++) {
            sprintf(temp2, "%03d.",(unsigned char) *((char *) (&ip->daddr) + i));
            strcat(temp1, temp2);
            printf("%03d.",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        sprintf(temp2, "(");
        strcat(temp1, temp2);
        printf("(");

        for (i = 0; i < 4; i++) {
            sprintf(temp2, "%02x ",(unsigned char) *((char *) (&ip->daddr) + i));
            strcat(temp1, temp2);
            printf("%02x ",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        sprintf(temp2, ")\n");
        strcat(temp1, temp2);
        printf(")\n");

        sprintf(temp2, "Source port %d\n", ntohs(tcp->source));
        strcat(temp1, temp2);
        printf("Source port %d\n", ntohs(tcp->source));
        sprintf(temp2, "Dest port %d \n", ntohs(tcp->dest));
        strcat(temp1, temp2);
        printf("Dest port %d \n", ntohs(tcp->dest));
        sprintf(temp2, "FIN:%d SYN:%d RST:%d PSH:%d ACK:%d URG:%d \n", ntohs(tcp->fin) && 1, ntohs(tcp->syn) && 1, ntohs(tcp->rst) && 1, ntohs(tcp->psh) && 1, ntohs(tcp->ack) && 1, ntohs(tcp->urg) && 1);
        strcat(temp1, temp2);
        printf("FIN:%d SYN:%d RST:%d PSH:%d ACK:%d URG:%d \n", ntohs(tcp->fin) && 1, ntohs(tcp->syn) && 1, ntohs(tcp->rst) && 1, ntohs(tcp->psh) && 1, ntohs(tcp->ack) && 1, ntohs(tcp->urg) && 1);
        sprintf(temp2, "--------------------------------------------------\n");
        strcat(temp1, temp2);
        printf("--------------------------------------------------\n");

        ui->log->appendPlainText(temp1);
        qApp->processEvents();
    }
}

void MainWindow::sniffer_main(char *interface) {
    // 设置网卡混杂模式
    set_promiscuous_mode(interface);

    // 开始嗅探
    sniffer();
}

void MainWindow::on_startButton_clicked()
{
    // get the interface name from ui
    char *interface;
    QString str = ui->interfaceEdit->text();
    QByteArray ba = str.toLatin1();
    interface = ba.data();

    // start the sniffer main process
    sniffer_main(interface);
}

void MainWindow::on_stopButton_clicked()
{
    stop = 1;
}
