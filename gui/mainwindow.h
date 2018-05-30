#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

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

#define BUFFER_SIZE 65535

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_startButton_clicked();

    void on_stopButton_clicked();

private:
    int stop;
    Ui::MainWindow *ui;
    void set_promiscuous_mode(char *);
    void sniffer();
    void sniffer_main(char *);
};

#endif // MAINWINDOW_H
