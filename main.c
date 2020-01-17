#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <netinet/ip.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnet.h>
#include <arpa/inet.h>

struct filter_rule {
    uint32_t ip;
    uint16_t port;
    char *keyword;
    uint32_t len_keyword;
};

static struct filter_rule rules;
static uint32_t global_counter = 0;

static uint32_t find_appearances(char* needle, uint32_t len_needle, char *haystack, uint32_t len_haystack) {
    uint32_t appearance = 0;

    for (int i = 0; i <= len_haystack-len_needle; i++) {
        if (!memcmp(haystack + i, needle, len_needle)){
            appearance++;
        }
    }

    return appearance;
}

static void filter(struct nfq_data *data, struct filter_rule *rule) {
    struct iphdr *ipHeader;
    struct udphdr *udpHeader;
    struct pkt_buff* pktBuff;
    uint32_t appearences;
    char *payload;
    int ret;

    ret = nfq_get_payload(data, &payload);
    if (!ret) {
        fprintf(stderr, "Empty packet received.", ret);
    }

    pktBuff = pktb_alloc(AF_INET, payload, ret, 0);

    if (!pktBuff) {
        fprintf(stderr, "Could not allocate pktb_buff");
    }

    // Parse IP header
    ipHeader = nfq_ip_get_hdr(pktBuff);
    if (!ipHeader){
        fprintf(stderr, "Could not parse IP header");
    }

    // Check if IP matches and udp is used
    if (ipHeader->saddr == rule->ip && ipHeader->protocol == IPPROTO_UDP) {
        // Populate transport header in pktBuf
        nfq_ip_set_transport_header(pktBuff, ipHeader);
        // Parse UDP header
        udpHeader = nfq_udp_get_hdr(pktBuff);

        if (udpHeader->uh_sport == rule->port) {
            char* udpPayload = nfq_udp_get_payload(udpHeader, pktBuff);
            appearences = find_appearances(rule->keyword, rule->len_keyword, udpPayload, ntohs(udpHeader->len) - 8);
            if (appearences) {
                global_counter--;
                printf("payload: %.*s appearances: %u\n", udpHeader->len, udpPayload, appearences);
            }
        }
    }

    pktb_free(pktBuff);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    filter(nfa, &rules);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

uint32_t parse_args(char **argv) {
    struct sockaddr_in sa;
    int ret = inet_pton(AF_INET, argv[1], &(sa.sin_addr));
    if (!ret) {
        fprintf(stderr, "Could not parse IP address.");
        return 0;
    }
    uint32_t ip = sa.sin_addr.s_addr;
    uint16_t port = htons(atoi(argv[2]));
    uint32_t str_len = strlen(argv[4]);
    uint32_t  counter = atoi(argv[3]);

    rules.ip = ip;
    rules.port = port;
    rules.keyword = argv[4];
    rules.len_keyword = str_len;


    return counter;
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    global_counter = 0;

    if (argc < 5) {
        puts("Missing parameters. Call: ./feuerwand ip port counter string");
        exit(1);
    }

    global_counter = parse_args(argv);
    if (!global_counter) {
        exit(1);
    }

    system("iptables -I INPUT -j NFQUEUE");

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }


    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }


    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }


    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }


    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
        if (global_counter <= 0) {
            break;
        }
    }


    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
       * it detaches other programs/sockets from AF_INET, too ! */
      printf("unbinding from AF_INET\n");
      nfq_unbind_pf(h, AF_INET);
#endif
    nfq_close(h);

    system("iptables -D INPUT -j NFQUEUE");
    exit(0);
}
