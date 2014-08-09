/*
 * Program: bsd-routing-sockets.c
 *
 * Test IPv6 Routing sockets
*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <pwd.h>

#define TRUE		1
#define FALSE		0
#ifdef __linux__
/* Consulting the routing table */
#define MAX_NLPAYLOAD 1024
#else
#define MAX_RTPAYLOAD 1024
#endif

#ifndef SA_SIZE
#if defined(__APPLE__)
#define SA_SIZE(sa)                                            \
        (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?  \
           sizeof(long)         :                               \
           ((struct sockaddr *)(sa))->sa_len )
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__)
#define SA_SIZE(sa)                                            \
        (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?  \
           sizeof(long)         :                               \
           1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#else
	#define SA_SIZE(sa) sizeof(struct sockaddr)
#endif
#endif

#ifndef SA_NEXT
	#define SA_NEXT(sa) (sa= (struct sockaddr *) ( (char *) sa + SA_SIZE(sa)))
#endif

#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
    #ifndef s6_addr16
	    #define s6_addr16	__u6_addr.__u6_addr16
    #endif

    #ifndef s6_addr
	    #define s6_addr		__u6_addr.__u6_addr8
    #endif

    #ifndef s6_addr8
	    #define s6_addr8	__u6_addr.__u6_addr8
    #endif

    #ifndef s6_addr32
	    #define s6_addr32	__u6_addr.__u6_addr32
    #endif
#elif defined __linux__ || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
    #ifndef s6_addr16
	    #define s6_addr16	__in6_u.__u6_addr16
    #endif

	#ifndef s6_addr32
		#define s6_addr32	__in6_u.__u6_addr32
	#endif
#endif

#ifdef IFNAMSIZ
#define IFACE_LENGTH	IFNAMSIZ
#else
#define IFACE_LENGTH	255
#endif

unsigned int		print_ipv6_address(char *s, struct in6_addr *);



int main(int argc, char *argv[]){
	int					sockfd;
	pid_t				pid;
	int					seq;
	ssize_t				r;
	size_t				ssize;
	unsigned int		queries=0;
	char				reply[MAX_RTPAYLOAD];
	unsigned char		nhifindex_f=0;
	unsigned int		nhifindex;
	char				nhiface[IFACE_LENGTH], pv6addr[INET6_ADDRSTRLEN];

#if defined(__APPLE__)
	char				aflink_f= FALSE;
#endif

	struct rt_msghdr	*rtm;
	struct sockaddr_in6	*sin6;
	struct	sockaddr_dl	*sockpptr;
	struct sockaddr		*sa;
	struct sockaddr		*so[RTAX_MAX];
	char			*cp;
	int			i;
	void				*end;
	unsigned char		onlink_f=FALSE, nhaddr_f=FALSE, verbose_f=TRUE, debug_f=FALSE;
	struct in6_addr		dstaddr, nhaddr;

	if(argc < 2){
		puts("usage:  lookup [-v] IPV6_ADDRESS");
		exit(1);
	}
	else if(argc > 2){
		debug_f= TRUE;
	}

	if( (sockfd=socket(AF_ROUTE, SOCK_RAW, 0)) == -1){
		if(verbose_f)
			puts("Error in socket() call from sel_next_hop()");

		return(EXIT_FAILURE);
	}

	if ( inet_pton(AF_INET6, (strlen(argv[1]) <= 2 && debug_f)?argv[2]:argv[1], &dstaddr) <= 0){
		puts("inet_pton(): Target Address not valid");
		exit(EXIT_FAILURE);
	}

	nhaddr= dstaddr;

	do{
		if(debug_f)
			printf("DEBUG: %u SOCKET_RAW query\n", queries+1);

		rtm= (struct rt_msghdr *) reply;
		memset(rtm, 0, sizeof(struct rt_msghdr));
		rtm->rtm_msglen= sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in6);
		rtm->rtm_version= RTM_VERSION;
		rtm->rtm_type= RTM_GET;
		rtm->rtm_addrs= RTA_DST | RTA_IFP;
		rtm->rtm_pid= pid= getpid();
		rtm->rtm_seq= seq= random();

		sin6= (struct sockaddr_in6 *) (rtm + 1);
		memset(sin6, 0, sizeof(struct sockaddr_in6));
		sin6->sin6_len= sizeof(struct sockaddr_in6);
		sin6->sin6_family= AF_INET6;
		sin6->sin6_addr= nhaddr;

#if defined(__APPLE__)
		if(IN6_IS_ADDR_LINKLOCAL(&nhaddr)){
			aflink_f= TRUE;
		}
#endif

		if(write(sockfd, rtm, rtm->rtm_msglen) == -1){
			if(verbose_f)
				puts("write() failed. No route to the intenteded destination in the local routing table");

			exit(EXIT_FAILURE);
		}

		do{
			if( (r=read(sockfd, rtm, MAX_RTPAYLOAD)) < 0){
				if(verbose_f)
					puts("Error in read() call from sel_next_hop()");

				exit(EXIT_FAILURE);
			}

			/* The size of the structure should be at least sizof(long) */
			end= (char *) rtm + r - (sizeof(long) -1);

			if(debug_f){
				puts("DEBUG: Received message");
				printf("DEBUG: rtm_type: %d (%d), rtm_pid: %d (%d), rtm_seq: %d (%d)\n", rtm->rtm_type, RTM_GET, rtm->rtm_pid, pid, \
				rtm->rtm_seq, seq);
			}
		}while( rtm->rtm_type != RTM_GET || rtm->rtm_pid != pid || rtm->rtm_seq != seq);

		/* The rt_msghdr{} structure is followed by sockaddr structures */
		cp = (char *)(rtm + 1);
		for (i = 0; i < RTAX_MAX; i++) {
			if (rtm->rtm_addrs & (1 << i)) {
				so[i] = (struct sockaddr *)cp;
				cp += SA_SIZE((struct sockaddr *)cp);
			} else
				so[i] = NULL;
		}

		if(so[RTAX_DST] != NULL) {
			sa = (struct sockaddr *)so[RTAX_DST];

			if(debug_f){
				puts("DEBUG: RTA_DST was set");
				print_ipv6_address("RTA_DST: ", &( ((struct sockaddr_in6 *)sa)->sin6_addr));
			}
		}

		if(so[RTAX_GATEWAY] != NULL){
			sa = (struct sockaddr *)so[RTAX_GATEWAY];

			if(debug_f){
				puts("DEBUG: RTA_GATEWAY was set");
				printf("DEBUG: Family: %d, size %d, realsize: %lu\n", sa->sa_family, sa->sa_len, SA_SIZE(sa));
				printf("DEBUG: sizeof(AF_LINK): %lu, sizeof(AF_INET6): %lu\n", sizeof(struct sockaddr_dl), sizeof(struct sockaddr_in6));
			}

			if(sa->sa_family == AF_INET6){
				nhaddr= ((struct sockaddr_in6 *) sa)->sin6_addr;
				nhaddr_f=TRUE;

				if(debug_f){
					print_ipv6_address("DEBUG: RTA_GATEWAY: ", &nhaddr);
				}
			}
		}

		if (so[RTAX_IFP] != NULL) {
			sa = (struct sockaddr *)so[RTAX_IFP];

			sockpptr = (struct sockaddr_dl *) (sa);
			if(debug_f){
				puts("DEBUG: RTA_IFP was set");
				printf("DEBUG: Family: %d, size %d, realsize: %lu\n", sa->sa_family, sa->sa_len, SA_SIZE(sa));
			}
			if (sockpptr->sdl_family == AF_LINK) {
				nhifindex= sockpptr->sdl_index;
				nhifindex_f=TRUE;
				if (sockpptr->sdl_nlen >= sizeof(nhiface)) {
					puts("ifname is too long.");
					return(EXIT_FAILURE);
				}
				strncpy(nhiface, sockpptr->sdl_data,
				    sockpptr->sdl_nlen);
				nhiface[sizeof(nhiface) - 1] = '\0';

				if(debug_f)
					printf("DEBUG: RTA_IFP: Name: %s, Index: %d\n", nhiface, nhifindex);
				onlink_f=TRUE;
			}
		}

		queries++;
	}while(!onlink_f && queries < 10);

	if(debug_f)
		printf("DEBUG: Quitted loop. onlink_f: %d, queries: %d\n", onlink_f, queries);

	close(sockfd);

	if(nhifindex_f){
		if(IN6_IS_ADDR_LINKLOCAL(&nhaddr)){
			/* BSDs store the interface index in s6_addr16[1], so we must clear it */
			nhaddr.s6_addr16[1] =0;
			nhaddr.s6_addr16[2] =0;
			nhaddr.s6_addr16[3] =0;
		}

		if(nhaddr_f){
			if(inet_ntop(AF_INET6, &nhaddr, pv6addr, sizeof(pv6addr)) == NULL){
				puts("inet_ntop(): Error converting IPv6 Address to presentation format");
				exit(EXIT_FAILURE);
			}

			printf("Next-Hop address: %s\n", pv6addr);
		}

		printf("Outgoing interface: %s (Index: %d)\n", nhiface, nhifindex);

		return(EXIT_SUCCESS);
	}
	else{
		return(EXIT_FAILURE);
	}
}




/*
 * Function: print_ipv6_addresss()
 *
 * Prints an IPv6 address with a legend
 */

unsigned int print_ipv6_address(char *s, struct in6_addr *v6addr){
	char 				pv6addr[INET6_ADDRSTRLEN];

	if(inet_ntop(AF_INET6, v6addr, pv6addr, sizeof(pv6addr)) == NULL){
		puts("inet_ntop(): Error converting IPv6 Source Address to presentation format");
		return(EXIT_FAILURE);
	}

	printf("%s%s\n", s, pv6addr);
	return(EXIT_SUCCESS);
}

