#ifndef __RTCPTRACKER_H__
#define __RTCPTRACKER_H__

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <features.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/ip.h>
#include <string.h>
#include <net/ethernet.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>


#include "mod.h"
#include "commons.h"
#include "IPassembler.h"
#include "TCPassembler.h"
#include "UniversalTCPAssembler.h"

#ifdef _USE_CB_
#include "CallBuffer.h"
#endif

#include "SIPSession.h"

#ifdef _USE_SKINNY_
#include "SKINNYSession.h"
#endif

#ifdef _USE_UNISTIM_
#include "UNISTIMSession.h"
#endif

#include "RTPSession.h"
#include "RTCPSession.h"
#include "NDleeTrazas.h"
#include "list.h"

#define CLEAN_UP_BY_PACKET_COUNT 25000
#define UDP_HLEN 8

#define N_ARGS 9

#ifdef _USE_SKINNY_
#define _PRINT_SKINNY_TS_
#endif

//#define _DEBUG_TEST_CONNECTIONS_

#define PCAP_LIVE 0
#define NDLT_DEAD 1

#define OK 0
#define ERROR -1

#endif


