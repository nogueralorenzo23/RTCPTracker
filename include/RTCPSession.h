
#ifndef __RTCPSession_H__
#define __RTCPSession_H__

//#define DEBUG 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <math.h>
#include <pcap.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <stdint.h>
#include <math.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "list.h"
#include "mod.h"
#include "Functions.h"
#include "dim.h"

#ifdef _USE_CB_
#include "CallBuffer.h"
#endif


// Module return values
#define OK_RTCP 0
#define ERR_RTCP_FILE 1

typedef struct pcaprec_hdr_sc {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_tc;

typedef struct callInfoC {

	uint8_t media_type;
	uint16_t port;
	uint32_t IP;
	char IPC [1024];

	uint8_t ptte_arr [MAX_NUM_PACK/100];
	uint32_t n_ptte_p;

#ifdef _USE_CB_
	CallBuffer *first;
	CallBuffer *last;
	uint8_t payload [2000];

#else
	uint8_t payload[MAX_PAYLOAD];
	uint8_t payload_packet_sizes[MAX_NUM_PACK];
	uint32_t payload_packet_ts[MAX_NUM_PACK];
	uint8_t media_types[MAX_NUM_PACK];
#endif

	uint32_t offset;

	uint64_t begin;
	uint64_t end;

	uint64_t nbytes;
	uint32_t npack;
	uint32_t npack_rtcp_inserted;
	uint64_t sqr_sum_pack;
	double max_int_time;
	double min_int_time;
	double sum_int_time;
	uint16_t prev_sequence_number;
	uint32_t lost_packet;
	uint8_t first_packet;

} CallInfoC;

typedef struct sessionRTCP {

	CallInfoC caller;
	CallInfoC called;

	uint64_t begin_signaling;
	node_l *active_node;

	char callID [MAX_CALLID];
	char to [MAX_TOFROM];
	char from [MAX_TOFROM];

	uint8_t * payload;
	uint8_t ptte;

#ifdef _DEBUG_RTCP_
	uint64_t offset_payload_pcap;
	uint8_t payload_pcap [MAX_PAYLOAD*2];
#endif

} RTCPSession;

//typedef struct Jittertcp {
	//uint64_t Jfinal;
 	//uint64_t Jant; 
	//uint64_t D;
 	//uint64_t J; 
	//uint64_t last_time_packet_arrive;
	//uint64_t last_time_packet_arrive_anterior;
	//uint64_t timestamp_anterior; 
	//uint64_t timestamp_actual;
	//int Num;
//}Jtr;

//void jitter(struct pcap_pkthdr *h,Jtr * jitrtcp);//jitter

//*****************************************
// Mem. functions
//*****************************************
void allocRTCPSessionPool(void);
void releaseRTCPSession(RTCPSession* f);
void freeRTCPSessionPool(void);
RTCPSession* getRTCPSession(void);
//*****************************************
// Struct-management function
//*****************************************
RTCPSession * insertRTCPCall (RTCPSession * rtcpsession);
void updateRTCPSession (RTCPSession * session, RTCPSession * current_session, CallInfoC * direction);

#ifndef _DEBUG_RTCP_
	void insertPacketRTCP (RTCPSession * session);
#else
	void insertPacketRTCP (RTCPSession * session, RTCPSession** rtcpsession_modified);
#endif

// Aux functions
float calculateMOSRTCP(double lostPackRate, uint8_t mediaType);

//*****************************************
// Clean-up functions
//*****************************************
RTCPSession * removeSessionRTCP (node_l * current_node);
void exportMultimediaDataC(char * raw_file, char * paq_file, CallInfoC * direction);
void exportRTCP(RTCPSession *session);
void cleanup_RTCP ();

//*****************************************
// Indexing function
//*****************************************
uint32_t getCallIndex2(RTCPSession *srtcp);

//*****************************************
// Comp. functions
//*****************************************
int compareCallRTCP2(void *a, void *b);
int compareCallRTCP(void *a, void *b);

#ifdef _DEBUG_RTCP_
RTCPSession* insertRTCP_debug(RTCPSession* current_session,uint8_t *bp, struct pcap_pkthdr *h);
#endif

int initRTCPModule(config_t * cfg_f);

#endif

