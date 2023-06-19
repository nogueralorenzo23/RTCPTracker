#include "RTCPSession.h"

//*****************************************************
// Mem. variables
//*****************************************************
extern uint64_t total_structures_RTCP;
extern uint64_t used_structures_RTCP;
uint32_t lspacketc = 0;

//*****************************************************
FILE * RTCP_ts_data_file = NULL;
uint64_t new_RTCP = 0;
//*****************************************************

node_l *rtcp_session_pool_free=NULL;
node_l *rtcp_session_pool_used=NULL;
RTCPSession *rtcps;

uint64_t active_RTCP_session_list_size = 0;
node_l *active_RTCP_session_list = NULL;

//node_l *RTCP_table[MAX_FLOWS_TABLE_SIZE] = { 0 };
node_l **RTCP_table;
uint64_t MAX_RTCP_TABLE_SIZE = 1024; // Default value
uint64_t MAX_POOL_RTCP_FLOW = 27;

extern FILE *RTCP_records;
extern uint64_t last_packet_timestamp;
extern uint64_t expiration_RTCP_time;
extern char recolectar_RAW;
extern char directory[100];
extern node_l static_node;
extern uint8_t hdrLinkLen;


extern FILE * error_log_f, * log_f;
extern char log_message_aux[1000];

void allocRTCPSessionPool(void)
{
	int i = 0;
	node_l *n = NULL;
	rtcps = calloc(MAX_POOL_RTCP_FLOW,sizeof(RTCPSession));
	memset(rtcps,0,MAX_POOL_RTCP_FLOW*sizeof(RTCPSession));
	assert (rtcps != NULL);

	for(i=0;i<MAX_POOL_RTCP_FLOW;i++) {

		n = list_alloc_node(rtcps+i);
		list_prepend_node(&rtcp_session_pool_free,n);
		total_structures_RTCP++;
	}

	RTCP_table = (node_l **)calloc(MAX_RTCP_TABLE_SIZE,sizeof(node_l *));
	assert(RTCP_table != NULL);
	memset(RTCP_table, 0, MAX_RTCP_TABLE_SIZE*sizeof(node_l *));
}

RTCPSession * getRTCPSession(void) {

	node_l *n = list_pop_first_node(&rtcp_session_pool_free);

	if(rtcp_session_pool_free == NULL) {

		printLogMessage("ERROR: empty RTCP pool", error_log_f);
		return NULL;
	}

	list_prepend_node(&rtcp_session_pool_used,n);
	used_structures_RTCP++;
	new_RTCP++;

	return (n->data);
}

void releaseRTCPSession(RTCPSession * f) {

	node_l *n = list_pop_first_node(&rtcp_session_pool_used);
	n->data = (void*)f;
	list_prepend_node(&rtcp_session_pool_free,n);
	used_structures_RTCP--;
}


//*****************************************************


//*****************************************************
void freeRTCPSessionPool(void) {

	node_l *n = NULL;
	int i;

	while(rtcp_session_pool_free != NULL) {

		n = list_pop_first_node(&rtcp_session_pool_free);
		free(n);
	}

	while(rtcp_session_pool_used != NULL) {

		n = list_pop_first_node(&rtcp_session_pool_used);
		free(n);
		used_structures_RTCP--;
	}

	free(rtcps);

	if (RTCP_table != NULL) {
	for (i = 0; i < MAX_RTCP_TABLE_SIZE; i++) {

		n = RTCP_table[i];

		while(n != NULL) {
			releaseNodel(n);
			n = list_pop_first_node(&RTCP_table[i]);
		}
	}

	free(RTCP_table);
	}

	if (RTCP_ts_data_file) fclose(RTCP_ts_data_file);
}

uint32_t getCallIndex2(RTCPSession *srtcp) {//////Puedo cambiar aquí mismo el valor del puerto para que sea el del rtcp?
	return (srtcp->caller.IP + srtcp->caller.port + srtcp->called.IP + srtcp->called.port) % MAX_RTCP_TABLE_SIZE;
}

int compareCallRTCP2(void *a, void *b) {

	if ((((RTCPSession*)a)->caller.IP == ((RTCPSession*)b)->caller.IP) &&
		(((RTCPSession*)a)->caller.port == ((RTCPSession*)b)->caller.port) &&
		(((RTCPSession*)a)->called.IP == ((RTCPSession*)b)->called.IP) &&
		(((RTCPSession*)a)->called.port == ((RTCPSession*)b)->called.port)) {

		return 0;
	}

	return 1;
}

int compareCallRTCP(void *a, void *b) {

	if((((RTCPSession*)a)->caller.IP == ((RTCPSession*)b)->caller.IP) &&
		(((RTCPSession*)a)->caller.port == ((RTCPSession*)b)->caller.port) &&
		(((RTCPSession*)a)->called.IP == ((RTCPSession*)b)->called.IP) &&
		(((RTCPSession*)a)->called.port == ((RTCPSession*)b)->called.port)) {
		return 0;
	}

	return 1;
}

RTCPSession * insertRTCPCall (RTCPSession * rtcpsession) {

	uint32_t index;
	node_l *naux = NULL, *new_active_node = NULL;

	index = getCallIndex2(rtcpsession);

	list_alloc_node_no_malloc(rtcpsession);
	node_l *current_node = list_search(&(RTCP_table[index]),&static_node,compareCallRTCP);

	if (current_node == NULL) {

#ifdef _DEBUG_TEST_CONNECTIONS_
char IP3[16], IP4[16];
printf("RTCPS138 - Insert RTCPCall: CallerIP:%s -- CalledIP:%s \n", int2ip(&(rtcpsession->caller.IP),IP3),int2ip(&(rtcpsession->called.IP),IP4));
#endif

		(rtcpsession->caller).first_packet=YES;
		(rtcpsession->called).first_packet=YES;

		(rtcpsession->caller).n_ptte_p=0;
		(rtcpsession->called).n_ptte_p=0;

		(rtcpsession->caller).npack_rtcp_inserted = 0;
		(rtcpsession->called).npack_rtcp_inserted = 0;

		(rtcpsession->called).sqr_sum_pack = 0;
		(rtcpsession->caller).sqr_sum_pack = 0;

		(rtcpsession->caller).max_int_time = 0;
		(rtcpsession->called).max_int_time = 0;
		(rtcpsession->caller).min_int_time = 0;
		(rtcpsession->called).min_int_time = 0;
		(rtcpsession->caller).sum_int_time = 0;
		(rtcpsession->called).sum_int_time = 0;

		(rtcpsession->caller).prev_sequence_number = 0;
		(rtcpsession->called).prev_sequence_number = 0;

		(rtcpsession->caller).lost_packet = 0;
		(rtcpsession->called).lost_packet = 0;

		(rtcpsession->caller).npack=0;
		(rtcpsession->called).npack=0;

		(rtcpsession->caller).nbytes=0;
		(rtcpsession->called).nbytes=0;

		(rtcpsession->called).media_type=0;
		(rtcpsession->caller).media_type=0;

		(rtcpsession->caller).begin=last_packet_timestamp;
		(rtcpsession->caller).end=last_packet_timestamp;

		(rtcpsession->called).begin=last_packet_timestamp;
		(rtcpsession->called).end=last_packet_timestamp;

		(rtcpsession->called).offset=0;
		(rtcpsession->caller).offset=0;

#ifdef _DEBUG_RTCP_
		rtcpsession->offset_payload_pcap=0;
#endif

		naux=getNodel();
		naux->data=rtcpsession;

		list_prepend_node(&(RTCP_table[index]),naux);

		new_active_node=getNodel();
		new_active_node->data=naux;
		(rtcpsession->active_node)=new_active_node;
		list_prepend_node(&active_RTCP_session_list,new_active_node);

		return NULL;
	}

	return rtcpsession;
}

#ifdef _DEBUG_RTCP_

RTCPSession* insertRTCP_debug(RTCPSession* current_session,uint8_t *bp, struct pcap_pkthdr *h) {

	pcaprec_hdr_tc hdr;
	hdr.incl_len=h->caplen;
	hdr.orig_len=h->len;
	hdr.ts_sec=h->ts.tv_sec;
	hdr.ts_usec=h->ts.tv_usec;

	if( (h->caplen+sizeof(pcaprec_hdr_tc)+current_session->offset_payload_pcap) < 2*MAX_PAYLOAD-sizeof(struct pcap_file_header)-1)
	{

		memcpy(&((current_session->payload_pcap)[current_session->offset_payload_pcap]),&hdr,sizeof(pcaprec_hdr_tc));//cabecera
		(current_session->offset_payload_pcap)+=sizeof(pcaprec_hdr_tc);


		memcpy(&((current_session->payload_pcap)[current_session->offset_payload_pcap]),bp,h->caplen);//? paquete, len?
		(current_session->offset_payload_pcap)+=h->caplen;

	}
	return current_session;

}
#endif

#ifndef _DEBUG_RTCP_
	void insertPacketRTCP (RTCPSession * session) {
#else
	void insertPacketRTCP (RTCPSession * session, RTCPSession** rtcpsession_modified) {
#endif

	node_l *current_node = NULL;
	RTCPSession *current_session=NULL;
	uint32_t index = 0;
	uint32_t swap = 0;

#ifdef _DEBUG_RTCP_
	*rtcpsession_modified=NULL;
#endif

	index = getCallIndex2(session);
	list_alloc_node_no_malloc(session);

	current_node=list_search(&(RTCP_table[index]),&static_node,compareCallRTCP);

	if (current_node!=NULL)	{

		current_session=(RTCPSession*)(current_node->data);
		updateRTCPSession (session, current_session, &(current_session->caller));

#ifdef _DEBUG_RTCP_
		*rtcpsession_modified=current_session;
#endif

	} else {
		// Swap IPs
		swap = (session->caller).IP;
		(session->caller).IP = (session->called).IP;
		(session->called).IP = swap;

		// Swap Ports
		swap = (session->caller).port;
		(session->caller).port = (session->called).port;
		(session->called).port = swap;

		index = getCallIndex2(session);
		list_alloc_node_no_malloc(session);
		current_node=list_search(&(RTCP_table[index]),&static_node,compareCallRTCP);

		if(current_node != NULL) {

			current_session=(RTCPSession*)(current_node->data);
			updateRTCPSession (session, current_session,&(current_session->called));

#ifdef _DEBUG_RTCP_
			*rtcpsession_modified=current_session;
#endif
		}
	}
}

void updateRTCPSession (RTCPSession * session, RTCPSession * current_session, CallInfoC * direction) {

	uint16_t seq_number = htons(*((uint16_t*)((session->payload)+2)));
	int rtcp_header = 0;
	int dataLen = 0;
	printf("%.2x ",session->payload[5]);
//	session->payload += 8;
#ifdef _DEBUG_TEST_CONNECTIONS_
#ifdef _DEBUG_TEST_PAYLOAD_
printf("RTCPS193 - %x%x%x\n",session->payload[0],session->payload[1],session->payload[2]);
#endif
#endif
	rtcp_header = (session->payload[0]&0x0F)*4+12;
	dataLen = ((session->caller).offset)-rtcp_header;

#ifdef _DEBUG_TEST_CONNECTIONS_
printf("RTCPS300 - rtcp_header: %d -- dataLen: %d -- ((session->caller).offset): %d\n",rtcp_header,dataLen,((session->caller).offset));
#endif

	if (direction->first_packet == YES) {

		direction->first_packet = NO;
		direction->begin = last_packet_timestamp;
		direction->nbytes = 0;
		direction->npack = 0;
		direction->media_type = session->payload[1]&0x7F;
#ifdef _USE_CB_
		direction->last = NULL;
		direction->first = NULL;
#endif
		direction->npack_rtcp_inserted = 0;
		direction->prev_sequence_number = seq_number;
	}

	else {
	/////(session->payload[1]&0x7F) != 0
		if ((seq_number > direction->prev_sequence_number+1) &&
			 ((session->payload[1]&0x7F) <= 34))

			direction->lost_packet += seq_number-(direction->prev_sequence_number+1);
			lspacketc+=(uint16_t) (seq_number-(direction->prev_sequence_number+1));
			printf("INFO: LOST RTCP messages: %"PRIu32"\n",
		    	lspacketc);			

		if (direction->max_int_time == 0) {

			direction->max_int_time = (double)(last_packet_timestamp - direction->end)/1000000;
			direction->min_int_time = (double)(last_packet_timestamp - direction->end)/1000000;
			direction->sum_int_time += (double)(last_packet_timestamp - direction->end)/1000000;

		} else {

			if(direction->max_int_time < (double)(last_packet_timestamp-direction->end)/1000000)
				direction->max_int_time = (double)(last_packet_timestamp-direction->end)/1000000;

			if(direction->min_int_time > (double)(last_packet_timestamp-direction->end)/1000000)
				direction->min_int_time = (double)(last_packet_timestamp-direction->end)/1000000;

			direction->sum_int_time += (double)(last_packet_timestamp-direction->end)/1000000;
		}

		direction->prev_sequence_number = seq_number;
	}


	if ((session->ptte != 0) && ((session->payload[1]&0x7F) == session->ptte)) {

		direction->ptte_arr[direction->n_ptte_p] = session->payload[12];
		direction->n_ptte_p++;
	}

	if ((session->payload[1]&0x7F) <= 34) {

		direction->nbytes += session->caller.offset+14+20+8;
		direction->npack++;
		direction->sqr_sum_pack += ((session->caller.offset+14+20+8)*(session->caller.offset+14+20+8));

		if (recolectar_RAW == '1') {

			direction->npack_rtcp_inserted++;

#ifdef _USE_CB_
//printf("dataLen: %" PRIu64 " *** ",dataLen);
			direction->last = copyData2CB(direction->last,
				                          session->payload+rtcp_header,
				                          session->payload[1]&0x7F,
				                          dataLen);

			if (direction->first == NULL) direction->first = direction->last;
#else
			if (MAX_PAYLOAD-direction->offset > dataLen) {

				memcpy(direction->payload+direction->offset,session->payload+rtcp_header,dataLen);
				direction->offset+=dataLen;

				if(direction->npack_rtcp_inserted<MAX_NUM_PACK) {

					direction->payload_packet_sizes[direction->npack_rtcp_inserted] = dataLen;
					direction->media_types[direction->npack_rtcp_inserted] = session->payload[1]&0x7F;
					direction->payload_packet_ts[direction->npack_rtcp_inserted] = (uint32_t)session->payload[4];
				}
			}
#endif
		}
	}


	direction->end=last_packet_timestamp;
	list_unlink(&active_RTCP_session_list,current_session->active_node);
	list_prepend_node(&active_RTCP_session_list,current_session->active_node);
}

void cleanup_RTCP () {

	node_l *n = NULL,*naux = NULL;
	node_l *current_node_session_table = NULL;
	RTCPSession *current_session = NULL;
	uint64_t last_time_packet_arrive = 0;

	fprintf(RTCP_ts_data_file,"%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",last_packet_timestamp/1000000,used_structures_RTCP,new_RTCP);
	new_RTCP = 0;

	n = list_get_last_node(&active_RTCP_session_list);

	while(n != NULL) {
		current_node_session_table=(node_l*)n->data;
		current_session=(RTCPSession*)current_node_session_table->data;
		last_time_packet_arrive=MAX((current_session->caller).end, (current_session->called).end);

		if (last_packet_timestamp-last_time_packet_arrive > expiration_RTCP_time) {
			naux=n;
			n = list_get_prev_node(&active_RTCP_session_list, n);
			exportRTCP(removeSessionRTCP(naux));
		} else {
			break;
		}
	}
}

RTCPSession * removeSessionRTCP (node_l * current_node)
{
	RTCPSession *current_session=NULL;
	node_l *current_node_session_table=NULL;
	uint32_t index=0;

	if (current_node == NULL)
		return NULL;

	current_node_session_table= (node_l*)(current_node->data);
	current_session=(RTCPSession*)(current_node_session_table->data);

	index=getCallIndex2(current_session);

	list_unlink(&(RTCP_table[index]),current_node_session_table);
	releaseNodel(current_node_session_table);

	list_unlink(&active_RTCP_session_list,current_node);
	releaseNodel(current_node);

	active_RTCP_session_list_size--;

	return current_session;
}

void exportRTCP(RTCPSession *session){

	// File paths
	char raw_caller_fname[(256*4)];
	char raw_called_fname[(256*4)];

	char paq_caller_fname[(256*4)];
	char paq_called_fname[(256*4)];

	char dynamic_directory[1500];

#ifdef _DEBUG_RTCP_
	char RTCP_pcap_fname[(256*4)];
	int RTCP_pcap_file = 0;
	struct pcap_file_header global_hdr;
#endif

	char IP3[16],IP4[16];
	char begin_string[100];
	char end_string[100];

	uint64_t end = 0, begin = 0;

	double AvgSizePack_caller;
	double AvgSizePack_called;
	double StdSizePack_caller;
	double StdSizePack_called;

	time_t begin_sec;
	time_t end_sec;
	struct tm begin_tm;
	struct tm end_tm;

	uint64_t duracion_caller;
	uint64_t duracion_called;

	float MOScaller = 1, MOScalled = 1;
	double lost_packets_rate_caller = (session->caller.npack==0?-1:(double)session->caller.lost_packet/(session->caller.npack+session->caller.lost_packet));
	double lost_packets_rate_called = (session->called.npack==0?-1:(double)session->called.lost_packet/(session->called.npack+session->called.lost_packet));

	// Calculate MOS
	MOScaller = calculateMOSRTCP(lost_packets_rate_caller,session->caller.media_type);
	MOScalled = calculateMOSRTCP(lost_packets_rate_called,session->called.media_type);

	if ((session->caller.npack >= 0)  || (session->called.npack >= 0)) {

		if (session->to[0] == 0) strcpy(session->to,"EMPTY_TO");
		if (session->from[0]==0) strcpy(session->from,"EMPTY_FROM");

		end = MAX(session->caller.end,session->called.end);

		begin = (session->begin_signaling)/1000000;
//		begin = begin-(begin%3600);

		sprintf(dynamic_directory,"%s/RAW/%" PRIu64 "",directory,begin);

		if (recolectar_RAW == '1') {

			mkdir(dynamic_directory, O_CREAT|(mode_t)0777);

			// Init. file names
			sprintf(raw_caller_fname, "%s/%s-%s-%" PRIu64 ".raw", dynamic_directory,
			                                                      session->to,session->from,
			                                                      begin);

			sprintf(paq_caller_fname,"%s/%s-%s-%" PRIu64 "-%lf.paq", dynamic_directory,session->to,
			                                                         session->from,
			                                                         begin,
			                                                         MOScaller);

			sprintf(raw_called_fname,"%s/%s-%s-%" PRIu64 ".raw", dynamic_directory,session->from,
			                                                     session->to,
			                                                     begin);

			sprintf(paq_called_fname,"%s/%s-%s-%" PRIu64 "-%lf.paq", dynamic_directory,session->from,
			                                                         session->to,begin,
			                                                         MOScalled);

			//--------------------------------------------------------------------------
			// Export multimedia data
			//--------------------------------------------------------------------------
			exportMultimediaDataC(raw_caller_fname, paq_caller_fname, &(session->caller));
			exportMultimediaDataC(raw_called_fname, paq_called_fname, &(session->called));
		} else {
			sprintf(raw_caller_fname,"%s","Nocapture");
			sprintf(paq_caller_fname,"%s","Nocapture");
			sprintf(raw_called_fname,"%s","Nocapture");
			sprintf(paq_called_fname,"%s","Nocapture");
		}

#ifdef _DEBUG_RTCP_

		sprintf(RTCP_pcap_fname,"%s/%s-%s-%" PRIu64 ".rtcp.pcap",dynamic_directory,
		                                                       session->to,
		                                                       session->from,
		                                                       begin);

		if ((RTCP_pcap_file = open(RTCP_pcap_fname,O_RDWR | O_APPEND | O_CREAT, (mode_t)0777)) == -1) {

			sprintf(log_message_aux,
			        "ERROR: Error opening pcap file %s, with RTCP traffic",
			        RTCP_pcap_fname);
			printLogMessage(log_message_aux, error_log_f);

		} else {

			//rellenamos cabecera global
			global_hdr.magic=0xa1b2c3d4;
			global_hdr.version_major=2;
			global_hdr.version_minor=4;
			global_hdr.thiszone=0;
			global_hdr.sigfigs=0;
			global_hdr.snaplen=0;
			global_hdr.linktype=DLT_EN10MB;

#ifdef _USE_PCAP_BUFFER_



#else
			//la escribimos al fichero
			write(RTCP_pcap_file,&global_hdr,sizeof(struct pcap_file_header));

			if (session->offset_payload_pcap != 0) {

				if (write(RTCP_pcap_file,session->payload_pcap,session->offset_payload_pcap)!=session->offset_payload_pcap) {

					sprintf(log_message_aux,
							"ERROR: Error while writing in pcap file %s, with RTCP traffic",
							RTCP_pcap_fname);
					printLogMessage(log_message_aux, error_log_f);
				}
			}
#endif

			close(RTCP_pcap_file);
		}
#endif

		begin = min_nozero(session->caller.begin,session->called.begin);
		end = MAX(session->caller.end,session->called.end);

		begin_sec=begin/1000000;
		end_sec=end/1000000;

		localtime_r(&begin_sec,&begin_tm);
		sprintf(begin_string, "\"%d %02d %02d %02d %02d %02d\"", begin_tm.tm_year+1900, begin_tm.tm_mon+1,
		                                                         begin_tm.tm_mday, begin_tm.tm_hour,
		                                                         begin_tm.tm_min, begin_tm.tm_sec);

		localtime_r(&end_sec,&end_tm);
		sprintf(end_string, "\"%d %02d %02d %02d %02d %02d\"", end_tm.tm_year+1900, end_tm.tm_mon+1,
		                                                       end_tm.tm_mday, end_tm.tm_hour,
		                                                       end_tm.tm_min, end_tm.tm_sec);

		duracion_caller = session->caller.end-session->caller.begin;
		duracion_called = session->called.end-session->called.begin;

		AvgSizePack_caller = (session->caller.npack == 0 ?
			-1 : (double)session->caller.nbytes/session->caller.npack);
		AvgSizePack_called = (session->called.npack == 0 ?
		    -1 : (double)session->called.nbytes/session->called.npack);
		StdSizePack_caller = (session->caller.npack == 0 ?
		    -1 : sqrt(((double)(session->caller.sqr_sum_pack)/session->caller.npack)-AvgSizePack_caller*AvgSizePack_caller));
		StdSizePack_called = (session->called.npack == 0 ?
		    -1 : sqrt(((double)(session->called.sqr_sum_pack)/session->called.npack)-AvgSizePack_called*AvgSizePack_called));

// 1begin, 2end, 3callID, 4caller_port, 5called_port,
// 6ip_caller, 7ip_called,
// 8caller_mediatype, 9called_mediatype,10raw_callerFile,11raw_calledFile,
// 12npack_caller, 13npack_called, 14caller_nbytes, 15called_nbytes,
// 16thrbytes_caller
// 17thrbytes_called,
// 18thrpack_caller,
// 19thrpack_called,
// 20ratio_loss_caller,
// 21ratio_loss_called,
// 22avgpacketsize_caller,
// 23avgpacketsize_called,
// 24avginterarr_caller,
// 25avginterarr_called,
// 26maxinterarr_caller, 27maxinterarr_called,
// 28mininterarr_caller, 29mininterarr_called,
// 30dur_caller, 31dur_called
// 32MOS_caller, 33MOS_called, 34std_packsize_caller, 35std_packsize_called, 36pcap_RTCP

#ifndef _DEBUG_RTCP_

	fprintf(RTCP_records,
	        //    1           2         3   4   5   6   7   8   9  10  11  12  13      14
	        "%" PRIu64 "\t%" PRIu64 "\t%s\t%u\t%u\t%s\t%s\t%u\t%u\t%s\t%s\t%u\t%u\t%" PRIu64 "\t"
	        //    15      16  17  18  19  20  21  22  23  24  25  26  27  28  29      30            30
	        "%" PRIu64 "\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%" PRIu64 ".%06" PRIu64 "\t"
	        //    31            31      32  33  34  35     36
	        "%" PRIu64 ".%06" PRIu64 "\t%f\t%f\t%f\t%f\tNO_AVAILABLE\n",
	        //1     2         3                 4                 5
	        begin, end, session->callID, session->caller.port, session->called.port,////cambiar
	        //        6                           7
	        int2ip(&(session->caller.IP),IP3), int2ip(&(session->called.IP),IP4),
	        //        8                        9                         10              11
	        session->caller.media_type, session->called.media_type, raw_caller_fname, raw_called_fname,
	        //       12                   13                     14                     15
	        session->caller.npack, session->called.npack, session->caller.nbytes, session->called.nbytes,
	        //       16
	        (duracion_caller==0?-1:(double)session->caller.nbytes/(session->caller.end-session->caller.begin)*1000000),
	        //       17
	        (duracion_called==0?-1:(double)session->called.nbytes/(session->called.end-session->called.begin)*1000000),
	        //       18
	        (duracion_caller==0?-1:(double)session->caller.npack/(session->caller.end-session->caller.begin)*1000000),
	        //       19
	        (duracion_called==0?-1:(double)session->called.npack/(session->called.end-session->called.begin)*1000000),
	        //       20
	        (session->caller.npack==0?-1:(double)session->caller.lost_packet/(session->caller.npack+session->caller.lost_packet)),
	        //       21
	        (session->called.npack==0?-1:(double)session->called.lost_packet/(session->called.npack+session->called.lost_packet)),
	        //       22
	        (session->caller.npack==0?-1:(double)session->caller.nbytes/session->caller.npack),
	        //       23
	        (session->called.npack==0?-1:(double)session->called.nbytes/session->called.npack),
	        //       24
	        avg(session->caller.sum_int_time, session->caller.npack),
	        //       25
	        avg(session->called.sum_int_time, session->called.npack),
	        //       26                         27
	        session->caller.max_int_time, session->called.max_int_time,
	        //       28                         29
	        session->caller.min_int_time, session->called.min_int_time,
			//       30                         30                         31                      31
	        duracion_caller/1000000, duracion_caller%1000000, duracion_called/1000000, duracion_called%1000000,
			//   32       33             34              35
	        MOScaller, MOScalled, StdSizePack_caller, StdSizePack_called);

#else

// 1begin, 2end, 3callID, 4caller_port, 5called_port,
// 6ip_caller, 7ip_called,
// 8caller_mediatype, 9called_mediatype,10raw_callerFile,11raw_calledFile,
// 12npack_caller, 13npack_called, 14caller_nbytes, 15called_nbytes,
// 16thrbytes_caller
// 17thrbytes_called,
// 18thrpack_caller,
// 19thrpack_called,
// 20ratio_loss_caller,
// 21ratio_loss_called,
// 22avgpacketsize_caller,
// 23avgpacketsize_called,
// 24avginterarr_caller,
// 25avginterarr_called,
// 26maxinterarr_caller, 27maxinterarr_called,
// 28mininterarr_caller, 29mininterarr_called,
// 30dur_caller, 31dur_called
// 32MOS_caller, 33MOS_called, 34std_packsize_caller, 35std_packsize_called, 36pcap_RTCP

	fprintf(RTCP_records,
	        //    1            2        3   4   5   6   7   8   9  10  11  12  13      14
	        "%" PRIu64 "\t%" PRIu64 "\t%s\t%u\t%u\t%s\t%s\t%u\t%u\t%s\t%s\t%u\t%u\t%" PRIu64
	        //   15         16  17  18  19  20  21  22  23  24  25  26  27  28  29     30
	        "\t%" PRIu64 "\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%f\t%" PRIu64
	        //     31             32            33      34  35  36  37  38
	        ".%06" PRIu64 "\t%" PRIu64 ".%06" PRIu64 "\t%f\t%f\t%f\t%f\t%s\n",

			// 1   2     3                4                     5                    6
	        begin,end,session->callID,session->caller.port,session->called.port,int2ip(&(session->caller.IP),IP3),
	        // 7                                 8                        9                         10
	        int2ip(&(session->called.IP),IP4),session->caller.media_type,session->called.media_type,raw_caller_fname,
	        // 11                 12                      13                   14                    15
	        raw_called_fname, session->caller.npack,session->called.npack,session->caller.nbytes,session->called.nbytes,
	        // 16
	        (duracion_caller==0?-1:(double)session->caller.nbytes/(session->caller.end-session->caller.begin)*1000000),
	        // 17
	        (duracion_called==0?-1:(double)session->called.nbytes/(session->called.end-session->called.begin)*1000000),
	        // 18
	        (duracion_caller==0?-1:(double)session->caller.npack/(session->caller.end-session->caller.begin)*1000000),
	        // 19
	        (duracion_called==0?-1:(double)session->called.npack/(session->called.end-session->called.begin)*1000000),
	        // 20
	        (session->caller.npack==0?-1:(double)session->caller.lost_packet/(session->caller.npack+session->caller.lost_packet)),
	        // 21
	        (session->called.npack==0?-1:(double)session->called.lost_packet/(session->called.npack+session->called.lost_packet)),
	        // 22
	        (session->caller.npack==0?-1:(double)session->caller.nbytes/session->caller.npack),
	        // 23
	        (session->called.npack==0?-1:(double)session->called.nbytes/session->called.npack),
	        // 24                                                    25
	        avg(session->caller.sum_int_time,session->caller.npack), avg(session->called.sum_int_time,session->called.npack),
	        // 26                         27                            28
	        session->caller.max_int_time, session->called.max_int_time, session->caller.min_int_time,
	        // 29                         30                       30                       31
	        session->called.min_int_time, duracion_caller/1000000, duracion_caller%1000000, duracion_called/1000000,
	        // 31                    32         33         34                  35                  36
	        duracion_called%1000000, MOScaller, MOScalled, StdSizePack_caller, StdSizePack_called, RTCP_pcap_fname);

#endif
	fflush(RTCP_records);

	}

	releaseRTCPSession(session);
}

void exportMultimediaDataC(char * raw_file, char * paq_file, CallInfoC * direction) {

	// File pointers & descriptors
	FILE * paq_file_p = NULL;
	int fd_raw = 0;
	int fd_paq = 0;

#ifndef _USE_CB_

	int i = 0, n_pckt = 0;
#endif

	// Open caller RAW file
	fd_raw = open(raw_file,O_WRONLY|O_APPEND|O_CREAT,(mode_t)0777);

	if (fd_raw < 0) {

		sprintf(log_message_aux,
				"Error opening file %s, with RAW audio data",
				raw_file);
		printLogMessage(log_message_aux, error_log_f);
		return;
	}

	// Open caller paq file
	fd_paq = open(paq_file,O_WRONLY|O_APPEND|O_CREAT,(mode_t)0777);

	if (fd_paq < 0) {
		sprintf(log_message_aux,
				"Error opening file %s, with audio packets information",
				paq_file);
		printLogMessage(log_message_aux, error_log_f);
		return;
	}

	paq_file_p = fdopen(fd_paq, "w");


#ifdef _USE_CB_
	exportCB2file(direction->first,
	              fd_raw,
	              paq_file_p);
	direction->first = NULL;
	direction->last = NULL;

#else

	// Write RAW
	if (write(fd_raw,direction->payload,direction->offset) != direction->offset) {

		sprintf(log_message_aux,
				"Error writing file %s, with RAW audio data",
				raw_file);
		printLogMessage(log_message_aux, error_log_f);
		return;
	}

	// Write paq
	n_pckt = MIN(direction->npack_rtcp_inserted,MAX_NUM_PACK);

	for (i=0;i<n_pckt;i++) {
		fprintf(paq_file_p,"%d %d %d\n", direction->payload_packet_sizes[i],
		                                 direction->media_types[i],
		                                 direction->payload_packet_ts[i]);
	}
#endif

	close(fd_raw);
	fclose(paq_file_p);
	close(fd_paq);

}

float calculateMOSRTCP(double lostPackRate, uint8_t mediaType) {

	float retMOS = 0;
	double bpl = 0;
	double ie = 0;
	double ie_eff = 0;
	double rlq = 0;

	if ((lostPackRate < 1) && (lostPackRate >= 0)) {

		if (mediaType == 18) {
			// 729
			bpl = 17;
			ie = 10;
		} else {
			// 711 PCMU & PCMA and others
			bpl = 10;
			ie = 0;
		}

		ie_eff = (ie + (95.0 - ie) * (lostPackRate*100) / ((lostPackRate*100) + bpl));
		rlq = (93.2 - ie_eff);
		retMOS = (0.78 + rlq * 0.035 + rlq * (100 - rlq) * (rlq - 60) * 0.000007);

		if (retMOS < 1) {
			return 1;
		} else {
			return retMOS;
		}
	}

	return 1;
}

int initRTCPModule(config_t * cfg_f) {

	int ret = OK_RTCP;

	if (cfg_f) {
		/* Get parameters by name */
		if (config_lookup_int(cfg_f, "MAX_RTCP_TABLE_SIZE", &MAX_RTCP_TABLE_SIZE)) {

			sprintf(log_message_aux,
					"INFO: MAX_RTCP_TABLE_SIZE: %"PRIu64"",
					MAX_RTCP_TABLE_SIZE);
			printLogMessage(log_message_aux, log_f);

		} else {

			sprintf(log_message_aux,
					"INFO: No 'MAX_RTCP_TABLE_SIZE' setting in configuration file. Using default value (%"PRIu64")",
					MAX_RTCP_TABLE_SIZE);
			printLogMessage(log_message_aux, log_f);
		}

		if (config_lookup_int(cfg_f, "MAX_POOL_RTCP_FLOW", &MAX_POOL_RTCP_FLOW)) {

			sprintf(log_message_aux,
					"INFO: MAX_POOL_RTCP_FLOW: %"PRIu64"",
					MAX_POOL_RTCP_FLOW);
			printLogMessage(log_message_aux, log_f);

		} else {

			sprintf(log_message_aux,
					"INFO: No 'MAX_POOL_RTCP_FLOW' setting in configuration file. Using default value (%"PRIu64")",
					MAX_POOL_RTCP_FLOW);
			printLogMessage(log_message_aux, log_f);
		}
	} else {
			sprintf(log_message_aux,
					"INFO: No configuration file. Using default value for 'MAX_RTCP_TABLE_SIZE' (%"PRIu64")",
					MAX_RTCP_TABLE_SIZE);
			printLogMessage(log_message_aux, log_f);

			sprintf(log_message_aux,
					"INFO: No configuration file. Using default value for 'MAX_POOL_RTCP_FLOW' (%"PRIu64")",
					MAX_POOL_RTCP_FLOW);
			printLogMessage(log_message_aux, log_f);
	}

    RTCP_ts_data_file = fopen("RTCP_ts_calls.dat","w");

    if (RTCP_ts_data_file == NULL) {

		printLogMessage("Error: can't open RTCP ts file", error_log_f);
		ret = ERR_RTCP_FILE;
	} else {

	    fprintf(RTCP_ts_data_file,"%%1Timestamp,2RTCPStructures,3NewConnections\n");
	}

	allocRTCPSessionPool();
	return ret;
}

//void jitter(struct pcap_pkthdr *h, Jtr * jitrtcp){
	
	//node_l *n = NULL,*naux = NULL;
	//node_l *current_node_session_table = NULL;
	//RTCPSession *current_session = NULL;
	//pcaprec_hdr_tc hdr;
	//hdr.ts_sec=h->ts.tv_sec;  //timestamp segundos  
	//hdr.ts_usec=h->ts.tv_usec;   //timestamp milisegundos
	//uint64_t t_usec = ToUInt64(hdr.ts_usec);
	//uint64_t t_sec = ToUInt64(hdr.ts_sec);
	//jitrtcp->timestamp_actual =t_sec* 1000000 +t_usec;  

	//current_node_session_table=(node_l*)n->data;
	//current_session=(RTCPSession*)current_node_session_table->data;
	//jitrtcp->last_time_packet_arrive=MAX((current_session->caller).end, (current_session->called).end);

	//if(jitrtcp->Num == 0){
		//jitrtcp->D= 0 ;
		//jitrtcp->J=0;
		//jitrtcp->last_time_packet_arrive_anterior=jitrtcp->last_time_packet_arrive;
		//jitrtcp->timestamp_anterior = jitrtcp->timestamp_actual; 
	//}
	//else{
		//jitrtcp->D= (jitrtcp->last_time_packet_arrive - jitrtcp->timestamp_actual) - (jitrtcp->last_time_packet_arrive_anterior - jitrtcp->timestamp_anterior);
		//jitrtcp->J=jitrtcp->Jant+(abs(jitrtcp->D) - jitrtcp->Jant)/16;
		//jitrtcp->Jant = jitrtcp->J;
		//jitrtcp->last_time_packet_arrive_anterior=jitrtcp->last_time_packet_arrive;
		//jitrtcp->timestamp_anterior = jitrtcp->timestamp_actual; 
	//}
	//jitrtcp->Jfinal += jitrtcp->J;
//}




