
#include "RTPTracker.h"
#include "RTPSession.h"

#include<stdio.h>
 
#include<string.h>

#include <time.h>

extern uint32_t lspacket;
extern uint32_t lspacketc;

//************************************************************
// Mem. control variables
//************************************************************

int i2=0;
FILE *fp;

uint64_t  nrtps = 0;

uint32_t result;

uint64_t total_structures_SIP=0;
uint64_t used_structures_SIP=0;
uint64_t lost_SIP=0;

uint64_t total_structures_RTP=0;
uint64_t used_structures_RTP=0;
uint64_t lost_RTP=0;

uint64_t total_structures_RTCP=0;
uint64_t used_structures_RTCP=0;
uint64_t lost_RTCP=0;

uint64_t total_structures_TCPA=0;
uint64_t used_structures_TCPA=0;

uint64_t total_structures_IPFRAG = 0;
uint64_t used_structures_IPFRAG = 0;

#ifdef _USE_SKINNY_
uint64_t total_structures_SKINNY = 0;
uint64_t used_structures_SKINNY = 0;
uint64_t lost_SKINNY=0;
#endif

#ifdef _USE_UNISTIM_
uint64_t total_structures_UNISTIM = 0;
uint64_t used_structures_UNISTIM = 0;
uint64_t lost_UNISTIM=0;
#endif

uint64_t total_nodes=0;
uint64_t used_nodes=0;

uint64_t n_pack = 0;

//************************************************************
// Counters
//************************************************************
uint64_t count_num_bytes = 0;
uint64_t count_num_pckt = 0;
uint64_t count_num_pckt_rtcp = 0;
uint64_t count_num_sr = 0;
uint64_t count_num_ds = 0;
uint64_t invite_num = 0;

int pqsender = 0;
int pqreceiver = 0;

unsigned int ret = 0;
uint64_t llamadas_insertadas = 0;
uint64_t llamadas_activadas = 0;
uint64_t llamadas_insertadas_rechazadas = 0;
uint64_t llamadas_activadas_rechazadas = 0;

//************************************************************
// Output-file pointers
//************************************************************

FILE *SIP_records = NULL;
FILE *RTP_records = NULL;
FILE *RTCP_records = NULL;

#ifdef _USE_SKINNY_
FILE * SKINNY_call_records = NULL;
FILE * SKINNY_connection_records = NULL;
#endif

#ifdef _USE_UNISTIM_
FILE * UNISTIM_call_records = NULL;
#endif

FILE *list_pcaps = NULL;
char directory[100];

//************************************************************
// Timestamps
//************************************************************
uint64_t last_packet_timestamp = 0;
uint64_t first_packet_timestamp = 0;
uint64_t prev_timestamp = 0;
double sum_of_differences = 0.0;
double sum_of_differences_ds = 0.0;
double av_jitter = 0.0;
double av_jitter_ds = 0.0;
uint64_t last_timep;
uint64_t last_timep_ds;

//************************************************************
// Expiration times
//************************************************************
uint64_t expiration_RTCP_time = 15000000;       //DUDA
uint64_t expiration_RTP_time = 15000000;       // Default
uint64_t expiration_SIP_time = 300000000;      // Default

#ifdef _USE_SKINNY_
uint64_t expiration_SKINNY_time = 300000000;   // Default
#endif

#ifdef _USE_UNISTIM_
uint64_t expiration_UNISTIM_time = 300000000;  // Default
#endif

extern char log_message_aux[1000];

//************************************************************
// Aux pointers
//************************************************************
SIPSession *SIP_aux_session = NULL;

#ifdef _USE_SKINNY_
SKINNYSession * SKINNY_aux_session = NULL;
#endif

RTPSession *rtpsession = NULL;
RTCPSession *rtcpsession = NULL;

#ifdef _USE_UNISTIM_
UNISTIMSession * UNISTIM_aux_session = NULL;
#endif

//************************************************************
// Stats variables
//************************************************************
uint64_t bytesventana = 0;
uint64_t packetsventana = 0;
uint64_t muestras = 0;
uint64_t num_traces = 0;
uint64_t jittersenderfin = 0; 
uint64_t jitterreceiverfin = 0;
double jtr;
double previousJitter = 0.0;
char ipaddress[16];

//************************************************************
// Date variables
//************************************************************
char globalDate[40];

//************************************************************
// Static aux variables
//************************************************************
node_l static_node;
RTPSession rtpsession_static;
RTCPSession rtcpsession_static;
SIPSession sipsession_static;

#ifdef _USE_SKINNY_
SKINNYSession skinnysession_static;
#endif

//************************************************************
// Conf parameters
//************************************************************
char recolectar_RAW = '0';
char mode;
int sock1 = 0;
char flag_while = 0;
uint8_t flag_30_sec = 0;
uint8_t hdrLinkLen = 14;
//pcap_t *p;
pcap_t * p_live = NULL;
NDLTdata_t *p = NULL;
char *map;
char format[100] = "pcap";

FILE * aux_error_log_f = NULL, * aux_log_f = NULL;
FILE * error_log_f = NULL, * log_f = NULL;

struct tpacket_req req;
struct iovec *ring;

char aux_final_pcap_path[256], aux_final_audio_path[256];
char *final_pcap_path = aux_final_pcap_path, *final_audio_path = aux_final_audio_path;

char bpf_filter_str[20000] = {0};

// Flags to control present arguments
char flag_format = 0, flag_input = 0, flag_output = 0, flag_path = 0, flag_conf = 0, flag_log_f = 0, flag_log_f_err = 0, flag_debug = '0', flag_bpf = 0;

//************************************************************
// Functions
//************************************************************
void getCurrentDate();
char isMemmoryFull();
uint32_t receptor_file(char *file);
uint32_t receptor_file_live(char *interfaz);
int createSocketRawRx1(char *interfaz);
uint32_t receptor ();
void freeResources();
void process_packet(uint8_t * bp, struct pcap_pkthdr * h);
void cleanHandler(uint64_t packetTimestamp);

#ifdef _USE_UTCPA_
TCPSession * aux_TCP_ress = NULL;
#else
TCPSession aux_TCP_ress_struct;
TCPSession * aux_TCP_ress = &aux_TCP_ress_struct;
#endif

extern uint16_t vlan[2];
extern int n_vlan;

struct timeval init_p, end_p;

//************************************************************
// Input - output files information
//************************************************************
char out_name_file[5000];
char argv_7[5000];
char argv_5[5000];
char argv_2[5000];
char out_name_file_sip[5000];
char *auxiliar;
char out_name_file_rtp[5000];
char out_name_file_rtcp[5000];

#ifdef _USE_SKINNY_
char out_name_file_skinny_calls[5000];
#ifdef _STRICT_CONNECTION_CHECK_
char out_name_file_skinny_connections[5000];
#endif
#endif

#ifdef _USE_UNISTIM_
char out_name_file_unistim_calls[5000];
#endif

char pcap_to_read[5000];
char pcap_to_move[5000];
char pcap_to_read_with_path[5000];

struct stat st;
config_t cfg;

#ifdef _PRINT_STR_SIZES_
void printSizes() {

	sprintf(log_message_aux,
		    "INFO: Node Size: %lu",
		    sizeof(node_l));
	printLogMessage(log_message_aux, log_f); //DUDA logs

	sprintf(log_message_aux,
		    "INFO: RTP Size: %lu",
		    sizeof(RTPSession));
	printLogMessage(log_message_aux, log_f);


	sprintf(log_message_aux,
		    "INFO: SIP Size: %lu",
		    sizeof(SIPSession));
	printLogMessage(log_message_aux, log_f);

#ifdef _USE_SKINNY_
	sprintf(log_message_aux,
		    "INFO: SKINNY Size: %lu",
		    sizeof(SKINNYSession));
	printLogMessage(log_message_aux, log_f);
#endif

#ifdef _USE_UNISTIM_
	sprintf(log_message_aux,
		    "INFO: UNISTIM Size: %lu",
		    sizeof(UNISTIMSession));
	printLogMessage(log_message_aux, log_f);
#endif

	sprintf(log_message_aux,
		    "INFO: TCPA Size: %lu",
		    sizeof(Frag_tcp_packet));
	printLogMessage(log_message_aux, log_f);

	sprintf(log_message_aux,
		    "INFO: IPA Size: %lu",
		    sizeof(Frag_ip_packet));
	printLogMessage(log_message_aux, log_f);

	sprintf(log_message_aux,
		    "INFO: CB Size: %lu",
		    sizeof(CallBuffer));
	printLogMessage(log_message_aux, log_f);
}
#endif

void freeResources() {

	sprintf(log_message_aux,
		    "INFO: LOST SIP messages: %"PRIu64"",
		    lost_SIP);
	printLogMessage(log_message_aux, log_f);

#ifdef _USE_SKINNY_
	sprintf(log_message_aux,
		    "INFO: LOST SKINNY messages: %"PRIu64"",
		    lost_SKINNY);
	printLogMessage(log_message_aux, log_f);
#endif

#ifdef _USE_UNISTIM_
	sprintf(log_message_aux,
		    "INFO: LOST UNISTIM messages: %"PRIu64"",
		    lost_UNISTIM);
	printLogMessage(log_message_aux, log_f);
#endif

	sprintf(log_message_aux,
		    "INFO: LOST RTP messages: %"PRIu32"",
		    lspacket);
	printLogMessage(log_message_aux, log_f);

	sprintf(log_message_aux,
		    "INFO: LOST RTCP messages: %"PRIu32"",
		    result);
	printLogMessage(log_message_aux, log_f);


	sprintf(log_message_aux,
		    "INFO: Average Delay: %.2f ms",
		    av_jitter);
	printLogMessage(log_message_aux, log_f);

	sprintf(log_message_aux,
		    "INFO: Número de paquetes: %"PRIu64"",
		    count_num_pckt);
	printLogMessage(log_message_aux, log_f); 

	sprintf(log_message_aux,
		    "INFO: Número de paquetes RTP: %"PRIu64"",
		    nrtps);
	printLogMessage(log_message_aux, log_f); 

	sprintf(log_message_aux,
		    "INFO: Número de paquetes RTCP: %"PRIu64"",
		    count_num_pckt_rtcp);
	printLogMessage(log_message_aux, log_f); 

	if(pqsender != 0){
		sprintf(log_message_aux,
		    	"INFO: Jitter sender RTCP: %"PRIu64"",
		    	jittersenderfin/pqsender);
		printLogMessage(log_message_aux, log_f); 
	}

	if(pqreceiver != 0){
		sprintf(log_message_aux,
			"INFO: Jitter receiver RTCP: %"PRIu64"",
		    	jitterreceiverfin/pqreceiver);
		printLogMessage(log_message_aux, log_f); 
	}

	if (flag_conf) config_destroy(&cfg);

	if (SIP_aux_session != NULL) {
		releaseSIPSession(SIP_aux_session);
	}

	if (SIP_records != NULL) {
		fclose(SIP_records);
		SIP_records = NULL;
	}

	if (RTP_records != NULL) {
		fclose(RTP_records);
		RTP_records = NULL;
	}

	if (RTCP_records != NULL) {
		fclose(RTCP_records);
		RTCP_records = NULL;
	}

#ifdef _USE_SKINNY_
	if (SKINNY_call_records != NULL) {
		fclose(SKINNY_call_records);
		SKINNY_call_records = NULL;
	}

	if (SKINNY_connection_records != NULL) {
		fclose(SKINNY_connection_records);
		SKINNY_connection_records = NULL;
	}
#endif

#ifdef _USE_UNISTIM_

	if (UNISTIM_call_records != NULL) {
		fclose(UNISTIM_call_records);
		UNISTIM_call_records = NULL;
	}
#endif


	if (list_pcaps != NULL) {
		fclose(list_pcaps);
		list_pcaps = NULL;
	}

	getCurrentDate();

	printLogMessage("INFO: End of execution", log_f);
	printLogMessage("INFO: Liberating resources...", log_f);
	printLogMessage("INFO: Liberating segmented messages pools...", log_f);
	freeSIPFragPacket();
#ifdef _USE_UTCPA_
	freeTCPSessionPool();
#endif
	printLogMessage("INFO: Liberating IP-fragment pool...", log_f);
	freeIPFragPacket();

	printLogMessage("INFO: Liberating session pools...", log_f);

	freeSIPSessionPool();

#ifdef _USE_SKINNY_
	freeSKINNYSessionPool();
#endif

	freeRTPSessionPool();

	freeRTCPSessionPool();

#ifdef _USE_UNISTIM_
	freeUNISTIMSessionPool();
#endif

#ifdef _USE_CB_
	freeCallBufferPool();
#endif

	printLogMessage("INFO: Liberating node pool...", log_f);
	freeNodelPool();

	printLogMessage("INFO: Closing log files...", log_f);
	if (flag_log_f) {fclose(log_f); log_f = stdin;}
	if (flag_log_f_err) {fclose(error_log_f); error_log_f = stderr;}
}

//************************************************************
void capturaSenial (int nSenial) {

	printLogMessage("INFO: Signal captured", log_f);

	last_packet_timestamp = INFINITO;
	cleanup_SIP ();
	cleanup_RTP ();
	cleanup_RTCP ();

#ifdef _USE_SKINNY_
	cleanup_SKINNY();
#endif

#ifdef _USE_UNISTIM_
	cleanup_UNISTIM();
#endif

	cleanup_connections();
	cleanup_IPFragments ();

	freeResources();

	exit(OK);
}

void printHelp(char *argv[]) {

	printf("\n%s\n\n", argv[0]);
	printf("\t-f, --format: Format of input and mode of execution. Available options:\n");
	printf("\t\t0 Read from interface (Raw sockets)\n\t\t1 Read from traffic file\n\t\t2 Read from folder\n\t\t3 Read from a list\n\t\t4 Read from interface (using libpcap)\n\t\t5 Read from list (using NDlee. API)\n\n");
	printf("\t-i, --input: Input name (without path)\n\n");
	printf("\t-s, --time-signaling: SIGNALING expiration time (s)\n\n");
	printf("\t-m, --time-multimedia: Multimedia connections expiration time (s)\n\n");
	printf("\t-o, --output: Output PATH\n\n");
	printf("\t-w, --save-multimedia: Save multimedia raw data. Available options:\n");
	printf("\t\t0 No (Default)\n\t\t1 Yes\n\n");
	printf("\t-p, --input-path: Input path\n\n");
	printf("\t-t, --input-format: Input format for traffic files. Available options:\n\t\tpcap\n\t\traw\n\n");
	printf("\t-c, --configuration-file: File (with path) with configuration parameters\n\n");
	printf("\t-e, --error-log: File to export error logs\n\n");
	printf("\t-l, --info-log: File to export informative logs\n\n");
	printf("\t-d, --save-pcap: Save signaling pcap files. Available options:\n");
	printf("\t\t0 No (Default)\n\t\t1 Yes\n\n");
	printf("\t-b, --filet: BPF filter\n\n");
	printf("\t-h, --help: Print this help and exit\n\n");
	printf("\tSorry, no verbose option ;)\n\n");

	freeResources();
	exit(OK);
}


void readArguments(int argc, char *argv[]) {

	error_log_f = stderr;     // Default
	log_f = stdout;           // Default
	char c;

	static struct option options[] = {
		{"format",required_argument,0,'f'},
		{"input",required_argument,0,'i'},
		{"time-signaling",required_argument,0,'s'},
		{"time-multimedia",required_argument,0,'m'},
		{"time-control",required_argument,0,'q'},
		{"output",required_argument,0,'o'},
		{"save-multimedia",required_argument,0,'w'},
		{"input-path",required_argument,0,'p'},
		{"input-format",required_argument,0,'t'},
		{"configuration-file",required_argument,0,'c'},
		{"error-log",required_argument,0,'e'},
		{"info-log",required_argument,0,'l'},
		{"save-pcap",required_argument,0,'d'},
		{"filter",required_argument,0,'b'},
		{"help",no_argument,0,'h'},
		{0,0,0,0}
	};

	while ((c = getopt_long(argc, argv, "f:i:s:m:o:w:p:t:c:e:l:d:b:h", options, NULL)) != -1) {

		if (c == 255) break;

		switch (c) { //DUDA AÑADIR CASO PARA RTCP SI ES ASI COMO LLAMARLO EN LA ESTRUCTURA OPTIONS

			case 'f':

				flag_format = 1;
				mode = atoi(optarg);
				break;

			case 'i':

				flag_input = 1;
				argv_2[0]=0;
				strcat(argv_2,optarg);
				break;

			case 's':

				expiration_SIP_time=1000000*atol(optarg);
				break;

			case 'm':

				expiration_RTP_time=1000000*atol(optarg);
				break;

			case 'q':

				expiration_RTCP_time=1000000*atol(optarg);
				break;

			case 'o':

				flag_output = 1;
				argv_5[0]=0;
				strcpy(directory,optarg);
				strcat(argv_5,optarg);
				//strcat(argv_5,"/records/");
				break;

			case 'w':

				recolectar_RAW=optarg[0];
				break;

			case 'p':

				flag_path = 1;
				argv_7[0]=0;
				strcat(argv_7,optarg);
				break;

			case 't':

				strcpy(format,optarg);
				break;

			case 'c':

				flag_conf = 1;

				config_init(&cfg);
				if (!config_read_file(&cfg, optarg)) {

					sprintf(log_message_aux,
					        "ERROR: %d -- %s", config_error_line(&cfg), config_error_text(&cfg));

					printLogMessage(log_message_aux, error_log_f);
					config_destroy(&cfg);
					exit(ERROR);
				}

				break;

			case 'e':

				flag_log_f_err = 1;

				if (!(aux_error_log_f = fopen(optarg,"w"))) {

					printLogMessage("ERROR: can't open new error log file", error_log_f);
					exit(ERROR);

				}	else {

					printLogMessage("INFO: redirecting error log file", log_f);
					error_log_f = aux_error_log_f;
				}

				break;

			case 'l':

				flag_log_f = 1;

				if (!(aux_log_f = fopen(optarg,"w"))) {

					printLogMessage("ERROR: can't open new log file", error_log_f);
					exit(ERROR);

				}	else {

					printLogMessage("INFO: redirecting log file", log_f);
					log_f = aux_log_f;
				}

				break;

			case 'd':

				flag_debug=optarg[0];
				break;

			case 'b':
				strcpy(bpf_filter_str,optarg);
				flag_bpf = 1;
				break;

			case 'h':

				printLogMessage("INFO: Printing help", log_f);
				printHelp(argv);
				exit(OK);
				break;

			case '?' :
				printLogMessage("ERROR: Bad execution", error_log_f);
				printHelp(argv);
				exit(ERROR);
				break;

			default:
				printLogMessage("ERROR: Bad execution", error_log_f);
				printHelp(argv);
				exit(ERROR);
				break;
		}
	}

	if (!(flag_format && flag_input && flag_output && flag_path)) {

		printLogMessage("ERROR: mode, input, input path, output path and configuration file are compulsory!", error_log_f);
		printHelp(argv);
		exit(ERROR);
	}
}

//************************************************************
int main (int argc, char *argv[]) {

	readArguments(argc,argv);

#ifdef _PRINT_STR_SIZES_

	printSizes();

#endif

	if (flag_debug == '1') printLogMessage("INFO: Signaling traces will be saved", log_f);

	if (flag_bpf) {

		sprintf(log_message_aux,
				"INFO: BPF filter: %s",
				bpf_filter_str);
		printLogMessage(log_message_aux, error_log_f);
	}

	printLogMessage("INFO: Registering signal handler", log_f);
	signal (SIGINT, capturaSenial);

	umask(0);

	sprintf(log_message_aux,
		    "INFO: Input format: %s",
		    format);
	printLogMessage(log_message_aux, log_f);

#ifdef _USE_SKINNY_
	expiration_SKINNY_time = expiration_SIP_time;
#endif

#ifdef _USE_UNISTIM_
	expiration_UNISTIM_time = expiration_SIP_time;
#endif

	out_name_file[0]=0;
	strcat(out_name_file,argv_5);
	strcat(out_name_file,"/records/");

	if(stat(out_name_file,&st) != 0) {

		sprintf(log_message_aux,
				"INFO: %s directory is not present and required! I am creating it.",
				out_name_file);
		printLogMessage(log_message_aux, error_log_f);

		mkdir(out_name_file, O_CREAT|(mode_t)0777);
//		freeResources();
//		exit(ERROR);
	}

    // Initizalizing output file names
	strcat(out_name_file,argv_2);
	out_name_file_rtp[0] = 0;
	strcat(out_name_file_rtp, out_name_file);
	strcat(out_name_file_rtp, "-RTPrecords.dat"); //File to RTPs

	out_name_file_rtcp[0] = 0;
	strcat(out_name_file_rtcp, out_name_file);
	strcat(out_name_file_rtcp, "-RTCPrecords.dat"); 

#ifdef _USE_SKINNY_
    out_name_file_skinny_calls[0]=0;
#ifdef _STRICT_CONNECTION_CHECK_
    out_name_file_skinny_connections[0]=0;
#endif

	strcat(out_name_file_skinny_calls,out_name_file);
	strcat(out_name_file_skinny_calls,"-SKINNYCalls.dat");             //File to SkinnyCalls

#ifdef _STRICT_CONNECTION_CHECK_
	strcat(out_name_file_skinny_connections,out_name_file);
	strcat(out_name_file_skinny_connections,"-SKINNYConnections.dat"); //File to SkinnyConnections
#endif
#endif

	strcat(out_name_file_sip,out_name_file);
	strcat(out_name_file_sip,"-SIPrecords.dat");

#ifdef _USE_UNISTIM_
	strcat(out_name_file_unistim_calls,out_name_file);
	strcat(out_name_file_unistim_calls,"-UNISTIMCalls.dat");             //File to UNISTIMCalls
#endif

	if ((SIP_records = fopen (out_name_file_sip, "w")) == NULL) {

		sprintf(log_message_aux,
				"ERROR: can't open file %s",
				out_name_file);
		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(ERROR);
	}

	if ((RTP_records = fopen (out_name_file_rtp, "w")) == NULL) {

		sprintf(log_message_aux,
				"ERROR: can't open file %s",
				out_name_file_rtp);
		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(ERROR);
	}

	if ((RTCP_records = fopen (out_name_file_rtcp, "w")) == NULL) {

		sprintf(log_message_aux,
				"ERROR: can't open file %s",
				out_name_file_rtcp);
		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(ERROR);
	}

#ifdef _USE_SKINNY_
	if ((SKINNY_call_records = fopen(out_name_file_skinny_calls, "w")) == NULL) {

		sprintf(log_message_aux,
				"ERROR: can't open file %s",
				out_name_file_skinny_calls);
		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(ERROR);
	}

#ifdef _STRICT_CONNECTION_CHECK_
	if ((SKINNY_connection_records = fopen(out_name_file_skinny_connections, "w")) == NULL) {

		sprintf(log_message_aux,
				"ERROR: can't open file %s",
				out_name_file_skinny_connections);
		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(ERROR);
	}
#endif
#endif

#ifdef _USE_UNISTIM_
	if ((UNISTIM_call_records = fopen(out_name_file_unistim_calls, "w")) == NULL) {

		sprintf(log_message_aux,
				"ERROR: can't open file %s",
				out_name_file_unistim_calls);
		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(ERROR);
	}
#endif

	out_name_file[0]=0;
	strcat(out_name_file,argv_5);
	strcat(out_name_file,"/");
	strcat(out_name_file,"RAW/\0");

	mkdir(out_name_file, O_CREAT|(mode_t)0777);

	getCurrentDate();

	printLogMessage("INFO: Starting execution...", log_f);

	(flag_conf) ? readPathconfiguration(&cfg,&(final_pcap_path),&(final_audio_path)) : readPathconfiguration(NULL,&(final_pcap_path),&(final_audio_path));

	printLogMessage("INFO: Allocating resources...", log_f);

	(flag_conf) ? initSIPModule(&cfg) : initSIPModule(NULL);
	(flag_conf) ? initRTPModule(&cfg) : initRTPModule(NULL);
	(flag_conf) ? initRTCPModule(&cfg) : initRTCPModule(NULL);

#ifdef _USE_SKINNY_
	(flag_conf) ? initSKINNYModule(&cfg) : initSKINNYModule(NULL);
#endif

#ifdef _USE_UNISTIM_
	allocUNISTIMSessionPool();
#endif

	(flag_conf) ? initListModule(&cfg) : initListModule(NULL);
#ifdef _USE_UTCPA_
	(flag_conf) ? initTCPSessionModule(&cfg) : initTCPSessionModule(NULL);
#endif
	(flag_conf) ? initTCPAModule(&cfg) : initTCPAModule(NULL);
	(flag_conf) ? initIPAModule(&cfg) : initIPAModule(NULL);

#ifdef _USE_CB_
	if (recolectar_RAW == '1') {
		(flag_conf) ? initCBModule(&cfg) : initCBModule(NULL);
	}
#endif

	printLogMessage("INFO: Resources allocated!", log_f);

	if(mode == 0) {

		if(createSocketRawRx1(argv_2) == -1) {
			freeResources();
			exit(ERROR);
		}

		if (receptor() == ERROR) {

			printLogMessage("ERROR: can't receive from interface", error_log_f);
		}

		struct tpacket_stats st;
		int len = sizeof(struct tpacket_stats);
		getsockopt(sock1,SOL_PACKET,PACKET_STATISTICS,(char *)&st,(socklen_t*)&len);
	}

	else if((mode == 1) || (mode == 5)){

		out_name_file[0] = 0;
		strcat(out_name_file,argv_7);
		strcat(out_name_file,"/");
		strcat(out_name_file,argv_2);

		sprintf(log_message_aux,
				"INFO: pcap to read: %s",
				out_name_file);
		printLogMessage(log_message_aux, log_f);

		if (receptor_file(out_name_file) != OK) {

			sprintf(log_message_aux,
					"ERROR: pcap file not found: %s",
					out_name_file);
			printLogMessage(log_message_aux, error_log_f);
			freeResources();
			exit(ERROR);
		}

	} else if (mode == 2) {

		struct stat st;
		out_name_file[0]=0;

		strcat(out_name_file,argv_7);
		strcat(out_name_file,"/");

		if (stat(strcat(out_name_file,"analizadas"),&st) != 0) {

			sprintf(log_message_aux,
					"INFO: %s is not present and required for mode 2! I am creating it",
					out_name_file);
			printLogMessage(log_message_aux, log_f);
			mkdir(out_name_file, O_CREAT|(mode_t)0777);
//			freeResources();
//			exit(ERROR);
		}

		while (flag_while == 0) {

			out_name_file[0]=0;
			pcap_to_read[0]=0;
			pcap_to_move[0]=0;
			pcap_to_read_with_path[0]=0;

			strcat(out_name_file,argv_7);
			strcat(out_name_file,"/");

			auxiliar = get2oldest (out_name_file,&pcap_to_read[0]);

			if (auxiliar == NULL) {

				printLogMessage("ERROR: can't get pcap to read", error_log_f);
				freeResources();
				exit(ERROR);
			}

			if (pcap_to_read[0] == 0) {
				sleep(1);

			} else {

				if (SIP_records != NULL) {
					fclose(SIP_records);
					SIP_records = NULL;
				}

				if (RTP_records != NULL) {
					fclose(RTP_records);
					RTP_records = NULL;
				}

				if (RTCP_records != NULL) {
					fclose(RTCP_records);
					RTCP_records = NULL;
				}

#ifdef _USE_SKINNY_
				if (SKINNY_call_records != NULL) {
					fclose(SKINNY_call_records);
					SKINNY_call_records = NULL;
				}
#ifdef _STRICT_CONNECTION_CHECK_
				if (SKINNY_connection_records != NULL) {
					fclose(SKINNY_connection_records);
					SKINNY_connection_records = NULL;
				}
#endif
#endif
				num_traces++;
				out_name_file_rtp[0]=0;
				out_name_file_rtcp[0]=0;

#ifdef _USE_SKINNY_
				out_name_file_skinny_calls[0]=0;
#ifdef _STRICT_CONNECTION_CHECK_
				out_name_file_skinny_connections[0]=0;
#endif
#endif
				out_name_file_sip[0]=0;

				strcat(out_name_file_rtp,argv_5);
				strcat(out_name_file_rtp,"/records/");
				strcat(out_name_file_rtp,pcap_to_read);
				strcat(out_name_file_rtp,"-RTPrecords.dat");                       //File to RTPs

				strcat(out_name_file_rtcp,argv_5);
				strcat(out_name_file_rtcp,"/records/");
				strcat(out_name_file_rtcp,pcap_to_read);
				strcat(out_name_file_rtcp,"-RTCPrecords.dat");    

#ifdef _USE_SKINNY_
				strcat(out_name_file_skinny_calls,argv_5);
				strcat(out_name_file_skinny_calls,"/records/");
				strcat(out_name_file_skinny_calls,pcap_to_read);
				strcat(out_name_file_skinny_calls,"-SKINNYCalls.dat");             //File to SkinnyCalls

#ifdef _STRICT_CONNECTION_CHECK_
				strcat(out_name_file_skinny_connections,argv_5);
				strcat(out_name_file_skinny_connections,"/records/");
				strcat(out_name_file_skinny_connections,pcap_to_read);
				strcat(out_name_file_skinny_connections,"-SKINNYConnections.dat"); //File to SkinnyConnections
#endif
#endif

				strcat(out_name_file_sip,argv_5);
				strcat(out_name_file_sip,"/records/");
				strcat(out_name_file_sip,pcap_to_read);
				strcat(out_name_file_sip,"-SIPrecords.dat");

				if ((SIP_records = fopen (out_name_file_sip, "w")) == NULL) {

					sprintf(log_message_aux,
							"ERROR: Can't open output file: %s",
							out_name_file);
					printLogMessage(log_message_aux, error_log_f);
					continue;
				}

				if ((RTP_records = fopen (out_name_file_rtp, "w")) == NULL) {

					sprintf(log_message_aux,
							"ERROR: Can't open output file: %s",
							out_name_file_rtp);
					printLogMessage(log_message_aux, error_log_f);
					continue;
				}

				if ((RTCP_records = fopen (out_name_file_rtcp, "w")) == NULL) {

					sprintf(log_message_aux,
							"ERROR: Can't open output file: %s",
							out_name_file_rtcp);
					printLogMessage(log_message_aux, error_log_f);
					continue;
				}

#ifdef _USE_SKINNY_
				if ((SKINNY_call_records = fopen(out_name_file_skinny_calls, "w")) == NULL) {

					sprintf(log_message_aux,
							"ERROR: Can't open output file: %s",
							out_name_file_skinny_calls);
					printLogMessage(log_message_aux, error_log_f);
					continue;
				}

#ifdef _STRICT_CONNECTION_CHECK_
				if ((SKINNY_connection_records = fopen(out_name_file_skinny_connections, "w")) == NULL) {

					sprintf(log_message_aux,
							"ERROR: Can't open output file: %s",
							out_name_file_skinny_connections);
					printLogMessage(log_message_aux, error_log_f);
					continue;
				}
#endif
#endif

				strcat(pcap_to_read_with_path,out_name_file);
				strcat(pcap_to_read_with_path,pcap_to_read);

				sprintf(log_message_aux,
						"INFO: Pcap to read: %s",
						pcap_to_read_with_path);
				printLogMessage(log_message_aux, log_f);

#ifdef _PRINT_PROC_TIME_
gettimeofday(&init_p,NULL);
#endif

			  	if (receptor_file(pcap_to_read_with_path) == OK) {

					strcat(pcap_to_move,out_name_file);
					strcat(pcap_to_move,"analizadas/");
					strcat(pcap_to_move,pcap_to_read);

					sprintf(log_message_aux,
							"INFO: Moving %s to %s",
							pcap_to_read_with_path,pcap_to_move);
					printLogMessage(log_message_aux, log_f);
					rename(pcap_to_read_with_path,pcap_to_move);

					sprintf(log_message_aux,
							"INFO: Ended trace %"PRIu64" with %"PRIu64" packets",
							num_traces, count_num_pckt);
					printLogMessage(log_message_aux, log_f);
					count_num_pckt=0;

#ifdef _PRINT_PROC_TIME_
					gettimeofday(&end_p,NULL);
					sprintf(log_message_aux,
							"INFO: Time to proc. file: %lu",
							(end_p.tv_sec*1000000+end_p.tv_usec)-(init_p.tv_sec*1000000+init_p.tv_usec));
					printLogMessage(log_message_aux, log_f);
#endif

				} else {

					sprintf(log_message_aux,
							"ERROR: pcap file not found: %s",
							pcap_to_read_with_path);
					printLogMessage(log_message_aux, error_log_f);
					continue;
				}
			}
		}
	} else if (mode == 3) {

		out_name_file[0] = 0;
		pcap_to_read[0] = 0;
		strcat(out_name_file,argv_7);

		strcat(out_name_file,"/");
		strcat(out_name_file,argv_2);

		sprintf(log_message_aux,
				"INFO: List with the Pcap files: %s",
				out_name_file);
		printLogMessage(log_message_aux, log_f);

		list_pcaps=fopen(out_name_file,"r");

		if (list_pcaps == NULL) {

			sprintf(log_message_aux,
					"ERROR: List with the Pcap files does not exist: %s",
					out_name_file);
			printLogMessage(log_message_aux, error_log_f);
			freeResources();
			exit(ERROR);
		}

		while(fscanf(list_pcaps,"%s",pcap_to_read)>0) {

			sprintf(log_message_aux,
					"INFO: pcap to read %s",
					pcap_to_read);
			printLogMessage(log_message_aux, log_f);

#ifdef _PRINT_PROC_TIME_
gettimeofday(&init_p,NULL);
#endif
			if (receptor_file(pcap_to_read) != OK) {

				sprintf(log_message_aux,
						"ERROR: pcap file not found: %s",
						pcap_to_read);
				printLogMessage(log_message_aux, error_log_f);
				continue;
			}

#ifdef _PRINT_PROC_TIME_
gettimeofday(&end_p,NULL);

		sprintf(log_message_aux,
			    "INFO: Time to proc. file: %lu",
			    (end_p.tv_sec*1000000+end_p.tv_usec)-(init_p.tv_sec*1000000+init_p.tv_usec));
		printLogMessage(log_message_aux, log_f);

fprintf(stdout,"\n",;
#endif

		}

		fclose(list_pcaps);
		list_pcaps = NULL;

	} else if (mode == 4) { //leer desde interfaz pero API pcap

		sprintf(log_message_aux,
			    "INFO: Reading from interface: %s",
			    argv_2);
		printLogMessage(log_message_aux, log_f);

		if (receptor_file_live(argv_2) != OK) {

			sprintf(log_message_aux,
					"ERROR: Interace not found: %s",
					argv_2);
			printLogMessage(log_message_aux, error_log_f);
			freeResources();
			exit(ERROR);
		}


	} else {

		sprintf(log_message_aux,
		        "ERROR: Wrong execution mode: %d",
			    mode);

		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(ERROR);
	}
	
	////////Hacer un bucle que vaya contando los paquetes que han llegado, si el puerto del paquete es el mismo que rtcp entra y se mete en el jitter y suma +1 al Num () numero de paquetes, cuando termine dividirá el numero el jitter entre N//////

	last_packet_timestamp = INFINITO;
	cleanup_SIP ();

#ifdef _USE_SKINNY_
	cleanup_SKINNY ();
#endif

	cleanup_RTP ();
	cleanup_RTCP ();
	cleanup_connections();
	cleanup_IPFragments ();
	fclose(fp);
	freeResources();
	printLogMessage("INFO: Ending...", log_f);
	exit(OK);
}

uint32_t receptor () {

	uint32_t i=0;
	muestras=0;
	struct pcap_pkthdr hcap;
	struct pollfd pfd;
	for (i=0;;) {
		while(*(unsigned long*)ring[i].iov_base) {
			
			struct tpacket_hdr *h = ring[i].iov_base;
			unsigned char *bp = (unsigned char *)h + h->tp_mac;
			hcap.len = h->tp_len;
			hcap.ts.tv_sec = h->tp_sec;
			hcap.ts.tv_usec = h->tp_usec;
			h->tp_status = 0;
			i= (i == req.tp_frame_nr-1)? 0: i+1;

		}

		pfd.fd = sock1;
		pfd.events = POLLIN|POLLERR;
		pfd.revents = 0;
		poll(&pfd, 1, -1);

		cleanup_SIP();

#ifdef _USE_SKINNY_
    	cleanup_SKINNY();
#endif

		cleanup_RTP();
		cleanup_RTCP();
	}

	return OK;
}


uint32_t receptor_file(char *file) {

	uint8_t *bp;
	struct pcap_pkthdr h;
	char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _USE_PCAP_

	FILE *fp=NULL;
	struct pcap_file_header hdr;
   	size_t amt_read;

	if (!(p = pcap_open_offline (file, errbuf))) {

#else

	if (mode == 5) {

		(flag_bpf) ? (p = NDLTabrirTraza(file, format, &(bpf_filter_str[0]), 1, errbuf)) : (p = NDLTabrirTraza(file, format, NULL, 1, errbuf));

	} else {

		(flag_bpf) ? (p = NDLTabrirTraza(file, format, &(bpf_filter_str[0]), 0, errbuf)) : (p = NDLTabrirTraza(file, format, NULL, 0, errbuf));

	}

	if (!p) {
#endif

		sprintf(log_message_aux,
				"ERROR: can't open file %s in read mode: %s",
				file, errbuf);
		printLogMessage(log_message_aux, error_log_f);

		return -1;
	}

	//uint16_t tamartcp;
	while ((bp = (uint8_t *) get_next_TCPassambler (&h)) != NULL) {

		count_num_pckt++;
		process_packet(bp, &h);

	}

#ifdef _USE_PCAP_
	sprintf(log_message_aux,
			"INFO: Closing file: %s",
			file);
	printLogMessage(log_message_aux, log_f);
	pcap_close(p);
#else

	sprintf(log_message_aux,
			"INFO: Closing file: %s",
			file);
	printLogMessage(log_message_aux, log_f);
	NDLTclose(p);
#endif

	return 0;
}


void process_packet(uint8_t * bp, struct pcap_pkthdr * h) {

	uint8_t * bp_aux = NULL;
	uint64_t packetTimestamp;
	uint8_t  isIP=0;
	uint16_t ipLen = 0;
	int ip=1;
	uint16_t ipHLen = 0;
	uint16_t jl = 66;
	uint32_t tcpHLen = 0;
	uint16_t TYPE=9;
	uint16_t PROT=9;
	uint16_t UDPp=8;
	uint16_t Jittersend=40;
	uint16_t Jitterrec=20;
	uint16_t SENDERlen=52;
	uint16_t RECEIVERlen=32;
	uint16_t puertosend = 0;
	uint16_t puertorec = 0;
	uint16_t puertosend2 = 0;
	uint16_t puertorec2 = 0;
	uint32_t jittersender = 0; 
	uint32_t jitterreceiver = 0; 
	uint32_t paqperdrtcp = 0;
	uint32_t tampaq = 0;
	uint32_t xpaq = 0;
	uint32_t ypaq = 0;
	uint16_t lrtcp = 0;
	uint16_t longtot = 0;
	uint8_t F_lost = 0;
	uint8_t tipopq = 0;
	uint8_t tipopq2 = 0;
	uint8_t protocolo = 0;
	uint8_t version = 0;
	uint16_t tamartcp = 0;
	uint64_t timep = 0;
	char buf[80];
	int timei;
	uint32_t test = 0; 
	uint32_t test2 = 0; 

	int srip;
	int dsip;

	int np = 0;

	bp_aux = bp;
	isIP = 0;

	packetTimestamp=((uint64_t) ((uint64_t) ((h->ts).tv_sec) * 1000000) +(uint64_t) ((h->ts).tv_usec));
	cleanHandler(packetTimestamp);


	
	if (hdrLinkLen > 0) {

		if ((bp[hdrLinkLen-2] == 0x08) &&
		    (bp[hdrLinkLen-1] == 0x00)) {

			isIP = 1; 

		} else {
				isIP = 0;
		}

		bp += hdrLinkLen;
	}

	if (isIP) {

		ip++;
		last_packet_timestamp = packetTimestamp;
#ifdef _USE_UTCPA_
		if (aux_TCP_ress == NULL) aux_TCP_ress = getTCPSession();
#endif
		memcpy(&(aux_TCP_ress->src_IP), bp + IP_SIP,IP_ALEN);
		memcpy(&(aux_TCP_ress->dst_IP), bp + IP_DIP,IP_ALEN);

		aux_TCP_ress->src_IP = ntohl(aux_TCP_ress->src_IP);
		aux_TCP_ress->dst_IP = ntohl(aux_TCP_ress->dst_IP);
		ipHLen = (bp[0] & 0x0F) * IP_ALEN;
		ipLen = ntohs(*((uint16_t *)(&bp[2])));

		if(count_num_pckt == 1){
			srip = aux_TCP_ress->src_IP;
			dsip = aux_TCP_ress->dst_IP;
		}

		if(count_num_pckt == 1){
			last_timep = packetTimestamp;
		}
		else {
			uint64_t difference = packetTimestamp - last_timep;
        	sum_of_differences += difference;
        	jtr = previousJitter + ((fabs(difference) - previousJitter) / 16.0);
        	last_timep = packetTimestamp;
        	av_jitter =sum_of_differences / (1000*(count_num_pckt - 1));
		}


		


		memcpy (&(aux_TCP_ress->dst_port), bp + ipHLen + sizeof (uint16_t),sizeof (uint16_t));
		aux_TCP_ress->dst_port = ntohs(aux_TCP_ress->dst_port);

		memcpy (&(aux_TCP_ress->src_port), bp+ipHLen, sizeof (uint16_t));
	        aux_TCP_ress->src_port = ntohs(aux_TCP_ress->src_port);

		if (bp[IP_PROTO] == UDP_PROTO) {
			//memcpy (&(aux_TCP_ress->src_port), bp+ipHLen, sizeof (uint16_t));
	        	//aux_TCP_ress->src_port = ntohs(aux_TCP_ress->src_port);

			//memcpy (&(paqperdrtcp), bp+ipHLen+41, sizeof (uint8_t));
			//memcpy (&(xpaq), bp+ipHLen+42, sizeof (uint8_t));
			
			//paqperdrtcp = ntohl(paqperdrtcp);
			
			
			timep = (h->ts.tv_sec*1000000)+h->ts.tv_usec;
			tampaq = h->caplen;
			
			//Comprobar que hay mas trama por delante.
			memcpy (&(tamartcp), bp+2, sizeof (uint16_t));
			tamartcp = ntohs(tamartcp);
			memcpy (&(protocolo), bp+9, sizeof (uint8_t));
			
			if(tamartcp >= 56 && protocolo == 17){
				memcpy (&(tipopq), bp+ipHLen+TYPE, sizeof (uint8_t));
				memcpy (&(F_lost), bp+60, sizeof (uint8_t));
				memcpy (&(version), bp+28, sizeof (uint8_t));
				memcpy (&(lrtcp), bp+30, sizeof (uint16_t));
				lrtcp = ntohs(lrtcp);
				memcpy (&(longtot), bp+2, sizeof (uint16_t));
				longtot = ntohs(longtot);
				longtot+=14;
			}
			else{
				return;
			}
			
			if((tipopq == 200 || tipopq == 201)  && lrtcp >= 7 && protocolo == 17){
			
				if(tipopq == 200){
					jittersender = 0;
					if(longtot >= 60){
						memcpy (&(jittersender), bp+ipHLen+UDPp+Jittersend, sizeof (uint32_t));
	        				jittersender = ntohl(jittersender);
						pqsender++;
					}
					uint8_t pr1;
					uint8_t pr2;
					uint8_t pr3;
					uint8_t a = 0x00;
					memcpy (&(pr1), bp+61, sizeof (uint8_t));
					memcpy (&(pr2), bp+62, sizeof (uint8_t));
					memcpy (&(pr3), bp+63, sizeof (uint8_t));
					paqperdrtcp |= ((uint32_t)a) << 24;  
    				paqperdrtcp |= ((uint32_t)pr1) << 16;  
    				paqperdrtcp |= ((uint32_t)pr2) << 8;   
    				paqperdrtcp |= (uint32_t)pr3; 
					/*printf("PR1: %d ",pr1);
					printf("PR2: %d ",pr2);
					printf("PR1: %d ",pr3);
					printf("Result shift: 0x%.8X ", paqperdrtcp);
					printf("Result dec: %lu \n",paqperdrtcp);*/
					result = paqperdrtcp;
		
					/*printf("N.paq: %"PRIu64"",count_num_pckt);
					printf("Time: %lu ",timep);
					//printf("Test: %lu ",test);
					//printf("Test2: %lu ",test2);
					printf("Seconds: %lu ",h->ts.tv_sec);
					printf("Micro: %lu \n",h->ts.tv_usec);
					printf("T. paquete: %d ",h->caplen);
					printf("T. paquete 2: %d ",longtot);
					printf("Source Port:%d ",aux_TCP_ress->src_port );
					printf("Destination Port:%d ",aux_TCP_ress->dst_port );
					printf("Longitud RTCP: %d ",lrtcp);
					printf("Protocolo: %d ",protocolo);
					printf("Frac.lost: %d/256 ",F_lost);
					printf("Jitter: %lu \n",jittersender);*/
					if(tamartcp >= 112){
						memcpy (&(tipopq2), bp+ipHLen+UDPp+SENDERlen+1, sizeof (uint8_t));
						if(tipopq2 == 201){
							memcpy (&(jitterreceiver), bp+ipHLen+UDPp+SENDERlen+Jitterrec, sizeof (uint32_t));
	        					jitterreceiver = ntohl(jitterreceiver);
							pqreceiver++;
						}
					}
				}

				if(tipopq == 201){
					if(tamartcp >= 60){
						memcpy (&(jitterreceiver), bp+ipHLen+UDPp+Jitterrec, sizeof (uint32_t));
	        				jitterreceiver = ntohl(jitterreceiver);
						pqreceiver++;
					}
					//printf("%d ",jittertc);
					if(tamartcp >= 112){
						memcpy (&(tipopq2), bp+ipHLen+UDPp+RECEIVERlen+1, sizeof (uint8_t));
						if(tipopq2 == 200){
							memcpy (&(jittersender), bp+ipHLen+UDPp+RECEIVERlen+Jittersend, sizeof (uint32_t));
	        					jittersender = ntohl(jittersender);
							pqsender++;
						}
					} 
				}
				uint64_t segundos = (timep/1e6);
				uint64_t micro = timep - segundos*1e6;
				time_t rawtime = segundos; 
				struct tm ts; 
				ts = *localtime(&rawtime); 
				strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
   				sprintf(buf, "%s.%06lu", buf,micro);
   				uint8_t octet1 = (aux_TCP_ress->src_IP >> 24) & 0xFF;
    			uint8_t octet2 = (aux_TCP_ress->src_IP >> 16) & 0xFF;
    			uint8_t octet3 = (aux_TCP_ress->src_IP >> 8) & 0xFF;
    			uint8_t octet4 = aux_TCP_ress->src_IP & 0xFF;

    			sprintf(ipaddress, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
				//printf("%s",buf);
				CSV(ipaddress, buf, jittersender, jitterreceiver,tampaq, result, av_jitter); 

				jittersenderfin = jittersenderfin + jittersender;
				jitterreceiverfin = jitterreceiverfin+ jitterreceiver;

			}
			
		    
		}

		if (bp[IP_PROTO] == UDP_PROTO) {

	        tcpHLen = 8;
		bp += ipHLen;

#ifdef _USE_UNISTIM_
			if ((aux_TCP_ress->src_port == 5000) || (aux_TCP_ress->src_port == 5100) ||
				(aux_TCP_ress->dst_port == 5000) || (aux_TCP_ress->dst_port == 5100)) {

				if (UNISTIM_aux_session == NULL) UNISTIM_aux_session = getUNISTIMSession();
				if (UNISTIM_aux_session == NULL) {
					lost_UNISTIM++;
					sprintf(log_message_aux,
						    "ERROR: No free UNISTIM structures. I'm lossing information! -- TOTAL lost UNISTIM messages: %"PRIu64"",
					        lost_UNISTIM);
					printLogMessage(log_message_aux, error_log_f);
					return;
				}

				UNISTIM_aux_session->payload_ptr = bp+tcpHLen;
				UNISTIM_aux_session->dataLen = MIN(ipLen - ipHLen - tcpHLen, h->caplen - ipHLen - tcpHLen);
				UNISTIM_aux_session->caller.port = aux_TCP_ress->src_port;
				UNISTIM_aux_session->called.port = aux_TCP_ress->dst_port;
				UNISTIM_aux_session->caller.IP = aux_TCP_ress->src_IP;
				UNISTIM_aux_session->called.IP = aux_TCP_ress->dst_IP;

				if (n_vlan >= 1) {
					UNISTIM_aux_session->n_vlan = 1;
					UNISTIM_aux_session->vlan_tag[0] = vlan[0];
				}

				if (n_vlan == 2) {
					UNISTIM_aux_session->n_vlan = 2;
					UNISTIM_aux_session->vlan_tag[1] = vlan[1];
				}

				UNISTIM_aux_session = getUNISTIMInfo(UNISTIM_aux_session, h, bp_aux);
			}
#endif

			if ((aux_TCP_ress->src_port == 5060) || (aux_TCP_ress->src_port == 5070) ||
			    (aux_TCP_ress->dst_port == 5060) || (aux_TCP_ress->dst_port == 5070)) {

				if (SIP_aux_session == NULL) SIP_aux_session = getSIPSession();
				if (SIP_aux_session == NULL) {
					lost_SIP++;
					sprintf(log_message_aux,
						    "ERROR: No free SIP structures. I'm lossing information! -- TOTAL lost SIP messages: %"PRIu64"",
					        lost_SIP);
					printLogMessage(log_message_aux, error_log_f);
					return;
				}


				SIP_aux_session->payload_ptr = bp+tcpHLen;
				SIP_aux_session->dataLen = MIN(ipLen - ipHLen - tcpHLen,h->caplen - ipHLen - tcpHLen);
				SIP_aux_session->sip_source_port = aux_TCP_ress->src_port;
				SIP_aux_session->sip_destination_port = aux_TCP_ress->dst_port;
				SIP_aux_session->sip_source_ip = aux_TCP_ress->src_IP;
				SIP_aux_session->sip_destination_ip = aux_TCP_ress->dst_IP;

				if (n_vlan >= 1) {
					SIP_aux_session->n_vlan = 1;
					SIP_aux_session->vlan_tag[0] = vlan[0];
				}

				if (n_vlan == 2) {
					SIP_aux_session->n_vlan = 2;
					SIP_aux_session->vlan_tag[1] = vlan[1];
				}

				SIP_aux_session = SIPPacketDispatcher(SIP_aux_session, bp_aux, h);

			}

			else if (protocolo == 17  && (version & 0xc0) ==128 && (tipopq < 200  || tipopq >204)) { 
				//if((version & 0xc0) ==128 && (tipopq < 200  || tipopq >204)){
				//if(nrtps == 0){
					//(rtpsession_static.caller).port = aux_TCP_ress->src_port;
					//(rtpsession_static.called).port = aux_TCP_ress->dst_port;
					//nrtps++;
				//}
				//if((rtpsession_static.caller).port == aux_TCP_ress->src_port || (rtpsession_static.called).port == aux_TCP_ress->dst_port || (rtpsession_static.caller).port == aux_TCP_ress->dst_port || (rtpsession_static.called).port == aux_TCP_ress->src_port ){
					(rtpsession_static.caller).IP = aux_TCP_ress->src_IP;
					(rtpsession_static.caller).port = aux_TCP_ress->src_port;
					(rtpsession_static.called).IP = aux_TCP_ress->dst_IP;
					(rtpsession_static.called).port = aux_TCP_ress->dst_port;
					if(puertosend == puertosend || puertosend == puertorec || puertosend == aux_TCP_ress->src_port || puertosend == aux_TCP_ress->dst_port){
						puertosend = aux_TCP_ress->src_port;
						puertorec = aux_TCP_ress->dst_port;
					}
					else{
						puertosend2 = aux_TCP_ress->src_port;
						puertorec2 = aux_TCP_ress->dst_port;
					}
					rtpsession_static.payload = bp + 8;
					(rtpsession_static.caller).offset = ipLen - ipHLen - 8;
					nrtps++;
#ifndef _DEBUG_RTP_
					insertPacketRTP(&rtpsession_static);
#else
					RTPSession* rtpsession_modified = NULL;
					insertPacketRTP(&rtpsession_static, &rtpsession_modified);
					
					if(rtpsession_modified != NULL) {
						insertRTP_debug(rtpsession_modified, bp_aux, h);
					}
				//}
#endif
			}
			else{
				///poner un if con los tipos de paquete de 200 a 204, si no es ninguno de estos no puede pasar
				if(protocolo == 17 && (version & 0xc0) ==128 &&  (tipopq >= 200 &&  tipopq <= 204)){
				count_num_pckt_rtcp++;
				//memcpy (&(aux_TCP_ress->src_port), bp+ipHLen, sizeof (uint16_t));
	        		//aux_TCP_ress->src_port = ntohs(aux_TCP_ress->src_port);
				//memcpy (&(jittertc), bp+ipHLen, sizeof (uint16_t));
	        		//jittertc = ntohs(jittertc);

				if(count_num_pckt_rtcp!=1){
					//printf("%d ", (aux_TCP_ress->src_port));
					//printf("%llu ",timep);
					//printf("%x ",jittersender);
					//printf("%lu ",paqperdrtcp);
					//printf("%d ",lrtcp);
				}
				//printf("%d ",aux_TCP_ress->src_port);
				(rtcpsession_static.caller).IP = aux_TCP_ress->src_IP;
				(rtcpsession_static.caller).port = (aux_TCP_ress->src_port);
				(rtcpsession_static.called).IP = aux_TCP_ress->dst_IP;
				(rtcpsession_static.called).port = (aux_TCP_ress->dst_port);
				//if((puertosend+1)==(rtcpsession_static.caller).port || (puertosend+1)==(rtcpsession_static.called).port || (puertosend2+1)==(rtcpsession_static.caller).port || (puertosend2+1)==(rtcpsession_static.called).port ){
					//printf("%x ",jittersender);
				//}
				rtcpsession_static.payload = bp + 8;
				(rtcpsession_static.caller).offset = ipLen - ipHLen - 8;
				}

#ifndef _DEBUG_RTCP_
				insertPacketRTCP(&rtcpsession_static);
#else
				RTCPSession* rtcpsession_modified = NULL;
				insertPacketRTCP(&rtcpsession_static, &rtcpsession_modified);

				if(rtcpsession_modified != NULL) {
					insertRTCP_debug(rtcpsession_modified, bp_aux, h);
				}
#endif
				}
			}
		
		} else if (bp[IP_PROTO] == TCP_PROTO) {


			bp += ipHLen;
			tcpHLen = (((bp[12] >> 4) & 0x0F) * 4);
			aux_TCP_ress->flags=bp[13];

			// SIP
			if ((aux_TCP_ress->src_port == 5060) || (aux_TCP_ress->src_port == 5070) ||
			    (aux_TCP_ress->dst_port == 5060) || (aux_TCP_ress->dst_port == 5070)) {


				//bp = testSegmentation(aux_TCP_ress, h);
				//if (bp == NULL) return;

				if (SIP_aux_session == NULL) SIP_aux_session = getSIPSession();
				if (SIP_aux_session == NULL) {
					lost_SIP++;
					sprintf(log_message_aux,
						    "ERROR: No free SIP structures. I'm lossing information! -- TOTAL lost SIP messages: %"PRIu64"",
					        lost_SIP);
					printLogMessage(log_message_aux, error_log_f);
					return;
				}


				SIP_aux_session->payload_ptr = bp+tcpHLen;
				SIP_aux_session->dataLen = MIN(ipLen - ipHLen - tcpHLen, h->caplen - ipHLen - tcpHLen);
				SIP_aux_session->sip_source_port = aux_TCP_ress->src_port;
				SIP_aux_session->sip_destination_port = aux_TCP_ress->dst_port;
				SIP_aux_session->sip_source_ip = aux_TCP_ress->src_IP;
				SIP_aux_session->sip_destination_ip = aux_TCP_ress->dst_IP;

				if (n_vlan >= 1) {
					SIP_aux_session->n_vlan = 1;
					SIP_aux_session->vlan_tag[0] = vlan[0];
				}

				if (n_vlan == 2) {
					SIP_aux_session->n_vlan = 2;
					SIP_aux_session->vlan_tag[1] = vlan[1];
				}

				SIP_aux_session = SIPPacketDispatcher(SIP_aux_session, bp_aux, h);

			// SKINNY
#ifdef _USE_SKINNY_
			} else if ((aux_TCP_ress->src_port == 2000) || (aux_TCP_ress->dst_port == 2000)) {


#define _DEBUG_TEST_CONNECTIONS_


				//if (testSegmentation(aux_TCP_ress, h) == NULL) return;

				if (SKINNY_aux_session == NULL) SKINNY_aux_session = getSKINNYSession();
				if (SKINNY_aux_session == NULL) {
					lost_SKINNY++;
					sprintf(log_message_aux,
						    "ERROR: No free SKINNY structures. I'm lossing information! -- TOTAL lost SKINNY messages: %"PRIu64"",
					        lost_SKINNY);
					printLogMessage(log_message_aux, error_log_f);
					return;
				}

				SKINNY_aux_session->payload_ptr = bp+tcpHLen;
				SKINNY_aux_session->dataLen = MIN(ipLen - ipHLen - tcpHLen, h->caplen - ipHLen - tcpHLen);
				SKINNY_aux_session->caller.port = aux_TCP_ress->src_port;
				SKINNY_aux_session->called.port = aux_TCP_ress->dst_port;
				SKINNY_aux_session->caller.IP = aux_TCP_ress->src_IP;
				SKINNY_aux_session->called.IP = aux_TCP_ress->dst_IP;

				if (n_vlan >= 1) {
					SKINNY_aux_session->n_vlan = 1;
					SKINNY_aux_session->vlan_tag[0] = vlan[0];
				}

				if (n_vlan == 2) {
					SKINNY_aux_session->n_vlan = 2;
					SKINNY_aux_session->vlan_tag[1] = vlan[1];
				}

				SKINNY_aux_session = getSKINNYInfo(SKINNY_aux_session, h, bp_aux);
			}
#else
			}
#endif

		}

	}




void cleanHandler(uint64_t packetTimestamp) {

	char flag_clean = 0;
	uint64_t actual = 0;

	actual=packetTimestamp/1000000;

	if ((prev_timestamp < actual) && (prev_timestamp != 0)) {
		flag_clean=1;
	} else {
		prev_timestamp=actual;
	}

	if (flag_clean == 1) {

		flag_clean=0;
		flag_30_sec++;

		if (flag_30_sec > 30) {

			if (mode==0) {
				struct tpacket_stats st;
				int len=sizeof(struct tpacket_stats);
				getsockopt(sock1,SOL_PACKET,PACKET_STATISTICS,(char *)&st,(socklen_t*)&len);
			}

			packetsventana=0;
			bytesventana=0;
			fflush(SIP_records);
			fflush(RTP_records);
			fflush(RTCP_records);
			flag_30_sec=0;
		}

		first_packet_timestamp = packetTimestamp;
		last_packet_timestamp = packetTimestamp;

		cleanup_SIP ();

#ifdef _USE_SKINNY_
		cleanup_SKINNY ();
#endif

#ifdef _USE_UNISTIM_
		cleanup_UNISTIM();
#endif

		cleanup_RTP ();
		cleanup_RTCP ();
		cleanup_connections();
		cleanup_IPFragments ();
		prev_timestamp=actual;
	}
}

//************************************************************
// getCurrentDate
//************************************************************
void getCurrentDate() {

	time_t t;
	struct tm *stmf;
	char fecha[40];

	char *auxFecha;
	int i;
	t = time(NULL);
	stmf = localtime(&t);
	strftime(fecha,sizeof(fecha),"%Y-%m-%d-%H:%M:%S",stmf);

	auxFecha = fecha;

	for(i=0;i<35;i++) globalDate[i]=auxFecha[i];
}

//************************************************************
//
//************************************************************

void CSV(char *ipad, char *tp, uint32_t *jits, uint32_t *jitr, uint32_t len, uint32_t res, double jitc) {
//void CSV(uint64_t *tp, uint32_t *jits, uint32_t *jitr, uint32_t len) {

	char filename[100]="prueba.csv";
	int j2;

	
 	if(i2==0){
		fp=fopen(filename,"w+");
		fprintf(fp,"IP, Time, JitterSender, JitterReceiver, Length, LostPackets, Delay");
		i2++;
	}

	fprintf(fp,"\n%s, %s, %d, %d, %d, %d, %.2f",ipad, tp, jits, jitr, len, res, jitc);
}

//************************************************************
// isMemmoryFull
//************************************************************
char isMemmoryFull() {

#ifdef DEBUG 
//	printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",used_structures_SIP,total_structures_SIP,used_structures_RTP,total_structures_RTP);
#endif

	if ((((float)used_structures_SIP/(float)total_structures_SIP))>MAX_USE_RATIO_SIP)
		return  YES;

	if ((((float)used_structures_RTP/(float)total_structures_RTP))>MAX_USE_RATIO_RTP)
		return YES;

	if ((((float)used_structures_RTCP/(float)total_structures_RTCP))>MAX_USE_RATIO_RTP)
		return YES;

	if ((((float)used_structures_TCPA/(float)total_structures_TCPA))>MAX_USE_RATIO_TCP)
		return YES;

	if((((float)used_nodes/(float)total_nodes))>MAX_USE_RATIO_NODES)
		return YES;

	return NO;
}

int createSocketRawRx1(char *interfaz) {

	int r1, i=0;
	struct sockaddr_ll r1_address;
	struct ifreq ifr;
	int ret,sock_buf_size;

	sock_buf_size=16777216;

	r1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (r1 == -1)  {
		printf("Error: can't open socket\n");
		return -1;
	}

	/* Setup the fd for mmap() ring buffer */
	req.tp_block_size=2048*2;
	req.tp_frame_size=2048;
	req.tp_block_nr=2000;
	req.tp_frame_nr=4000;

	if ((setsockopt(r1, SOL_PACKET, PACKET_RX_RING, (char *)&req, sizeof(req))) != 0) {

		perror("setsockopt():PACKET_RX_RING");
		exit(-1);
	}

	/* mmap() the sucker */
	map = mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, r1, 0);

	if (map == MAP_FAILED) {
		perror("mmap()");
		close(r1);
		exit(-1);
	}

	/* Setup our ringbuffer */
	ring = malloc(req.tp_frame_nr * sizeof(struct iovec));

	for (i=0; i<req.tp_frame_nr; i++) {

		ring[i].iov_base=(void *)((long)map)+(i*req.tp_frame_size);
		ring[i].iov_len=req.tp_frame_size;
	}

	memset(&r1_address, 0, sizeof(r1_address));
	strncpy((char *)ifr.ifr_name,interfaz, IFNAMSIZ);

    if((ioctl(r1, SIOCGIFINDEX, &ifr)) == -1) {

		printLogMessage("ERROR: can't obtain data from interface", error_log_f);
        return -1;
    }

	r1_address.sll_family = AF_PACKET;
	r1_address.sll_protocol = htons(ETH_P_ALL);
	r1_address.sll_ifindex = ifr.ifr_ifindex;

	ret = setsockopt(r1, SOL_SOCKET, SO_RCVBUF,(char *)&sock_buf_size, sizeof(sock_buf_size));

	if(ret<0) {
		perror("secsockopt:SO_RCVBUF");
		return -1;
	}

	if (bind(r1, (struct sockaddr *) &r1_address,sizeof(r1_address)) != 0) {

		printLogMessage("ERROR: can't open interface", error_log_f);
		return -1;
	}

	sock1=r1;
	return r1;
}

//************************************************************
// receptor_file_live
//************************************************************
u_int32_t receptor_file_live(char *interfaz) {

	u_int8_t *bp;

	struct pcap_pkthdr h;
	uint16_t tamartcp;

	printLogMessage("INFO: Live capture!", error_log_f);

	char errbuf[PCAP_ERRBUF_SIZE];
	if (!(p_live = pcap_open_live (interfaz,65536, 1, 0, errbuf))) {

		sprintf(log_message_aux,
				"ERROR: can't open interface %s: %s",
				interfaz,errbuf);
		printLogMessage(log_message_aux, error_log_f);
		freeResources();
		exit(-1);
	}

	while ((bp = (u_int8_t *) get_next_TCPassambler (&h)) != NULL) {
	//while ((bp = (u_int8_t *) get_next_IPassambler (&h)) != NULL) {
		
		memcpy (&(tamartcp), bp+2, sizeof (uint16_t));
		tamartcp = ntohs(tamartcp);
		
		//if(tamartcp != 64 && tamartcp != 97){
			process_packet(bp,&h);
		//}

		if (isMemmoryFull()==YES)	{

			getCurrentDate();
			printf("\nReset\n\n");

			printLogMessage("INFO: Reset", log_f);

			last_packet_timestamp = INFINITO;
			cleanup_SIP();

#ifdef _USE_SKINNY_
			cleanup_SKINNY();
#endif

#ifdef _USE_UNISTIM_
			cleanup_UNISTIM();
#endif
			cleanup_RTP();
			cleanup_RTCP();
			cleanup_connections();
			cleanup_IPFragments();

			freeResources();

			exit(OK);
		}
	}

	pcap_close (p_live);
	return OK;
}



