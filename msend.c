/*
 * msend.c  -- Sends UDP packets to a multicast group
 * 
 * (c)  Jianping Wang, Yvan Pointurier, Jorg Liebeherr, 2002
 *      Multimedia Networks Group, University of Virginia
 *
 * SOURCE CODE RELEASED TO THE PUBLIC DOMAIN
 * 
 * version 2.0 - 5/20/2002 
 * version 2.1 - 12/4/2002  
 * 	By default, msend does not join multicast group. If  -join option is 
 * 	given, msend joins the multicast group. 
 * version 2.2 - 05/17/2003  
 *      Most commandline parameters are assigned default values. The 
 *      usage information is changed according to README_msend.txt
 * 
 * 
 * Based on this public domain program:
 * u_mctest.c            (c) Bob Quinn           2/4/97
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>

#define TRUE 1
#define FALSE 0
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif
#define LOOPMAX   20
#define BUFSIZE   1024
#define SEQ_SIZE   9
#define TIME_SIZE 18

char *TEST_ADDR = "224.1.1.1";
int TEST_PORT = 4444;
int TTL_VALUE = 1;
int SLEEP_TIME = 1;
int END_TIME=1000;
unsigned long IP = INADDR_ANY;
int NUM = 0;
char RESULT[100];
int join_flag = 0;		/* not join */


typedef struct timerhandler_s {
	int s;
	char *achOut;
	int len;
	int n;
	struct sockaddr *stTo;
	int addr_size;
} timerhandler_t;
timerhandler_t handler_par;
void timerhandler();
char* itoa(int value, char* result, int base);

void printHelp(void)
{
	printf("msend version %s\n\
Usage:  msend [-g GROUP] [-p PORT] [-join] [-i ADDRESS] [-t TTL] [-P PERIOD]\n\
	      [-text \"text\"|-n]\n\
	msend [-v | -h]\n\
\n\
  -g GROUP     IP multicast group address to send to.  Default: 224.1.1.1\n\
  -p PORT      UDP port number used in the multicast packets.  Default: 4444\n\
  -i ADDRESS   IP address of the interface to use to send the packets.\n\
               The default is to use the system default interface.\n\
  -join        Multicast sender will join the multicast group.\n\
               By default a sender never joins the group.\n\
  -P PERIOD    PPI number  Default 1000 msec\n\
  -t TTL       The TTL value (1-255) used in the packets.  You must set\n\
               this higher if you want to route the traffic, otherwise\n\
               the first router will drop the packets!  Default: 1\n\
  -text \"text\" Specify a string to use as payload in the packets, also\n\
               displayed by the mreceive command.  Default: empty\n\
  -n           Encode -text argument as a number instead of a string.\n\
  -v           Print version information.\n\
  -h           Print the command usage.\n\n", VERSION);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in stLocal, stTo;
	char achOut[BUFSIZE] = "";
	int s, i;
	struct ip_mreq stMreq;
	int iTmp, iRet;
	int ii = 1;
	int addr_size = sizeof(struct sockaddr_in);
	struct itimerval times;
	sigset_t sigset;
	struct sigaction act;

	if ((argc == 2) && (strcmp(argv[ii], "-v") == 0)) {
		printf("msend version 2.2\n");
		return 0;
	}
	if ((argc == 2) && (strcmp(argv[ii], "-h") == 0)) {
		printHelp();
		return 0;
	}

	while (ii < argc) {
		if (strcmp(argv[ii], "-g") == 0) {
			ii++;
			if ((ii < argc) && !(strchr(argv[ii], '-'))) {
				TEST_ADDR = argv[ii];
				ii++;
			}
		} else if (strcmp(argv[ii], "-p") == 0) {
			ii++;
			if ((ii < argc) && !(strchr(argv[ii], '-'))) {
				TEST_PORT = atoi(argv[ii]);
				ii++;
			}
		} else if (strcmp(argv[ii], "-join") == 0) {
			join_flag++;;
			ii++;
		} else if (strcmp(argv[ii], "-i") == 0) {
			ii++;
			if ((ii < argc) && !(strchr(argv[ii], '-'))) {
				IP = inet_addr(argv[ii]);
				ii++;
			}
		} else if (strcmp(argv[ii], "-t") == 0) {
			ii++;
			if ((ii < argc) && !(strchr(argv[ii], '-'))) {
				TTL_VALUE = atoi(argv[ii]);
				ii++;
			}
		} else if (strcmp(argv[ii], "-P") == 0) {
			ii++;
			if ((ii < argc) && !(strchr(argv[ii], '-'))) {
				SLEEP_TIME = atoi(argv[ii]);
				ii++;
			}
		} else if (strcmp(argv[ii], "-limit") == 0) {
			ii++;
			if ((ii < argc) && !(strchr(argv[ii], '-'))) {
				END_TIME = atoi(argv[ii]);
				ii++;
			}
		} else if (strcmp(argv[ii], "-n") == 0) {
			ii++;
			NUM = 1;
			ii++;
		} else if (strcmp(argv[ii], "-text") == 0) {
			ii++;
			if ((ii < argc) && !(strchr(argv[ii], '-'))) {
				strcpy(achOut, argv[ii]);
				ii++;
			}
		} else {
			printf("wrong parameters!\n\n");
			printHelp();
			return 1;
		}
	}

	/* get a datagram socket */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == INVALID_SOCKET) {
		printf("socket() failed.\n");
		exit(1);
	}

	/* avoid EADDRINUSE error on bind() */
	iTmp = TRUE;
	iRet = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&iTmp, sizeof(iTmp));
	if (iRet == SOCKET_ERROR) {
		printf("setsockopt() SO_REUSEADDR failed.\n");
		exit(1);
	}

	/* name the socket */
	stLocal.sin_family = AF_INET;
	stLocal.sin_addr.s_addr = IP;
	stLocal.sin_port = htons(TEST_PORT);
	iRet = bind(s, (struct sockaddr *)&stLocal, sizeof(stLocal));
	if (iRet == SOCKET_ERROR) {
		printf("bind() failed.\n");
		exit(1);
	}

	/* join the multicast group. */
	stMreq.imr_multiaddr.s_addr = inet_addr(TEST_ADDR);
	stMreq.imr_interface.s_addr = IP;
	if (join_flag == 1) {
		iRet = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&stMreq, sizeof(stMreq));
		if (iRet == SOCKET_ERROR) {
			printf("setsockopt() IP_ADD_MEMBERSHIP failed.\n");
			exit(1);
		}
	}

	/* set TTL to traverse up to multiple routers */
	iTmp = TTL_VALUE;
	iRet = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&iTmp, sizeof(iTmp));
	if (iRet == SOCKET_ERROR) {
		printf("setsockopt() IP_MULTICAST_TTL failed.\n");
		exit(1);
	}

	/* enable loopback */
	iTmp = TRUE;
	iRet = setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&iTmp, sizeof(iTmp));
	if (iRet == SOCKET_ERROR) {
		printf("setsockopt() IP_MULTICAST_LOOP failed.\n");
		exit(1);
	}

	/* assign our destination address */
	stTo.sin_family = AF_INET;
	stTo.sin_addr.s_addr = inet_addr(TEST_ADDR);
	stTo.sin_port = htons(TEST_PORT);
	printf("Now sending to multicast group: %s\n", TEST_ADDR);

	SLEEP_TIME = 1000000/SLEEP_TIME;	/* convert to microsecond */
	if (SLEEP_TIME > 0) {
		/* block SIGALRM */
		sigemptyset(&sigset);
		sigaddset(&sigset, SIGALRM);
		sigprocmask(SIG_BLOCK, &sigset, NULL);

		/* set up handler for SIGALRM */
		act.sa_handler = &timerhandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_SIGINFO;
		sigaction(SIGALRM, &act, NULL);
		/*
		 * set up interval timer
		 */
		times.it_value.tv_sec = 0;	/* wait a bit for system to "stabilize"  */
		times.it_value.tv_usec = 1;	/* tv_sec or tv_usec cannot be both zero */
		times.it_interval.tv_sec = (time_t)(SLEEP_TIME / 1000000);
		times.it_interval.tv_usec = (long)(SLEEP_TIME % 1000000);
		setitimer(ITIMER_REAL, &times, NULL);

		handler_par.s = s;
		handler_par.achOut = achOut;
		handler_par.len = strlen(achOut) + 1;
		handler_par.n = 0;
		handler_par.stTo = (struct sockaddr *)&stTo;
		handler_par.addr_size = addr_size;

		/* now wait for the alarms */
		sigemptyset(&sigset);
		for (;;) {
			sigsuspend(&sigset);
		}
		return 0;
	} else {
		for (i = 0; i < 10; i++) {
			int addr_size = sizeof(struct sockaddr_in);

			if (NUM) {
				achOut[3] = (unsigned char)(i >> 24);
				achOut[2] = (unsigned char)(i >> 16);
				achOut[1] = (unsigned char)(i >> 8);
				achOut[0] = (unsigned char)(i);
				printf("Send out msg %d to %s:%d\n", i, TEST_ADDR, TEST_PORT);
			} else {
				printf("Send out msg %d to %s:%d: %s\n", i, TEST_ADDR, TEST_PORT, achOut);
			}

			iRet = sendto(s, achOut, (NUM ? 4 : strlen(achOut) + 1), 0, (struct sockaddr *)&stTo, addr_size);
			if (iRet < 0) {
				printf("sendto() failed.\n");
				exit(1);
			}
		}		/* end for(;;) */
	}

	return 0;
}				/* end main() */

void timerhandler(void)
{
	int iRet;
	static int iCounter = 1;

	if (NUM) {
		handler_par.achOut = (char *)(&iCounter);
		handler_par.len = sizeof(iCounter);
		printf("Sending msg %d, TTL %d, to %s:%d\n", iCounter, TTL_VALUE, TEST_ADDR, TEST_PORT);
	} else {
		if(0 != insertSequenceAndTimestamp(handler_par.achOut, strlen(handler_par.achOut), iCounter)){
			printf("Error: The data what we send is too short!\n", END_TIME);
			exit(0);
		}	
	}
	iRet = sendto(handler_par.s, handler_par.achOut, handler_par.len, handler_par.n, handler_par.stTo, handler_par.addr_size);
	if (iRet < 0) {
		printf("sendto() failed.\n");
		exit(1);
	}
	iCounter++;
	//exit the loop when limit is meet
	if(iCounter > END_TIME ){
		printf("Sent %d packages\n", END_TIME);
		exit(0);
	}
	return;
}

/* 
* args:
*  - array   : The raw data ,it is also the return value.
*  - lenth   : the lenth of raw data, it should be long enough
*  - sequence: the message sequence
*
*  e.g.  begin: WWWWWWWWWWWWWWWWWWWWWWWWWWWWW
*        end  : 99999999[1565343077328587]WWW
*
*/
int insertSequenceAndTimestamp(char *array, size_t lenth, int sequence)                                                                                             
{
    if(lenth < TIME_SIZE + SEQ_SIZE || NULL == array)
    {
        printf("the data is too short!! Please input longer!\n");
        return -1;
    }

    char *p = array;
    int i = 0;

    //1. insert sequence
    char head_tag[SEQ_SIZE];
    sprintf(head_tag, "%d", sequence);
    
    for( ; i < SEQ_SIZE; i++)
    {
        if('\0' == head_tag[i])
        {
            break;
        }
        *p++ = head_tag[i];
    }

    *p++ = '[';

    //2. insert timestamp
    //get current timestamp
    struct timeval tv;
    gettimeofday(&tv,NULL);
    long us_time = tv.tv_sec * 1000000 + tv.tv_usec;
    //printf("get current time, usec: %ld\n", us_time);

    char tmpTimeArray[TIME_SIZE];
    sprintf(tmpTimeArray, "%ld", us_time);

    //insert the timestamp
    i = 0;
    while(*p != '\0' && tmpTimeArray[i] != '\0')
    {
        *p++ = tmpTimeArray[i++];
    }

    *p = ']';

    //printf("%s\n", array);

    return 0;
}


/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
