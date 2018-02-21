/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

File: 12dsp_audio_transcode_net_api.c

Copyright (c) 2012 Octasic Inc. All rights reserved.
    
Description:

    This samples demonstrates how to open a packet-to-packet voice transcoding
    channel using the Vocallo Net API.

    Block diagram:

           +------------------+  +---------+  +---------+  +------------------+
HOST<->|   | VOCALLO HOST A   |  |  VOC    |->|  VOC    |  | VOCALLO HOST B   |   |<->HOST
 A     |   +----------------+ |  |  TERM A |  |  TERM B |  | +----------------+   |    B
       |   | RTP SESSION A  | |  |         |  |         |  | | RTP SESSION B  |   |
       |   +--------------+ | |  |  G.711  |  |  G.711  |  | | +--------------+   |
       |<->| RTP MEMBER A |<|-|->| (U-LAW) |<-| (A-LAW) |<-|-|>| RTP MEMBER B |<->|
           +--------------+-+-+  +---------+  +---------+  +-+-+--------------+

|----------------- SIDE A ------------------||----------------- SIDE B ------------------|

This source code is Octasic Confidential. Use of and access to this code
is covered by the Octasic Device Enabling Software License Agreement.
Acknowledgement of the Octasic Device Enabling Software License was
required for access to this code. A copy was also provided with the release.

$Octasic_Release: Vocallo Software Development Kit OCTVOC-01.08.00-B49-BETA (2012/02/29) $

$Octasic_Revision: 27006 $

BPRozier : Changed to create the maximum number of VOIP connections on 
           PCIe-8120/ATCA-8320.
           The main purpose of this software is to load the DSPs with maximum
           IP-IP channels so the test is arranged in pairs of physical DSPs
           This code assumes there 12 DSPs available and that the code is 
           running on the P4080 under Linux (ATCA-8320) or on a Xeon Server host 
           with RHEL (PCIe-8120) though it should run on other hosts.
           Note main change is to change the data structures to large arrays
           Some functions are copied from existing example files and are named
           MyXXXXXXX where XXXXXX is the original function name.
           Not all of these  functions are changed but are needed by the 
           function which has been changed.
           DSP IP Addresses are controlled by these #defines
           #define DSP_IP_BASE 0xC0A84C00
           #define DSP_IP_START 201 
           #define DSP_IP_FINISH (DSP_IP_START+MAX_DSPS-1) 
           So with current settings these IP addresses are used 
           DSP0  IP :  192.168.76.201
           DSP11 IP :  192.168.76.212
           
           Where functions expect User Input, this has been removed. see below 
           for command line options
           
           The Object model has these changes :-
           One packet API session Instance is shared among all Contexts.
           There is a Device Context for each DSP
           There is a Stats structure for each DSP
           
           usage: 12dsp_audio_transcode_net_api <Host MAC Address> <Number of iterations>
           Host MAC Address usually 10G interface: XX:XX:XX:XX:XX:XX
           Number of iterations: -1 for run contiuously
           Example usage:
               12dsp_audio_transcode_net_api EC:9E:CD:03:7D:FF -1


\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

#define OCTVC1_OPT_DECLARE_DEFAULTS

/***************************  INCLUDE FILES  *********************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Vocallo API header files */
#include "vocallo/main/octvc1_main_api.h"
#include "vocallo/main/octvc1_main_api_swap.h"
#include "vocallo/main/octvc1_main_default.h"
#include "vocallo/main/octvc1_main_version.h"
#include "vocallo/net/octvc1_net_api.h"
#include "vocallo/net/octvc1_net_api_swap.h"
#include "vocallo/net/octvc1_net_default.h"
#include "vocallo/pkt_api/octvc1_pkt_api.h"
#include "vocallo/pkt_api/octvc1_pkt_api_default.h"
#include "vocallo/vspmp_voc/octvc1_vspmp_voc_api.h"
#include "vocallo/vspmp_voc/octvc1_vspmp_voc_api_swap.h"
#include "vocallo/vspmp_voc/octvc1_vspmp_voc_default.h"

/* Octasic applications' common header files */
#include "oct_common_macro.h"
#include "octvocsamples_string_utils.h"
/* Vocallo samples' common header files */
#include "octvocsamples_pkt_api_session.h"
#include "octvocsamples_main_api_stats.h"
#include "octvocsamples_vspmp_voc_api_stats.h"

/* Verbose OCTVC1 return code */
#define OCTVC1_RC2STRING_DECLARE
#include "vocallo/octvc1_rc2string.h"

/***************************  DEFINES  ***************************************/

/*
 * Voice termination profile indexes.
 */
#define cOCTVOCSAMPLES_TERM_PROFILE_INDEX_A 0
#define cOCTVOCSAMPLES_TERM_PROFILE_INDEX_B 1

/***************************  TYPE DEFINITIONS  ******************************/

/*
 * This structure contains application configuration data.
 */
typedef struct tOCTVOCSAMPLES_APP_CFG_TAG
{
    /* Packet API's physical network interfaces for commands and responses. */
    tOCT_UINT8          abyProcessorCtrlMacAddr[6];                              /* Processor control port's MAC address. */
    tOCT_UINT8          abyVocalloCtrlMacAddr[6];                                /* Vocallo control port's MAC address (port 0 or 1). */
    /* Side A's settings. */
    tOCTVC1_UDP_ADDRESS HostRtpUdpAddressA;                                      /* Host A's RTP UDP address. */
    tOCTVC1_UDP_ADDRESS HostRtcpUdpAddressA;                                     /* Host A's RTCP UDP address. */
    char                szHostRtcpCnameA[cOCTVC1_NET_MAX_CNAME_LENGTH + 1];      /* Host A's RTCP canonical name. */
    tOCT_UINT32         ulVocalloHostEthPortA;                                   /* Vocallo host A's Ethernet port (port 0 or 1). */
    tOCTVC1_IP_ADDRESS  VocalloHostIpAddrA;                                      /* Vocallo host A's IP address. */
    tOCTVC1_IP_ADDRESS  VocalloHostNetworkMaskA;                                 /* Vocallo host A's network mask. */
    tOCT_UINT32         ulRtpMemberRtpUdpPortA;                                  /* RTP member A's RTP UDP port. */
    tOCT_UINT32         ulRtpMemberRtcpUdpPortA;                                 /* RTP member A's RTCP UDP port. */
    tOCT_UINT32         ulRtpPayloadTypeA;                                       /* RTP member A's RTP payload type */
    tOCT_UINT32         ulPktEncodingTypeA;                                      /* RTP member A's packet encoding type */
    char                szRtpMemberRtcpCnameA[cOCTVC1_NET_MAX_CNAME_LENGTH + 1]; /* RTP member A's RTCP canonical name. */
    /* Side B's settings. */
    tOCTVC1_UDP_ADDRESS HostRtpUdpAddressB;                                      /* Host B's RTP UDP address. */
    tOCTVC1_UDP_ADDRESS HostRtcpUdpAddressB;                                     /* Host B's RTCP UDP address. */
    char                szHostRtcpCnameB[cOCTVC1_NET_MAX_CNAME_LENGTH + 1];      /* Host B's RTCP canonical name. */
    tOCT_UINT32         ulVocalloHostEthPortB;                                   /* Vocallo host B's Ethernet port (port 0 or 1). */
    tOCTVC1_IP_ADDRESS  VocalloHostIpAddrB;                                      /* Vocallo host B's IP address. */
    tOCTVC1_IP_ADDRESS  VocalloHostNetworkMaskB;                                 /* Vocallo host B's network mask. */
    tOCT_UINT32         ulRtpMemberRtpUdpPortB;                                  /* RTP member B's RTP UDP port. */
    tOCT_UINT32         ulRtpMemberRtcpUdpPortB;                                 /* RTP member B's RTCP UDP port. */
    tOCT_UINT32         ulRtpPayloadTypeB;                                       /* RTP member B's RTP payload type */
    tOCT_UINT32         ulPktEncodingTypeB;                                      /* RTP member B's packet encoding type */
    char                szRtpMemberRtcpCnameB[cOCTVC1_NET_MAX_CNAME_LENGTH + 1]; /* RTP member B's RTCP canonical name. */
} tOCTVOCSAMPLES_APP_CFG, *tPOCTVOCSAMPLES_APP_CFG, **tPPOCTVOCSAMPLES_APP_CFG;

/*
 * This structure contains application context data.
 */
#define MAX_CONNECTIONS 710
typedef struct tOCTVOCSAMPLES_APP_CTX_TAG
{
    tOCTVOCSAMPLES_PKT_API_INFO PktApiInfo;     /* Packet API information. */
    tOCTVC1_HANDLE              ahEthLinks[2];  /* Ethernet link handles. */
    tOCTVC1_HANDLE              hVocalloHostA;  /* Vocallo host A's handle. */
    tOCTVC1_HANDLE		hVocTermA[MAX_CONNECTIONS];      /* Voice termination A's handle. */
    tOCTVC1_HANDLE              hRtpSessionA[MAX_CONNECTIONS];   /* RTP session A's handle. */
    tOCT_UINT32                 ulRtpMemberIdA[MAX_CONNECTIONS]; /* RTP member A's ID. */
    tOCTVC1_HANDLE              hVocalloHostB;  /* Vocallo host B's handle. */
    tOCTVC1_HANDLE		hVocTermB[MAX_CONNECTIONS];      /* Voice termination B's handle. */
    tOCTVC1_HANDLE		hRtpSessionB[MAX_CONNECTIONS];   /* RTP session B's handle. */
    tOCT_UINT32                 ulRtpMemberIdB[MAX_CONNECTIONS]; /* RTP member B's ID. */
    tOCTVC1_HANDLE              hForwarder;         /* Forwarder's handle. */
    tOCT_UINT32                 ulForwarderFifoId;  /* Forwarder's FIFO ID. */
    tOCTVC1_MAIN_OPUS_CORE_INFO aCoreInfo[cOCTVC1_MAIN_MAX_CORE_NUMBER]; /* Array of core information. */
    tOCT_UINT8                  szProcessImageName[(cOCTVC1_MAIN_PROCESS_IMAGE_NAME_MAX_LENGTH+1)];
    tOCT_UINT32                 ulNumActiveCores;   /* Number of active cores. */
} tOCTVOCSAMPLES_APP_CTX, *tPOCTVOCSAMPLES_APP_CTX, **tPPOCTVOCSAMPLES_APP_CTX;

/***************************  GLOBAL VARIABLES  ******************************/
#define MAX_DSPS 12
#define DSP_IP_BASE 0xC0A84C00
#define DSP_IP_START 201 
#define DSP_IP_FINISH (DSP_IP_START+2*MAX_DSPS-1) 

/*
 * Application configuration data.
 *
 * Note: The values used in this sample are provided as a guide for supplying
 *       the real values in the actual system.
 */
tOCTVOCSAMPLES_APP_CFG g_AppCfg[MAX_DSPS];
#if 0
{
    /* Packet API's physical network interfaces for commands and responses. */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                           /* Processor control port's MAC address. */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                           /* Vocallo control port's MAC address (port 0 or 1). */
    /* Side A's settings. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80064, 0, 0, 0 } }, 1024 }, /* Host A's RTP UDP address [192.168.0.100:1024]. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80064, 0, 0, 0 } }, 1025 }, /* Host A's RTCP UDP address [192.168.0.100:1025]. */
    "host_a@octasic.com",                                             /* Host A's RTCP canonical name. */
    0,                                                                /* Vocallo host A's Ethernet port (port 0 or 1). */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80040, 0, 0, 0 } },           /* Vocallo host A's IP address [192.168.0.64]. */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },           /* Vocallo host A's network mask [255.255.255.0]. */
    1024,                                                             /* RTP member A's RTP UDP port. */
    1025,                                                             /* RTP member A's RTCP UDP port. */
    0,                                                                /* RTP member A's RTP payload type */
    cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_U_LAW,                             /* RTP member A's packet encoding type */
    "rtp_member_a@octasic.com",                                       /* RTP member A's RTCP canonical name. */
    /* Side B's settings. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A64, 0, 0, 0 } }, 1024 }, /* Host B's RTP UDP address [192.168.10.100:1024]. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A64, 0, 0, 0 } }, 1025 }, /* Host B's RTCP UDP address [192.168.10.100:1025]. */
    "host_b@octasic.com",                                             /* Host B's RTCP canonical name. */
    0,                                                                /* Vocallo host B's Ethernet port (port 0 or 1). */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A40, 0, 0, 0 } },           /* Vocallo host B's IP address [192.168.10.64]. */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },           /* Vocallo host B's network mask [255.255.255.0]. */
    1024,                                                             /* RTP member B's RTP UDP port. */
    1025,                                                             /* RTP member B's RTCP UDP port. */
    8,                                                                /* RTP member B's RTP payload type */
    cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_A_LAW,                             /* RTP member B's packet encoding type */
    "rtp_member_b@octasic.com"                                        /* RTP member B's RTCP canonical name. */
};
#endif
/*
 * Application context data.
 */
tOCTVOCSAMPLES_APP_CTX g_AppCtx[MAX_DSPS];

tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP g_AppStats[MAX_DSPS];

/***************************  FUNCTION PROTOTYPES  ***************************/

static int CloseEthernetLinks(tOCT_UINT32 ulCtx);
static int CloseSideA(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber);
static int CloseSideB(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber);
tOCT_UINT32 MyOctVocSamplesOpenPktApiSession(tPOCTVOCSAMPLES_PKT_API_INFO f_pPktApiInfo,
                                           tOCT_UINT8                   f_abyLocalMacAddr[6],
                                           tOCT_UINT8                   f_abyRemoteMacAddr[6]);
static tOCT_UINT32 MySelectLocalMacAddr(tOCT_UINT8 f_abyLocalMacAddr[6]);
static tOCT_UINT32 MySelectRemoteMacAddr(const tPOCTVOCSAMPLES_PKT_API_INFO f_pPktApiInfo,
                                       tOCT_UINT8                         f_abyRemoteMacAddr[6]);
static tOCT_UINT32 MyInitializePktApiInst(tPOCTVOCSAMPLES_PKT_API_INFO f_pPktApiInfo,
                                        const tOCT_UINT8             f_abyLocalMacAddr[6]);
tOCT_UINT32 OctVocSamplesPrintVocTermMcStats(tPOCTVC1_PKT_API_SESS      f_pPktApiSess,
                                             tOCTVC1_HANDLE             *f_phVocTerm,
                                             tOCTVC1_OBJECT_CURSOR_ENUM *f_pulGetMode);
tOCT_UINT32 OctVocSamplesPrintModuleNetConfigInfo(tPOCTVC1_PKT_API_SESS f_pPktApiSess);
static void MonitorLinks(tOCT_UINT32 ulCtx);
static int GetInfoOpusCore(tOCT_UINT32 ulCtx);
static int GetCpuUsage(tOCT_UINT32 ulCtx);
static int GetNumberOfConnections(tOCT_UINT32 ulCtx);
/***************************  PRIVATE FUNCTIONS  *****************************/

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       OpenEthernetLinks

Description:    Opens all Ethernet links (0 and 1).

BPR: This is one half of OpenNetworkResources in audio_transcode_net_api.c
     The function is split as Host links only need to be opened once whereas 
     The Vocallo Hosts need muliple instances

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int OpenEthernetLinks(tOCT_UINT32 ulCtx)
{
    tOCT_UINT32 i;

    /*************************************************************************\
     * Open Ethernet links.
    \*************************************************************************/

    for (i = 0; i < 2; i++)
    {
        tOCTVC1_NET_MSG_ETH_LINK_OPEN_CMD EthLinkOpenCmd;
        tOCTVC1_NET_MSG_ETH_LINK_OPEN_RSP EthLinkOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS CmdExecuteParms;
        tOCT_UINT32                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_ETH_LINK_OPEN_CMD_DEF(&EthLinkOpenCmd);
        EthLinkOpenCmd.ulEthPort         = i;
        EthLinkOpenCmd.IPv4.ulEnableFlag = cOCT_TRUE;
        EthLinkOpenCmd.IPv6.ulEnableFlag = cOCT_TRUE;
        mOCTVC1_NET_MSG_ETH_LINK_OPEN_CMD_SWAP(&EthLinkOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &EthLinkOpenCmd;
        CmdExecuteParms.pRsp           = &EthLinkOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(EthLinkOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_ETH_LINK_OPEN_CID failed (Ethernet %u), rc = 0x%08x\n", i, ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_NET_MSG_ETH_LINK_OPEN_RSP_SWAP(&EthLinkOpenRsp);

        /*
         * Save the handle of the opened Ethernet link.
         */
        g_AppCtx[ulCtx].ahEthLinks[i] = EthLinkOpenRsp.hEthLink;
    }


    return 0;

ErrorHandling:
    CloseEthernetLinks(ulCtx);
    return -1;
}


/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CreateHostSideAB

Description:    Creates Local Host Object.
BPR: This is one half of OpenNetworkResources in audio_transcode_net_api.c
     The function is split as Host links only need to be opened once whereas 
     The Vocallo Hosts need muliple instances

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CreateHostSideAB(tOCT_UINT32 ulCtx){

    /*************************************************************************\
     * Open Vocallo host A.
    \*************************************************************************/
    {
        tOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD LocalHostOpenCmd;
        tOCTVC1_NET_MSG_LOCAL_HOST_OPEN_RSP LocalHostOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS   CmdExecuteParms;
        tOCT_UINT32                         ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD_DEF(&LocalHostOpenCmd);
        LocalHostOpenCmd.IpAddress   = g_AppCfg[ulCtx].VocalloHostIpAddrA;
        LocalHostOpenCmd.NetworkMask = g_AppCfg[ulCtx].VocalloHostNetworkMaskA;
        LocalHostOpenCmd.hLink       = g_AppCtx[ulCtx].ahEthLinks[g_AppCfg[ulCtx].ulVocalloHostEthPortA];
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD_SWAP(&LocalHostOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostOpenCmd;
        CmdExecuteParms.pRsp           = &LocalHostOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_RSP_SWAP(&LocalHostOpenRsp);

        /*
         * Save the handle of the opened local host.
         */
        g_AppCtx[ulCtx].hVocalloHostA = LocalHostOpenRsp.hLocalHost;
    }

    /*************************************************************************\
     * Open Vocallo host B.
    \*************************************************************************/
    {
        tOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD LocalHostOpenCmd;
        tOCTVC1_NET_MSG_LOCAL_HOST_OPEN_RSP LocalHostOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS   CmdExecuteParms;
        tOCT_UINT32                         ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD_DEF(&LocalHostOpenCmd);
	    LocalHostOpenCmd.IpAddress   = g_AppCfg[ulCtx].VocalloHostIpAddrB;
	    LocalHostOpenCmd.NetworkMask = g_AppCfg[ulCtx].VocalloHostNetworkMaskB;
        LocalHostOpenCmd.hLink       = g_AppCtx[ulCtx].ahEthLinks[g_AppCfg[ulCtx].ulVocalloHostEthPortB];
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD_SWAP(&LocalHostOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostOpenCmd;
        CmdExecuteParms.pRsp           = &LocalHostOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_RSP_SWAP(&LocalHostOpenRsp);

        /*
         * Save the handle of the opened local host.
         */
        g_AppCtx[ulCtx].hVocalloHostB = LocalHostOpenRsp.hLocalHost;
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       DestroyHostSideAB

Description:    Destroys Local Host Object.
BPR: This is one half of CloseNetworkResources in audio_transcode_net_api.c
     The function is split as Host links only need to be closed once whereas 
     The Vocallo Hosts need muliple instances to be closed

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int DestroyHostSideAB(tOCT_UINT32 ulCtx){

    /*************************************************************************\
     * Close Vocallo host A.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hVocalloHostA.aulHandle[0])
    {
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD LocalHostCloseCmd;
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_RSP LocalHostCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_DEF(&LocalHostCloseCmd);
        LocalHostCloseCmd.hLocalHost = g_AppCtx[ulCtx].hVocalloHostA;
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_SWAP(&LocalHostCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostCloseCmd;
        CmdExecuteParms.pRsp           = &LocalHostCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx[ulCtx].hVocalloHostA.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close Vocallo host B.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hVocalloHostB.aulHandle[0])
    {
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD LocalHostCloseCmd;
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_RSP LocalHostCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_DEF(&LocalHostCloseCmd);
        LocalHostCloseCmd.hLocalHost = g_AppCtx[ulCtx].hVocalloHostB;
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_SWAP(&LocalHostCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostCloseCmd;
        CmdExecuteParms.pRsp           = &LocalHostCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx[ulCtx].hVocalloHostB.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }


	return 0;
ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseEthernetLinks

Description:    Closes all Ethernet links (0 and 1).
BPR: This is one half of CloseNetworkResources in audio_transcode_net_api.c
     The function is split as Host links only need to be closed once whereas 
     The Vocallo Hosts need muliple instances to be closed

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CloseEthernetLinks(tOCT_UINT32 ulCtx)
{
    tOCT_UINT32 i;
    /*************************************************************************\
     * Close Ethernet links.
    \*************************************************************************/

    for (i = 0; i < 2; i++)
    {
        if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].ahEthLinks[i].aulHandle[0])
        {
            tOCTVC1_NET_MSG_ETH_LINK_CLOSE_CMD EthLinkCloseCmd;
            tOCTVC1_NET_MSG_ETH_LINK_CLOSE_RSP EthLinkCloseRsp;
            tOCTVC1_PKT_API_CMD_EXECUTE_PARMS  CmdExecuteParms;
            tOCT_UINT32                        ulResult;

            /*
             * Prepare command data.
             */
            mOCTVC1_NET_MSG_ETH_LINK_CLOSE_CMD_DEF(&EthLinkCloseCmd);
            EthLinkCloseCmd.hEthLink = g_AppCtx[ulCtx].ahEthLinks[i];
            mOCTVC1_NET_MSG_ETH_LINK_CLOSE_CMD_SWAP(&EthLinkCloseCmd);

            /*
             * Execute the command.
             */
            mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
            CmdExecuteParms.pCmd           = &EthLinkCloseCmd;
            CmdExecuteParms.pRsp           = &EthLinkCloseRsp;
            CmdExecuteParms.ulMaxRspLength = sizeof(EthLinkCloseRsp);
            ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
            if (cOCTVC1_RC_OK != ulResult)
            {
                fprintf(stderr, "Error: cOCTVC1_NET_MSG_ETH_LINK_CLOSE_CID failed (Ethernet %u), rc = 0x%08x\n", i, ulResult);
                fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
                goto ErrorHandling;
            }
            g_AppCtx[ulCtx].ahEthLinks[i].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
        }
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CreateSideA

Description:    Creates side A.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CreateSideA(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Set the media-coder parameters of the voice termination profile A.
    \*************************************************************************/
    {
        tOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD ModuleModifyProfileMcCmd;
        tOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_RSP ModuleModifyProfileMcRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                  CmdExecuteParms;
        tOCT_UINT32                                        ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD_DEF(&ModuleModifyProfileMcCmd);
        ModuleModifyProfileMcCmd.ulProfileIndex                             = cOCTVOCSAMPLES_TERM_PROFILE_INDEX_A;
        ModuleModifyProfileMcCmd.ulRestoreDefaultFlag                       = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulPcmLaw                         = cOCTVC1_VSPMP_VOC_PCM_ENUM_LAW_U;
        mOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD_SWAP(&ModuleModifyProfileMcCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &ModuleModifyProfileMcCmd;
        CmdExecuteParms.pRsp           = &ModuleModifyProfileMcRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(ModuleModifyProfileMcRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
    }

    /*************************************************************************\
     * Open voice termination A.
    \*************************************************************************/
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CMD TermOpenCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_RSP TermOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS   CmdExecuteParms;
        tOCT_UINT32                         ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CMD_DEF(&TermOpenCmd);
        TermOpenCmd.ulProfileIndex          = cOCTVOCSAMPLES_TERM_PROFILE_INDEX_A;
        TermOpenCmd.ulOperState             = cOCTVC1_VSPMP_VOC_TERM_STATE_ENUM_VOICE;
        TermOpenCmd.ulRxExpectedVocoderType = cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64;
        TermOpenCmd.ulTxVocoderType         = cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64;
        TermOpenCmd.aulAllowedVocoders[mOCTVC1_GET_VOCMASK_INDEX(cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64)]
                                            |= mOCTVC1_GET_VOCMASK_BIT(cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64);
        mOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CMD_SWAP(&TermOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermOpenCmd;
        CmdExecuteParms.pRsp           = &TermOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_RSP_SWAP(&TermOpenRsp);

        /*
         * Save the handle of the opened voice termination.
         */
        g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber] = TermOpenRsp.hTerm;
    }

    /*************************************************************************\
     * Open RTP session A.
    \*************************************************************************/
    {
        tOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD RtpSessionOpenCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_OPEN_RSP RtpSessionOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD_DEF(&RtpSessionOpenCmd);
        RtpSessionOpenCmd.hLocalHost = g_AppCtx[ulCtx].hVocalloHostA;
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD_SWAP(&RtpSessionOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionOpenCmd;
        CmdExecuteParms.pRsp           = &RtpSessionOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_OPEN_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_RSP_SWAP(&RtpSessionOpenRsp);

        /*
         * Save the handle of the opened RTP session.
         */
        g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber] = RtpSessionOpenRsp.hRtpSession;
    }

    /*************************************************************************\
     * Activate RTP member A.
    \*************************************************************************/
    {
        tOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD RtpSessionActivateMemberCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_RSP RtpSessionActivateMemberRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS               CmdExecuteParms;
        tOCT_UINT32                                     ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD_DEF(&RtpSessionActivateMemberCmd);
        RtpSessionActivateMemberCmd.hRtpSession                        = g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber];
        RtpSessionActivateMemberCmd.hTerm                              = g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber];
        RtpSessionActivateMemberCmd.ulRxPktFilter                      = cOCTVC1_NET_RX_PKT_FILTER_ENUM_NONE;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtp                  = g_AppCfg[ulCtx].ulRtpMemberRtpUdpPortA;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtcp                 = g_AppCfg[ulCtx].ulRtpMemberRtcpUdpPortA;
        RtpSessionActivateMemberCmd.ulLocalCnameLength                 = strlen(g_AppCfg[ulCtx].szRtpMemberRtcpCnameA);
        strncpy((char *)RtpSessionActivateMemberCmd.achLocalCname, g_AppCfg[ulCtx].szRtpMemberRtcpCnameA, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtp                = g_AppCfg[ulCtx].HostRtpUdpAddressA;
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtcp               = g_AppCfg[ulCtx].HostRtcpUdpAddressA;
        RtpSessionActivateMemberCmd.ulRemoteCnameLength                = strlen(g_AppCfg[ulCtx].szHostRtcpCnameA);
        strncpy((char *)RtpSessionActivateMemberCmd.achRemoteCname, g_AppCfg[ulCtx].szHostRtcpCnameA, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.ulNumProfEntry                     = 1;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulPktEncodingType = g_AppCfg[ulCtx].ulPktEncodingTypeA;;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulRtpPayloadType  = g_AppCfg[ulCtx].ulRtpPayloadTypeA;
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD_SWAP(&RtpSessionActivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionActivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionActivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionActivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_RSP_SWAP(&RtpSessionActivateMemberRsp);
                    
        /*
         * Save the ID of the activated RTP member.
         */
        g_AppCtx[ulCtx].ulRtpMemberIdA[ulConnectionNumber] = RtpSessionActivateMemberRsp.ulLocalMemberId;
    }

    return 0;

ErrorHandling:
    CloseSideA(ulCtx,ulConnectionNumber);
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseSideA

Description:    Closes side A.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CloseSideA(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Deactivate RTP member A.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD RtpSessionDeactivateMemberCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_RSP RtpSessionDeactivateMemberRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                 CmdExecuteParms;
        tOCT_UINT32                                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_DEF(&RtpSessionDeactivateMemberCmd);
        RtpSessionDeactivateMemberCmd.hRtpSession     = g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber];
        RtpSessionDeactivateMemberCmd.ulLocalMemberId = g_AppCtx[ulCtx].ulRtpMemberIdA[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_SWAP(&RtpSessionDeactivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionDeactivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionDeactivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionDeactivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
    }

    /*************************************************************************\
     * Close RTP session A.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD RtpSessionCloseCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_RSP RtpSessionCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS     CmdExecuteParms;
        tOCT_UINT32                           ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_DEF(&RtpSessionCloseCmd);
        RtpSessionCloseCmd.hRtpSession = g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_SWAP(&RtpSessionCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionCloseCmd;
        CmdExecuteParms.pRsp           = &RtpSessionCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close voice termination A.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD TermCloseCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_RSP TermCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_DEF(&TermCloseCmd);
        TermCloseCmd.hTerm = g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber];
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_SWAP(&TermCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermCloseCmd;
        CmdExecuteParms.pRsp           = &TermCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CreateSideB

Description:    Creates side B.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CreateSideB(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Set the media-coder parameters of the voice termination profile B.
    \*************************************************************************/
    {
        tOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD ModuleModifyProfileMcCmd;
        tOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_RSP ModuleModifyProfileMcRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                  CmdExecuteParms;
        tOCT_UINT32                                        ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD_DEF(&ModuleModifyProfileMcCmd);
        ModuleModifyProfileMcCmd.ulProfileIndex                             = cOCTVOCSAMPLES_TERM_PROFILE_INDEX_B;
        ModuleModifyProfileMcCmd.ulRestoreDefaultFlag                       = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulPcmLaw                         = cOCTVC1_VSPMP_VOC_PCM_ENUM_LAW_A;
        ModuleModifyProfileMcCmd.McProfile.ulTxEnableSilenceSuppressionFlag = cOCT_TRUE;/* BPR Change */
        mOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD_SWAP(&ModuleModifyProfileMcCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &ModuleModifyProfileMcCmd;
        CmdExecuteParms.pRsp           = &ModuleModifyProfileMcRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(ModuleModifyProfileMcRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
    }

    /*************************************************************************\
     * Open voice termination B.
    \*************************************************************************/
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CMD TermOpenCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_RSP TermOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS   CmdExecuteParms;
        tOCT_UINT32                         ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CMD_DEF(&TermOpenCmd);
        TermOpenCmd.ulProfileIndex          = cOCTVOCSAMPLES_TERM_PROFILE_INDEX_B;
        TermOpenCmd.ulOperState             = cOCTVC1_VSPMP_VOC_TERM_STATE_ENUM_VOICE;
        TermOpenCmd.ulRxExpectedVocoderType = cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64;
        TermOpenCmd.ulTxVocoderType         = cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64;
        TermOpenCmd.aulAllowedVocoders[mOCTVC1_GET_VOCMASK_INDEX(cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64)]
                                            |= mOCTVC1_GET_VOCMASK_BIT(cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64);
        mOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CMD_SWAP(&TermOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermOpenCmd;
        CmdExecuteParms.pRsp           = &TermOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_RSP_SWAP(&TermOpenRsp);

        /*
         * Save the handle of the opened voice termination.
         */
        g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber] = TermOpenRsp.hTerm;
    }

    /*************************************************************************\
     * Open RTP session B.
    \*************************************************************************/
    {
        tOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD RtpSessionOpenCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_OPEN_RSP RtpSessionOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD_DEF(&RtpSessionOpenCmd);
        RtpSessionOpenCmd.hLocalHost = g_AppCtx[ulCtx].hVocalloHostB;
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD_SWAP(&RtpSessionOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionOpenCmd;
        CmdExecuteParms.pRsp           = &RtpSessionOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_OPEN_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_RSP_SWAP(&RtpSessionOpenRsp);

        /*
         * Save the handle of the opened RTP session.
         */
        g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber] = RtpSessionOpenRsp.hRtpSession;
    }

    /*************************************************************************\
     * Activate RTP member B.
    \*************************************************************************/
    {
        tOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD RtpSessionActivateMemberCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_RSP RtpSessionActivateMemberRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS               CmdExecuteParms;
        tOCT_UINT32                                     ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD_DEF(&RtpSessionActivateMemberCmd);
        RtpSessionActivateMemberCmd.hRtpSession                        = g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber];
        RtpSessionActivateMemberCmd.hTerm                              = g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber];
        RtpSessionActivateMemberCmd.ulRxPktFilter                      = cOCTVC1_NET_RX_PKT_FILTER_ENUM_NONE;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtp                  = g_AppCfg[ulCtx].ulRtpMemberRtpUdpPortB;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtcp                 = g_AppCfg[ulCtx].ulRtpMemberRtcpUdpPortB;
        RtpSessionActivateMemberCmd.ulLocalCnameLength                 = strlen(g_AppCfg[ulCtx].szRtpMemberRtcpCnameB);
        strncpy((char *)RtpSessionActivateMemberCmd.achLocalCname, g_AppCfg[ulCtx].szRtpMemberRtcpCnameB, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtp                = g_AppCfg[ulCtx].HostRtpUdpAddressB;
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtcp               = g_AppCfg[ulCtx].HostRtcpUdpAddressB;
        RtpSessionActivateMemberCmd.ulRemoteCnameLength                = strlen(g_AppCfg[ulCtx].szHostRtcpCnameB);
        strncpy((char *)RtpSessionActivateMemberCmd.achRemoteCname, g_AppCfg[ulCtx].szHostRtcpCnameB, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.ulNumProfEntry                     = 1;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulPktEncodingType = g_AppCfg[ulCtx].ulPktEncodingTypeB;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulRtpPayloadType  = g_AppCfg[ulCtx].ulRtpPayloadTypeB;
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD_SWAP(&RtpSessionActivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionActivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionActivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionActivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_RSP_SWAP(&RtpSessionActivateMemberRsp);
                    
        /*
         * Save the ID of the activated RTP member.
         */
        g_AppCtx[ulCtx].ulRtpMemberIdB[ulConnectionNumber] = RtpSessionActivateMemberRsp.ulLocalMemberId;
    }

    return 0;

ErrorHandling:
    CloseSideB(ulCtx,ulConnectionNumber);
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseSideB

Description:    Closes side B.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CloseSideB(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Deactivate RTP member B.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD RtpSessionDeactivateMemberCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_RSP RtpSessionDeactivateMemberRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                 CmdExecuteParms;
        tOCT_UINT32                                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_DEF(&RtpSessionDeactivateMemberCmd);
        RtpSessionDeactivateMemberCmd.hRtpSession     = g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber];
        RtpSessionDeactivateMemberCmd.ulLocalMemberId = g_AppCtx[ulCtx].ulRtpMemberIdB[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_SWAP(&RtpSessionDeactivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionDeactivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionDeactivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionDeactivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
    }

    /*************************************************************************\
     * Close RTP session B.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD RtpSessionCloseCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_RSP RtpSessionCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS     CmdExecuteParms;
        tOCT_UINT32                           ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_DEF(&RtpSessionCloseCmd);
        RtpSessionCloseCmd.hRtpSession = g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_SWAP(&RtpSessionCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionCloseCmd;
        CmdExecuteParms.pRsp           = &RtpSessionCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close voice termination B.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD TermCloseCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_RSP TermCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_DEF(&TermCloseCmd);
        TermCloseCmd.hTerm = g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber];
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_SWAP(&TermCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermCloseCmd;
        CmdExecuteParms.pRsp           = &TermCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }


    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       ConnectTerms

Description:    Connects the two voice terminations (A and B).

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int ConnectTerms(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber)
{
    tOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_CMD TermConnectCmd;
    tOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_RSP TermConnectRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS      CmdExecuteParms;
    tOCT_UINT32                            ulResult;

    /*
     * Prepare command data.
     */
    mOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_CMD_DEF(&TermConnectCmd);
    TermConnectCmd.hTermFirst  = g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber];
    TermConnectCmd.hTermSecond = g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber];
    mOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_CMD_SWAP(&TermConnectCmd);

    /*
     * Execute the command.
     */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &TermConnectCmd;
    CmdExecuteParms.pRsp           = &TermConnectRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(TermConnectRsp);
    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {            
        fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_CID failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
        goto ErrorHandling;
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       DisconnectTerms

Description:    Disconnects both voice terminations (A and B).

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int DisconnectTerms(tOCT_UINT32 ulCtx,tOCT_UINT32 ulConnectionNumber)
{
    if (cOCTVC1_HANDLE_INVALID != g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_CMD TermDisconnectCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_RSP TermDisconnectRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS         CmdExecuteParms;
        tOCT_UINT32                               ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_CMD_DEF(&TermDisconnectCmd);
        TermDisconnectCmd.hTerm = g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber];
        mOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_CMD_SWAP(&TermDisconnectCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermDisconnectCmd;
        CmdExecuteParms.pRsp           = &TermDisconnectRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermDisconnectRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       InitApplication

Description:    Performs initialization tasks required by the application.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int InitApplication(tOCT_UINT8 *abyProcessorCtrlMacAddr)
{
    tOCT_UINT32 ulResult;
    tOCT_UINT32 ulConnectionNumber;
    tOCT_UINT32 ulCtx;/* counter to index Context Array */
    

	memset(g_AppCfg,0,(MAX_DSPS*sizeof(tOCTVOCSAMPLES_APP_CFG)));
    for(ulCtx=0;ulCtx<MAX_DSPS;ulCtx++){
    /* set up Application Contexts */
    	memcpy(g_AppCfg[ulCtx].abyProcessorCtrlMacAddr,abyProcessorCtrlMacAddr,6);

    /* Side A's settings. */
		/*    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80064, 0, 0, 0 } }, 1024 }, */
		/* Host A's RTP UDP address [192.168.76.212:1024]. */
		g_AppCfg[ulCtx].HostRtpUdpAddressA.IpAddress.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].HostRtpUdpAddressA.IpAddress.aulIpAddress[0]=0xC0A84C00+(DSP_IP_FINISH-ulCtx);
		g_AppCfg[ulCtx].HostRtpUdpAddressA.ulUdpPort=1024;

    	/*{ { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80064, 0, 0, 0 } }, 1025 }, */
    	/* Host A's RTCP UDP address [192.168.76.212:1025]. */
		g_AppCfg[ulCtx].HostRtcpUdpAddressA.IpAddress.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].HostRtcpUdpAddressA.IpAddress.aulIpAddress[0]=0xC0A84C00+(DSP_IP_FINISH-ulCtx);
		g_AppCfg[ulCtx].HostRtcpUdpAddressA.ulUdpPort=1025;
		/* Host A's RTCP canonical name. */
	    sprintf(g_AppCfg[ulCtx].szHostRtcpCnameA,"host_a_%d",DSP_IP_FINISH-ulCtx);
	    /* Side A Source */
	    g_AppCfg[ulCtx].ulVocalloHostEthPortA=0;/* Vocallo host A's Ethernet port (port 0 or 1). Use 0 on PCIe-8120/ATCA-8320 and 1 on EB */
	    /*{ cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80040, 0, 0, 0 } },  */         
	    /* Vocallo host A's IP address [192.168.76.201]. */
		g_AppCfg[ulCtx].VocalloHostIpAddrA.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].VocalloHostIpAddrA.aulIpAddress[0]=0xC0A84C00+(DSP_IP_START+ulCtx);
    
	    /*{ cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },           */
	    /* Vocallo host A's network mask [255.255.248.0]. */
		g_AppCfg[ulCtx].VocalloHostNetworkMaskA.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].VocalloHostNetworkMaskA.aulIpAddress[0]=0xFFFFF800;
	    g_AppCfg[ulCtx].ulRtpMemberRtpUdpPortA=1024;/* RTP member A's RTP UDP port. */
	    g_AppCfg[ulCtx].ulRtpMemberRtcpUdpPortA=1025;/* RTP member A's RTCP UDP port. */
    	g_AppCfg[ulCtx].ulRtpPayloadTypeA=0;/* RTP member A's RTP payload type */
	    g_AppCfg[ulCtx].ulPktEncodingTypeA=cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_U_LAW;/* RTP member A's packet encoding type */
    	sprintf(g_AppCfg[ulCtx].szRtpMemberRtcpCnameA,"rtp_member_a_%d",ulCtx);/* RTP member A's RTCP canonical name. */
	    /* Side B's settings. */
		/*	    g_AppCfg[ulCtx].HostRtpUdpAddressB={ { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A84B0A, 0, 0, 0 } }, 0x8000 }; */
		/* Dest Host B's RTP UDP address [192.168.75.212:1024]. */
		g_AppCfg[ulCtx].HostRtpUdpAddressB.IpAddress.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].HostRtpUdpAddressB.IpAddress.aulIpAddress[0]=0xC0A84B00+(DSP_IP_FINISH-ulCtx);
		g_AppCfg[ulCtx].HostRtpUdpAddressB.ulUdpPort=1024;
		/*	    g_AppCfg[ulCtx].HostRtcpUdpAddressB={ { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A84B0A, 0, 0, 0 } }, 0x8001 }; */
		/* Dest Host B's RTCP UDP address [192.168.75.212:1025]. */
		g_AppCfg[ulCtx].HostRtcpUdpAddressB.IpAddress.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].HostRtcpUdpAddressB.IpAddress.aulIpAddress[0]=0xC0A84B00+(DSP_IP_FINISH-ulCtx);
		g_AppCfg[ulCtx].HostRtcpUdpAddressB.ulUdpPort=1025;
	    sprintf(g_AppCfg[ulCtx].szHostRtcpCnameB,"host_b_%d",DSP_IP_FINISH-ulCtx);
	    /* Side B Source */
	    g_AppCfg[ulCtx].ulVocalloHostEthPortB=0;/* Vocallo host B's Ethernet port (port 0 or 1). Use 0 on PCIe-8120/ATCA-8320 and 1 on EB */
		/*	    g_AppCfg[ulCtx].VocalloHostIpAddrB={ cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A84BC9, 0, 0, 0 } };*/
		/* Vocallo host B's IP address [192.168.75.201]. */
		g_AppCfg[ulCtx].VocalloHostIpAddrB.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].VocalloHostIpAddrB.aulIpAddress[0]=0xC0A84B00+(DSP_IP_START+ulCtx);
		/*	    g_AppCfg[ulCtx].VocalloHostNetworkMaskB={ cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFF800, 0, 0, 0 } };*/
		/* Vocallo host B's network mask [255.255.248.0]. */
		g_AppCfg[ulCtx].VocalloHostNetworkMaskB.ulIpVersion=cOCTVC1_IP_VERSION_ENUM_4;
	    g_AppCfg[ulCtx].VocalloHostNetworkMaskB.aulIpAddress[0]=0xFFFFF800;
	    g_AppCfg[ulCtx].ulRtpMemberRtpUdpPortB=1024;/* RTP member B's RTP UDP port. */
	    g_AppCfg[ulCtx].ulRtpMemberRtcpUdpPortB=1025;/* RTP member B's RTCP UDP port. */
	    g_AppCfg[ulCtx].ulRtpPayloadTypeB=8;/* RTP member B's RTP payload type */
	    g_AppCfg[ulCtx].ulPktEncodingTypeB=cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_A_LAW;/* RTP member B's packet encoding type */
	    sprintf(g_AppCfg[ulCtx].szRtpMemberRtcpCnameB,"rtp_member_b_%d",ulCtx);/* RTP member B's RTCP canonical name. */

	    /*
	     * Initialize all handles to invalid.
	     */
	    g_AppCtx[ulCtx].ahEthLinks[0].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
	    g_AppCtx[ulCtx].ahEthLinks[1].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
	    for (ulConnectionNumber=0;ulConnectionNumber<MAX_CONNECTIONS;ulConnectionNumber++){
		    g_AppCtx[ulCtx].hVocalloHostA.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
		    g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber].aulHandle[0]     = cOCTVC1_HANDLE_INVALID;
		    g_AppCtx[ulCtx].hRtpSessionA[ulConnectionNumber].aulHandle[0]  = cOCTVC1_HANDLE_INVALID;
		    g_AppCtx[ulCtx].hVocalloHostB.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
		    g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber].aulHandle[0]     = cOCTVC1_HANDLE_INVALID;
		    g_AppCtx[ulCtx].hRtpSessionB[ulConnectionNumber].aulHandle[0]  = cOCTVC1_HANDLE_INVALID;
		}
	    /*
	     * Open a transport packet API session.
	     */
		    ulResult = MyOctVocSamplesOpenPktApiSession(&g_AppCtx[ulCtx].PktApiInfo,
		                                              g_AppCfg[ulCtx].abyProcessorCtrlMacAddr,
		                                              g_AppCfg[ulCtx].abyVocalloCtrlMacAddr);
	    if (cOCTVC1_RC_OK != ulResult)
	    {
	        fprintf(stderr, "Error: OctVocSamplesOpenPktApiSession() failed, rc = 0x%08x\n", ulResult);
	        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
	        goto ErrorHandling;
	    }
	
	    /*
	     * Update Ethernet port number to the port we are connected to.
	     */
	    printf("Connected to port %u of Vocallo device\n", g_AppCtx[ulCtx].PktApiInfo.ulPktApiCnctPortIdx);
	    if (g_AppCfg[ulCtx].ulVocalloHostEthPortA != g_AppCtx[ulCtx].PktApiInfo.ulPktApiCnctPortIdx &&
	        g_AppCfg[ulCtx].ulVocalloHostEthPortB != g_AppCtx[ulCtx].PktApiInfo.ulPktApiCnctPortIdx)
	    {
	        printf("Updating Vocallo host A Ethernet port configuration to %u\n\n", g_AppCtx[ulCtx].PktApiInfo.ulPktApiCnctPortIdx);
	        g_AppCfg[ulCtx].ulVocalloHostEthPortA = g_AppCtx[ulCtx].PktApiInfo.ulPktApiCnctPortIdx;
	    }
	    else
	        printf("\n");
	
	    /*
	     * Print the version of Vocallo in use on the device.
	     */
	    ulResult = OctVocSamplesPrintModuleVersionInfo(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess);
	    if (cOCTVC1_RC_OK != ulResult)
	    {
	        fprintf(stderr, "Error: OctVocSamplesPrintModuleVersionInfo() failed, rc = 0x%08x\n", ulResult);
	        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
	        return -1;
	    }
	    
	    /*
	     * Print the info for the device.
	     */
	    ulResult = OctVocSamplesPrintDeviceInfo(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess);
	    if (cOCTVC1_RC_OK != ulResult)
	    {
	        fprintf(stderr, "Error: OctVocSamplesPrintDeviceInfo() failed, rc = 0x%08x\n", ulResult);
	        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
	        return -1;
	    }
	
	    /*
	     * Free the resources previously allocated by the CPP, VSPMP and NET APIs.
	     */
	    {
	        tOCTVC1_MAIN_MSG_MODULE_CLEANUP_API_RESOURCE_CMD ModuleCleanupApiResourceCmd;
	        tOCTVC1_MAIN_MSG_MODULE_CLEANUP_API_RESOURCE_RSP ModuleCleanupApiResourceRsp;
	        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                CmdExecuteParms;
	
	        /*
	         * Prepare command data.
	         */
	        mOCTVC1_MAIN_MSG_MODULE_CLEANUP_API_RESOURCE_CMD_DEF(&ModuleCleanupApiResourceCmd);
	        mOCTVC1_MAIN_MSG_MODULE_CLEANUP_API_RESOURCE_CMD_SWAP(&ModuleCleanupApiResourceCmd);
	
	        /*
	         * Execute the command.
	         */
	        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
	        CmdExecuteParms.pCmd           = &ModuleCleanupApiResourceCmd;
	        CmdExecuteParms.pRsp           = &ModuleCleanupApiResourceRsp;
	        CmdExecuteParms.ulMaxRspLength = sizeof(ModuleCleanupApiResourceRsp);
	        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
	        if (cOCTVC1_RC_OK != ulResult)
	        {
	            fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_MODULE_CLEANUP_API_RESOURCE_CID failed, rc = 0x%08x\n", ulResult);
	            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
	            goto ErrorHandling;
	        }
	    }
	}
    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       ExitApplication

Description:    Frees any resources used by the application.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static void ExitApplication(void)
{
#if 0 
    tOCT_UINT32 ulResult;
    

    /*
     * Close the only packet API session.
     */
    /* BPR This causes an error remove for now 
       Error: OctVocSamplesClosePktApiSession() failed, rc = 0x0a0a0103
       (cOCTVC1_PKT_API_RC_INST_CNCT_DEP)
    */
    ulResult = OctVocSamplesClosePktApiSession(&(g_AppCtx[0].PktApiInfo));
    if (cOCTVC1_RC_OK != ulResult)
    {
        fprintf(stderr, "Error: OctVocSamplesClosePktApiSession() failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
    }
#endif
}


/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       main

Description:    Main program.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

int main(int argc, char *argv[])
{
	tOCT_UINT32 ulNumConnections = 0;
    tOCT_UINT32 ulConnectionNumber;
    tOCT_UINT32 ulCtx;/* counter to index Context Array */
    tOCT_UINT8 abyProcessorCtrlMacAddr[6];
    tOCT_UINT32 auProcessorCtrlMacAddr[6];
    tOCT_INT32 iterations=0;
    /*
     * Display application version information.
     */
    mOCT_PRINT_APP_VERSION_INFO("12dsp_audio_transcode_net_api",
                                ((cOCTVC1_MAIN_VERSION_ID >> 25 ) & 0x7F),
                                ((cOCTVC1_MAIN_VERSION_ID >> 18)  & 0x7F),
                                ((cOCTVC1_MAIN_VERSION_ID >> 11)  & 0x7F));

    /* 
     * Parse Input line *
     */
    if ((argc == 3)&&
        (sscanf(argv[1],"%2x:%2x:%2x:%2x:%2x:%2x",
                        &auProcessorCtrlMacAddr[0],
                        &auProcessorCtrlMacAddr[1],
                        &auProcessorCtrlMacAddr[2],
                        &auProcessorCtrlMacAddr[3],
                        &auProcessorCtrlMacAddr[4],
                        &auProcessorCtrlMacAddr[5])==6))
    {
        tOCT_UINT8 i;
        iterations = atoi(argv[2]);
        for (i=0;i<6;i++) /* sscanf only works with int so copy to byte array */
            abyProcessorCtrlMacAddr[i] = (tOCT_UINT8)auProcessorCtrlMacAddr[i];
    }
    else
    {
        printf("usage: 12dsp_audio_transcode_net_api <Host MAC Address> <Number of iterations> \n");
        printf("Host MAC Address usually 10G interface: XX:XX:XX:XX:XX:XX \n");
        printf("Number of iterations: -1 for run contiuously\n");
        printf("Example usage: \n");
        printf("    12dsp_audio_transcode_net_api EC:9E:CD:03:7D:FF -1\n");
        exit(1);
    }

    /*
     * Perform initialization tasks required by the application.
     */
    if (0 != InitApplication(abyProcessorCtrlMacAddr))
    {
        return 1;
    }
	/* Loop through DSPs */
    for(ulCtx=0;ulCtx<MAX_DSPS;ulCtx++){
    	/* this is only really need once and then copy to all contexts ??? */
		/* Find out how many Terminations we are allowed. */
		ulNumConnections =GetNumberOfConnections(ulCtx);
		assert(ulNumConnections<=MAX_CONNECTIONS);
		if ((ulNumConnections>MAX_CONNECTIONS)||(ulNumConnections==0))
		{
			printf("ulNumConnections out of range : %d\n",ulNumConnections);
	        goto ErrorHandling;
	    }
			
		/* Check to see how many the TDM side can handle */
		OctVocSamplesPrintModuleSwConfigInfo(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess);

    /*
     * Create the packet-to-packet voice transcoding channel.
     */
	    if (0 != OpenEthernetLinks(ulCtx))
	    {
	        goto ErrorHandling;
	    }
	    if (0 != CreateHostSideAB(ulCtx))
	    {
	        goto ErrorHandling;
	    }
		/* Loop trhough DSPs */
		
	    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
	    {
	        if ((0 != CreateSideA(ulCtx,ulConnectionNumber)) ||
	    		(0 != CreateSideB(ulCtx,ulConnectionNumber)) ||
	    		(0 != ConnectTerms(ulCtx,ulConnectionNumber)))
		    {
		        goto ErrorHandling;
		    }

	        /* Increment UDP ports by two as odd and even are seperate */
	        g_AppCfg[ulCtx].ulRtpMemberRtpUdpPortA+=2;/* Source RTP port */
	        g_AppCfg[ulCtx].ulRtpMemberRtcpUdpPortA+=2;/* Source RTCP port */
	        g_AppCfg[ulCtx].HostRtpUdpAddressA.ulUdpPort+=2;/* Destination RTP UDP port. */
	    	g_AppCfg[ulCtx].HostRtcpUdpAddressA.ulUdpPort+=2;/* Destination RTCP UDP port. */
	        g_AppCfg[ulCtx].ulRtpMemberRtpUdpPortB+=2;/* Source RTP port */
	        g_AppCfg[ulCtx].ulRtpMemberRtcpUdpPortB+=2;/* Source RTCP port */
	        g_AppCfg[ulCtx].HostRtpUdpAddressB.ulUdpPort+=2;/* Destination RTP UDP port. */
	    	g_AppCfg[ulCtx].HostRtcpUdpAddressB.ulUdpPort+=2;/* Destination RTCP UDP port. */
#if 0
			if(ulConnectionNumber%100==0){
				printf("ulCtx = %d ulConnectionNumber = %d\n",ulCtx,ulConnectionNumber-1);
			    printf("Press [Enter] to continue\n");
			    getchar();
			}
#endif
		}
		printf("ulCtx = %d ulConnectionNumber = %d\n",ulCtx,ulConnectionNumber-1);
	}
	if (iterations<0)
	{
	    tOCT_INT32 i=0;
	    forever:
            printf("*** Loop: %d ***\n",i++);	    
	        //MonitorLinks();
	    goto forever;
	} else {
	    tOCT_INT32 i;
	    tOCT_INT32 ulCtx=0;
            for(ulCtx=0;ulCtx<MAX_DSPS;ulCtx++){
            
	        for (i=0;i<iterations;i++)
	        {
                    //printf("*** Link Loop: %d ***\n",i);	    
	            //     MonitorLinks();
	            g_AppCtx[ulCtx].ulNumActiveCores = 0;
                    printf("\n\nRetrieving Opus core information from DSP#%d:\n\n", i);
                    if (0 != GetInfoOpusCore(ulCtx))
                    {
                       goto ErrorHandling;
                    } 
                    printf("*** CPU Loop: %d ***\n",i);	    
                    int result = GetCpuUsage(ulCtx);
                    if (0 != result)
                    {
                        goto ErrorHandling;
                    }
                    printf("*** CPU Loop End: %d ***\n",i);	    
	        }
	    }
        }
#if 0
    /*
     * Wait for the user to quit the application.
     */
    printf("Ready to perform packet-to-packet voice transcoding...\n\n");
    printf("Press [Enter] to quit the application\n");
    getchar();
#endif
	/* Loop through DSPs */
    for(ulCtx=0;ulCtx<MAX_DSPS;ulCtx++){

    /*
     * Close the packet-to-packet voice transcoding channel.
     */
		for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
		{
			DisconnectTerms(ulCtx,ulConnectionNumber);
            CloseSideB(ulCtx,ulConnectionNumber);
            CloseSideA(ulCtx,ulConnectionNumber);
		}
		DestroyHostSideAB(ulCtx);
		CloseEthernetLinks(ulCtx);
	}
    /*
     * Free any resources used by the application.
     */
    ExitApplication();

    return 0;

ErrorHandling:
    ExitApplication();

    return 1;
}
/* functions borrowed from octvocsamples_pkt_api_session.c */
/***************************  TYPE DEFINITIONS  ******************************/

/*
 * Device port information.
 */
typedef struct tOCTVOCSAMPLES_DEV_PORT_INFO_TAG
{
    tOCT_UINT8  abyPort0MacAddr[6]; /* Vocallo device's port 0 MAC address. */
    tOCT_UINT32 fIsPort0Reachable;  /* Flag: cOCT_TRUE if port 0 is reachable. */
    tOCT_UINT8  abyPort1MacAddr[6]; /* Vocallo device's port 1 MAC address. */
    tOCT_UINT32 fIsPort1Reachable;  /* Flag: cOCT_TRUE if port 1 is reachable. */
} tOCTVOCSAMPLES_DEV_PORT_INFO, *tPOCTVOCSAMPLES_DEV_PORT_INFO, **tPPOCTVOCSAMPLES_DEV_PORT_INFO;

/***************************  CONSTANTS  *************************************/

extern const tOCT_UINT8 g_abyNullMacAddr[6];

/***************************  PRIVATE FUNCTIONS  *****************************/

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MyInitializePktApiInst

Description:    Initializes a packet API instance.

BPR: Copied from octvocsamples_pkt_api_session.c

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static tOCT_UINT32 MyInitializePktApiInst(tPOCTVOCSAMPLES_PKT_API_INFO f_pPktApiInfo,
                                        const tOCT_UINT8             f_abyLocalMacAddr[6])
{
    tOCTVC1_PKT_API_INST_GET_SIZE_PARMS InstGetSizeParms;
    tOCTVC1_PKT_API_INST_INIT_PARMS     InstInitParms;
    tOCT_UINT32                         ulResult;
    tOCT_UINT16                         usTime;

    /*
     * Get current time to create unique instance.
     */
#if (!1)
    /* use it prior to SDK 03.xx.xx */
    usTime = (tOCT_UINT16)OctOsalGetTimeMs( NULL );
#else
    /* use it for later SDK 03.xx.xx */
    usTime = (tOCT_UINT16)OctOsalGetTimeMs();
#endif
    mOCTVC1_PKT_API_INST_GET_SIZE_PARMS_DEF(&InstGetSizeParms);
    InstGetSizeParms.pInitParms = &InstInitParms;

    mOCTVC1_PKT_API_INST_INIT_PARMS_DEF(&InstInitParms);
    InstInitParms.ulMaxConnection = MAX_DSPS;/* BPR Change */
    InstInitParms.ulMaxSession    = 1;
    InstInitParms.ulMaxSyncCmd    = 8;
    InstInitParms.ulMaxRetry      = 1;
    InstInitParms.usSessionInstanceStart = usTime;
    memcpy(&InstInitParms.abyLocalMac, f_abyLocalMacAddr, 6);

    /*
     * Get the size, in bytes, of the packet API instance.
     */
    ulResult = OctVc1PktApiInstGetSize(&InstGetSizeParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        goto ErrorHandling;
    }

    /*
     * Allocate memory for the packet API instance.
     */
    f_pPktApiInfo->pPktApiInst = (tPOCTVC1_PKT_API_INST)malloc(InstGetSizeParms.ulRequiredSize);
    if (NULL == f_pPktApiInfo->pPktApiInst)
    {
        return cOCTVC1_PKT_API_RC_OS_ERROR;
    }

    /*
     * Initialize a packet API instance.
     */
    ulResult = OctVc1PktApiInstInit(f_pPktApiInfo->pPktApiInst, &InstInitParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        goto ErrorHandling;
    }

    return cOCTVC1_RC_OK;

ErrorHandling:
    if (f_pPktApiInfo->pPktApiInst)
    {
        free(f_pPktApiInfo->pPktApiInst);
        f_pPktApiInfo->pPktApiInst = NULL;
    }

    return ulResult;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MyOpenPktApiCnct

Description:    Opens a connection between the transport packet API instance
                and the Vocallo device.

BPR: Copied from octvocsamples_pkt_api_session.c

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static tOCT_UINT32 MyOpenPktApiCnct(tPOCTVOCSAMPLES_PKT_API_INFO f_pPktApiInfo,
                                  const tOCT_UINT8             f_abyRemoteMacAddr[6])
{
    tOCTVC1_PKT_API_CNCT_OPEN_PARMS CnctOpenParms;
    tOCT_UINT32                     ulResult;

    mOCTVC1_PKT_API_CNCT_OPEN_PARMS_DEF(&CnctOpenParms);
    memcpy(CnctOpenParms.abyRemoteMac, f_abyRemoteMacAddr, 6);

    ulResult = OctVc1PktApiCnctOpen(f_pPktApiInfo->pPktApiInst, &CnctOpenParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        goto ErrorHandling;
    }
    f_pPktApiInfo->pPktApiCnct = CnctOpenParms.pConnection;

    return cOCTVC1_RC_OK;

ErrorHandling:
    return ulResult;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       GetNumLocalNetworkAdapters

Description:    Returns the number of local network adapters present.

BPR: Copied from octvocsamples_pkt_api_session.c

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static tOCT_UINT32 GetNumLocalNetworkAdapters(void)
{
    tOCTVC1_PKT_API_SYSTEM_GET_MAC_ADDR_PARMS SystemGetLocalMacAddrParms;

    for (SystemGetLocalMacAddrParms.ulAdaptorIndex = 0; cOCT_TRUE; SystemGetLocalMacAddrParms.ulAdaptorIndex++)
    {
        if (cOCTVC1_RC_OK !=  OctVc1PktApiGetLocalMacAddr(&SystemGetLocalMacAddrParms))
        {
            break;
        }
    }
    
    return (SystemGetLocalMacAddrParms.ulAdaptorIndex);
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MySelectLocalMacAddr

Description:    Lets the user select a MAC address from the list of available
                local MAC addresses.

BPR: Copied from octvocsamples_pkt_api_session.c

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static tOCT_UINT32 MySelectLocalMacAddr(tOCT_UINT8 f_abyLocalMacAddr[6])
{
    tOCTVC1_PKT_API_SYSTEM_GET_MAC_ADDR_PARMS SystemGetLocalMacAddrParms;
    tOCT_UINT32                               ulSelectedAdapterIndex;
    tOCT_UINT32                               ulNumAdapters;
    tOCT_UINT32                               ulResult;

    /*
     * Get the number of local network adapters present.
     */
    ulNumAdapters = GetNumLocalNetworkAdapters();
    if (0 == ulNumAdapters)
    {
        printf("No network adapters found\n\n");
        return cOCTVC1_PKT_API_RC_LOCAL_MAC_INDEX_NOT_FOUND;
    }

    if (1 < ulNumAdapters)
    {
        /*
         * List all local network adapters.
         */
        printf("Local network adapters:\n");
        for (SystemGetLocalMacAddrParms.ulAdaptorIndex = 0; cOCT_TRUE; SystemGetLocalMacAddrParms.ulAdaptorIndex++)
        {
            char szMacAddr[18];

            ulResult = OctVc1PktApiGetLocalMacAddr(&SystemGetLocalMacAddrParms);
            if (cOCTVC1_RC_OK != ulResult)
            {
                break;
            }

            OctVocSamplesMacAddr2Str(szMacAddr, SystemGetLocalMacAddrParms.abyLocalMac);
            printf(" [%u]: %s\n", SystemGetLocalMacAddrParms.ulAdaptorIndex, szMacAddr);
        }

        /*
         * Prompt the user to select an adapter.
         */
        while (cOCT_TRUE)
        {
            char szChoice[80];

            printf("Select an adapter [default: 0]: ");
            fgets(szChoice, 80, stdin);

            ulSelectedAdapterIndex = atoi(szChoice);
            if (ulSelectedAdapterIndex < SystemGetLocalMacAddrParms.ulAdaptorIndex)
            {
                break;
            }
        }
        fputc('\n', stdout);
    }
    else
    {
        /*
         * Only one adapter is present.
         */
        ulSelectedAdapterIndex = 0;
    }

    /*
     * Return the selected network adapter's MAC address.
     */
    SystemGetLocalMacAddrParms.ulAdaptorIndex = ulSelectedAdapterIndex;
    ulResult = OctVc1PktApiGetLocalMacAddr(&SystemGetLocalMacAddrParms);
    memcpy(f_abyLocalMacAddr, SystemGetLocalMacAddrParms.abyLocalMac, 6);

    return ulResult;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MySelectRemoteMacAddr

Description:    Lets the user select a MAC address from the list of available
                remote MAC addresses.

BPR: Copied from octvocsamples_pkt_api_session.c

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static tOCT_UINT32 MySelectRemoteMacAddr(const tPOCTVOCSAMPLES_PKT_API_INFO f_pPktApiInfo,
                                       tOCT_UINT8                         f_abyRemoteMacAddr[6])
{
    tOCTVC1_PKT_API_INST_DISCOVER_DEV_PARMS InstDiscoverDevParms = { 0 };
    tOCT_UINT32                             ulDeviceIdx;
    tOCT_UINT32                             ulSelectedDevIndex;
    tPOCTVC1_PKT_API_DEV_INFO               pSelectedDevInfo = NULL;
    tOCTVOCSAMPLES_DEV_PORT_INFO            DevPortInfo = { { 0 } };
    tOCT_UINT32                             ulPortIndex;
    tOCT_UINT32                             ulSelectedPortIndex = 0;

    /*
     * Discover the Vocallo devices reachable through the specified instance.
     */
    mOCTVC1_PKT_API_INST_DISCOVER_DEV_PARMS_DEF(&InstDiscoverDevParms);
    InstDiscoverDevParms.ulTimeoutMs = 2000;
    OctVc1PktApiInstDiscoverDev(f_pPktApiInfo->pPktApiInst, &InstDiscoverDevParms);

    if (0 == InstDiscoverDevParms.ulDeviceCnt)
    {
        printf("No Vocallo device found\n\n");
        return cOCTVC1_PKT_API_RC_TRANSPORT_ERROR;
    }
#if 0 /* BPR Change */
    if (1 < InstDiscoverDevParms.ulDeviceCnt)
    {
        /*
         * List all Vocallo devices.
         */
        printf("Vocallo devices:\n");
        for (ulDeviceIdx = 0; ulDeviceIdx < InstDiscoverDevParms.ulDeviceCnt; ulDeviceIdx++)
        {
            tPOCTVC1_PKT_API_DEV_INFO pDevInfo = &InstDiscoverDevParms.aDeviceInfo[ulDeviceIdx];

            printf(" [%u]: Vocallo %u\n", ulDeviceIdx, ulDeviceIdx + 1);
            for (ulPortIndex = 0; ulPortIndex < pDevInfo->ulPortCnt; ulPortIndex++)
            {
                if (cOCTVC1_PKT_API_DEV_PORT_TYPE_ETH == pDevInfo->aPortInfo[ulPortIndex].ulPortType)
                {
                    if (pDevInfo->aPortInfo[ulPortIndex].fReachable)
                    {
                        char szMacAddr[18];

                        OctVocSamplesMacAddr2Str(szMacAddr, pDevInfo->aPortInfo[ulPortIndex].Type.Eth.abyMacAddr);
                        printf("  Port %u: %s\n", pDevInfo->aPortInfo[ulPortIndex].Type.Eth.ulPortId, szMacAddr);
                    }
                }
            }
        }

        /*
         * Prompt the user to select a Vocallo device.
         */
        while (cOCT_TRUE)
        {
            char szChoice[80];

            printf("Select a device [default: 0]: ");
            fgets(szChoice, 80, stdin);

            ulSelectedDevIndex = atoi(szChoice);
            if (ulSelectedDevIndex < ulDeviceIdx)
            {
                break;
            }
        }
        fputc('\n', stdout);
    }
    else
    {
        /*
         * Only one Vocallo device is present.
         */
        ulSelectedDevIndex = 0;
    }
#else /* BPR Change */
    if (MAX_DSPS == InstDiscoverDevParms.ulDeviceCnt)
    {
    	/* We have a full compliment of DSPS */
        /*
         * List all Vocallo devices.
         */
        printf("Vocallo devices:\n");
        for (ulDeviceIdx = 0; ulDeviceIdx < InstDiscoverDevParms.ulDeviceCnt; ulDeviceIdx++)
        {
            tPOCTVC1_PKT_API_DEV_INFO pDevInfo = &InstDiscoverDevParms.aDeviceInfo[ulDeviceIdx];

            printf(" [%u]: Vocallo %u\n", ulDeviceIdx, ulDeviceIdx + 1);
            for (ulPortIndex = 0; ulPortIndex < pDevInfo->ulPortCnt; ulPortIndex++)
            {
                if (cOCTVC1_PKT_API_DEV_PORT_TYPE_ETH == pDevInfo->aPortInfo[ulPortIndex].ulPortType)
                {
                    if (pDevInfo->aPortInfo[ulPortIndex].fReachable)
                    {
                        char szMacAddr[18];

                        OctVocSamplesMacAddr2Str(szMacAddr, pDevInfo->aPortInfo[ulPortIndex].Type.Eth.abyMacAddr);
                        printf("  Port %u: %s\n", pDevInfo->aPortInfo[ulPortIndex].Type.Eth.ulPortId, szMacAddr);
                        /* whatever the first reachable ethernet port is use it. */
                        /* This makes a big assumption that it will be port 0 ??? */
                        memcpy(g_AppCfg[ulDeviceIdx].abyVocalloCtrlMacAddr,pDevInfo->aPortInfo[ulPortIndex].Type.Eth.abyMacAddr,6);
						break; /* Drop out of port loop */
                    }
                }
            }
        }
        /* regardless of how many they are we assume that this function will only be called once so return the MAC for the first device */
        ulSelectedDevIndex = 0;
    } else {
    	printf("Can't cope with less than 12 DSPs \n");
    	assert( 1 == 0 );
    }


#endif /* BPR Change */
    pSelectedDevInfo = &InstDiscoverDevParms.aDeviceInfo[ulSelectedDevIndex];

    /*
     * Retrieve the port information of the selected device.
     */
    for (ulPortIndex = 0; ulPortIndex < pSelectedDevInfo->ulPortCnt; ulPortIndex++)
    {
        if (cOCTVC1_PKT_API_DEV_PORT_TYPE_ETH == pSelectedDevInfo->aPortInfo[ulPortIndex].ulPortType)
        {
            if (0 == pSelectedDevInfo->aPortInfo[ulPortIndex].Type.Eth.ulPortId)
            {
                /* Ethernet port 0. */
                memcpy(DevPortInfo.abyPort0MacAddr, pSelectedDevInfo->aPortInfo[ulPortIndex].Type.Eth.abyMacAddr, 6);
                DevPortInfo.fIsPort0Reachable = pSelectedDevInfo->aPortInfo[ulPortIndex].fReachable;
            }
            else if (1 == pSelectedDevInfo->aPortInfo[ulPortIndex].Type.Eth.ulPortId)
            {
                /* Ethernet port 1. */
                memcpy(DevPortInfo.abyPort1MacAddr, pSelectedDevInfo->aPortInfo[ulPortIndex].Type.Eth.abyMacAddr, 6);
                DevPortInfo.fIsPort1Reachable = pSelectedDevInfo->aPortInfo[ulPortIndex].fReachable;
            }
        }
    }
#if 0 /* BPR Change */
    if (DevPortInfo.fIsPort0Reachable && DevPortInfo.fIsPort1Reachable)
    {
        char szMacAddr[18];

        /*
         * List all reachable ports.
         */
        printf("Two reachable ports were found:\n");
        OctVocSamplesMacAddr2Str(szMacAddr, DevPortInfo.abyPort0MacAddr);
        printf(" [0]: Port 0: %s\n", szMacAddr);
        OctVocSamplesMacAddr2Str(szMacAddr, DevPortInfo.abyPort1MacAddr);
        printf(" [1]: Port 1: %s\n", szMacAddr);

        /*
         * Prompt the user to select a port.
         */
        while (cOCT_TRUE)
        {
            char szChoice[80];
            
            printf("Select a port [default: 0]: ");
            fgets(szChoice, 80, stdin);
            
            ulSelectedPortIndex = atoi(szChoice);
            if (ulSelectedPortIndex < 2)
            {
                break;
            }
        }
        fputc('\n', stdout);
    }
    else if (DevPortInfo.fIsPort0Reachable)
    {
        /*
         * Only Ethernet port 0 is reachable.
         */
        ulSelectedPortIndex = 0;
    }
    else if (DevPortInfo.fIsPort1Reachable)
    {
        /*
         * Only Ethernet port 1 is reachable.
         */
        ulSelectedPortIndex = 1;
    }
#else /* BPR Change */
	/* Always use Port 0 */
	ulSelectedPortIndex = 0;
#endif /* BPR Change */
    /*
     * Return the selected port's MAC address.
     */
    if (0 == ulSelectedPortIndex)
    {
        memcpy(f_abyRemoteMacAddr, DevPortInfo.abyPort0MacAddr, 6);
        f_pPktApiInfo->ulPktApiCnctPortIdx = 0;
    }
    else
    {
        memcpy(f_abyRemoteMacAddr, DevPortInfo.abyPort1MacAddr, 6);
        f_pPktApiInfo->ulPktApiCnctPortIdx = 1;
    }

    return cOCTVC1_RC_OK;
}
/***************************  PUBLIC FUNCTIONS  ******************************/

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MyOctVocSamplesOpenPktApiSession

Description:    Opens a packet API session.

BPR: Copied from octvocsamples_pkt_api_session.c
                My version ony opens one Instance and copies it to every 
                subsequent session created.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
extern const tOCT_UINT8 g_abyNullMacAddr[6];
tOCT_UINT32 MyOctVocSamplesOpenPktApiSession(tPOCTVOCSAMPLES_PKT_API_INFO f_pPktApiInfo,
                                           tOCT_UINT8                   f_abyLocalMacAddr[6],
                                           tOCT_UINT8                   f_abyRemoteMacAddr[6])
{
    tOCTVC1_PKT_API_SESS_OPEN_PARMS SessOpenParms;
    tOCT_UINT32                     ulResult;

	/* is this the first Session */
	if(f_pPktApiInfo==&(g_AppCtx[0].PktApiInfo)){/* BPR Change */
	    /*
	     * Make sure a local MAC address has been specified.
	     */
	      printf("MyOctVocSamplesOpenPktApiSession:Host MAC Address %02x:%02x:%02x:%02x:%02x:%02x\n",
           f_abyLocalMacAddr[0],
           f_abyLocalMacAddr[1],
           f_abyLocalMacAddr[2],
           f_abyLocalMacAddr[3],
           f_abyLocalMacAddr[4],
           f_abyLocalMacAddr[5]);

	    if (0 == memcmp(f_abyLocalMacAddr, g_abyNullMacAddr, 6))
	    {
	        ulResult = MySelectLocalMacAddr(f_abyLocalMacAddr);/* BPR Change */
	        if (cOCTVC1_RC_OK != ulResult)
	        {
	            goto ErrorHandling;
	        }
	    }
	
	    /*
	     * Initialize a packet API instance on the specified local MAC address.
	     */
	    ulResult = MyInitializePktApiInst(f_pPktApiInfo, f_abyLocalMacAddr);/* BPR Change */
	    if (cOCTVC1_RC_OK != ulResult)
	    {
	        goto ErrorHandling;
	    }
	} else {/* BPR Change */
		/* Copy the Instance from first Session */
		memcpy(f_pPktApiInfo,&(g_AppCtx[0].PktApiInfo),sizeof(tOCTVOCSAMPLES_PKT_API_INFO));
	}/* BPR Change */

    /*
     * Make sure a remote MAC address has been specified.
     */
    if (0 == memcmp(f_abyRemoteMacAddr, g_abyNullMacAddr, 6))
    {
        ulResult = MySelectRemoteMacAddr(f_pPktApiInfo, f_abyRemoteMacAddr);/* BPR Change */
        if (cOCTVC1_RC_OK != ulResult)
        {
            goto ErrorHandling;
        }
    }

    /*
     * Open a connection between the transport packet API instance and the Vocallo device.
     */
    ulResult = MyOpenPktApiCnct(f_pPktApiInfo, f_abyRemoteMacAddr);/* BPR Change */
    if (cOCTVC1_RC_OK != ulResult)
    {
        goto ErrorHandling;
    }

    /*
     * Open a packet API session to communicate with the MGW process running on Vocallo.
     */
    mOCTVC1_PKT_API_SESS_OPEN_PARMS_DEF(&SessOpenParms);
    SessOpenParms.ulControlProcessFifoId = cOCTVC1_FIFO_ID_MGW_CONTROL;

    ulResult = OctVc1PktApiSessOpen(f_pPktApiInfo->pPktApiCnct, &SessOpenParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        goto ErrorHandling;
    }
    f_pPktApiInfo->pPktApiSess = SessOpenParms.pSession;

    return cOCTVC1_RC_OK;

ErrorHandling:
    OctVocSamplesClosePktApiSession(f_pPktApiInfo);

    return ulResult;
}
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       GetNumberOfConnections

Description:    Fonds out how many conenctions device can handle.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int GetNumberOfConnections(tOCT_UINT32 ulCtx)
{
    tOCTVC1_VSPMP_VOC_MSG_MODULE_GET_CONFIG_CMD ModuleGetConfigCmd;
    tOCTVC1_VSPMP_VOC_MSG_MODULE_GET_CONFIG_RSP ModuleGetConfigRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS CmdExecuteParms;
    tOCT_UINT32 ulResult;

    /*
     * Prepare command data.
     */
    mOCTVC1_VSPMP_VOC_MSG_MODULE_GET_CONFIG_CMD_DEF(&ModuleGetConfigCmd);
    /* No parameters to set */
    mOCTVC1_VSPMP_VOC_MSG_MODULE_GET_CONFIG_CMD_SWAP(&ModuleGetConfigCmd);

    /*
     * Execute the command.
     */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &ModuleGetConfigCmd;
    CmdExecuteParms.pRsp           = &ModuleGetConfigRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(ModuleGetConfigRsp);
    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        fprintf(stderr, "Error: cOOCTVC1_VSPMP_VOC_MSG_MODULE_GET_CONFIG failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
        goto ErrorHandling;
    }

    /*
     * Swap the command response.
     */
    mOCTVC1_VSPMP_VOC_MSG_MODULE_GET_CONFIG_RSP_SWAP(&ModuleGetConfigRsp);
#if 0
    /*
     * Dump it all.
     */
    printf("ulMaxNumTermination: 0x%8.8x\n",ModuleGetConfigRsp.ulMaxNumTermination);
    printf("ulMaxNumEchoTermination: 0x%8.8x\n",ModuleGetConfigRsp.ulMaxNumEchoTermination);       
    printf("ulMaxNumConferenceParticipants %x\n",ModuleGetConfigRsp.ulMaxNumConferenceParticipants);
    printf("ulNumTermProfile: 0x%8.8x\n",ModuleGetConfigRsp.ulNumTermProfile);              
    printf("ulMaxNumPlaylist: 0x%8.8x\n",ModuleGetConfigRsp.ulMaxNumPlaylist);              
    printf("ulMaxNumUserTone: 0x%8.8x\n",ModuleGetConfigRsp.ulMaxNumUserTone);              
    printf("ulMaxPktSizeMs: 0x%8.8x\n",ModuleGetConfigRsp.ulMaxPktSizeMs);                
    printf("ulMaxRxJitterPdvMs: 0x%8.8x\n",ModuleGetConfigRsp.ulMaxRxJitterPdvMs);     
#endif
/* Could save these too?
	ModuleGetConfigRsp.ulMaxNumEchoTermination;
	ModuleGetConfigRsp.ulMaxNumConferenceParticipants;
	ModuleGetConfigRsp.ulNumTermProfile;
	ModuleGetConfigRsp.ulMaxNumPlaylist;
	ModuleGetConfigRsp.ulMaxNumUserTone;
	ModuleGetConfigRsp.ulMaxPktSizeMs;
	ModuleGetConfigRsp.ulMaxRxJitterPdvMs;
	*/
	return (ModuleGetConfigRsp.ulMaxNumTermination/2);/* Each IP-IP so each uses two terminations */

ErrorHandling:
    return 0;
}
#if 0
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       PrintLinks

Description:    Lets the user select a Link To Monitor

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static void PrintLinks(void)
{
	tOCT_UINT8 ch=0x00;
    tOCT_UINT32 ulCtx=0;/* counter to index Context Array */
    tOCT_UINT32 ulConnectionNumber=0;
    tOCT_UINT32 ulResult;
    tOCT_UINT32 ulGetMode;
	
	while(ch!='q'){
	    printf("DSP[%d]:",ulCtx);
    	ch=getchar();
    	printf("%c (%x)\n",ch,ch);
    	
		if(ch!='\n'){
			ulCtx=atoi(&ch);    	
    	}
	    printf("Channel (0-399)[%d]:",ulConnectionNumber);
    	ch=getchar();
    	printf("%c (%x)\n",ch,ch);
    	
		if(ch!='\n'){
			ulConnectionNumber=atoi(&ch);    	
    	}
    	assert((ulCtx>=0) && (ulCtx<MAX_DSPS));
    	assert((ulConnectionNumber>=0) && (ulConnectionNumber<MAX_CONNECTIONS));	
    	
    	ulGetMode=cOCTVC1_OBJECT_CURSOR_ENUM_FIRST;
    	ulResult= OctVocSamplesPrintVocTermMcStats(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess,
                                             &g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber],
                                             &ulGetMode);

        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: OctVocSamplesPrintVocTermMcStats failed , rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
        }
	    printf("Enter to continue or q to quit:");
    	ch=getchar();
    	printf("%c (%x)\n",ch,ch);
    }

}
#endif

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\
 *
 * Function:       GetProcInfo
 *
 * Description:    Retrieve the information for a specific process.
 *
 * \*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int GetProcInfo(int f_Idx)
{
    tOCTVC1_MAIN_MSG_PROCESS_INFO_CMD MainProcessInfoCmd;
    tOCTVC1_MAIN_MSG_PROCESS_INFO_RSP MainProcessInfoRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS CmdExecuteParms;
    tOCT_UINT32                       ulResult;
    tOCT_UINT32                       ulCtx;

    /*
 *      * Prepare command data.
 *           */
    mOCTVC1_MAIN_MSG_PROCESS_INFO_CMD_DEF(&MainProcessInfoCmd);
    MainProcessInfoCmd.hProcess = g_AppCtx[ulCtx].aCoreInfo[f_Idx].hProcess;
    mOCTVC1_MAIN_MSG_PROCESS_INFO_CMD_SWAP(&MainProcessInfoCmd);

    /*
 *      * Execute the command.
 *           */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &MainProcessInfoCmd;
    CmdExecuteParms.pRsp           = &MainProcessInfoRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(MainProcessInfoRsp);
    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_PROCESS_INFO_CID failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
        goto ErrorHandling;
    }

    mOCTVC1_MAIN_MSG_PROCESS_INFO_RSP_SWAP(&MainProcessInfoRsp);

    /*
 *      * Store the process' name for printout.
 *           */
    memcpy(g_AppCtx[ulCtx].szProcessImageName, MainProcessInfoRsp.szProcessImageName, sizeof(MainProcessInfoRsp.szProcessImageName));

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\
 *
 * Function:       GetInfoOpusCore
 *
 * Description:    Retrieve Opus core information from device.
 *
 * \*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int GetInfoOpusCore(tOCT_UINT32 ulCtx)
{
    tOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CMD MainInfoOpusCoreCmd;
    tOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_RSP MainInfoOpusCoreRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS          CmdExecuteParms;
    tOCT_UINT32                                ulResult;
    tOCT_UINT32                                i;

    /*
 *      * Prepare command data.
 *           */
    mOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CMD_DEF(&MainInfoOpusCoreCmd);
    mOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CMD_SWAP(&MainInfoOpusCoreCmd);

    /*
 *      * Execute the command.
 *           */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &MainInfoOpusCoreCmd;
    CmdExecuteParms.pRsp           = &MainInfoOpusCoreRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(MainInfoOpusCoreRsp);
    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CID failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
        goto ErrorHandling;
    }

    /*
 *      * Swap the command response.
 *           */
    mOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_RSP_SWAP(&MainInfoOpusCoreRsp);

    /*
 *      * Save the returned Opus core information.
 *           */
    memcpy (g_AppCtx[ulCtx].aCoreInfo, MainInfoOpusCoreRsp.aCoreInfo, sizeof(MainInfoOpusCoreRsp.aCoreInfo) );

    /*
 *      * Retrieve process information for all cores.
 *           */
    for (i = 0; i < cOCTVC1_MAIN_MAX_CORE_NUMBER; i++)
    {
        if (cOCTVC1_HANDLE_INVALID == g_AppCtx[ulCtx].aCoreInfo[i].hProcess)
        {
            g_AppCtx[ulCtx].ulNumActiveCores = i;
            break;
        }

        //ulResult = GetProcInfo(i);
        //if (cOCTVC1_RC_OK != ulResult)
        //{
        //     goto ErrorHandling;
        //}

        printf("Core #%02u is running process \"%s\" on DSP#%d\n", g_AppCtx[ulCtx].aCoreInfo[i].ulPhysicalCoreId, g_AppCtx[ulCtx].szProcessImageName, ulCtx);
    }

    if (!g_AppCtx[ulCtx].ulNumActiveCores)
        g_AppCtx[ulCtx].ulNumActiveCores = i;

    printf("\n%u cores are active on the DPS#%d.\n\n",  g_AppCtx[ulCtx].ulNumActiveCores, ulCtx);

    return 0;

ErrorHandling:
    return -1;
}


/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\
 
Function:       GetCpuUsage
 
Description:    Retrieve CPU usage for a specific process.
 
\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int GetCpuUsage(tOCT_UINT32 ulCtx)
{
    tOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_CMD MainProcInfCpuUsgCmd;
    tOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_RSP MainProcInfCpuUsgRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS           CmdExecuteParms;
    tOCT_UINT32                                 ulResult;
    tOCT_UINT32                                 i;
    tOCT_UINT32                                 ulPrintVSPFlag = 0;
    //tOCT_UINT32 ulCtx;/* counter to index Context Array */
    printf("Entered into GetCpuUsage function\n");
    for (i = 0; i < g_AppCtx[ulCtx].ulNumActiveCores; i++)
    {
        if ( (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_INVALID == g_AppCtx[ulCtx].aCoreInfo[i].ulProcessImageType) ||
            (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_CONTROL == g_AppCtx[ulCtx].aCoreInfo[i].ulProcessImageType) ||
            (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_AF_SRV == g_AppCtx[ulCtx].aCoreInfo[i].ulProcessImageType) ||
            (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_VSPMGR == g_AppCtx[ulCtx].aCoreInfo[i].ulProcessImageType) )
        {
            if ( (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_VSPMGR == g_AppCtx[ulCtx].aCoreInfo[i].ulProcessImageType) && !ulPrintVSPFlag )
            {
                /*
                 * Only print once the usage for VSPMGR.
                 */
                ulPrintVSPFlag = 1;
            }
            else
                continue;
        }
       /*
        * Prepare command data.
        */
        mOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_CMD_DEF(&MainProcInfCpuUsgCmd);
        MainProcInfCpuUsgCmd.hProcess = g_AppCtx[ulCtx].aCoreInfo[i].hProcess;
        mOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_CMD_SWAP(&MainProcInfCpuUsgCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &MainProcInfCpuUsgCmd;
        CmdExecuteParms.pRsp           = &MainProcInfCpuUsgRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(MainProcInfCpuUsgRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_RSP_SWAP(&MainProcInfCpuUsgRsp);

       /* ulResult = GetProcInfo(i);
        if (cOCTVC1_RC_OK != ulResult)
        {
            goto ErrorHandling;
        }*/

        printf("CPU usage is %u%% for process %s on DSP#%d\n ", MainProcInfCpuUsgRsp.ulProcessCpuUsagePercent, g_AppCtx[ulCtx].szProcessImageName, ulCtx);
    }
return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MonitorLinks

Description:    Loop through all DSPs and collate error data

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static void MonitorLinks(tOCT_UINT32 ulCtx)
{
	tOCT_UINT8 side;
    //tOCT_UINT32 ulCtx;/* counter to index Context Array */
	tOCT_UINT32 ulNumConnections = 0;
    tOCT_UINT32 ulConnectionNumber=0;
    tOCT_UINT32 ulResult;
    tOCT_UINT32 ulGetMode;
    tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD TermStatsMcCmd;
    tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP TermStatsMcRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS       CmdExecuteParms;

	/* Clear stats structure */
	memset(g_AppStats,0,(MAX_DSPS*sizeof(tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP)));
	
	/* Loop through DSPs */
    	/* this is only really need once and then copy to all contexts ??? */
		/* Find out how many Terminations we are allowed. */
		ulNumConnections =GetNumberOfConnections(ulCtx);
		assert(ulNumConnections<=MAX_CONNECTIONS);
		if ((ulNumConnections>MAX_CONNECTIONS)||(ulNumConnections==0))
		{
			printf("ulNumConnections out of range : %d\n",ulNumConnections);
	        //continue;
	        goto ErrorHandling;
	    }
	    OctVocSamplesPrintModuleNetConfigInfo(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess);
	    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
	    {
	    	/* Alternate between side A and B */
    		for (side=0;side<2;side++){
		    	//ulGetMode=cOCTVC1_OBJECT_CURSOR_ENUM_FIRST;
		    	ulGetMode=cOCTVC1_OBJECT_CURSOR_ENUM_SPECIFIC;
		    	
			    /*
			     * Prepare command data.
			     */
			    mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD_DEF(&TermStatsMcCmd);
			    if(side==0){
			    	TermStatsMcCmd.ObjectGet.hObject   = g_AppCtx[ulCtx].hVocTermA[ulConnectionNumber];
			    }else{
			    	TermStatsMcCmd.ObjectGet.hObject   = g_AppCtx[ulCtx].hVocTermB[ulConnectionNumber];
			    }
			    TermStatsMcCmd.ObjectGet.ulGetMode = ulGetMode;
			    mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD_SWAP(&TermStatsMcCmd);
			
			    /*
			     * Execute the command.
			     */
			    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
			    CmdExecuteParms.pCmd           = &TermStatsMcCmd;
			    CmdExecuteParms.pRsp           = &TermStatsMcRsp;
			    CmdExecuteParms.ulMaxRspLength = sizeof(TermStatsMcRsp);
			    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx[ulCtx].PktApiInfo.pPktApiSess, &CmdExecuteParms);
			    if (cOCTVC1_RC_OK != ulResult)
			    {
	                //continue;
                          goto ErrorHandling;
			    }
			
			    /*
			     * Swap the command response.
			     */
			    mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP_SWAP(&TermStatsMcRsp);
			
			    /*
			     * Print the statistics.
			     */
	
	/* how to handle 64 bit numbers ???
			    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulRxInPktCnt);
			    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulRxInByteCnt);
			    */
			    g_AppStats[ulCtx].ulRxOutPktCnt           +=TermStatsMcRsp.ulRxOutPktCnt;
			    g_AppStats[ulCtx].ulRxInSidPktCnt         +=TermStatsMcRsp.ulRxInSidPktCnt;
			    g_AppStats[ulCtx].ulRxNoPktCnt            +=TermStatsMcRsp.ulRxNoPktCnt;
			    g_AppStats[ulCtx].ulRxBadPktTypeCnt       +=TermStatsMcRsp.ulRxBadPktTypeCnt;
			    g_AppStats[ulCtx].ulRxBadRtpPayloadTypeCnt+=TermStatsMcRsp.ulRxBadRtpPayloadTypeCnt;   
			    g_AppStats[ulCtx].ulRxBadPktHdrFormatCnt  +=TermStatsMcRsp.ulRxBadPktHdrFormatCnt;
			    g_AppStats[ulCtx].ulRxBadPktLengthCnt     +=TermStatsMcRsp.ulRxBadPktLengthCnt;
			    g_AppStats[ulCtx].ulRxMisorderedPktCnt    +=TermStatsMcRsp.ulRxMisorderedPktCnt;
			    g_AppStats[ulCtx].ulRxLostPktCnt          +=TermStatsMcRsp.ulRxLostPktCnt;
			    g_AppStats[ulCtx].ulRxBadPktChecksumCnt   +=TermStatsMcRsp.ulRxBadPktChecksumCnt;
			    g_AppStats[ulCtx].ulRxUnderrunSlipCnt     +=TermStatsMcRsp.ulRxUnderrunSlipCnt;
			    g_AppStats[ulCtx].ulRxOverrunSlipCnt      +=TermStatsMcRsp.ulRxOverrunSlipCnt;
			    if(g_AppStats[ulCtx].ulRxLastVocoderType!=TermStatsMcRsp.ulRxLastVocoderType)
			    	g_AppStats[ulCtx].ulRxLastVocoderType=TermStatsMcRsp.ulRxLastVocoderType;
			    g_AppStats[ulCtx].ulRxVocoderChangeCnt    +=TermStatsMcRsp.ulRxVocoderChangeCnt;
			    if(TermStatsMcRsp.ulRxMaxDetectedPdv>g_AppStats[ulCtx].ulRxMaxDetectedPdv)
			    	g_AppStats[ulCtx].ulRxMaxDetectedPdv=TermStatsMcRsp.ulRxMaxDetectedPdv;
			    g_AppStats[ulCtx].ulRxDecdrRate           +=TermStatsMcRsp.ulRxDecdrRate;
			    if(TermStatsMcRsp.ulRxJitterCurrentDelay>g_AppStats[ulCtx].ulRxJitterCurrentDelay)
			    	g_AppStats[ulCtx].ulRxJitterCurrentDelay=TermStatsMcRsp.ulRxJitterCurrentDelay;
			    g_AppStats[ulCtx].ulRxJitterEstimatedDelay+=TermStatsMcRsp.ulRxJitterEstimatedDelay;
			    g_AppStats[ulCtx].lRxJitterClkDriftingDelta         +=TermStatsMcRsp.lRxJitterClkDriftingDelta;
			    g_AppStats[ulCtx].ulRxJitterClkDriftingCorrectionCnt+=TermStatsMcRsp.ulRxJitterClkDriftingCorrectionCnt;
			    if(TermStatsMcRsp.ulRxJitterInitializationCnt>g_AppStats[ulCtx].ulRxJitterInitializationCnt)
			    	g_AppStats[ulCtx].ulRxJitterInitializationCnt=TermStatsMcRsp.ulRxJitterInitializationCnt;
			    g_AppStats[ulCtx].ulRxCircularBufferWriteErrCnt     +=TermStatsMcRsp.ulRxCircularBufferWriteErrCnt;
			    g_AppStats[ulCtx].ulRxApiEventCnt                   +=TermStatsMcRsp.ulRxApiEventCnt;
			    if(g_AppStats[ulCtx].ulTxCurrentVocoderType!=TermStatsMcRsp.ulTxCurrentVocoderType)
			    	g_AppStats[ulCtx].ulTxCurrentVocoderType=TermStatsMcRsp.ulTxCurrentVocoderType;
			    g_AppStats[ulCtx].ulTxInPktCnt                      +=TermStatsMcRsp.ulTxInPktCnt;
	/*		    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulTxOutPktCnt;
			    printf("| TxOutPktCnt                 : %s\n", szBuffer;
			    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulTxOutByteCnt;
			    printf("| TxOutByteCnt                : %s\n", szBuffer;
			    */
				g_AppStats[ulCtx].ulTxInBadPktPayloadCnt      +=TermStatsMcRsp.ulTxInBadPktPayloadCnt;
				g_AppStats[ulCtx].ulTxTimestampGapCnt         +=TermStatsMcRsp.ulTxTimestampGapCnt;
				g_AppStats[ulCtx].ulTxTdmWriteErrCnt          +=TermStatsMcRsp.ulTxTdmWriteErrCnt;
				g_AppStats[ulCtx].ulRxToneDetectedCnt         +=TermStatsMcRsp.ulRxToneDetectedCnt;
				g_AppStats[ulCtx].ulRxToneRelayEventPktCnt    +=TermStatsMcRsp.ulRxToneRelayEventPktCnt;
				g_AppStats[ulCtx].ulRxToneRelayUnsupportedCnt +=TermStatsMcRsp.ulRxToneRelayUnsupportedCnt;
				g_AppStats[ulCtx].ulTxToneRelayEventPktCnt    +=TermStatsMcRsp.ulTxToneRelayEventPktCnt;
				g_AppStats[ulCtx].ulTxApiEventCnt             +=TermStatsMcRsp.ulTxApiEventCnt;
				g_AppStats[ulCtx].ulTxNoRtpEntryPktDropCnt    +=TermStatsMcRsp.ulTxNoRtpEntryPktDropCnt;
				g_AppStats[ulCtx].ulConnectionWaitAckFlag     +=TermStatsMcRsp.ulConnectionWaitAckFlag;
				g_AppStats[ulCtx].ulRxMipsProtectionDropCnt   +=TermStatsMcRsp.ulRxMipsProtectionDropCnt;
				g_AppStats[ulCtx].ulTxMipsProtectionDropCnt   +=TermStatsMcRsp.ulTxMipsProtectionDropCnt;
				if(TermStatsMcRsp.ulCallTimerMsec>g_AppStats[ulCtx].ulCallTimerMsec)
					g_AppStats[ulCtx].ulCallTimerMsec=TermStatsMcRsp.ulCallTimerMsec;
	
			}
		}
	    /*
	     * Print the statistics.
	     */
#if 0 
	    printf("+-- VOC TERM MC STATISTICS (%08x-%08x-%08x) ----------------------\n",
        TermStatsMcRsp.ObjectGet.hObject.aulHandle[0],
        TermStatsMcRsp.ObjectGet.hObject.aulHandle[1],
        TermStatsMcRsp.ObjectGet.hObject.aulHandle[2]);
#endif
	    printf("+-- VOC TERM MC STATISTICS (DSP %02d) ----------------------\n",ulCtx);

		/*
	    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulRxInPktCnt);
	    printf("| RxInPktCnt                  : %s\n", szBuffer);
	    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulRxInByteCnt);
	    printf("| RxInByteCnt                 : %s\n", szBuffer);*/
	    printf("| RxOutPktCnt                      : %u\n", g_AppStats[ulCtx].ulRxOutPktCnt);
	    printf("| RxInSidPktCnt                    : %u\n", g_AppStats[ulCtx].ulRxInSidPktCnt);
	    printf("| RxNoPktCnt                       : %u\n", g_AppStats[ulCtx].ulRxNoPktCnt);
	    printf("| RxBadPktTypeCnt                  : %u\n", g_AppStats[ulCtx].ulRxBadPktTypeCnt);
	    printf("| RxBadRtpPayloadTypeCnt           : %u\n", g_AppStats[ulCtx].ulRxBadRtpPayloadTypeCnt);    
	    printf("| RxBadPktHdrFormatCnt             : %u\n", g_AppStats[ulCtx].ulRxBadPktHdrFormatCnt);
	    printf("| RxBadPktLengthCnt                : %u\n", g_AppStats[ulCtx].ulRxBadPktLengthCnt);
	    printf("| RxMisorderedPktCnt               : %u\n", g_AppStats[ulCtx].ulRxMisorderedPktCnt);
	    printf("| RxLostPktCnt                     : %u\n", g_AppStats[ulCtx].ulRxLostPktCnt);
	    printf("| RxBadPktChecksumCnt              : %u\n", g_AppStats[ulCtx].ulRxBadPktChecksumCnt);
	    printf("| RxUnderrunSlipCnt                : %u\n", g_AppStats[ulCtx].ulRxUnderrunSlipCnt);
	    printf("| RxOverrunSlipCnt                 : %u\n", g_AppStats[ulCtx].ulRxOverrunSlipCnt);
	    printf("| RxLastVocoderType                : %u\n", g_AppStats[ulCtx].ulRxLastVocoderType);
	    printf("| RxVocoderChangeCnt               : %u\n", g_AppStats[ulCtx].ulRxVocoderChangeCnt);
	    printf("| RxMaxDetectedPdv                 : %u (in 125 us)\n", g_AppStats[ulCtx].ulRxMaxDetectedPdv);
	    printf("| RxDecdrRate                      : %u\n", g_AppStats[ulCtx].ulRxDecdrRate);
	    printf("| RxMaxJitterCurrentDelay          : %u (in 125 us)\n", g_AppStats[ulCtx].ulRxJitterCurrentDelay);
	    printf("| RxJitterEstimatedDelay           : %u (in 125 us)\n", g_AppStats[ulCtx].ulRxJitterEstimatedDelay);
	    printf("| RxJitterEstimatedDelay           : %u (in 125 us)\n", g_AppStats[ulCtx].lRxJitterClkDriftingDelta);
	    printf("| RxJitterClkDriftingCorrectionCnt : %u\n", g_AppStats[ulCtx].ulRxJitterClkDriftingCorrectionCnt);
	    printf("| RxMaxJitterInitializationCnt     : %u\n", g_AppStats[ulCtx].ulRxJitterInitializationCnt);
	    printf("| RxCircularBufferWriteErrCnt      : %u\n", g_AppStats[ulCtx].ulRxCircularBufferWriteErrCnt);
	    printf("| RxApiEventCnt                    : %u\n", g_AppStats[ulCtx].ulRxApiEventCnt);
	    printf("| TxCurrentVocoderType             : %u\n", g_AppStats[ulCtx].ulTxCurrentVocoderType);
	    printf("| TxInPktCnt                       : %u\n", g_AppStats[ulCtx].ulTxInPktCnt);
		/*
	    mOCT_UINT64TOA(szBuffer, g_AppStats[ulCtx].aulTxOutPktCnt);
	    printf("| TxOutPktCnt                 : %s\n", szBuffer);
	    mOCT_UINT64TOA(szBuffer, g_AppStats[ulCtx].aulTxOutByteCnt);
	    printf("| TxOutByteCnt                : %s\n", szBuffer);*/
	    printf("| TxInBadPktPayloadCnt             : %u\n", g_AppStats[ulCtx].ulTxInBadPktPayloadCnt);
	    printf("| TxTimestampGapCnt                : %u\n", g_AppStats[ulCtx].ulTxTimestampGapCnt);
	    printf("| TxTdmWriteErrCnt                 : %u\n", g_AppStats[ulCtx].ulTxTdmWriteErrCnt);
	    printf("| RxToneDetectedCnt                : %u\n", g_AppStats[ulCtx].ulRxToneDetectedCnt);
	    printf("| RxToneRelayEventPktCnt           : %u\n", g_AppStats[ulCtx].ulRxToneRelayEventPktCnt);
	    printf("| RxToneRelayUnsupportedCnt        : %u\n", g_AppStats[ulCtx].ulRxToneRelayUnsupportedCnt);
	    printf("| TxToneRelayEventPktCnt           : %u\n", g_AppStats[ulCtx].ulTxToneRelayEventPktCnt);
	    printf("| TxApiEventCnt                    : %u\n", g_AppStats[ulCtx].ulTxApiEventCnt);
	    printf("| TxNoRtpEntryPktDropCnt           : %u\n", g_AppStats[ulCtx].ulTxNoRtpEntryPktDropCnt);
	    printf("| ConnectionWaitAckFlag            : %u\n", g_AppStats[ulCtx].ulConnectionWaitAckFlag);
	    printf("| RxMipsProtectionDropCnt          : %u\n", g_AppStats[ulCtx].ulRxMipsProtectionDropCnt);
	    printf("| TxMipsProtectionDropCnt          : %u\n", g_AppStats[ulCtx].ulTxMipsProtectionDropCnt);
	    printf("| CallTimerMsec                    : %u\n", g_AppStats[ulCtx].ulCallTimerMsec);
	    printf("\n");   
	    
	    
	    if( (g_AppStats[ulCtx].ulRxBadPktTypeCnt       !=0) ||
			(g_AppStats[ulCtx].ulRxBadRtpPayloadTypeCnt!=0) ||  
			(g_AppStats[ulCtx].ulRxBadPktHdrFormatCnt  !=0) ||
			(g_AppStats[ulCtx].ulRxBadPktLengthCnt     !=0) ||
			(g_AppStats[ulCtx].ulRxMisorderedPktCnt    !=0) ||
			(g_AppStats[ulCtx].ulRxLostPktCnt          !=0) ||
			(g_AppStats[ulCtx].ulRxBadPktChecksumCnt   !=0) ||
			(g_AppStats[ulCtx].ulRxUnderrunSlipCnt     !=0) ||
			(g_AppStats[ulCtx].ulRxOverrunSlipCnt      !=0) ||			    
			(g_AppStats[ulCtx].ulRxVocoderChangeCnt         !=0) ||
			(g_AppStats[ulCtx].ulRxCircularBufferWriteErrCnt!=0) ||
			(g_AppStats[ulCtx].ulRxApiEventCnt              !=0) ||
			(g_AppStats[ulCtx].ulTxInBadPktPayloadCnt       !=0) ||
			(g_AppStats[ulCtx].ulTxTimestampGapCnt          !=0) ||
			(g_AppStats[ulCtx].ulTxTdmWriteErrCnt           !=0) ||
			(g_AppStats[ulCtx].ulRxToneDetectedCnt          !=0) ||
			(g_AppStats[ulCtx].ulRxToneRelayEventPktCnt     !=0) ||
			(g_AppStats[ulCtx].ulRxToneRelayUnsupportedCnt  !=0) ||
			(g_AppStats[ulCtx].ulTxToneRelayEventPktCnt     !=0) ||
			(g_AppStats[ulCtx].ulTxApiEventCnt              !=0) ||
			(g_AppStats[ulCtx].ulTxNoRtpEntryPktDropCnt     !=0) ||
			(g_AppStats[ulCtx].ulConnectionWaitAckFlag      !=0) ||
			(g_AppStats[ulCtx].ulRxMipsProtectionDropCnt    !=0) ||
			(g_AppStats[ulCtx].ulTxMipsProtectionDropCnt    !=0) ){
			    printf("!!! DSP %02d Serious Errors !!!\n",ulCtx);
			}
#if (!1)
       /*
        * Prior to SDK 03.xx.xx 
        */
        ulResult = OctOsalSleepMs(&g_AppCtx[ulCtx], 60*1000);
#else
       /* 
        * later SDK 03.xx.xx 
        */
        ulResult = OctOsalSleepMs(60*1000);/* Wait one minute */
#endif
	if (cOCTVC1_RC_OK != ulResult)
	{
	   goto ErrorHandling;
	}
ErrorHandling:
    ExitApplication();

}
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MyOctVocSamplesPrintVocTermMcStats

Description:    Prints the media-coder statistics of a voice termination.

Note:           See the Vocallo Scheduled Process Media Processor (VSPMP)
                documentation for the cOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CID
                command.

BPR: Copied from octvocsamples_vspmp_voc_api_stats.c

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

tOCT_UINT32 MyOctVocSamplesPrintVocTermMcStats(tPOCTVC1_PKT_API_SESS      f_pPktApiSess,
                                             tOCTVC1_HANDLE             *f_phVocTerm,
                                             tOCTVC1_OBJECT_CURSOR_ENUM *f_pulGetMode)
{
    tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD TermStatsMcCmd;
    tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP TermStatsMcRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS       CmdExecuteParms;
    char                                    szBuffer[32];
    tOCT_UINT32                             ulResult;

    /*
     * Prepare command data.
     */
    mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD_DEF(&TermStatsMcCmd);
    TermStatsMcCmd.ObjectGet.hObject   = *f_phVocTerm;
    TermStatsMcCmd.ObjectGet.ulGetMode = *f_pulGetMode;
    mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD_SWAP(&TermStatsMcCmd);

    /*
     * Execute the command.
     */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &TermStatsMcCmd;
    CmdExecuteParms.pRsp           = &TermStatsMcRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(TermStatsMcRsp);
    ulResult = OctVc1PktApiSessCmdExecute(f_pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        goto ErrorHandling;
    }

    /*
     * Swap the command response.
     */
    mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP_SWAP(&TermStatsMcRsp);

    /*
     * Print the statistics.
     */
    printf("+-- VOC TERM MC STATISTICS (%08x-%08x-%08x) ----------------------\n",
            TermStatsMcRsp.ObjectGet.hObject.aulHandle[0],
            TermStatsMcRsp.ObjectGet.hObject.aulHandle[1],
            TermStatsMcRsp.ObjectGet.hObject.aulHandle[2]);
    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulRxInPktCnt);
    printf("| RxInPktCnt                  : %s\n", szBuffer);
    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulRxInByteCnt);
    printf("| RxInByteCnt                 : %s\n", szBuffer);
    printf("| RxOutPktCnt                 : %u\n", TermStatsMcRsp.ulRxOutPktCnt);
    printf("| RxInSidPktCnt               : %u\n", TermStatsMcRsp.ulRxInSidPktCnt);
    printf("| RxNoPktCnt                  : %u\n", TermStatsMcRsp.ulRxNoPktCnt);
    printf("| RxBadPktTypeCnt             : %u\n", TermStatsMcRsp.ulRxBadPktTypeCnt);
    printf("| RxBadRtpPayloadTypeCnt      : %u\n", TermStatsMcRsp.ulRxBadRtpPayloadTypeCnt);    
    printf("| RxBadPktHdrFormatCnt        : %u\n", TermStatsMcRsp.ulRxBadPktHdrFormatCnt);
    printf("| RxBadPktLengthCnt           : %u\n", TermStatsMcRsp.ulRxBadPktLengthCnt);
    printf("| RxMisorderedPktCnt          : %u\n", TermStatsMcRsp.ulRxMisorderedPktCnt);
    printf("| RxLostPktCnt                : %u\n", TermStatsMcRsp.ulRxLostPktCnt);
    printf("| RxBadPktChecksumCnt         : %u\n", TermStatsMcRsp.ulRxBadPktChecksumCnt);
    printf("| RxUnderrunSlipCnt           : %u\n", TermStatsMcRsp.ulRxUnderrunSlipCnt);
    printf("| RxOverrunSlipCnt            : %u\n", TermStatsMcRsp.ulRxOverrunSlipCnt);
    printf("| RxLastVocoderType           : %u\n", TermStatsMcRsp.ulRxLastVocoderType);
    printf("| RxVocoderChangeCnt          : %u\n", TermStatsMcRsp.ulRxVocoderChangeCnt);
    printf("| RxMaxDetectedPdv            : %u (in 125 us)\n", TermStatsMcRsp.ulRxMaxDetectedPdv);
    printf("| RxDecdrRate                 : %u\n", TermStatsMcRsp.ulRxDecdrRate);
    printf("| RxJitterCurrentDelay        : %u (in 125 us)\n", TermStatsMcRsp.ulRxJitterCurrentDelay);
    printf("| RxJitterEstimatedDelay      : %u (in 125 us)\n", TermStatsMcRsp.ulRxJitterEstimatedDelay);
    printf("| RxJitterEstimatedDelay      : %u (in 125 us)\n", TermStatsMcRsp.lRxJitterClkDriftingDelta);
    printf("| RxJitterClkDriftingCorrectionCnt : %u\n", TermStatsMcRsp.ulRxJitterClkDriftingCorrectionCnt);
    printf("| RxJitterInitializationCnt   : %u\n", TermStatsMcRsp.ulRxJitterInitializationCnt);
    printf("| RxCircularBufferWriteErrCnt : %u\n", TermStatsMcRsp.ulRxCircularBufferWriteErrCnt);
    printf("| RxApiEventCnt               : %u\n", TermStatsMcRsp.ulRxApiEventCnt);
    printf("| TxCurrentVocoderType        : %u\n", TermStatsMcRsp.ulTxCurrentVocoderType);
    printf("| TxInPktCnt                  : %u\n", TermStatsMcRsp.ulTxInPktCnt);
    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulTxOutPktCnt);
    printf("| TxOutPktCnt                 : %s\n", szBuffer);
    mOCT_UINT64TOA(szBuffer, TermStatsMcRsp.aulTxOutByteCnt);
    printf("| TxOutByteCnt                : %s\n", szBuffer);
    printf("| TxInBadPktPayloadCnt        : %u\n", TermStatsMcRsp.ulTxInBadPktPayloadCnt);
    printf("| TxTimestampGapCnt           : %u\n", TermStatsMcRsp.ulTxTimestampGapCnt);
    printf("| TxTdmWriteErrCnt            : %u\n", TermStatsMcRsp.ulTxTdmWriteErrCnt);
    printf("| RxToneDetectedCnt           : %u\n", TermStatsMcRsp.ulRxToneDetectedCnt);
    printf("| RxToneRelayEventPktCnt      : %u\n", TermStatsMcRsp.ulRxToneRelayEventPktCnt);
    printf("| RxToneRelayUnsupportedCnt   : %u\n", TermStatsMcRsp.ulRxToneRelayUnsupportedCnt);
    printf("| TxToneRelayEventPktCnt      : %u\n", TermStatsMcRsp.ulTxToneRelayEventPktCnt);
    printf("| TxApiEventCnt               : %u\n", TermStatsMcRsp.ulTxApiEventCnt);
    printf("| TxNoRtpEntryPktDropCnt      : %u\n", TermStatsMcRsp.ulTxNoRtpEntryPktDropCnt);
    printf("| ConnectionWaitAckFlag       : %u\n", TermStatsMcRsp.ulConnectionWaitAckFlag);
    printf("| RxMipsProtectionDropCnt     : %u\n", TermStatsMcRsp.ulRxMipsProtectionDropCnt);
    printf("| TxMipsProtectionDropCnt     : %u\n", TermStatsMcRsp.ulTxMipsProtectionDropCnt);
    printf("| CallTimerMsec               : %u\n", TermStatsMcRsp.ulCallTimerMsec);
    printf("\n");

    *f_phVocTerm  = TermStatsMcRsp.ObjectGet.hObject;
    *f_pulGetMode = TermStatsMcRsp.ObjectGet.ulGetMode;
    
    return cOCTVC1_RC_OK;

ErrorHandling:
    return ulResult;
}

tOCT_UINT32 OctVocSamplesPrintModuleNetConfigInfo(tPOCTVC1_PKT_API_SESS f_pPktApiSess)
{
    tOCTVC1_NET_MSG_MODULE_GET_CONFIG_CMD ModuleGetConfigCmd;
    tOCTVC1_NET_MSG_MODULE_GET_CONFIG_RSP ModuleGetConfigRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS     CmdExecuteParms;
    tOCT_UINT32                           ulResult;

    /*
 *      * Prepare command data.
 *           */
    mOCTVC1_NET_MSG_MODULE_GET_CONFIG_CMD_DEF(&ModuleGetConfigCmd);
    mOCTVC1_NET_MSG_MODULE_GET_CONFIG_CMD_SWAP(&ModuleGetConfigCmd);

    /*
 *      * Execute the command.
 *           */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &ModuleGetConfigCmd;
    CmdExecuteParms.pRsp           = &ModuleGetConfigRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(ModuleGetConfigRsp);
    ulResult = OctVc1PktApiSessCmdExecute(f_pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
        goto ErrorHandling;
    }

    /*
 *      * Swap the command response.
 *           */
    mOCTVC1_NET_MSG_MODULE_GET_CONFIG_RSP_SWAP(&ModuleGetConfigRsp);
/*
 *      * Print the information.
 *           */
    printf("+-- MODULE CONFIGURATION INFORMATION -----------------------------------------\n");
    printf("| Static Parameters\n");
    printf("|  MaxRtpMember   : %u\n", ModuleGetConfigRsp.Static.ulMaxRtpMember);
    printf("|  MaxRtpSession  : %u\n", ModuleGetConfigRsp.Static.ulMaxRtpSession);
    printf("|  MaxLocalIpHost : %u\n", ModuleGetConfigRsp.Static.ulMaxLocalIpHost);
    printf("\n");

    return cOCTVC1_RC_OK;

ErrorHandling:
    return ulResult;
}
