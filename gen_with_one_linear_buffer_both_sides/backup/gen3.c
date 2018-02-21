/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

File: generator.c

Copyright (c) 2016 Octasic Inc. All rights reserved.
    
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

Release: Vocallo Software Development Kit VOCALLO_MGW-03.01.01-B1210 (2016/08/26)

$Revision: 29117 $

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

#define OCTVC1_OPT_DECLARE_DEFAULTS

/***************************  INCLUDE FILES  *********************************/

#include <stdio.h>
#include <string.h>

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
#define cOCTVOCSAMPLES_PCM 1

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
    tOCT_UINT32         ulSidRtpPayloadTypeA;                                    /* RTP member A's RTP payload type for SID */
    tOCT_UINT32         ulSidPktEncodingTypeA;                                   /* RTP member A's packet encoding type for SID*/
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
    tOCT_UINT32         ulSidRtpPayloadTypeB;                                    /* RTP member B's RTP payload type for SID */
    tOCT_UINT32         ulSidPktEncodingTypeB;                                   /* RTP member B's packet encoding type for SID*/
    char                szRtpMemberRtcpCnameB[cOCTVC1_NET_MAX_CNAME_LENGTH + 1]; /* RTP member B's RTCP canonical name. */
} tOCTVOCSAMPLES_APP_CFG, *tPOCTVOCSAMPLES_APP_CFG, **tPPOCTVOCSAMPLES_APP_CFG;

#define MAX_DSPS 1
#define MAX_CONNECTIONS 100
/*
 * This structure contains application context data.
 */
typedef struct tOCTVOCSAMPLES_APP_CTX_TAG
{
    tOCTVOCSAMPLES_PKT_API_INFO PktApiInfo;     /* Packet API information. */
    tOCTVC1_HANDLE              ahEthLinks[2];  /* Ethernet link handles. */
    tOCTVC1_HANDLE              hVocalloHostA;  /* Vocallo host A's handle. */
    tOCTVC1_HANDLE              hVocTermA[MAX_CONNECTIONS];      /* Voice termination A's handle. */
    tOCTVC1_HANDLE              hRtpSessionA[MAX_CONNECTIONS];   /* RTP session A's handle. */
    tOCT_UINT32                 ulRtpMemberIdA[MAX_CONNECTIONS]; /* RTP member A's ID. */
    tOCTVC1_HANDLE              hVocalloHostB;  /* Vocallo host B's handle. */
    tOCTVC1_HANDLE              hVocTermB[MAX_CONNECTIONS];      /* Voice termination B's handle. */
    tOCTVC1_HANDLE              hRtpSessionB[MAX_CONNECTIONS];   /* RTP session B's handle. */
    tOCT_UINT32                 ulRtpMemberIdB[MAX_CONNECTIONS]; /* RTP member B's ID. */
    tOCTVC1_MAIN_OPUS_CORE_INFO aCoreInfo[cOCTVC1_MAIN_MAX_CORE_NUMBER]; /* Array of core information. */
    tOCT_UINT8                  szProcessImageName[(cOCTVC1_MAIN_PROCESS_IMAGE_NAME_MAX_LENGTH+1)];
    tOCT_UINT32                 ulNumActiveCores;   /* Number of active cores. */
    tOCTVC1_HANDLE_OBJECT       hBufferNum[cOCTVOCSAMPLES_PCM];
    tOCT_UINT8                  CloseReceiveFlagA; /* Flag to stop receive thread. */
    tOCT_UINT8                  CloseReceiveFlagB; /* Flag to stop receive thread. */
} tOCTVOCSAMPLES_APP_CTX, *tPOCTVOCSAMPLES_APP_CTX, **tPPOCTVOCSAMPLES_APP_CTX;

/***************************  GLOBAL VARIABLES  ******************************/

/*
 * Application configuration data.
 *
 * Note: The values used in this sample are provided as a guide for supplying
 *       the real values in the actual system.
 */
tOCTVOCSAMPLES_APP_CFG g_AppCfg =
{
    /* Packet API's physical network interfaces for commands and responses. */
    { 0xec, 0x9e, 0xcd, 0x19, 0x73, 0xc8 },                            /* Processor control port's MAC address. */
    //{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                            /* Processor control port's MAC address. */
    { 0x00, 0x0c, 0x90, 0x33, 0x2b, 0x2e },                            /* Vocallo control port's MAC address (port 0 or 1). */
    //{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                            /* Vocallo control port's MAC address (port 0 or 1). */
    /* Side A's settings. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80040, 0, 0, 0 } }, 49754 }, /* Host A's RTP UDP address [192.168.0.100:49152]. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80040, 0, 0, 0 } }, 49755 }, /* Host A's RTCP UDP address [192.168.0.100:49153]. */
    "host_a@octasic.com",                                              /* Host A's RTCP canonical name. */
    0,                                                                 /* Vocallo host A's Ethernet port (port 0 or 1). */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A8004B, 0, 0, 0 } },            /* Vocallo host A's IP address [192.168.0.64]. */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },            /* Vocallo host A's network mask [255.255.255.0]. */
    49754,                                                             /* RTP member A's RTP UDP port. */
    49755,                                                             /* RTP member A's RTCP UDP port. */
    0,                                                                 /* RTP member A's RTP payload type */
    cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_U_LAW,                              /* RTP member A's packet encoding type */
    1,                                                                 /* RTP member A's RTP payload type for SID */
    cOCTVOCNET_PKT_D_TYPE_ENUM_GEN_SID,                                /* RTP member A's packet encoding type for SID*/
    "rtp_member_a3@octasic.com",                                       /* RTP member A's RTCP canonical name. */
    /* Side B's settings. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A40, 0, 0, 0 } }, 49754 }, /* Host B's RTP UDP address [192.168.10.100:49152]. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A40, 0, 0, 0 } }, 49755 }, /* Host B's RTCP UDP address [192.168.10.100:49153]. */
    "host_b@octasic.com",                                              /* Host B's RTCP canonical name. */
    0,                                                                 /* Vocallo host B's Ethernet port (port 0 or 1). */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A4B, 0, 0, 0 } },            /* Vocallo host B's IP address [192.168.10.64]. */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },            /* Vocallo host B's network mask [255.255.255.0]. */
    49754,                                                             /* RTP member B's RTP UDP port. */
    49755,                                                             /* RTP member B's RTCP UDP port. */
    8,                                                                 /* RTP member B's RTP payload type */
    cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_A_LAW,                              /* RTP member B's packet encoding type */
    1,                                                                 /* RTP member B's RTP payload type for SID */
    cOCTVOCNET_PKT_D_TYPE_ENUM_GEN_SID,                                /* RTP member B's packet encoding type for SID*/
    "rtp_member_b3@octasic.com"                                        /* RTP member B's RTCP canonical name. */
};

tOCT_UINT8 szBufferName[cOCTVOCSAMPLES_PCM][cOCTVC1_MAIN_FILE_NAME_MAX_LENGTH+1]={
    "../../common/media/audio/IW105_50_BE.pcm"
};

/*
 * Application context data.
 */
tOCTVOCSAMPLES_APP_CTX g_AppCtx;
tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP g_AppStats;
pthread_t th_Recv;

/***************************  FUNCTION PROTOTYPES  ***************************/

static int CloseNetworkResources(void);
static int CloseSideA(tOCT_UINT32 ulConnectionNumber);
static int CloseSideB(tOCT_UINT32 ulConnectionNumber);
static int GetCpuUsage(void);
static int GetProcInfo(int f_Idx);
static int GetInfoOpusCore(void);
static void MonitorLinks(void);

/***************************  PRIVATE FUNCTIONS  *****************************/

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       OpenNetworkResources

Description:    Opens all Ethernet links (0 and 1) and Vocallo host.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int OpenNetworkResources(void)
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
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.ahEthLinks[i] = EthLinkOpenRsp.hEthLink;
    }

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
        LocalHostOpenCmd.IpAddress   = g_AppCfg.VocalloHostIpAddrA;
        LocalHostOpenCmd.NetworkMask = g_AppCfg.VocalloHostNetworkMaskA;
        LocalHostOpenCmd.hLink       = g_AppCtx.ahEthLinks[g_AppCfg.ulVocalloHostEthPortA];
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD_SWAP(&LocalHostOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostOpenCmd;
        CmdExecuteParms.pRsp           = &LocalHostOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.hVocalloHostA = LocalHostOpenRsp.hLocalHost;
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
        LocalHostOpenCmd.IpAddress   = g_AppCfg.VocalloHostIpAddrB;
        LocalHostOpenCmd.NetworkMask = g_AppCfg.VocalloHostNetworkMaskB;
        LocalHostOpenCmd.hLink       = g_AppCtx.ahEthLinks[g_AppCfg.ulVocalloHostEthPortB];
        mOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CMD_SWAP(&LocalHostOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostOpenCmd;
        CmdExecuteParms.pRsp           = &LocalHostOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.hVocalloHostB = LocalHostOpenRsp.hLocalHost;
    }

    return 0;

ErrorHandling:
    CloseNetworkResources();
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseNetworkResources

Description:    Closes all Ethernet links (0 and 1) and Vocallo host.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CloseNetworkResources(void)
{
    tOCT_UINT32 i;

    /*************************************************************************\
     * Close Vocallo host A.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hVocalloHostA.aulHandle[0])
    {
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD LocalHostCloseCmd;
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_RSP LocalHostCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_DEF(&LocalHostCloseCmd);
        LocalHostCloseCmd.hLocalHost = g_AppCtx.hVocalloHostA;
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_SWAP(&LocalHostCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostCloseCmd;
        CmdExecuteParms.pRsp           = &LocalHostCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hVocalloHostA.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close Vocallo host B.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hVocalloHostB.aulHandle[0])
    {
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD LocalHostCloseCmd;
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_RSP LocalHostCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_DEF(&LocalHostCloseCmd);
        LocalHostCloseCmd.hLocalHost = g_AppCtx.hVocalloHostB;
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_SWAP(&LocalHostCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &LocalHostCloseCmd;
        CmdExecuteParms.pRsp           = &LocalHostCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(LocalHostCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hVocalloHostB.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close Ethernet links.
    \*************************************************************************/

    for (i = 0; i < 2; i++)
    {
        if (cOCTVC1_HANDLE_INVALID != g_AppCtx.ahEthLinks[i].aulHandle[0])
        {
            tOCTVC1_NET_MSG_ETH_LINK_CLOSE_CMD EthLinkCloseCmd;
            tOCTVC1_NET_MSG_ETH_LINK_CLOSE_RSP EthLinkCloseRsp;
            tOCTVC1_PKT_API_CMD_EXECUTE_PARMS  CmdExecuteParms;
            tOCT_UINT32                        ulResult;

            /*
             * Prepare command data.
             */
            mOCTVC1_NET_MSG_ETH_LINK_CLOSE_CMD_DEF(&EthLinkCloseCmd);
            EthLinkCloseCmd.hEthLink = g_AppCtx.ahEthLinks[i];
            mOCTVC1_NET_MSG_ETH_LINK_CLOSE_CMD_SWAP(&EthLinkCloseCmd);

            /*
             * Execute the command.
             */
            mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
            CmdExecuteParms.pCmd           = &EthLinkCloseCmd;
            CmdExecuteParms.pRsp           = &EthLinkCloseRsp;
            CmdExecuteParms.ulMaxRspLength = sizeof(EthLinkCloseRsp);
            ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
            if (cOCTVC1_RC_OK != ulResult)
            {
                fprintf(stderr, "Error: cOCTVC1_NET_MSG_ETH_LINK_CLOSE_CID failed (Ethernet %u), rc = 0x%08x\n", i, ulResult);
                fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
                goto ErrorHandling;
            }
            g_AppCtx.ahEthLinks[i].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
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

static int CreateSideA(tOCT_UINT32 ulConnectionNumber)
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
        ModuleModifyProfileMcCmd.McProfile.ulTxEnableSilenceSuppressionFlag           = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulTxSidFlag                                = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulRxPlcEnableFlag                          = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulRxJitterMode                             = cOCTVC1_VSPMP_VOC_JITTER_ENUM_ADAPTIVE;
        ModuleModifyProfileMcCmd.McProfile.ulPcmLaw                         = cOCTVC1_VSPMP_VOC_PCM_ENUM_LAW_U;
        mOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD_SWAP(&ModuleModifyProfileMcCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &ModuleModifyProfileMcCmd;
        CmdExecuteParms.pRsp           = &ModuleModifyProfileMcRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(ModuleModifyProfileMcRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.hVocTermA[ulConnectionNumber] = TermOpenRsp.hTerm;
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
        RtpSessionOpenCmd.hLocalHost = g_AppCtx.hVocalloHostA;
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD_SWAP(&RtpSessionOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionOpenCmd;
        CmdExecuteParms.pRsp           = &RtpSessionOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.hRtpSessionA[ulConnectionNumber] = RtpSessionOpenRsp.hRtpSession;
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
        RtpSessionActivateMemberCmd.hRtpSession                        = g_AppCtx.hRtpSessionA[ulConnectionNumber];
        RtpSessionActivateMemberCmd.hTerm                              = g_AppCtx.hVocTermA[ulConnectionNumber];
        RtpSessionActivateMemberCmd.ulRxPktFilter                      = cOCTVC1_NET_RX_PKT_FILTER_ENUM_NONE;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtp                  = g_AppCfg.ulRtpMemberRtpUdpPortA;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtcp                 = g_AppCfg.ulRtpMemberRtcpUdpPortA;
        RtpSessionActivateMemberCmd.ulLocalCnameLength                 = strlen(g_AppCfg.szRtpMemberRtcpCnameA);
        strncpy((char *)RtpSessionActivateMemberCmd.achLocalCname, g_AppCfg.szRtpMemberRtcpCnameA, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtp                = g_AppCfg.HostRtpUdpAddressA;
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtcp               = g_AppCfg.HostRtcpUdpAddressA;
        RtpSessionActivateMemberCmd.ulRemoteCnameLength                = strlen(g_AppCfg.szHostRtcpCnameA);
        strncpy((char *)RtpSessionActivateMemberCmd.achRemoteCname, g_AppCfg.szHostRtcpCnameA, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.ulNumProfEntry                     = 2;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulPktEncodingType = g_AppCfg.ulPktEncodingTypeA;;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulRtpPayloadType  = g_AppCfg.ulRtpPayloadTypeA;
        RtpSessionActivateMemberCmd.aRtpProfEntry[1].ulPktEncodingType = g_AppCfg.ulSidPktEncodingTypeA;;
        RtpSessionActivateMemberCmd.aRtpProfEntry[1].ulRtpPayloadType  = g_AppCfg.ulSidRtpPayloadTypeA;
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD_SWAP(&RtpSessionActivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionActivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionActivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionActivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.ulRtpMemberIdA[ulConnectionNumber] = RtpSessionActivateMemberRsp.ulLocalMemberId;
    }

    return 0;

ErrorHandling:
    CloseSideA(ulConnectionNumber);
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseSideA

Description:    Closes side A.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CloseSideA(tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Deactivate RTP member A.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hRtpSessionA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD RtpSessionDeactivateMemberCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_RSP RtpSessionDeactivateMemberRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                 CmdExecuteParms;
        tOCT_UINT32                                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_DEF(&RtpSessionDeactivateMemberCmd);
        RtpSessionDeactivateMemberCmd.hRtpSession     = g_AppCtx.hRtpSessionA[ulConnectionNumber];
        RtpSessionDeactivateMemberCmd.ulLocalMemberId = g_AppCtx.ulRtpMemberIdA[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_SWAP(&RtpSessionDeactivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionDeactivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionDeactivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionDeactivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hRtpSessionA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD RtpSessionCloseCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_RSP RtpSessionCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS     CmdExecuteParms;
        tOCT_UINT32                           ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_DEF(&RtpSessionCloseCmd);
        RtpSessionCloseCmd.hRtpSession = g_AppCtx.hRtpSessionA[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_SWAP(&RtpSessionCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionCloseCmd;
        CmdExecuteParms.pRsp           = &RtpSessionCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hRtpSessionA[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close voice termination A.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hVocTermA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD TermCloseCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_RSP TermCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_DEF(&TermCloseCmd);
        TermCloseCmd.hTerm = g_AppCtx.hVocTermA[ulConnectionNumber];
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_SWAP(&TermCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermCloseCmd;
        CmdExecuteParms.pRsp           = &TermCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CID failed (Side A), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hVocTermA[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CreateBuffer

Description:    Creates a playout buffer and loads its content from a
                 specified file.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
static int CreateBuffer(void)
{
    tOCT_INT32 i;

    for ( i = 0; i < cOCTVOCSAMPLES_PCM; i++)
    {
        /*
         * Open local file and check size
         */
        FILE * pFile;
        tOCT_INT32    lSize;
        pFile = fopen ( szBufferName[i] , "rb" );
        if ( pFile == NULL )
        {
            fprintf(stderr, "Error: Could not open file");
            goto ErrorHandling;
        }

        fseek (pFile , 0 , SEEK_END);
        lSize = ftell (pFile);
        rewind (pFile);

        if ( 0 == lSize )
        {
            fprintf(stderr, "Error: file is empty");
            goto ErrorHandling;
        }

        /*
         * Open Buffer
         */
{
            tOCTVC1_MAIN_MSG_BUFFER_OPEN_CMD        BufferOpenCmd;
            tOCTVC1_MAIN_MSG_BUFFER_OPEN_RSP        BufferOpenRsp;
            tOCTVC1_PKT_API_CMD_EXECUTE_PARMS       CmdExecuteParms;
            tOCT_UINT32                             ulResult;

            /*
             * Prepare command data.
             */
            mOCTVC1_MAIN_MSG_BUFFER_OPEN_CMD_DEF(&BufferOpenCmd);
            BufferOpenCmd.ulFormat = cOCTVC1_BUFFER_FORMAT_VSPMP_VOC_ENUM_RAW_LINEAR_8KSS;
            BufferOpenCmd.ulByteLength = lSize;
            strcpy(BufferOpenCmd.szBufferName, szBufferName[i]);
            mOCTVC1_MAIN_MSG_BUFFER_OPEN_CMD_SWAP(&BufferOpenCmd);

            /*
             * Execute the command.
             */
            mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
            CmdExecuteParms.pCmd           = &BufferOpenCmd;
            CmdExecuteParms.pRsp           = &BufferOpenRsp;
            CmdExecuteParms.ulMaxRspLength = sizeof(BufferOpenRsp);
            ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
            if (cOCTVC1_RC_OK != ulResult)
            {
                fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_BUFFER_OPEN_CID failed, rc = 0x%08x\n", ulResult);
                fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
                goto ErrorHandling;
            }
            /*
             * Swap the command response.
             */
            mOCTVC1_MAIN_MSG_BUFFER_OPEN_RSP_SWAP(&BufferOpenRsp);

            g_AppCtx.hBufferNum[i] = BufferOpenRsp.hBuffer;

        }

        /*
         * Send file to fill the buffer
         */
        {
            tOCT_INT32    lWriteOffset=0;

            do
            {
                tOCTVC1_MAIN_MSG_BUFFER_WRITE_CMD        BufferWriteCmd;
                tOCTVC1_MAIN_MSG_BUFFER_WRITE_RSP        BufferWriteRsp;
                tOCTVC1_PKT_API_CMD_EXECUTE_PARMS        CmdExecuteParms;
                tOCT_UINT32                              ulResult;


                /*
                 * Prepare command data.
                 */
                mOCTVC1_MAIN_MSG_BUFFER_WRITE_CMD_DEF(&BufferWriteCmd);
                BufferWriteCmd.hBuffer = g_AppCtx.hBufferNum[i];
                BufferWriteCmd.ulWriteByteOffset = lWriteOffset;
                BufferWriteCmd.ulWriteByteLength = (lSize < cOCTVC1_MAIN_BUFFER_MAX_DATA_BYTE_SIZE) ? lSize : cOCTVC1_MAIN_BUFFER_MAX_DATA_BYTE_SIZE;
                if ( fread(BufferWriteCmd.abyWriteData, sizeof(tOCT_UINT8), BufferWriteCmd.ulWriteByteLength, pFile) != BufferWriteCmd.ulWriteByteLength )
                {
                    fprintf(stderr, "Error: file read");
                    goto ErrorHandling;
                }

                mOCTVC1_MAIN_MSG_BUFFER_WRITE_CMD_SWAP(&BufferWriteCmd);

                /*
                 * Execute the command.
                 */
                mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
                CmdExecuteParms.pCmd           = &BufferWriteCmd;
                CmdExecuteParms.pRsp           = &BufferWriteRsp;
                CmdExecuteParms.ulMaxRspLength = sizeof(BufferWriteRsp);
                ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
                if (cOCTVC1_RC_OK != ulResult)
                {
                    fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_BUFFER_WRITE_CID failed, rc = 0x%08x\n", ulResult);
                    fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
                    goto ErrorHandling;
                }

                /*
                 * Swap the command response.
                 */
                mOCTVC1_MAIN_MSG_BUFFER_WRITE_RSP_SWAP(&BufferWriteRsp);

                lSize -= BufferWriteRsp.ulNumByteWritten;
                lWriteOffset += BufferWriteRsp.ulNumByteWritten;

            } while ( lSize > 0 );
        }
    }
 return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseBuffer

Description:    Removes the buffer from memory

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
static int CloseBuffer(void)
{
    tOCT_INT32 i;
    
    /*
     * Close buffer
     */
    for ( i = 0; i < cOCTVOCSAMPLES_PCM; i++)
    {
        tOCTVC1_MAIN_MSG_BUFFER_CLOSE_CMD        BufferCloseCmd;
        tOCTVC1_MAIN_MSG_BUFFER_CLOSE_RSP        BufferCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS        CmdExecuteParms;
        tOCT_UINT32                              ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_MAIN_MSG_BUFFER_CLOSE_CMD_DEF(&BufferCloseCmd);
        BufferCloseCmd.hBuffer = g_AppCtx.hBufferNum[i];
        mOCTVC1_MAIN_MSG_BUFFER_CLOSE_CMD_SWAP(&BufferCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &BufferCloseCmd;
        CmdExecuteParms.pRsp           = &BufferCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(BufferCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_BUFFER_CLOSE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_MAIN_MSG_BUFFER_CLOSE_RSP_SWAP(&BufferCloseRsp);
    }

    return 0;

ErrorHandling:
    return -1;
}
    
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CreateSideB

Description:    Creates side B.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CreateSideB(tOCT_UINT32 ulConnectionNumber)
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
        ModuleModifyProfileMcCmd.ulProfileIndex                                       = cOCTVOCSAMPLES_TERM_PROFILE_INDEX_B;
        ModuleModifyProfileMcCmd.ulRestoreDefaultFlag                                 = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulTxEnableSilenceSuppressionFlag           = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulTxSidFlag                                = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulRxPlcEnableFlag                          = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulRxJitterMode                             = cOCTVC1_VSPMP_VOC_JITTER_ENUM_ADAPTIVE;
        ModuleModifyProfileMcCmd.McProfile.ulPcmLaw                                   = cOCTVC1_VSPMP_VOC_PCM_ENUM_LAW_A;
        mOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CMD_SWAP(&ModuleModifyProfileMcCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &ModuleModifyProfileMcCmd;
        CmdExecuteParms.pRsp           = &ModuleModifyProfileMcRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(ModuleModifyProfileMcRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.hVocTermB[ulConnectionNumber] = TermOpenRsp.hTerm;
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
        RtpSessionOpenCmd.hLocalHost = g_AppCtx.hVocalloHostB;
        mOCTVC1_NET_MSG_RTP_SESSION_OPEN_CMD_SWAP(&RtpSessionOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionOpenCmd;
        CmdExecuteParms.pRsp           = &RtpSessionOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.hRtpSessionB[ulConnectionNumber] = RtpSessionOpenRsp.hRtpSession;
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
        RtpSessionActivateMemberCmd.hRtpSession                        = g_AppCtx.hRtpSessionB[ulConnectionNumber];
        RtpSessionActivateMemberCmd.hTerm                              = g_AppCtx.hVocTermB[ulConnectionNumber];
        RtpSessionActivateMemberCmd.ulRxPktFilter                      = cOCTVC1_NET_RX_PKT_FILTER_ENUM_NONE;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtp                  = g_AppCfg.ulRtpMemberRtpUdpPortB;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtcp                 = g_AppCfg.ulRtpMemberRtcpUdpPortB;
        RtpSessionActivateMemberCmd.ulLocalCnameLength                 = strlen(g_AppCfg.szRtpMemberRtcpCnameB);
        strncpy((char *)RtpSessionActivateMemberCmd.achLocalCname, g_AppCfg.szRtpMemberRtcpCnameB, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtp                = g_AppCfg.HostRtpUdpAddressB;
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtcp               = g_AppCfg.HostRtcpUdpAddressB;
        RtpSessionActivateMemberCmd.ulRemoteCnameLength                = strlen(g_AppCfg.szHostRtcpCnameB);
        strncpy((char *)RtpSessionActivateMemberCmd.achRemoteCname, g_AppCfg.szHostRtcpCnameB, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.ulNumProfEntry                     = 2;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulPktEncodingType = g_AppCfg.ulPktEncodingTypeB;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulRtpPayloadType  = g_AppCfg.ulRtpPayloadTypeB;
        RtpSessionActivateMemberCmd.aRtpProfEntry[1].ulPktEncodingType = g_AppCfg.ulSidPktEncodingTypeB;
        RtpSessionActivateMemberCmd.aRtpProfEntry[1].ulRtpPayloadType  = g_AppCfg.ulSidRtpPayloadTypeB;
        mOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CMD_SWAP(&RtpSessionActivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionActivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionActivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionActivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
        g_AppCtx.ulRtpMemberIdB[ulConnectionNumber] = RtpSessionActivateMemberRsp.ulLocalMemberId;
    }

    return 0;

ErrorHandling:
    CloseSideB(ulConnectionNumber);
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseSideB

Description:    Closes side B.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CloseSideB(tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Deactivate RTP member B.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hRtpSessionB[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD RtpSessionDeactivateMemberCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_RSP RtpSessionDeactivateMemberRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                 CmdExecuteParms;
        tOCT_UINT32                                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_DEF(&RtpSessionDeactivateMemberCmd);
        RtpSessionDeactivateMemberCmd.hRtpSession     = g_AppCtx.hRtpSessionB[ulConnectionNumber];
        RtpSessionDeactivateMemberCmd.ulLocalMemberId = g_AppCtx.ulRtpMemberIdB[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_SWAP(&RtpSessionDeactivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionDeactivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionDeactivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionDeactivateMemberRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hRtpSessionB[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD RtpSessionCloseCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_RSP RtpSessionCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS     CmdExecuteParms;
        tOCT_UINT32                           ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_DEF(&RtpSessionCloseCmd);
        RtpSessionCloseCmd.hRtpSession = g_AppCtx.hRtpSessionB[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_SWAP(&RtpSessionCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionCloseCmd;
        CmdExecuteParms.pRsp           = &RtpSessionCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hRtpSessionB[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close voice termination B.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hVocTermB[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD TermCloseCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_RSP TermCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_DEF(&TermCloseCmd);
        TermCloseCmd.hTerm = g_AppCtx.hVocTermB[ulConnectionNumber];
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_SWAP(&TermCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermCloseCmd;
        CmdExecuteParms.pRsp           = &TermCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CID failed (Side B), rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hVocTermB[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       ConnectTerms

Description:    Connects the two voice terminations (A and B).

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int ConnectTerms(tOCT_UINT32 ulConnectionNumber)
{
    tOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_CMD TermConnectCmd;
    tOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_RSP TermConnectRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS      CmdExecuteParms;
    tOCT_UINT32                            ulResult;

    /*
     * Prepare command data.
     */
    mOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_CMD_DEF(&TermConnectCmd);
    TermConnectCmd.hTermFirst  = g_AppCtx.hVocTermA[ulConnectionNumber];
    TermConnectCmd.hTermSecond = g_AppCtx.hVocTermB[ulConnectionNumber];
    mOCTVC1_VSPMP_VOC_MSG_TERM_CONNECT_CMD_SWAP(&TermConnectCmd);

    /*
     * Execute the command.
     */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &TermConnectCmd;
    CmdExecuteParms.pRsp           = &TermConnectRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(TermConnectRsp);
    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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

static int DisconnectTerms(tOCT_UINT32 ulConnectionNumber)
{
    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hVocTermA[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_CMD TermDisconnectCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_RSP TermDisconnectRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS         CmdExecuteParms;
        tOCT_UINT32                               ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_CMD_DEF(&TermDisconnectCmd);
        TermDisconnectCmd.hTerm = g_AppCtx.hVocTermA[ulConnectionNumber];
        mOCTVC1_VSPMP_VOC_MSG_TERM_DISCONNECT_CMD_SWAP(&TermDisconnectCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermDisconnectCmd;
        CmdExecuteParms.pRsp           = &TermDisconnectRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermDisconnectRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
Function:       Receive - thread function
           
Description:    Receives all responses sent using Sent API.
                                    
Arguments:      None
Return Value:   Success - 0
                Failure - (-1)

Note: The receive thread exits with timeout error 
    if no reponse to a command is received within 1 minute
\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
void* Receive(void *arg)
{
        tOCT_UINT32                       ulResult;
        tOCTVC1_PKT_API_INST_RECV_PARMS   PktApiInstRecvParms;
        tOCTVC1_PKT_API_INST_INIT_PARMS   PktApiInstInit;
        tOCT_UINT8                        abyPayload[1500];

        mOCTVC1_PKT_API_INST_RECV_PARMS_DEF(&PktApiInstRecvParms);
        PktApiInstRecvParms.PktRcvMask         = cOCTVC1_PKT_API_RCV_MASK_RSP;
        PktApiInstRecvParms.ulTimeoutMs        = 60000; //1 minute
        PktApiInstRecvParms.pPayload           = abyPayload;
        PktApiInstRecvParms.ulMaxPayloadLength = sizeof(abyPayload);
        if(g_AppCtx.PktApiInfo.pPktApiInst == NULL)
        {
                printf("\n g_AppCtx.PktApiInfo.pPktApiInst NULL ");
                pthread_exit((void*)-1);
        }

        while( cOCTVC1_RC_OK == (ulResult = OctVc1PktApiInstRecv(g_AppCtx.PktApiInfo.pPktApiInst, &PktApiInstRecvParms)))
        {
                /* Media Coder Response */
                if(PktApiInstRecvParms.Info.Rsp.ulCmdId == cOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CID)
                {
                        //continue;
                }
                //if(PktApiInstRecvParms.Info.Rsp.ulCmdId == cOCTVC1_VSPMP_VOC_MSG_TERM_PLAYOUT_STOP_EID)
                if(PktApiInstRecvParms.Info.Evt.ulEvtId == cOCTVC1_VSPMP_VOC_MSG_TERM_PLAYOUT_STOP_EID)
                {
                        printf("Playout stop events arrived.....!\n");
                }
                if(g_AppCtx.CloseReceiveFlagA == 1 && g_AppCtx.CloseReceiveFlagB == 1)
                {
                        break;
                }
        }

        if (cOCTVC1_PKT_API_RC_TIMEOUT == ulResult)
        {
                  /* The timeout interval has elapsed. */
                printf(" \n OctVc1PktApiInstRecv() TIMEOUT (Thread)");
                pthread_exit((void*)-1);

        }

        else if (cOCTVC1_RC_OK != ulResult)
        {
                fprintf(stderr, "Error: OctVc1PktApiInstRecv() failed, rc = 0x%08x\n", ulResult);
                fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
                pthread_exit((void*)-1);
        }

        pthread_exit((void*)0);
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       PlayPcmSideA

Description:    Plays the PCM file with playout

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int PlayPcmSideA(tOCTVC1_HANDLE_OBJECT f_ToneId, tOCT_UINT32 ulConnectionNumber)
{
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD    StartPlayoutCmd;
        tOCTVC1_PKT_API_CMD_SEND_PARMS                  CmdSendParms;
        tOCT_UINT32                                     ulResult;
        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD_DEF(&StartPlayoutCmd);
        StartPlayoutCmd.hTerm = g_AppCtx.hVocTermA[ulConnectionNumber];
        StartPlayoutCmd.ulNumPlayoutEntry = 1;
        StartPlayoutCmd.ulForceStartFlag = cOCT_TRUE;
        StartPlayoutCmd.ulRepeatForeverFlag = cOCT_TRUE;
        StartPlayoutCmd.aPlayoutEntry[0].hEntry = f_ToneId;
        StartPlayoutCmd.aPlayoutEntry[0].ulPlayoutDurationMs = cOCTVC1_VSPMP_VOC_DURATION_COMPLETE_ENTRY;
        StartPlayoutCmd.aPlayoutEntry[0].ulSilenceDurationMs = 50;
        StartPlayoutCmd.aPlayoutEntry[0].ulRepeatForeverFlag = cOCT_TRUE;
        mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD_SWAP(&StartPlayoutCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_SEND_PARMS_DEF(&CmdSendParms);
        CmdSendParms.pCmd           = &StartPlayoutCmd;
        ulResult = OctVc1PktApiSessCmdSend(g_AppCtx.PktApiInfo.pPktApiSess, &CmdSendParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: SideA TERM[%d]:cOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CID failed, rc = 0x%08x\n", ulConnectionNumber,ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
    }
    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       PlayPcmSideB

Description:    Plays the PCM file with playout

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int PlayPcmSideB(tOCTVC1_HANDLE_OBJECT f_ToneId, tOCT_UINT32 ulConnectionNumber)
{
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD    StartPlayoutCmd;
        tOCTVC1_PKT_API_CMD_SEND_PARMS                  CmdSendParms;
        tOCT_UINT32                                     ulResult;
        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD_DEF(&StartPlayoutCmd);
        StartPlayoutCmd.hTerm = g_AppCtx.hVocTermB[ulConnectionNumber];
        StartPlayoutCmd.ulNumPlayoutEntry = 1;
        StartPlayoutCmd.ulForceStartFlag = cOCT_TRUE;
        StartPlayoutCmd.ulRepeatForeverFlag = cOCT_TRUE;
        StartPlayoutCmd.aPlayoutEntry[0].hEntry = f_ToneId;
        StartPlayoutCmd.aPlayoutEntry[0].ulPlayoutDurationMs = cOCTVC1_VSPMP_VOC_DURATION_COMPLETE_ENTRY;
        StartPlayoutCmd.aPlayoutEntry[0].ulSilenceDurationMs = 50;
        StartPlayoutCmd.aPlayoutEntry[0].ulRepeatForeverFlag = cOCT_TRUE;
        mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD_SWAP(&StartPlayoutCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_SEND_PARMS_DEF(&CmdSendParms);
        CmdSendParms.pCmd           = &StartPlayoutCmd;
        ulResult = OctVc1PktApiSessCmdSend(g_AppCtx.PktApiInfo.pPktApiSess, &CmdSendParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: SideB TERM[%d]:cOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CID failed, rc = 0x%08x\n", ulConnectionNumber,ulResult);
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

static int InitApplication(void)
{
    tOCT_UINT32 ulResult;
    tOCT_UINT32 ulConnectionNumber;

    /*
     * Initialize all handles to invalid.
     */
    g_AppCtx.ahEthLinks[0].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    g_AppCtx.ahEthLinks[1].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    for (ulConnectionNumber=0;ulConnectionNumber<MAX_CONNECTIONS;ulConnectionNumber++){
        g_AppCtx.hVocalloHostA.aulHandle[0]                     = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hVocTermA[ulConnectionNumber].aulHandle[0]     = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hRtpSessionA[ulConnectionNumber].aulHandle[0]  = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hVocalloHostB.aulHandle[0]                     = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hVocTermB[ulConnectionNumber].aulHandle[0]     = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hRtpSessionB[ulConnectionNumber].aulHandle[0]  = cOCTVC1_HANDLE_INVALID;
    }
    /*
     * Open a transport packet API session.
     */
    ulResult = OctVocSamplesOpenPktApiSession(&g_AppCtx.PktApiInfo,
                                              g_AppCfg.abyProcessorCtrlMacAddr,
                                              g_AppCfg.abyVocalloCtrlMacAddr);
    if (cOCTVC1_RC_OK != ulResult)
    {
        fprintf(stderr, "Error: OctVocSamplesOpenPktApiSession() failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
        goto ErrorHandling;
    }

    /*
     * Update Ethernet port number to the port we are connected to.
     */
    printf("Connected to port %u of Vocallo device\n", g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx);
    if (g_AppCfg.ulVocalloHostEthPortA != g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx &&
        g_AppCfg.ulVocalloHostEthPortB != g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx)
    {
        printf("Updating Vocallo host A Ethernet port configuration to %u\n\n", g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx);
        g_AppCfg.ulVocalloHostEthPortA = g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx;
    }
    else
        printf("\n");

    /*
     * Print the version of Vocallo in use on the device.
     */
    ulResult = OctVocSamplesPrintModuleVersionInfo(g_AppCtx.PktApiInfo.pPktApiSess);
    if (cOCTVC1_RC_OK != ulResult)
    {
        fprintf(stderr, "Error: OctVocSamplesPrintModuleVersionInfo() failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
        return -1;
    }
    
    /*
     * Print the info for the device.
     */
    ulResult = OctVocSamplesPrintDeviceInfo(g_AppCtx.PktApiInfo.pPktApiSess);
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
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_MODULE_CLEANUP_API_RESOURCE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
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
    tOCT_UINT32 ulResult;

    /*
     * Close the packet API session.
     */
    printf("In ExitApplication function. closing API session\n");
    ulResult = OctVocSamplesClosePktApiSession(&g_AppCtx.PktApiInfo);
    if (cOCTVC1_RC_OK != ulResult)
    {
        fprintf(stderr, "Error: OctVocSamplesClosePktApiSession() failed, rc = 0x%08x\n", ulResult);
        fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
    }
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       main

Description:    Main program.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

int main(int argc, char *argv[])
{
    tOCT_UINT32 ulNumConnections = MAX_CONNECTIONS;
    tOCT_UINT32 ulConnectionNumber;
    tOCT_UINT8  CloseReceiveFlagA=0;
    tOCT_UINT8  CloseReceiveFlagB=0;
    tOCT_UINT32        i;
    /*
     * Display application version information.
     */
    mOCT_PRINT_APP_VERSION_INFO("generator",
				((cOCTVC1_MAIN_VERSION_ID >> 25 ) & 0x7F),
				((cOCTVC1_MAIN_VERSION_ID >> 18)  & 0x7F),
				((cOCTVC1_MAIN_VERSION_ID >> 11)  & 0x7F));
    /*
     * Perform initialization tasks required by the application.
     */
    if (0 != InitApplication())
    {
	return 1;
    }

    /*
     * Create the packet-to-packet voice transcoding channel.
     */
    if (0 != OpenNetworkResources())
    {
	return 1;
    }
   
    if (0 != CreateBuffer())
    {
        goto ErrorHandling;
    }

    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
    {
	if ((0 != CreateSideA(ulConnectionNumber)) ||
	(0 != CreateSideB(ulConnectionNumber)) ||
	(0 != ConnectTerms(ulConnectionNumber)))
      {
	    goto ErrorHandling;
      }
	
	g_AppCfg.ulRtpMemberRtpUdpPortA+=2;/* Source RTP port */
	g_AppCfg.ulRtpMemberRtcpUdpPortA+=2;/* Source RTCP port */
	g_AppCfg.HostRtpUdpAddressA.ulUdpPort+=2;/* Destination RTP UDP port. */
	g_AppCfg.HostRtcpUdpAddressA.ulUdpPort+=2;/* Destination RTCP UDP port. */
	g_AppCfg.ulRtpMemberRtpUdpPortB+=2;/* Source RTP port */
	g_AppCfg.ulRtpMemberRtcpUdpPortB+=2;/* Source RTCP port */
	g_AppCfg.HostRtpUdpAddressB.ulUdpPort+=2;/* Destination RTP UDP port. */
	g_AppCfg.HostRtcpUdpAddressB.ulUdpPort+=2;/* Destination RTCP UDP port. */
    }
    /*
     * Create a playout buffers 
     */
    
    printf("Press [Enter] to start the playout buffer\n");
    getchar();

    /*
     * Create Receive thread.
     */    
    if (0 != pthread_create(&th_Recv,NULL,Receive,NULL))
		goto ErrorHandling;

    /*
     * Start playout on SideA terminations.
     */
    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
    {
	printf("Playing out pcm file on SideA TERM#[%d]\n",ulConnectionNumber);
        for ( i = 0; i < cOCTVOCSAMPLES_PCM; i++ )
        {
	    if (0 != PlayPcmSideA(g_AppCtx.hBufferNum[i], ulConnectionNumber))
	    {
		goto ErrorHandling;
	    }
        }
        if ( ulConnectionNumber == ulNumConnections - 1 )
        {
	    g_AppCtx.CloseReceiveFlagA=1;
        }
        OctOsalSleepMs(1*1000);
    }


    /*
     * Start playout on SideB terminations.
     */
    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
    {
	printf("Playing out pcm file on SideB TERM#[%d]\n",ulConnectionNumber);
        for ( i = 0; i < cOCTVOCSAMPLES_PCM; i++ )
        {
	    if (0 != PlayPcmSideB(g_AppCtx.hBufferNum[i], ulConnectionNumber))
	    {
		goto ErrorHandling;
	    }
        }
        if ( ulConnectionNumber == ulNumConnections - 1 )
        {
	    g_AppCtx.CloseReceiveFlagB=1;
        }
        OctOsalSleepMs(1*1000);
    }
    //printf("Ready to perform packet-to-packet voice transcoding...\n\n");
    //printf("Press Q to stop stats gathering...\n\n");
    if (0 != GetInfoOpusCore())
    {
	goto ErrorHandling;
    }        

    while (!OctKbhit()) 
    {
	if (0 != GetCpuUsage())
	{
	    goto ErrorHandling;
	}
	MonitorLinks();
        //OctOsalSleepMs(5*1000);/* Wait 5 sec */
    }
    printf("Press [Enter] to quit the application\n");
    getchar();
    
    /*
     * close buffer
     */
     CloseBuffer();

    /*
     * Close the packet-to-packet voice transcoding channel.
     */
    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
    {
	DisconnectTerms(ulConnectionNumber);
	CloseSideB(ulConnectionNumber);
	CloseSideA(ulConnectionNumber);
    }
	CloseNetworkResources();
    /*
     * Free any resources used by the application.
     */
    ExitApplication();
    pthread_cancel(th_Recv);
    return 0;

ErrorHandling:
    ExitApplication();
    pthread_cancel(th_Recv);
    return 1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\
 
Function:       GetInfoOpusCore

Description:    Retrieve Opus core information from device.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
static int GetInfoOpusCore(void)
{
    tOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CMD MainInfoOpusCoreCmd;
    tOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_RSP MainInfoOpusCoreRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS          CmdExecuteParms;
    tOCT_UINT32                                ulResult;
    tOCT_UINT32                                i;
    /*
     * Prepare command data.
     */
    mOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CMD_DEF(&MainInfoOpusCoreCmd);
    mOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CMD_SWAP(&MainInfoOpusCoreCmd);
    /*
     * Execute the command.
     */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &MainInfoOpusCoreCmd;
    CmdExecuteParms.pRsp           = &MainInfoOpusCoreRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(MainInfoOpusCoreRsp);
    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
	fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_CID failed, rc = 0x%08x\n", ulResult);
	fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
	goto ErrorHandling;
    }
    /*
     * Swap the command response.
     */
    mOCTVC1_MAIN_MSG_DEVICE_INFO_OPUS_CORE_RSP_SWAP(&MainInfoOpusCoreRsp);
    /*
     * Save the returned Opus core information.
     */
    memcpy (g_AppCtx.aCoreInfo, MainInfoOpusCoreRsp.aCoreInfo, sizeof(MainInfoOpusCoreRsp.aCoreInfo) );
    /*
     * Retrieve process information for all cores.
     */
    for (i = 0; i < cOCTVC1_MAIN_MAX_CORE_NUMBER; i++)
    {
	if (cOCTVC1_HANDLE_INVALID == g_AppCtx.aCoreInfo[i].hProcess)
	{
	    g_AppCtx.ulNumActiveCores = i;
	    break;
	}
    }
    if (!g_AppCtx.ulNumActiveCores)
	g_AppCtx.ulNumActiveCores = i;
	    printf("\n%u cores are active on the DPS.\n\n",  g_AppCtx.ulNumActiveCores);
	    return 0;
	ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       GetCpuUsage
 
Description:    Retrieve CPU usage for a specific process.
    
\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int GetCpuUsage(void)
{
    tOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_CMD MainProcInfCpuUsgCmd;
    tOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_RSP MainProcInfCpuUsgRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS           CmdExecuteParms;
    tOCT_UINT32                                 ulResult;
    tOCT_UINT32                                 i;
    tOCT_UINT32                                 ulPrintVSPFlag = 0;
    for (i = 0; i < g_AppCtx.ulNumActiveCores; i++)
    {
	if ( (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_INVALID == g_AppCtx.aCoreInfo[i].ulProcessImageType) ||
	    (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_CONTROL == g_AppCtx.aCoreInfo[i].ulProcessImageType) ||
	    (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_AF_SRV == g_AppCtx.aCoreInfo[i].ulProcessImageType) ||
	    (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_VSPMGR == g_AppCtx.aCoreInfo[i].ulProcessImageType) )
	{
	    if ( (cOCTVC1_MAIN_PROCESS_TYPE_ENUM_VSPMGR == g_AppCtx.aCoreInfo[i].ulProcessImageType) && !ulPrintVSPFlag )
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
	MainProcInfCpuUsgCmd.hProcess = g_AppCtx.aCoreInfo[i].hProcess;
	mOCTVC1_MAIN_MSG_PROCESS_INFO_CPU_USAGE_CMD_SWAP(&MainProcInfCpuUsgCmd);
	/*
	 * Execute the command.
	 */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &MainProcInfCpuUsgCmd;
	CmdExecuteParms.pRsp           = &MainProcInfCpuUsgRsp;
	CmdExecuteParms.ulMaxRspLength = sizeof(MainProcInfCpuUsgRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
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
		ulResult = GetProcInfo(i);
	if (cOCTVC1_RC_OK != ulResult)
	     {
		  goto ErrorHandling;
	     }

		printf("CPU usage is %u%% for process %s on DSP\n ", MainProcInfCpuUsgRsp.ulProcessCpuUsagePercent, g_AppCtx.szProcessImageName);
    }
return 0;
ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       MonitorLinks

Description:    Loop through all DSPs and collate error data

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
static void MonitorLinks(void)
{
    tOCT_UINT8 side;
    tOCT_UINT32 ulNumConnections = MAX_CONNECTIONS;
    tOCT_UINT32 ulConnectionNumber=0;
    tOCT_UINT32 ulResult;
    tOCT_UINT32 ulGetMode;
    tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD TermStatsMcCmd;
    tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP TermStatsMcRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS       CmdExecuteParms;
    unsigned long long int rxInCnt=0;
	    /* Clear stats structure */
    memset(&g_AppStats,0,sizeof(tOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP));
	    //OctVocSamplesPrintModuleNetConfigInfo(g_AppCtx.PktApiInfo.pPktApiSess);
	    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
	{
	    /* Alternate between side A and B */
	    for (side=0;side<2;side++){
		ulGetMode=cOCTVC1_OBJECT_CURSOR_ENUM_SPECIFIC;
		//ulGetMode=cOCTVC1_OBJECT_CURSOR_ENUM_FIRST;
		/*
		 * Prepare command data.
		 */
		mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_CMD_DEF(&TermStatsMcCmd);
		if(side==0){
		    TermStatsMcCmd.ObjectGet.hObject   = g_AppCtx.hVocTermA[ulConnectionNumber];
		 }else{
		    TermStatsMcCmd.ObjectGet.hObject   = g_AppCtx.hVocTermB[ulConnectionNumber];
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
		ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
		if (cOCTVC1_RC_OK != ulResult)
		{
		    continue;
		    //goto ErrorHandling;
		}
		/*
		 * Swap the command response
		 */
		 mOCTVC1_VSPMP_VOC_MSG_TERM_STATS_MC_RSP_SWAP(&TermStatsMcRsp);
		 /*
		  * Print the statistics.
		  */
                 rxInCnt                            +=(unsigned long long)(((unsigned long long)TermStatsMcRsp.aulRxInPktCnt[0]) << 32) | ((tOCT_UINT32)TermStatsMcRsp.aulRxInPktCnt[1]);
		 g_AppStats.ulRxOutPktCnt           +=TermStatsMcRsp.ulRxOutPktCnt;
		 g_AppStats.ulRxInSidPktCnt         +=TermStatsMcRsp.ulRxInSidPktCnt;
		 g_AppStats.ulRxNoPktCnt            +=TermStatsMcRsp.ulRxNoPktCnt;
		 g_AppStats.ulRxBadPktTypeCnt       +=TermStatsMcRsp.ulRxBadPktTypeCnt;
		 g_AppStats.ulRxBadRtpPayloadTypeCnt+=TermStatsMcRsp.ulRxBadRtpPayloadTypeCnt;
		 g_AppStats.ulRxBadPktHdrFormatCnt  +=TermStatsMcRsp.ulRxBadPktHdrFormatCnt;
		 g_AppStats.ulRxBadPktLengthCnt     +=TermStatsMcRsp.ulRxBadPktLengthCnt;
		 g_AppStats.ulRxMisorderedPktCnt    +=TermStatsMcRsp.ulRxMisorderedPktCnt;
 		 g_AppStats.ulRxLostPktCnt          +=TermStatsMcRsp.ulRxLostPktCnt;
		 g_AppStats.ulRxBadPktChecksumCnt   +=TermStatsMcRsp.ulRxBadPktChecksumCnt;
		 g_AppStats.ulRxUnderrunSlipCnt     +=TermStatsMcRsp.ulRxUnderrunSlipCnt;
		 g_AppStats.ulRxOverrunSlipCnt      +=TermStatsMcRsp.ulRxOverrunSlipCnt;
		 if(g_AppStats.ulRxLastVocoderType!=TermStatsMcRsp.ulRxLastVocoderType)
		     g_AppStats.ulRxLastVocoderType=TermStatsMcRsp.ulRxLastVocoderType;
		 g_AppStats.ulRxVocoderChangeCnt    +=TermStatsMcRsp.ulRxVocoderChangeCnt;
		 if(TermStatsMcRsp.ulRxMaxDetectedPdv>g_AppStats.ulRxMaxDetectedPdv)
		     g_AppStats.ulRxMaxDetectedPdv=TermStatsMcRsp.ulRxMaxDetectedPdv;
		 g_AppStats.ulRxDecdrRate           +=TermStatsMcRsp.ulRxDecdrRate;
		 if(TermStatsMcRsp.ulRxJitterCurrentDelay>g_AppStats.ulRxJitterCurrentDelay)
		     g_AppStats.ulRxJitterCurrentDelay=TermStatsMcRsp.ulRxJitterCurrentDelay;
		 g_AppStats.ulRxJitterEstimatedDelay+=TermStatsMcRsp.ulRxJitterEstimatedDelay;
		 g_AppStats.lRxJitterClkDriftingDelta         +=TermStatsMcRsp.lRxJitterClkDriftingDelta;
		 g_AppStats.ulRxJitterClkDriftingCorrectionCnt+=TermStatsMcRsp.ulRxJitterClkDriftingCorrectionCnt;
		 if(TermStatsMcRsp.ulRxJitterInitializationCnt>g_AppStats.ulRxJitterInitializationCnt)
		     g_AppStats.ulRxJitterInitializationCnt=TermStatsMcRsp.ulRxJitterInitializationCnt;
		 g_AppStats.ulRxCircularBufferWriteErrCnt     +=TermStatsMcRsp.ulRxCircularBufferWriteErrCnt;
		 g_AppStats.ulRxApiEventCnt                   +=TermStatsMcRsp.ulRxApiEventCnt;
		 if(g_AppStats.ulTxCurrentVocoderType!=TermStatsMcRsp.ulTxCurrentVocoderType)
		     g_AppStats.ulTxCurrentVocoderType=TermStatsMcRsp.ulTxCurrentVocoderType;
		 g_AppStats.ulTxInPktCnt                      +=TermStatsMcRsp.ulTxInPktCnt;
		 g_AppStats.ulTxInBadPktPayloadCnt      +=TermStatsMcRsp.ulTxInBadPktPayloadCnt;
		 g_AppStats.ulTxTimestampGapCnt         +=TermStatsMcRsp.ulTxTimestampGapCnt;
		 g_AppStats.ulTxTdmWriteErrCnt          +=TermStatsMcRsp.ulTxTdmWriteErrCnt;
		 g_AppStats.ulRxToneDetectedCnt         +=TermStatsMcRsp.ulRxToneDetectedCnt;
		 g_AppStats.ulRxToneRelayEventPktCnt    +=TermStatsMcRsp.ulRxToneRelayEventPktCnt;
		 g_AppStats.ulRxToneRelayUnsupportedCnt +=TermStatsMcRsp.ulRxToneRelayUnsupportedCnt;
		 g_AppStats.ulTxToneRelayEventPktCnt    +=TermStatsMcRsp.ulTxToneRelayEventPktCnt;
		 g_AppStats.ulTxApiEventCnt             +=TermStatsMcRsp.ulTxApiEventCnt;
		 g_AppStats.ulTxNoRtpEntryPktDropCnt    +=TermStatsMcRsp.ulTxNoRtpEntryPktDropCnt;
		 g_AppStats.ulConnectionWaitAckFlag     +=TermStatsMcRsp.ulConnectionWaitAckFlag;
		 g_AppStats.ulRxMipsProtectionDropCnt   +=TermStatsMcRsp.ulRxMipsProtectionDropCnt;
		 g_AppStats.ulTxMipsProtectionDropCnt   +=TermStatsMcRsp.ulTxMipsProtectionDropCnt;
		 if(TermStatsMcRsp.ulCallTimerMsec>g_AppStats.ulCallTimerMsec)
		     g_AppStats.ulCallTimerMsec=TermStatsMcRsp.ulCallTimerMsec;
			}
		}
	    printf("+-- VOC TERM MC STATISTICS (DSP) ----------------------\n");
            printf("| RxInPktCnt                       : %llu\n", rxInCnt);
	    printf("| RxOutPktCnt                      : %u\n", g_AppStats.ulRxOutPktCnt);
	    printf("| RxInSidPktCnt                    : %u\n", g_AppStats.ulRxInSidPktCnt);
	    printf("| RxNoPktCnt                       : %u\n", g_AppStats.ulRxNoPktCnt);
	    printf("| RxBadPktTypeCnt                  : %u\n", g_AppStats.ulRxBadPktTypeCnt);
	    printf("| RxBadRtpPayloadTypeCnt           : %u\n", g_AppStats.ulRxBadRtpPayloadTypeCnt);
	    printf("| RxBadPktHdrFormatCnt             : %u\n", g_AppStats.ulRxBadPktHdrFormatCnt);
	    printf("| RxBadPktLengthCnt                : %u\n", g_AppStats.ulRxBadPktLengthCnt);
	    printf("| RxMisorderedPktCnt               : %u\n", g_AppStats.ulRxMisorderedPktCnt);
	    printf("| RxLostPktCnt                     : %u\n", g_AppStats.ulRxLostPktCnt);
	    printf("| RxBadPktChecksumCnt              : %u\n", g_AppStats.ulRxBadPktChecksumCnt);
	    printf("| RxUnderrunSlipCnt                : %u\n", g_AppStats.ulRxUnderrunSlipCnt);
	    printf("| RxOverrunSlipCnt                 : %u\n", g_AppStats.ulRxOverrunSlipCnt);
	    printf("| RxLastVocoderType                : %u\n", g_AppStats.ulRxLastVocoderType);
	    printf("| RxVocoderChangeCnt               : %u\n", g_AppStats.ulRxVocoderChangeCnt);
	    printf("| RxMaxDetectedPdv                 : %u (in 125 us)\n", g_AppStats.ulRxMaxDetectedPdv);
	    printf("| RxDecdrRate                      : %u\n", g_AppStats.ulRxDecdrRate);
	    printf("| RxMaxJitterCurrentDelay          : %u (in 125 us)\n", g_AppStats.ulRxJitterCurrentDelay);
	    printf("| RxJitterEstimatedDelay           : %u (in 125 us)\n", g_AppStats.ulRxJitterEstimatedDelay);
	    printf("| RxJitterEstimatedDelay           : %u (in 125 us)\n", g_AppStats.lRxJitterClkDriftingDelta);
	    printf("| RxJitterClkDriftingCorrectionCnt : %u\n", g_AppStats.ulRxJitterClkDriftingCorrectionCnt);
	    printf("| RxMaxJitterInitializationCnt     : %u\n", g_AppStats.ulRxJitterInitializationCnt);
	    printf("| RxCircularBufferWriteErrCnt      : %u\n", g_AppStats.ulRxCircularBufferWriteErrCnt);
	    printf("| RxApiEventCnt                    : %u\n", g_AppStats.ulRxApiEventCnt);
	    printf("| TxCurrentVocoderType             : %u\n", g_AppStats.ulTxCurrentVocoderType);
	    printf("| TxInPktCnt                       : %u\n", g_AppStats.ulTxInPktCnt);
	    printf("| TxInBadPktPayloadCnt             : %u\n", g_AppStats.ulTxInBadPktPayloadCnt);
	    printf("| TxTimestampGapCnt                : %u\n", g_AppStats.ulTxTimestampGapCnt);
	    printf("| TxTdmWriteErrCnt                 : %u\n", g_AppStats.ulTxTdmWriteErrCnt);
	    printf("| RxToneDetectedCnt                : %u\n", g_AppStats.ulRxToneDetectedCnt);
	    printf("| RxToneRelayEventPktCnt           : %u\n", g_AppStats.ulRxToneRelayEventPktCnt);
	    printf("| RxToneRelayUnsupportedCnt        : %u\n", g_AppStats.ulRxToneRelayUnsupportedCnt);
	    printf("| TxToneRelayEventPktCnt           : %u\n", g_AppStats.ulTxToneRelayEventPktCnt);
	    printf("| TxApiEventCnt                    : %u\n", g_AppStats.ulTxApiEventCnt);
	    printf("| TxNoRtpEntryPktDropCnt           : %u\n", g_AppStats.ulTxNoRtpEntryPktDropCnt);
	    printf("| ConnectionWaitAckFlag            : %u\n", g_AppStats.ulConnectionWaitAckFlag);
	    printf("| RxMipsProtectionDropCnt          : %u\n", g_AppStats.ulRxMipsProtectionDropCnt);
	    printf("| TxMipsProtectionDropCnt          : %u\n", g_AppStats.ulTxMipsProtectionDropCnt);
	    printf("| CallTimerMsec                    : %u\n", g_AppStats.ulCallTimerMsec);
	    printf("\n");
            printf("sleep for 5sec....\n");
	    ulResult = OctOsalSleepMs(5*1000);/* Wait 5 sec */
    //if (cOCTVC1_RC_OK != ulResult)
    //    {
	    //goto ErrorHandling;
       // }
    //ErrorHandling:
    //    ExitApplication();
}
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       GetProcInfo

Description:    Retrieve the information for a specific process.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
static int GetProcInfo(int f_Idx)
{
    tOCTVC1_MAIN_MSG_PROCESS_INFO_CMD MainProcessInfoCmd;
    tOCTVC1_MAIN_MSG_PROCESS_INFO_RSP MainProcessInfoRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS CmdExecuteParms;
    tOCT_UINT32                       ulResult;

    /*
     * Prepare command data.
     */
    mOCTVC1_MAIN_MSG_PROCESS_INFO_CMD_DEF(&MainProcessInfoCmd);
    MainProcessInfoCmd.hProcess = g_AppCtx.aCoreInfo[f_Idx].hProcess;
    mOCTVC1_MAIN_MSG_PROCESS_INFO_CMD_SWAP(&MainProcessInfoCmd);

    /*
     * Execute the command.
     */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &MainProcessInfoCmd;
    CmdExecuteParms.pRsp           = &MainProcessInfoRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(MainProcessInfoRsp);
    ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
    if (cOCTVC1_RC_OK != ulResult)
    {
	fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_PROCESS_INFO_CID failed, rc = 0x%08x\n", ulResult);
	fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
	goto ErrorHandling;
    }

    mOCTVC1_MAIN_MSG_PROCESS_INFO_RSP_SWAP(&MainProcessInfoRsp);

    /*
     * Store the process' name for printout.
     */
    memcpy(g_AppCtx.szProcessImageName, MainProcessInfoRsp.szProcessImageName, sizeof(MainProcessInfoRsp.szProcessImageName));
    return 0;

ErrorHandling:
    return -1;
}
