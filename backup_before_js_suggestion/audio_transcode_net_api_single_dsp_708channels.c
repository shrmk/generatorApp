/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

File: audio_transcode_net_api.c

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

#define MAX_CONNECTIONS 710
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
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                            /* Processor control port's MAC address. */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },                            /* Vocallo control port's MAC address (port 0 or 1). */
    /* Side A's settings. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80041, 0, 0, 0 } }, 49152 }, /* Host A's RTP UDP address [192.168.0.100:49152]. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80041, 0, 0, 0 } }, 49153 }, /* Host A's RTCP UDP address [192.168.0.100:49153]. */
    "host_a@octasic.com",                                              /* Host A's RTCP canonical name. */
    0,                                                                 /* Vocallo host A's Ethernet port (port 0 or 1). */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80040, 0, 0, 0 } },            /* Vocallo host A's IP address [192.168.0.64]. */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },            /* Vocallo host A's network mask [255.255.255.0]. */
    49152,                                                             /* RTP member A's RTP UDP port. */
    49153,                                                             /* RTP member A's RTCP UDP port. */
    0,                                                                 /* RTP member A's RTP payload type */
    cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_U_LAW,                              /* RTP member A's packet encoding type */
    "rtp_member_a@octasic.com",                                        /* RTP member A's RTCP canonical name. */
    /* Side B's settings. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A64, 0, 0, 0 } }, 49152 }, /* Host B's RTP UDP address [192.168.10.100:49152]. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A64, 0, 0, 0 } }, 49153 }, /* Host B's RTCP UDP address [192.168.10.100:49153]. */
    "host_b@octasic.com",                                              /* Host B's RTCP canonical name. */
    0,                                                                 /* Vocallo host B's Ethernet port (port 0 or 1). */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80A40, 0, 0, 0 } },            /* Vocallo host B's IP address [192.168.10.64]. */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },            /* Vocallo host B's network mask [255.255.255.0]. */
    49152,                                                             /* RTP member B's RTP UDP port. */
    49153,                                                             /* RTP member B's RTCP UDP port. */
    8,                                                                 /* RTP member B's RTP payload type */
    cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_A_LAW,                              /* RTP member B's packet encoding type */
    "rtp_member_b@octasic.com"                                         /* RTP member B's RTCP canonical name. */
};

/*
 * Application context data.
 */
tOCTVOCSAMPLES_APP_CTX g_AppCtx;

/***************************  FUNCTION PROTOTYPES  ***************************/

static int CloseNetworkResources(void);
static int CloseSideA(tOCT_UINT32 ulConnectionNumber);
static int CloseSideB(tOCT_UINT32 ulConnectionNumber);

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
        RtpSessionActivateMemberCmd.ulNumProfEntry                     = 1;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulPktEncodingType = g_AppCfg.ulPktEncodingTypeA;;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulRtpPayloadType  = g_AppCfg.ulRtpPayloadTypeA;
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
        ModuleModifyProfileMcCmd.ulProfileIndex                             = cOCTVOCSAMPLES_TERM_PROFILE_INDEX_B;
        ModuleModifyProfileMcCmd.ulRestoreDefaultFlag                       = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulPcmLaw                         = cOCTVC1_VSPMP_VOC_PCM_ENUM_LAW_A;
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
        RtpSessionActivateMemberCmd.ulNumProfEntry                     = 1;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulPktEncodingType = g_AppCfg.ulPktEncodingTypeB;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulRtpPayloadType  = g_AppCfg.ulRtpPayloadTypeB;
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
        g_AppCtx.hVocalloHostA.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hVocTermA[ulConnectionNumber].aulHandle[0]     = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hRtpSessionA[ulConnectionNumber].aulHandle[0]  = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hVocalloHostB.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
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
    tOCT_UINT32 ulNumConnections = 708;
    tOCT_UINT32 ulConnectionNumber;
    /*
     * Display application version information.
     */
    mOCT_PRINT_APP_VERSION_INFO("audio_transcode_net_api",
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
     * Wait for the user to quit the application.
     */
    printf("Ready to perform packet-to-packet voice transcoding...\n\n");
    printf("Press [Enter] to quit the application\n");
    getchar();

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

    return 0;

ErrorHandling:
    ExitApplication();

    return 1;
}

