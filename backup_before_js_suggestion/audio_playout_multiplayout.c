/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

File: audio_playout.c

Copyright (c) 2016 Octasic Inc. All rights reserved.
    
Description:

    This samples demonstrates how to use playout on a voice termination.

    Block diagram:

                    +----------------+  +---------+               +-------+
         HOST<--|   | VOCALLO HOST   |  |  VOC    |               |        \
                |   +--------------+ |  |  TERM   |               | PLAYOUT |
                |   | RTP SESSION  | |  |         |               | BUFFER  |
                |   +------------+ | |  |  G.711  |               | (LIST)  |
                |<--| RTP MEMBER |<|-|--|  u-law  |< - - - - - - -|         |
                    +------------+-+-+  +---------+               +---------+
                                             |
                                             v
                                        +---------+
      CONTROL<--|                       |         |
    PROCESSOR   |                       |  EVENT  |
                |                       |  FWRDR  |
                |        EVENTS         |         |
                |<----------------------|         |
                                        +---------+

This source code is Octasic Confidential. Use of and access to this code
is covered by the Octasic Device Enabling Software License Agreement.
Acknowledgement of the Octasic Device Enabling Software License was
required for access to this code. A copy was also provided with the release.

Release: Vocallo Software Development Kit VOCALLO_MGW-03.01.01-B1210 (2016/08/26)

$Revision: 37414 $

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

#define OCTVC1_OPT_DECLARE_DEFAULTS

/***************************  INCLUDE FILES  *********************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>

/* Vocallo API header files */
#include "vocallo/cpp/octvc1_cpp_api.h"
#include "vocallo/cpp/octvc1_cpp_api_swap.h"
#include "vocallo/cpp/octvc1_cpp_default.h"
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
#include "oct_common_getopt.h"
#include "oct_common_macro.h"

/* Vocallo samples' common header files */
#include "octvocsamples_pkt_api_session.h"
#include "octvocsamples_main_api_stats.h"
#include "octvocsamples_string_utils.h"
#include "octvocsamples_vspmp_voc_api_stats.h"

/* Verbose OCTVC1 return code */
#define OCTVC1_RC2STRING_DECLARE
#include "vocallo/octvc1_rc2string.h"

/***************************  DEFINES  ***************************************/

/*
 * Voice termination profile index.
 */
#define cOCTVOCSAMPLES_TERM_PROFILE_INDEX 0
#define cOCTVOCSAMPLES_MAX_NUM_TONES      64
#define cOCTVOCSAMPLES_NUM_DTMF           1
#define cOCTVOCSAMPLES_uLAW_PCM 5

/***************************  TYPE DEFINITIONS  ******************************/

/*
 * This structure contains application configuration data.
 */
typedef struct tOCTVOCSAMPLES_APP_CFG_TAG
{
    /* Packet API's physical network interfaces for commands and responses. */
    tOCT_UINT8          abyProcessorCtrlMacAddr[6];                             /* Processor control port's MAC address. */
    tOCT_UINT8          abyVocalloCtrlMacAddr[6];                               /* Vocallo control port's MAC address (port 0 or 1). */
    /* Host's settings. */
    tOCTVC1_UDP_ADDRESS HostRtpUdpAddress;                                      /* Host's RTP UDP address. */
    tOCTVC1_UDP_ADDRESS HostRtcpUdpAddress;                                     /* Host's RTCP UDP address. */
    char                szHostRtcpCname[cOCTVC1_NET_MAX_CNAME_LENGTH + 1];      /* Host's RTCP canonical name. */
    /* Vocallo's settings. */
    tOCT_UINT32         ulVocalloHostEthPort;                                   /* Vocallo host's Ethernet port (port 0 or 1). */
    tOCTVC1_IP_ADDRESS  VocalloHostIpAddr;                                      /* Vocallo host's IP address. */
    tOCTVC1_IP_ADDRESS  VocalloHostNetworkMask;                                 /* Vocallo host's network mask. */
    tOCT_UINT32         ulRtpMemberRtpUdpPort;                                  /* RTP member's RTP UDP port. */
    tOCT_UINT32         ulRtpMemberRtcpUdpPort;                                 /* RTP member's RTCP UDP port. */
    tOCT_UINT32         ulRtpPayloadType;                                       /* RTP member's RTP payload type */
    tOCT_UINT32         ulPktEncodingType;                                      /* RTP member's packet encoding type */
    char                szRtpMemberRtcpCname[cOCTVC1_NET_MAX_CNAME_LENGTH + 1]; /* RTP member's RTCP canonical name. */
} tOCTVOCSAMPLES_APP_CFG, *tPOCTVOCSAMPLES_APP_CFG, **tPPOCTVOCSAMPLES_APP_CFG;


#define MAX_CONNECTIONS 102 
/*
 * This structure contains application context data.
 */
typedef struct tOCTVOCSAMPLES_APP_CTX_TAG
{
    tOCTVOCSAMPLES_PKT_API_INFO PktApiInfo;         /* Packet API information. */
    tOCTVC1_HANDLE              ahEthLinks[2];      /* Ethernet link handles. */
    tOCTVC1_HANDLE              hVocalloHost;       /* Vocallo host's handle. */
    tOCTVC1_HANDLE              hForwarder;         /* Forwarder's handle. */
    tOCT_UINT32                 ulForwarderFifoId;  /* Forwarder's FIFO ID. */
    tOCTVC1_HANDLE              hVocTerm[MAX_CONNECTIONS];           /* Voice termination's handle. */
    tOCTVC1_HANDLE              hRtpSession[MAX_CONNECTIONS];        /* RTP session's handle. */
    tOCT_UINT32                 ulRtpMemberId[MAX_CONNECTIONS];      /* RTP member's ID. */
    tOCTVC1_HANDLE_OBJECT       hBufferNum[cOCTVOCSAMPLES_uLAW_PCM];
    tOCT_UINT8                  CloseReceiveFlag /* Flag to stop receive thread. */
//    tOCTVC1_HANDLE_OBJECT       hPlaylist;
  //  tOCT_UINT32                 ulNumTones;
 //   tOCT_UINT32                 aulToneList[cOCTVOCSAMPLES_MAX_NUM_TONES];
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
    /* Host's settings. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80040, 0, 0, 0 } }, 49952 }, /* Host's RTP UDP address [192.168.0.100:49152]. */
    { { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80040, 0, 0, 0 } }, 49953 }, /* Host's RTCP UDP address [192.168.0.100:49153]. */
    "host@octasic.com",                                                /* Host's RTCP canonical name. */
    /* Vocallo's settings. */
    0,                                                                 /* Vocallo host's Ethernet port (port 0 or 1). */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xC0A80045, 0, 0, 0 } },            /* Vocallo host's IP address [192.168.0.64]. */
    { cOCTVC1_IP_VERSION_ENUM_4, { 0xFFFFFF00, 0, 0, 0 } },            /* Vocallo host's network mask [255.255.255.0]. */
    49952,                                                             /* RTP member's RTP UDP port. */
    49953,                                                             /* RTP member's RTCP UDP port. */
    0,                                                                 /* RTP member's RTP payload type */
    cOCTVOCNET_PKT_D_TYPE_ENUM_PCM_U_LAW,                              /* RTP member's packet encoding type */
    "rtp_member@octasic.com"                                           /* RTP member's RTCP canonical name. */
};

tOCT_UINT8 szBufferName[cOCTVOCSAMPLES_uLAW_PCM][cOCTVC1_MAIN_FILE_NAME_MAX_LENGTH+1]={
    /*
    "../../common/media/audio/digits/0_ulaw.pcm",
    "../../common/media/audio/digits/1_ulaw.pcm",
    "../../common/media/audio/digits/2_ulaw.pcm",
    "../../common/media/audio/digits/3_ulaw.pcm",
    "../../common/media/audio/digits/4_ulaw.pcm",
    "../../common/media/audio/digits/5_ulaw.pcm",
    "../../common/media/audio/digits/6_ulaw.pcm",
    "../../common/media/audio/digits/7_ulaw.pcm",
    "../../common/media/audio/digits/8_ulaw.pcm",
    "../../common/media/audio/digits/9_ulaw.pcm",
    "../../common/media/audio/digits/star_ulaw.pcm",
    "../../common/media/audio/digits/pound_ulaw.pcm",
    "../../common/media/audio/digits/a_ulaw.pcm",
    "../../common/media/audio/digits/b_ulaw.pcm",
    "../../common/media/audio/digits/c_ulaw.pcm",
    "../../common/media/audio/digits/d_ulaw.pcm"
    */
    "../../common/media/audio/prompt0_ulaw.pcm",
    "../../common/media/audio/VoiceBuffer_ulaw.pcm",
    "../../common/media/audio/prompt0_ulaw1.pcm",
    "../../common/media/audio/VoiceBuffer_ulaw1.pcm",
    "../../common/media/audio/prompt0_ulaw2.pcm"
};

/*
 * Application context data.
 */
tOCTVOCSAMPLES_APP_CTX g_AppCtx;
pthread_t th_Recv;
/***************************  FUNCTION PROTOTYPES  ***************************/

static int CloseNetworkResources(void);
static int CloseVoicePath(tOCT_UINT32 ulConnectionNumber);
static int CloseVoiceResources(void);

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
     * Open Vocallo host.
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
        LocalHostOpenCmd.IpAddress   = g_AppCfg.VocalloHostIpAddr;
        LocalHostOpenCmd.NetworkMask = g_AppCfg.VocalloHostNetworkMask;
        LocalHostOpenCmd.hLink       = g_AppCtx.ahEthLinks[g_AppCfg.ulVocalloHostEthPort];
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
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_OPEN_CID failed, rc = 0x%08x\n", ulResult);
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
        g_AppCtx.hVocalloHost = LocalHostOpenRsp.hLocalHost;
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
     * Close Vocallo host.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hVocalloHost.aulHandle[0])
    {
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD LocalHostCloseCmd;
        tOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_RSP LocalHostCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CMD_DEF(&LocalHostCloseCmd);
        LocalHostCloseCmd.hLocalHost = g_AppCtx.hVocalloHost;
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
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_LOCAL_HOST_CLOSE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hVocalloHost.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
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

Function:       VoiceInit

Description:    Initialize voice resources.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int VoiceInit(void)
{
    /*************************************************************************\
     * Open a forwarder to transmit the events generated by voice
     * termination(s) to the control processor.
    \*************************************************************************/
    {
        tOCTVC1_CPP_MSG_FORWARD_OPEN_CMD  ForwardOpenCmd;
        tOCTVC1_CPP_MSG_FORWARD_OPEN_RSP  ForwardOpenRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS CmdExecuteParms;
        tOCT_UINT32                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_CPP_MSG_FORWARD_OPEN_CMD_DEF(&ForwardOpenCmd);
        memcpy(ForwardOpenCmd.SrcMacAddress.abyMacAddress, g_AppCfg.abyVocalloCtrlMacAddr, 6);
        memcpy(ForwardOpenCmd.DestMacAddress.abyMacAddress, g_AppCfg.abyProcessorCtrlMacAddr, 6);
        mOCTVC1_CPP_MSG_FORWARD_OPEN_CMD_SWAP(&ForwardOpenCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &ForwardOpenCmd;
        CmdExecuteParms.pRsp           = &ForwardOpenRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(ForwardOpenRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_CPP_MSG_FORWARD_OPEN_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_CPP_MSG_FORWARD_OPEN_RSP_SWAP(&ForwardOpenRsp);

        /*
         * Save the handle of the opened forwarder as well as the FIFO ID
         * from which the object receives packets.
         */
        g_AppCtx.hForwarder        = ForwardOpenRsp.hForward;
        g_AppCtx.ulForwarderFifoId = ForwardOpenRsp.ulFifoId;
    }

    /*************************************************************************\
     * Set the media-coder parameters of the voice termination profile.
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
        ModuleModifyProfileMcCmd.ulProfileIndex                             = cOCTVOCSAMPLES_TERM_PROFILE_INDEX;
        ModuleModifyProfileMcCmd.ulRestoreDefaultFlag                       = cOCT_TRUE;
        ModuleModifyProfileMcCmd.McProfile.ulTxEnableSilenceSuppressionFlag = cOCT_FALSE;
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
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_MODULE_MODIFY_PROFILE_MC_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseVoiceResources

Description:    Closes voice resources.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
static int CloseVoiceResources(void)
{
    /*************************************************************************\
     * Close forwarder.
    \*************************************************************************/
    
    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hForwarder.aulHandle[0])
    {
        tOCTVC1_CPP_MSG_FORWARD_CLOSE_CMD ForwardCloseCmd;
        tOCTVC1_CPP_MSG_FORWARD_CLOSE_RSP ForwardCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS CmdExecuteParms;
        tOCT_UINT32                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_CPP_MSG_FORWARD_CLOSE_CMD_DEF(&ForwardCloseCmd);
        ForwardCloseCmd.hForward = g_AppCtx.hForwarder;
        mOCTVC1_CPP_MSG_FORWARD_CLOSE_CMD_SWAP(&ForwardCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &ForwardCloseCmd;
        CmdExecuteParms.pRsp           = &ForwardCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(ForwardCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_CPP_MSG_FORWARD_CLOSE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hForwarder.aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    return 0;

ErrorHandling:
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CreateVoicePath

Description:    Creates voice path.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CreateVoicePath(tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Open voice termination.
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
        TermOpenCmd.ulProfileIndex          = cOCTVOCSAMPLES_TERM_PROFILE_INDEX;
        TermOpenCmd.ulOperState             = cOCTVC1_VSPMP_VOC_TERM_STATE_ENUM_VOICE;
        TermOpenCmd.ulRxExpectedVocoderType = cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64;
        TermOpenCmd.ulTxVocoderType         = cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64;
        TermOpenCmd.ulMode                  = cOCTVC1_VSPMP_TERM_MODE_ENUM_TX_ONLY;
        TermOpenCmd.aulAllowedVocoders[mOCTVC1_GET_VOCMASK_INDEX(cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64)]
                                            |= mOCTVC1_GET_VOCMASK_BIT(cOCTVC1_VSPMP_MEDIA_CODER_VOC_TYPE_ENUM_G711_64);
        TermOpenCmd.hEventDestObj           = g_AppCtx.hForwarder;
        TermOpenCmd.ulEventDestObjPort      = 0;
        TermOpenCmd.ulEventDestObjFifoId    = g_AppCtx.ulForwarderFifoId;
        TermOpenCmd.ulEventMask                = cOCTVC1_VSPMP_VOC_TERM_EVT_MASK_PLAYOUT_STOP;
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
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_OPEN_CID failed, rc = 0x%08x\n", ulResult);
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
        g_AppCtx.hVocTerm[ulConnectionNumber] = TermOpenRsp.hTerm;
    }

    /*************************************************************************\
     * Open RTP session.
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
        RtpSessionOpenCmd.hLocalHost = g_AppCtx.hVocalloHost;
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
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_OPEN_CID failed, rc = 0x%08x\n", ulResult);
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
        g_AppCtx.hRtpSession[ulConnectionNumber] = RtpSessionOpenRsp.hRtpSession;
    }

    /*************************************************************************\
     * Activate RTP member.
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
        RtpSessionActivateMemberCmd.hRtpSession                        = g_AppCtx.hRtpSession[ulConnectionNumber];
        RtpSessionActivateMemberCmd.hTerm                              = g_AppCtx.hVocTerm[ulConnectionNumber];
        RtpSessionActivateMemberCmd.ulRxPktFilter                      = cOCTVC1_NET_RX_PKT_FILTER_ENUM_NONE;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtp                  = g_AppCfg.ulRtpMemberRtpUdpPort;
        RtpSessionActivateMemberCmd.ulLocalUdpPortRtcp                 = g_AppCfg.ulRtpMemberRtcpUdpPort;
        RtpSessionActivateMemberCmd.ulLocalCnameLength                 = strlen(g_AppCfg.szRtpMemberRtcpCname);
        strncpy((char *)RtpSessionActivateMemberCmd.achLocalCname, g_AppCfg.szRtpMemberRtcpCname, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtp                = g_AppCfg.HostRtpUdpAddress;
        RtpSessionActivateMemberCmd.RemoteUdpAddressRtcp               = g_AppCfg.HostRtcpUdpAddress;
        RtpSessionActivateMemberCmd.ulRemoteCnameLength                = strlen(g_AppCfg.szHostRtcpCname);
        strncpy((char *)RtpSessionActivateMemberCmd.achRemoteCname, g_AppCfg.szHostRtcpCname, cOCTVC1_NET_MAX_CNAME_LENGTH);
        RtpSessionActivateMemberCmd.ulNumProfEntry                     = 1;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulPktEncodingType = g_AppCfg.ulPktEncodingType;
        RtpSessionActivateMemberCmd.aRtpProfEntry[0].ulRtpPayloadType  = g_AppCfg.ulRtpPayloadType;
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
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_ACTIVATE_MEMBER_CID failed, rc = 0x%08x\n", ulResult);
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
        g_AppCtx.ulRtpMemberId[ulConnectionNumber] = RtpSessionActivateMemberRsp.ulLocalMemberId;
    }

    return 0;

ErrorHandling:
    CloseVoicePath(ulConnectionNumber);
    return -1;
}

/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       CloseVoicePath

Description:    Closes voice path.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int CloseVoicePath(tOCT_UINT32 ulConnectionNumber)
{
    /*************************************************************************\
     * Deactivate RTP member.
    \*************************************************************************/
    //g_AppCtx.CloseReceiveFlag=1;
    
    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hRtpSession[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD RtpSessionDeactivateMemberCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_RSP RtpSessionDeactivateMemberRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                 CmdExecuteParms;
        tOCT_UINT32                                       ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_DEF(&RtpSessionDeactivateMemberCmd);
        RtpSessionDeactivateMemberCmd.hRtpSession     = g_AppCtx.hRtpSession[ulConnectionNumber];
        RtpSessionDeactivateMemberCmd.ulLocalMemberId = g_AppCtx.ulRtpMemberId[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CMD_SWAP(&RtpSessionDeactivateMemberCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionDeactivateMemberCmd;
        CmdExecuteParms.pRsp           = &RtpSessionDeactivateMemberRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionDeactivateMemberRsp);
        printf("start deactivating rtp members...\n");
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_DEACTIVATE_MEMBER_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        printf("Deactivating rtp members done...\n");
    }

    /*************************************************************************\
     * Close RTP session.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hRtpSession[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD RtpSessionCloseCmd;
        tOCTVC1_NET_MSG_RTP_SESSION_CLOSE_RSP RtpSessionCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS     CmdExecuteParms;
        tOCT_UINT32                           ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_DEF(&RtpSessionCloseCmd);
        RtpSessionCloseCmd.hRtpSession = g_AppCtx.hRtpSession[ulConnectionNumber];
        mOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CMD_SWAP(&RtpSessionCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &RtpSessionCloseCmd;
        CmdExecuteParms.pRsp           = &RtpSessionCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(RtpSessionCloseRsp);
        printf("start closing rtp session...\n");
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_NET_MSG_RTP_SESSION_CLOSE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        printf("Closing rtp session done...\n");
        g_AppCtx.hRtpSession[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
    }

    /*************************************************************************\
     * Close voice termination.
    \*************************************************************************/

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hVocTerm[ulConnectionNumber].aulHandle[0])
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD TermCloseCmd;
        tOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_RSP TermCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS    CmdExecuteParms;
        tOCT_UINT32                          ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_DEF(&TermCloseCmd);
        TermCloseCmd.hTerm = g_AppCtx.hVocTerm[ulConnectionNumber];
        mOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CMD_SWAP(&TermCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &TermCloseCmd;
        CmdExecuteParms.pRsp           = &TermCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(TermCloseRsp);
        printf("start closing term...\n");
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_TERM_CLOSE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        printf("closing term done...\n");
        g_AppCtx.hVocTerm[ulConnectionNumber].aulHandle[0] = cOCTVC1_HANDLE_INVALID;
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

    for ( i = 0; i < cOCTVOCSAMPLES_uLAW_PCM; i++)
    {
        /*
         * Open local file and check size
         */
        FILE * pFile;
        tOCT_INT32    lSize;
        printf("pcm file number %d is %s\n", i,szBufferName[i]);
        pFile = fopen ( szBufferName[i] , "rb" );
        if ( pFile == NULL )
        {
            fprintf(stderr, "Error: Could not open file number:%d\n", i);
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
            BufferOpenCmd.ulFormat = cOCTVC1_BUFFER_FORMAT_VSPMP_VOC_ENUM_RAW_G711_PCM_U_LAW;
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
                tOCTVC1_PKT_API_CMD_EXECUTE_PARMS       CmdExecuteParms;
                tOCT_UINT32                             ulResult;
                

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

Function:       CreatePlaylist

Description:    Creates a playlist with buffers

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

#if 0
static int CreatePlaylist(void)
{

    /*
     * Create the playlist
     */
    {
        tOCTVC1_VSPMP_VOC_MSG_PLAYLIST_OPEN_CMD    CreatePlaylistCmd;
        tOCTVC1_VSPMP_VOC_MSG_PLAYLIST_OPEN_RSP    CreatePlaylistRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS          CmdExecuteParms;
        tOCT_UINT32                                ulResult;
        
        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_OPEN_CMD_DEF(&CreatePlaylistCmd);
        CreatePlaylistCmd.ulMaxPlayoutEntry = cOCTVOCSAMPLES_MAX_NUM_TONES;
        mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_OPEN_CMD_SWAP(&CreatePlaylistCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &CreatePlaylistCmd;
        CmdExecuteParms.pRsp           = &CreatePlaylistRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(CreatePlaylistRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: cOCTVC1_VSPMP_MSG_PLAYLIST_OPEN_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Swap the command response.
         */
        mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_OPEN_RSP_SWAP(&CreatePlaylistRsp);

        g_AppCtx.hPlaylist = CreatePlaylistRsp.hPlaylist;
    }

    /*
     * Add buffers to playlist
     */
    {
        tOCT_UINT32        i, j;
        tOCT_UINT32        ulNumTone, ulEntryIndex = 0;

        i = 0;

        if (0 == g_AppCtx.ulNumTones)
        {
            fprintf(stderr, "Error: invalid number of tones");
            goto ErrorHandling;
        }

        do 
        {
            /*
             * Add a max of cOCTVC1_VSPMP_VOC_MAX_PLAYOUT_ENTRY (16) entries for each command
             */
            ulNumTone = (g_AppCtx.ulNumTones - i);
            ulNumTone = ( ulNumTone > cOCTVC1_VSPMP_VOC_MAX_PLAYOUT_ENTRY ) ? cOCTVC1_VSPMP_VOC_MAX_PLAYOUT_ENTRY : ulNumTone; 

            {
                tOCTVC1_VSPMP_VOC_MSG_PLAYLIST_MODIFY_CMD    ModifyPlaylistCmd;
                tOCTVC1_VSPMP_VOC_MSG_PLAYLIST_MODIFY_RSP    ModifyPlaylistRsp;
                tOCTVC1_PKT_API_CMD_EXECUTE_PARMS            CmdExecuteParms;
                tOCT_UINT32                                  ulResult;
                
                /*
                 * Prepare command data.
                 */
                mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_MODIFY_CMD_DEF(&ModifyPlaylistCmd);
                ModifyPlaylistCmd.hPlaylist = g_AppCtx.hPlaylist;
                ModifyPlaylistCmd.ulNumPlayoutEntry = ulNumTone;

                /*
                 * First iteration; reset playlist
                 */
                ModifyPlaylistCmd.ulResetFlag = ( i == 0 ) ? cOCT_TRUE : cOCT_FALSE;
            
                for ( j = 0; j < (int)ulNumTone; j++, i++ )
                {
                    ModifyPlaylistCmd.aPlayoutEntry[j].ulEntryIndex = i;
                    ModifyPlaylistCmd.aPlayoutEntry[j].hEntry = g_AppCtx.hBufferNum[g_AppCtx.aulToneList[i]];
                    ModifyPlaylistCmd.aPlayoutEntry[j].lGainDb = 4;
                    ModifyPlaylistCmd.aPlayoutEntry[j].ulPlayoutDurationMs = cOCTVC1_VSPMP_VOC_DURATION_COMPLETE_ENTRY;
                }

                mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_MODIFY_CMD_SWAP(&ModifyPlaylistCmd);

                /*
                 * Execute the command.
                 */
                mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
                CmdExecuteParms.pCmd           = &ModifyPlaylistCmd;
                CmdExecuteParms.pRsp           = &ModifyPlaylistRsp;
                CmdExecuteParms.ulMaxRspLength = sizeof(ModifyPlaylistRsp);
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
                mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_MODIFY_RSP_SWAP(&ModifyPlaylistRsp);

            }

        } while ( i < g_AppCtx.ulNumTones );
    }

    return 0;

ErrorHandling:
    return -1;
}
#endif
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       ClosePlaylistAndBuffers

Description:    Removes the playlist and buffers from memory

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
#if 0
static int ClosePlaylistAndBuffers(void)
{
    tOCT_INT32 i;

    if (cOCTVC1_HANDLE_INVALID != g_AppCtx.hPlaylist)
    {
        tOCTVC1_VSPMP_VOC_MSG_PLAYLIST_CLOSE_CMD PlaylistCloseCmd;
        tOCTVC1_VSPMP_VOC_MSG_PLAYLIST_CLOSE_RSP PlaylistCloseRsp;
        tOCTVC1_PKT_API_CMD_EXECUTE_PARMS      CmdExecuteParms;
        tOCT_UINT32                            ulResult;

        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_CLOSE_CMD_DEF(&PlaylistCloseCmd);
        PlaylistCloseCmd.hPlaylist = g_AppCtx.hPlaylist;
        mOCTVC1_VSPMP_VOC_MSG_PLAYLIST_CLOSE_CMD_SWAP(&PlaylistCloseCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
        CmdExecuteParms.pCmd           = &PlaylistCloseCmd;
        CmdExecuteParms.pRsp           = &PlaylistCloseRsp;
        CmdExecuteParms.ulMaxRspLength = sizeof(PlaylistCloseRsp);
        ulResult = OctVc1PktApiSessCmdExecute(g_AppCtx.PktApiInfo.pPktApiSess, &CmdExecuteParms);
        if (cOCTVC1_RC_OK != ulResult)
        {            
            fprintf(stderr, "Error: cOCTVC1_VSPMP_VOC_MSG_PLAYLIST_CLOSE_CID failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }
        g_AppCtx.hPlaylist = cOCTVC1_HANDLE_INVALID;
    }

    /*
     * Close buffers
     */
    for ( i = 0; i < cOCTVOCSAMPLES_NUM_DTMF; i++)
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
            fprintf(stderr, "Error: cOCTVC1_MAIN_MSG_BUFFER_OPEN_CID failed, rc = 0x%08x\n", ulResult);
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
#endif
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       StartPlaylist

Description:    Start playing playlist on the voice termination.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
#if 0
static int StartPlaylist(void)
{
    tOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_FROM_PLAYLIST_CMD    StartPlaylistCmd;
    tOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_FROM_PLAYLIST_RSP    StartPlaylistRsp;
    tOCTVC1_PKT_API_CMD_EXECUTE_PARMS                             CmdExecuteParms;
    tOCT_UINT32                                                   ulResult;
    
    /*
     * Prepare command data.
     */
    mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_FROM_PLAYLIST_CMD_DEF(&StartPlaylistCmd);
    StartPlaylistCmd.hPlaylist    = g_AppCtx.hPlaylist;
    StartPlaylistCmd.hTerm        = g_AppCtx.hVocTerm;
    mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_FROM_PLAYLIST_CMD_SWAP(&StartPlaylistCmd);

    /*
     * Execute the command.
     */
    mOCTVC1_PKT_API_CMD_EXECUTE_PARMS_DEF(&CmdExecuteParms);
    CmdExecuteParms.pCmd           = &StartPlaylistCmd;
    CmdExecuteParms.pRsp           = &StartPlaylistRsp;
    CmdExecuteParms.ulMaxRspLength = sizeof(StartPlaylistRsp);
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
    mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_FROM_PLAYLIST_RSP_SWAP(&StartPlaylistRsp);

    return 0;

ErrorHandling:
    return -1;
}
#endif
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       WaitTermPlayDoneEvent

Description:    Waits until a Play Done event is received.

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int WaitTermPlayDoneEvent(void)
{
    while (cOCT_TRUE)
    {
        tOCTVC1_PKT_API_INST_RECV_PARMS PktApiInstRecvParms;
        tOCT_UINT8                      abyPayload[1500]; /* 1500 is the MTU for Ethernet. */
        tOCT_UINT32                     ulResult;

        /*
         * Wait until an event is received.
         */
        mOCTVC1_PKT_API_INST_RECV_PARMS_DEF(&PktApiInstRecvParms);
        PktApiInstRecvParms.PktRcvMask         = cOCTVC1_PKT_API_RCV_MASK_EVENT;
        PktApiInstRecvParms.pPayload           = abyPayload;
        PktApiInstRecvParms.ulMaxPayloadLength = sizeof(abyPayload);
        ulResult = OctVc1PktApiInstRecv(g_AppCtx.PktApiInfo.pPktApiInst, &PktApiInstRecvParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: OctVc1PktApiInstRecv() failed, rc = 0x%08x\n", ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

        /*
         * Make sure we received a Play Done event.
         */
        if (cOCTVC1_VSPMP_VOC_MSG_TERM_PLAYOUT_STOP_EID == PktApiInstRecvParms.Info.Evt.ulEvtId)
        {
            printf("Playout stop events arrived.....!\n");
            break;
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
//                if(PktApiInstRecvParms.Info.Rsp.ulCmdId == cOCTVC1_VSPMP_VOC_MSG_TERM_PLAYOUT_STOP_EID)
                if(PktApiInstRecvParms.Info.Evt.ulEvtId == cOCTVC1_VSPMP_VOC_MSG_TERM_PLAYOUT_STOP_EID)
                {
                        printf("Playout stop events arrived.....!\n");
                        //continue;
                }
                if(g_AppCtx.CloseReceiveFlag == 1)
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

Function:       PlayTone

Description:    Plays the tones with playout

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/

static int PlayTone(tOCTVC1_HANDLE_OBJECT f_ToneId, tOCT_UINT32 ulConnectionNumber)
{
    {
        tOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD    StartPlayoutCmd;
        //tOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_RSP    StartPlayoutRsp;
        //tOCTVC1_PKT_API_CMD_EXECUTE_PARMS               CmdExecuteParms;
        tOCTVC1_PKT_API_CMD_SEND_PARMS               CmdSendParms;
        tOCT_UINT32                                     ulResult;
        
        /*
         * Prepare command data.
         */
        mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD_DEF(&StartPlayoutCmd);
        StartPlayoutCmd.hTerm = g_AppCtx.hVocTerm[ulConnectionNumber];
        StartPlayoutCmd.ulNumPlayoutEntry = 1;
        StartPlayoutCmd.ulRepeatForeverFlag = cOCT_TRUE;
        StartPlayoutCmd.aPlayoutEntry[0].hEntry = f_ToneId;
        StartPlayoutCmd.aPlayoutEntry[0].lGainDb = -6;
        //StartPlayoutCmd.aPlayoutEntry[0].ulEntryIndex = i;
        StartPlayoutCmd.aPlayoutEntry[0].ulPlayoutDurationMs = cOCTVC1_VSPMP_VOC_DURATION_COMPLETE_ENTRY;
        StartPlayoutCmd.aPlayoutEntry[0].ulSilenceDurationMs = 50;
        StartPlayoutCmd.ulForceStartFlag = cOCT_TRUE; 
        mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CMD_SWAP(&StartPlayoutCmd);

        /*
         * Execute the command.
         */
        mOCTVC1_PKT_API_CMD_SEND_PARMS_DEF(&CmdSendParms);
        CmdSendParms.pCmd           = &StartPlayoutCmd;
        //CmdExecuteParms.pRsp           = &StartPlayoutRsp;
        //CmdExecuteParms.ulMaxRspLength = sizeof(StartPlayoutRsp);
        ulResult = OctVc1PktApiSessCmdSend(g_AppCtx.PktApiInfo.pPktApiSess, &CmdSendParms);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: Channel[%d]:cOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_CID failed, rc = 0x%08x\n", ulConnectionNumber,ulResult);
            fprintf(stderr, "(%s)\n\n", octvc1_rc2string(ulResult));
            goto ErrorHandling;
        }

    /*
         * Swap the command response.
         */
        //mOCTVC1_VSPMP_VOC_MSG_TERM_START_PLAYOUT_RSP_SWAP(&StartPlayoutRsp);

    }

    /*
     * Wait for the operation to complete.
     */
   // printf("Playing out pcm file on channel[%d]\n",ulConnectionNumber);
    //WaitTermPlayDoneEvent();
    //OctOsalSleepMs(5*1000);
    return 0;

ErrorHandling:
    return -1;
}


/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:       TonePlayout

Description:    Plays the tones with playout, one at the time

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
#if 0
static int TonePlayout(void)
{
    tOCT_UINT32     ulResult;
    tOCT_UINT32        i;

    for ( i = 0; i < g_AppCtx.ulNumTones; i++ )
    {
        ulResult = PlayTone(g_AppCtx.aulToneList[i]);
        if (cOCTVC1_RC_OK != ulResult)
        {
            fprintf(stderr, "Error: during tone playout");
            goto ErrorHandling;
        }
    }

    return 0;

ErrorHandling:
    return -1;
}
#endif
/*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\

Function:      ParseEntry

Description:   Parse for a sequence of tones

\*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*/
#if 0
static int ParseEntry(void)
{
    tOCT_UINT8        chInputChar;
    tOCT_UINT32        i = 0;

    printf("Enter Tone sequence to play (0-9, *, #, A-D) and [ENTER]\n");

    do
    {
        chInputChar = getchar();
    
        if ( cOCTVOCSAMPLES_MAX_NUM_TONES == i )
        {
            printf("Maximum number of tones (64) reached");
            break;
        }

        switch(chInputChar) {
            case '0':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_0;
                break;
            case '1':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_1;
                break;
            case '2':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_2;
                break;
            case '3':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_3;
                break;
            case '4':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_4;
                break;
            case '5':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_5;
                break;
            case '6':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_6;
                break;
            case '7':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_7;
                break;
            case '8':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_8;
                break;
            case '9':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_9;
                break;
            case 'A':
            case 'a':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_A;
                break;
            case 'B':
            case 'b':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_B;
                break;
            case 'C':
            case 'c':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_C;
                break;
            case 'D':
            case 'd':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_D;
                break;
            case '*':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_STAR;
                break;
            case '#':
                g_AppCtx.aulToneList[i++] = cOCTVC1_TONE_ID_ENUM_TYPE_DTMF_POUND;
                break;
            /*
             * New line: [ENTER]
             */
            case 10:
                break;
            default:
                printf("Invalid entry\n");
                break;
        }

    } while ( chInputChar != 10 ); // new line

    if ( i == 0 )
    {
        fprintf(stderr, "Error: bad entry (no tone found)");
        goto ErrorHandling;
    }

    g_AppCtx.ulNumTones = i;

    return 0;

ErrorHandling:
    return -1;
}
#endif
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
        g_AppCtx.hVocalloHost.aulHandle[0]  = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hForwarder.aulHandle[0]    = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hVocTerm[ulConnectionNumber].aulHandle[0]      = cOCTVC1_HANDLE_INVALID;
        g_AppCtx.hRtpSession[ulConnectionNumber].aulHandle[0]   = cOCTVC1_HANDLE_INVALID;
    //g_AppCtx.ulNumTones                    = 0;
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
    if (g_AppCfg.ulVocalloHostEthPort != g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx)
    {
        printf("Updating Vocallo host Ethernet port configuration to %u\n\n", g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx);
        g_AppCfg.ulVocalloHostEthPort = g_AppCtx.PktApiInfo.ulPktApiCnctPortIdx;
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
    tOCT_UINT32 ulNumConnections = 100;
    tOCT_UINT32 ulConnectionNumber;
    tOCT_UINT8  CloseReceiveFlag=0;
    tOCT_UINT32        i;
    /*
     * Display application version information.
     */
    mOCT_PRINT_APP_VERSION_INFO("audio_playout",
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
     *  Media Gateway initialization:
     *    - Open Eth links
     *  - Initialize voice resources
     *  - Create a playout buffers
     */
    if ((0 != OpenNetworkResources()) ||
        (0 != VoiceInit()) ||
        (0 != CreateBuffer()))
    {
        goto ErrorHandling;
    }

    /*
     * Create the voice path.
     */
    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
    {
        if (0 != CreateVoicePath(ulConnectionNumber))
        {
            goto ErrorHandling;
        }
         g_AppCfg.ulRtpMemberRtpUdpPort+=2;/* Source RTP port */
         g_AppCfg.ulRtpMemberRtcpUdpPort+=2;/* Source RTCP port */
         g_AppCfg.HostRtpUdpAddress.ulUdpPort+=2;/* Destination RTP UDP port. */
         g_AppCfg.HostRtcpUdpAddress.ulUdpPort+=2;/* Destination RTCP UDP port. */
    }
    printf("dsp rtp port%d\n", g_AppCfg.ulRtpMemberRtpUdpPort);
    printf("host rtp port%d\n", g_AppCfg.HostRtpUdpAddress.ulUdpPort);

   
    /*
     *  Parse the input entries (tones that will be played) and
     *  create a playout playlist based on these input entries.
     */
    //if ((0 != ParseEntry()) ||
    //    (0 != CreatePlaylist()))
    //{
    //    goto ErrorHandling;
    //}

    /*
     * Wait to start any streaming engin.
     */
    printf("Press [Enter] to start the playout buffer\n");
    getchar();

    if (0 != pthread_create(&th_Recv,NULL,Receive,NULL))
                goto ErrorHandling;
    /*
     * Start playing every buffer with a playlist.
     */
    //if (0 != StartPlaylist())
    //{
    //    goto ErrorHandling;
   // }
   
    printf("Playout buffer is currently playing, waiting for PLAYOUT_STOP event ...\n\n");

    /*
     * Wait for the operation to complete (event),
     * then remove the playlist and buffers from memory.
     */
//    if (( 0 != WaitTermPlayDoneEvent()) )
        //( 0 != ClosePlaylistAndBuffers()))
  //  {
   //     goto ErrorHandling;
   // }

    /*
     * Start tone playout.
     * A command is used to play each tone,
     * thus, one event will be sent per tone
     */
    //if (0 != TonePlayout())
    //{
     //   goto ErrorHandling;
    //}

    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
    {
    printf("Playing out pcm file on channel[%d]\n",ulConnectionNumber);
            for ( i = 0; i < cOCTVOCSAMPLES_uLAW_PCM; i++ )
            {
                    if (0 != PlayTone(g_AppCtx.hBufferNum[i], ulConnectionNumber))
                    {
                        goto ErrorHandling;
                    }
            }
            if ( ulConnectionNumber == ulNumConnections - 1 )
            {
                g_AppCtx.CloseReceiveFlag=1;
            }
    OctOsalSleepMs(1*1000);
    }
    printf("Operation completed: press [Enter] to exit\n");
    getchar();
    
    //g_AppCtx.CloseReceiveFlag=1;
    //pthread_cancel(th_Recv);
    //printf("thread canceled\n");
    /*
     * Close the voice path.
     */
    for (ulConnectionNumber=0;ulConnectionNumber<ulNumConnections;ulConnectionNumber++)
    {
         printf("connection closed for term%d\n", ulConnectionNumber);
         if (0 != CloseVoicePath(ulConnectionNumber))
             {
                goto ErrorHandling;
             }
    }
    CloseVoiceResources();
    CloseNetworkResources();
    /*
     * Free any resources used by the application.
     */
    ExitApplication();
    //g_AppCtx.CloseReceiveFlag=1;
    OctOsalSleepMs(5*1000); 
    pthread_cancel(th_Recv);

    return 0;

ErrorHandling:
    ExitApplication();
    pthread_cancel(th_Recv);

    return 1;
}

