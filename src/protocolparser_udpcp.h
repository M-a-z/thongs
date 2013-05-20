
/****************************************************************/
/*                                                              *
 *                  LICENSE for THONGS                          *
 *                                                              *
 *  It is allowed to use this program for free, as long as:     *
 *                                                              *
 *      -You use this as permitted by local laws.               *
 *      -You do not use it for malicious purposes like          *
 *      harming networks by messing up arp tables etc.          *
 *      -You understand and accept that any harm caused by      *
 *      using this program is not program author's fault.       *
 *      -You let me know if you liked this, my mail             *
 *      Mazziesaccount@gmail.com is open for comments.          *
 *                                                              *
 *  It is also allowed to redistribute this program as long     *
 *  as you maintain this license and information about          *
 *  original author - Matti Vaittinen                           *
 *  (Mazziesaccount@gmail.com)                                  *
 *                                                              *
 *  Modifying this program is allowed as long as:               *
 *                                                              *
 *      -You maintain information about original author/SW      *
 *      BUT also add information that the SW you provide        *
 *      has been modified. (I cannot provide support for        *
 *      modified SW.)                                           *
 *      -If you correct bugs from this software, you should     *
 *      send corrections to me also (Mazziesaccount@gmail.com   *
 *      so I can include fixes to official version. If I stop   *
 *      developing this software then this requirement is no    *
 *      longer valid.                                           *
 *                                                              *
 ****************************************************************/

#ifndef PROTOCOLPARSER_UDPCP
#define PROTOCOLPARSER_UDPCP

#define UDPCP_FILTERS_AMNT 4
enum UdpcpFilterFuncs
{
    UdpcpFilterFuncs_msgtype = 0,
#define FILTERFUNC_UDPCP_MSGTYPE (unsigned long long int)UdpcpFilterFuncs_msgtype
    UdpcpFilterFuncs_msgid,
#define FILTERFUNC_UDPCP_MSGID (unsigned long long int)UdpcpFilterFuncs_msgid
    UdpcpFilterFuncs_datalen,
#define FILTERFUNC_UDPCP_DATALEN (unsigned long long int)UdpcpFilterFuncs_datalen
    UdpcpFilterFuncs_csum
#define FILTERFUNC_UDPCP_CSUM (unsigned long long int)UdpcpFilterFuncs_csum
};

#include "protocolparser.h"
typedef struct Sudpcp_frame
{
    uint32_t        checksum;
    unsigned char   magicfield;
    unsigned char   res;
    unsigned char   fragAmnt;
    unsigned char   fragNo;
    uint16_t        msgId;
    uint16_t        payload_len;
}__attribute__((packed)) Sudpcp_frame;

typedef struct protocolparser_udpcp
{
    protocolparser genparser;
    unsigned int last_filter;
    proto_filter_func filfunc[UDPCP_FILTERS_AMNT];
}protocolparser_udpcp;

protocolparser_udpcp *init_protocolparser_udpcp();

#endif
