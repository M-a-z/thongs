
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

#ifndef PROTOCOLPARSER_IP4
#define PROTOCOLPARSER_IP4

#define IP4_FILTERS_AMNT 5
enum Ip4FilterFuncs
{
    Ip4FilterFuncs_dst = 0,
#define FILTERFUNC_IP4_DST_ADDR (unsigned long long int)Ip4FilterFuncs_dst
    Ip4FilterFuncs_src,
#define FILTERFUNC_IP4_SRC_ADDR (unsigned long long int)Ip4FilterFuncs_src
    Ip4FilterFuncs_ttl,
#define FILTERFUNC_IP4_TTL (unsigned long long int)Ip4FilterFuncs_ttl
    Ip4FilterFuncs_len,
#define FILTERFUNC_IP4_LEN (unsigned long long int)Ip4FilterFuncs_len
    Ip4FilterFuncs_csum
#define FILTERFUNC_IP4_CSUM (unsigned long long int)Ip4FilterFuncs_csum
};

#include "protocolparser.h"
typedef struct Sip4_frame
{
    unsigned char vhl;
    unsigned char DS_ECN;
    uint16_t totallen;
    uint16_t id; 
    uint16_t FlagsNFrags;
    unsigned char ttl;
    unsigned char proto;
    uint16_t csum;
    uint32_t sip;
    uint32_t dip;
}__attribute__((packed)) Sip4_frame;

typedef struct protocolparser_ip4
{
    protocolparser genparser;
    unsigned int last_filter;
    proto_filter_func filfunc[IP4_FILTERS_AMNT];
}protocolparser_ip4;

protocolparser_ip4 *init_protocolparser_ip4();

#endif
