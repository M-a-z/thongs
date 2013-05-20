
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

#ifndef PROTOCOLPARSER_UDP
#define PROTOCOLPARSER_UDP

#define UDP_FILTERS_AMNT 4
enum UdpFilterFuncs
{
    UdpFilterFuncs_dst = 0,
#define FILTERFUNC_UDP_DST_PORT (unsigned long long int)UdpFilterFuncs_dst
    UdpFilterFuncs_src,
#define FILTERFUNC_UDP_SRC_PORT (unsigned long long int)UdpFilterFuncs_src
    UdpFilterFuncs_len,
#define FILTERFUNC_UDP_LEN (unsigned long long int)UdpFilterFuncs_len
    UdpFilterFuncs_csum
#define FILTERFUNC_UDP_CSUM (unsigned long long int)UdpFilterFuncs_csum
};

#include "protocolparser.h"
typedef struct Sudp_frame
{
    unsigned short sport;
    unsigned short dport;
    unsigned short len;
    unsigned short csum;
}__attribute__((packed)) Sudp_frame;

typedef struct protocolparser_udp
{
    protocolparser genparser;
    unsigned int last_filter;
    proto_filter_func filfunc[UDP_FILTERS_AMNT];
}protocolparser_udp;

protocolparser_udp *init_protocolparser_udp();

#endif
