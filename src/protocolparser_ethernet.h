
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

#ifndef PROTOCOLPARSER_ETHERNET
#define PROTOCOLPARSER_ETHERNET

#define ETHERNET_FILTERS_AMNT 3
enum EthernetFilterFuncs
{
    EthernetFilterFuncs_dst = 0,
#define FILTERFUNC_ETH_DST (unsigned long long int)EthernetFilterFuncs_dst
    EthernetFilterFuncs_src,
#define FILTERFUNC_ETH_SRC (unsigned long long int)EthernetFilterFuncs_src
    EthernetFilterFuncs_vlan
#define FILTERFUNC_ETH_VLAN (unsigned long long int)EthernetFilterFuncs_vlan
};

#include "protocolparser.h"
typedef struct Seth_frame
{
    unsigned char dmac[6];
    unsigned char smac[6];
    unsigned short ethtype; /* NOTE: if 802.1q or 802.1ad (QinQ) or even non standard QinQinQ are used, then we get VLAN tag here and real ethertype is further (header is extended) */
}__attribute__((packed)) Seth_frame;

typedef struct protocolparser_ethernet
{
    protocolparser genparser;
    unsigned int last_filter;
    proto_filter_func filfunc[ETHERNET_FILTERS_AMNT];
}protocolparser_ethernet;

protocolparser_ethernet *init_protocolparser_ethernet();

#endif
