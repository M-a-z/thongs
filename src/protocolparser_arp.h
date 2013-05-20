
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

#ifndef PROTOCOLPARSER_ARP
#define PROTOCOLPARSER_ARP

#define ARP_FILTERS_AMNT 6
enum ArpFilterFuncs
{
    ArpFilterFuncs_operreq = 0,
#define FILTERFUNC_ARP_OPERATION_REQUEST (unsigned long long int)ArpFilterFuncs_operreq
    ArpFilterFuncs_operres,
#define FILTERFUNC_ARP_OPERATION_REPLY (unsigned long long int)ArpFilterFuncs_operres
    ArpFilterFuncs_shwa,
#define FILTERFUNC_ARP_SENDER_HWA (unsigned long long int)ArpFilterFuncs_shwa
    ArpFilterFuncs_thwa,
#define FILTERFUNC_ARP_TARGET_HWA (unsigned long long int)ArpFilterFuncs_thwa
    ArpFilterFuncs_spa,
#define FILTERFUNC_ARP_SENDER_PA (unsigned long long int)ArpFilterFuncs_spa
    ArpFilterFuncs_tpa
#define FILTERFUNC_ARP_TARGET_PA (unsigned long long int)ArpFilterFuncs_tpa
};

#include "protocolparser.h"
typedef struct Sarp_frame
{
    uint16_t      hwtype;
    uint16_t      ptype;
    unsigned char hwlen;
    unsigned char plen; 
    uint16_t      oper;
    unsigned char sender_hwa[6];
    uint32_t      sender_pa;
    unsigned char target_hwa[6];;
    uint32_t      target_pa;
}__attribute__((packed)) Sarp_frame;

typedef struct protocolparser_arp
{
    protocolparser genparser;
    unsigned int last_filter;
    proto_filter_func filfunc[ARP_FILTERS_AMNT];
}protocolparser_arp;

protocolparser_arp *init_protocolparser_arp();

#endif
