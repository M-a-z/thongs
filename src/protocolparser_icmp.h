
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

#ifndef PROTOCOLPARSER_ICMP
#define PROTOCOLPARSER_ICMP

#define ICMP_FILTERS_AMNT 4
enum IcmpFilterFuncs
{
    IcmpFilterFuncs_type = 0,
#define FILTERFUNC_ICMP_TYPE (unsigned long long int)IcmpFilterFuncs_type
    IcmpFilterFuncs_code,
#define FILTERFUNC_ICMP_CODE (unsigned long long int)IcmpFilterFuncs_code
    IcmpFilterFuncs_csum,
#define FILTERFUNC_ICMP_CSUM (unsigned long long int)IcmpFilterFuncs_csum
    IcmpFilterFuncs_rest
#define FILTERFUNC_ICMP_REST (unsigned long long int)IcmpFilterFuncs_rest
};

#include "protocolparser.h"
typedef struct Sicmp_frame
{
    unsigned char type;
    unsigned char code;
    uint16_t csum;
    uint32_t rest;
}__attribute__((packed)) Sicmp_frame;

typedef struct protocolparser_icmp
{
    protocolparser genparser;
    unsigned int last_filter;
    proto_filter_func filfunc[ICMP_FILTERS_AMNT];
}protocolparser_icmp;

protocolparser_icmp *init_protocolparser_icmp();

#endif
