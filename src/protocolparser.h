
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

#ifndef PROTOCOLPARSER_H
#define PROTOCOLPARSER_H

#include <string.h>
#include <stdint.h>

typedef struct bollox_list
{
    struct bollox_list* head;
    struct bollox_list* next;
    struct bollox_list* prev;
}bollox_list;

#define BOLLOX_LIST_GET_FIRST(item) ((typeof(item))(((bollox_list *)(item))->head->next))
#define BOLLOX_LIST_GET_NEXT(item) ((typeof(item))(((bollox_list *)(item))->next))
#define BOLLOX_LIST_FIND(list,data) \
({ \
    typeof((list)+1) _tmp; \
    for(_tmp=BOLLOX_LIST_GET_FIRST((list));_tmp;_tmp=BOLLOX_LIST_GET_NEXT((list))) \
        if(!memcmp((((char*)(_tmp))+sizeof(bollox_list)),data,sizeof(*data))) \
        { \
            break; \
        } \
    _tmp; \
})
#define BOLLOX_LIST_DEL(list,data) \
({ \
    typeof((list)+1) _found; \
    _found=BOLLOX_LIST_FIND((list),(data)); \
    if(_found) \
    { \
        _found->prev->next=_found->next; \
        if(_found->next) \
            _found->next->prev=_found->prev; \
    } \
    _found; \
})

#define BOLLOX_LIST_INIT(list) \
({\
    memset((list),0,sizeof(*(list))); \
    (list)->head=(list); \
})
#define BOLLOX_LIST_ADD(list,data) \
({ \
    typeof((data)+1) _d; \
    typeof((list)+1) _p=calloc(1,sizeof(*_p)); \
    if(_p) \
    {  \
        _d=(typeof(_d))(((void **)(_p))+3); \
        _p->head=(_p->prev=(list)->head); \
        _p->next=_p->head->next; \
        _p->head->next=_p; \
        memcpy(_d,(data),sizeof(*_d)); \
    } \
    !_p; \
})

struct protocolparser;

typedef int (*proto_matchesF)(struct protocolparser *_this, unsigned short proto);

typedef struct protocolparser_list
{
    struct protocolparser_list *head;
    struct protocolparser_list *next;
    struct protocolparser_list *prev;
    struct protocolparser *parser;
}protocolparser_list;

typedef int (*proto_filter_func)(void *buff,size_t len ,void *value);
typedef struct filter_data
{
    int filtertype; // currently only hilight...
    void *filtervalue;
    proto_filter_func filfun;
}filter_data;
typedef struct proto_filter
{
    struct proto_filter *head;
    struct proto_filter *next;
    struct proto_filter *prev;
    filter_data fd;
}proto_filter;
/* At startup init parsers for different protocols. Set parent parsers for all parsers. Eg, ethernet parser would be parent for UDP parser. similarly UDP parser would be parent for UDPCP parser 
 *  set no active child parsers 
 *  When one wishes to for example highlight udpcp packets with msg id XXX => set filter function for msg ID in UDPCP parser's filter funcs.
 *  Then add UDPCP to in child parser pointers for all parents. (UDP parser). Furthermore, set UDP parser as child for all UDP's parent parsers. (Eg in ethernet parser)
 *  => when UDPCP packet arrives, always active ethernet parser checks for it's children and calls UDP. UDP checks for it's children and calls UDPCP and UDPCP checks for msg_id and returns.
 *  */
typedef void (*activateF)(struct protocolparser *); //adds this in all parent parsers + calls activate for all parents
typedef void (*activate_filterF)(struct protocolparser *,proto_filter_func, int filtertype, void *filter_value); //adds given filter in active filters list
typedef int (*evaluateF)(struct protocolparser *,void *buff, size_t len,uint32_t proto_from_parent, char *outputstring, size_t outputlen,int hl_matched); /// < public, calls evaluate_own, and if not match, then evaluate_children() which calls evaluate() for all childrens return != 0 if match found, else 0
typedef int (*evaluate_own_filtersF) (struct protocolparser *,void *buff, size_t len); //evaluate own filters, return != 0 if match found, else 0
typedef int (*evaluate_childrenF) (struct protocolparser *,void *buff, size_t len,uint32_t proto_from_parent,char *outputstring, size_t outputlen,int hl_matched); //call evaluate for all active children, and return the value children reports
typedef void *(*get_payloadF) (struct protocolparser *,void *buff, size_t len, size_t *newlen);
typedef proto_filter_func (*get_filterfuncF) (struct protocolparser *,unsigned long long int filter_type);
typedef unsigned short (*proto_getF)(struct protocolparser *_this,void *buf, size_t len);
typedef void (*install_filterF)(struct protocolparser *_this,char *filter, size_t len);
typedef unsigned long long int (*filter2numF)(struct protocolparser *_this,char **filter, size_t *len);
typedef void *(*filter2valF)(struct protocolparser *_this,unsigned long long int filnum,char *filter, size_t len);
typedef void (*outputformat_headerF)(struct protocolparser *_this,char *buff,size_t bufflen, char **outputstring, size_t *outputlen);

typedef struct protocolparser
{
    unsigned short proto;
    unsigned long long int tagging; /* we shall write the VLAN tag here if such exists */
    struct protocolparser_list activechildparsers;
    struct protocolparser_list childparsers;
    struct protocolparser_list parentparsers;
    proto_filter installed_filter_list;
    filter2valF filter2val;
    filter2numF filter2num;
    activateF activate;
    activateF deactivate;
    activate_filterF activate_filter;
    install_filterF  install_filter;
    install_filterF  remove_filter;
    evaluateF evaluate;
    evaluate_own_filtersF evaluate_own_filters;
    evaluate_childrenF evaluate_children;
    outputformat_headerF outputformat_header;
    outputformat_headerF outputformat_dummy;
    proto_matchesF proto_matches; /* see if given proto matches my own protocol number */
    proto_getF proto_get;         /* function extracting 'child' protocol from header */
    get_payloadF get_payload;
    get_filterfuncF get_filter;
}protocolparser;
/*
typedef int (*protoparser_add_parser)(struct filterfinder*, struct protocolparser *,unsigned short proto);
typedef protocolparser *(*find_parserF)(struct filterfinder*,void *proto, size_t maxlen);
typedef struct filterfinder
{
    int regged_parsers;
    unsigned short min_proto; 
    unsigned short max_proto; 
    protoparser_add_parser add_parser;
    find_parserF find_parser;
}filterfinder;
*/
void parser_add_2(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt);
void parser_add_1(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt);
void parser_add_0(protocolparser *parser);
/*
protocolparser_list *parser_list_find(protocolparser_list *item, protocolparser *parser);
protocolparser_list *parser_list_del(protocolparser_list *item,protocolparser *parser);
protocolparser_list *parser_list_get_first(protocolparser_list *item);
protocolparser_list *parser_list_get_next(protocolparser_list *item);
*/
//parser_list_init(protocolparser_list *head);
//int parser_list_add(protocolparser_list *item,protocolparser *parser);
void init_genparser(protocolparser *_this);
void parser_add_udpcp2udp(protocolparser *udpcp,protocolparser *udp);

#endif

