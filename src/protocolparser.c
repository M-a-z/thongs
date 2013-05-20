
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

#include <stdio.h>
#include <stdlib.h>
#include "protocolparser.h"
static int G_parser_list_inited=0;
protocolparser_list G_parser_list;
/*
proto_filter *parser_list_find(proto_filter *item, protocolparser *parser)
{
    for(item=item->head->next;item;item=item->next)
        if(item->parser==parser)
            break;
    return item;
}
*/
/*
proto_filter *parser_list_del(proto_filter *item,protocolparser *parser)
{
    if((item=parser_list_find(item,parser)))
    {
        item->prev->next=item->next;
        if(item->next)
            item->next->prev=item->prev;
    }
}
*/
/*
int parser_list_add(protocolparser_list *item,protocolparser *parser)
{
    protocolparser_list *p=calloc(1,sizeof(protocolparser_list));
    if(!p)
        return -1;
    p->head=(p->prev=item->head);
    p->next=p->head->next;
    p->head->next=p;
    p->parser=parser;
}
*/


static int proto_matches(protocolparser *_this, unsigned short proto)
{
    return proto==_this->proto;
}
/*
protocolparser_list *parser_list_find(protocolparser_list *item, protocolparser *parser)
{
    for(item=item->head->next;item;item=item->next)
        if(item->parser==parser)
            break;
    return item;
}
protocolparser_list *parser_list_del(protocolparser_list *item,protocolparser *parser)
{
    if((item=parser_list_find(item,parser)))
    {
        item->prev->next=item->next;
        if(item->next)
            item->next->prev=item->prev;
    }
}
protocolparser_list *parser_list_get_first(protocolparser_list *item)
{
    return item->head->next;
}
protocolparser_list *parser_list_get_next(protocolparser_list *item)
{
    return item->next;
}
*/
/*
parser_list_init(protocolparser_list *head)
{
    memset(head,0,sizeof(protocolparser_list));
    head->head=head;
}
*/
static void deactivate(protocolparser *_this)
{
    /* TODO: add freeing filters */
    protocolparser_list *p;
    for
    (
         p=BOLLOX_LIST_GET_FIRST(&(_this->parentparsers));
         p;
         p=BOLLOX_LIST_GET_NEXT(p)
    )
            BOLLOX_LIST_DEL(&(p->parser->activechildparsers),&_this);
}
static void activate(protocolparser *_this)
{
    protocolparser_list *p;
    for
    (
            p=BOLLOX_LIST_GET_FIRST(&(_this->parentparsers));
            p;
            p=BOLLOX_LIST_GET_NEXT(p)
    )
    {
        if(!BOLLOX_LIST_FIND(&(p->parser->activechildparsers),&_this))
        {
            BOLLOX_LIST_ADD(&(p->parser->activechildparsers),&_this);
        }
    }
}
/*
int parser_list_add(protocolparser_list *item,protocolparser *parser)
{
    protocolparser_list *p=calloc(1,sizeof(protocolparser_list));
    if(!p)
        return -1;
    p->head=(p->prev=item->head);
    p->next=p->head->next;
    p->head->next=p;
    p->parser=parser;
}
*/
/* 
 * proto == pointer to ethernet frame's ether type, 
 * maxlen == size of packet - offsetof ether type
 * (so we can safely search proto if type looks like 802.1q or 802.ad)
 */

static proto_filter_func get_filter (struct protocolparser *_this __attribute__((unused)),unsigned long long int filter_type __attribute__((unused)))
{
    return NULL;
}
static void activate_filter(protocolparser *_this,proto_filter_func func,int filtertype, void *value)
{
    filter_data fd;
    fd.filtertype=filtertype;
    fd.filtervalue=value;
    fd.filfun=func;
    BOLLOX_LIST_ADD(&(_this->installed_filter_list),&fd);
}

            //rval=_this->evaluate_children(_this,applpayload,newsize,_this->proto_get(_this,buff,len),outputstring,outputlen,hl_matched);
            //rval=_this->evaluate_children(_this,applpayload,newsize,_this->proto_get(_this,buff,len),outputstring,outputlen,hl_matched);
static int evaluate_children(protocolparser *_this,void *buff, size_t len, uint32_t proto_from_parent,char *outputstring, size_t outputlen,int hl_matched)
{
    protocolparser_list* p;
    int i;
    int rv;
    for(i=0,p=BOLLOX_LIST_GET_FIRST(&_this->activechildparsers);p;p=BOLLOX_LIST_GET_NEXT(p),i++)
    {
        if((rv=p->parser->evaluate(p->parser,buff,len,proto_from_parent,outputstring,outputlen,hl_matched)))
        {
            if(-5==rv)
                i--;
            else
                return 1;
        }
    }
    if(!i)
        _this->outputformat_dummy(_this,buff,len,&outputstring,&outputlen);
    return 0;
}

static void outputformat_dummy(protocolparser *_this, char *buff, size_t len,char **outputstring, size_t *outputlen)
{
    size_t rval;
    int i;
    for(i=0;i<len&&*outputlen;i++)
    {
        rval=snprintf(*outputstring,*outputlen,"%02x ",buff[i]);
        if(rval>*outputlen || (size_t)-1==rval)
        {
            (*outputstring)[*outputlen-1]='\0';
            *outputlen=0;
        }
        else
        {
            *outputlen-=rval;
            (*outputstring)=((*outputstring)+rval);
        }

    }
}

static int evaluate_own_filters(protocolparser *_this,void *buff, size_t len)
{
    proto_filter *f;

    for(
        f=BOLLOX_LIST_GET_FIRST(&(_this->installed_filter_list));
        f;
        f=BOLLOX_LIST_GET_NEXT(f)
    )
    {
        if(f->fd.filfun(buff,len,f->fd.filtervalue))
            return 1;
    }
    return 0;
}
static int evaluate(protocolparser *_this,void *buff, size_t len, uint32_t proto_from_parent,char *outputstring, size_t outputlen, int hl_matched)
{
    int rval=-5;
    size_t newsize;
    void *applpayload;
    
    //unsigned short proto;
//    proto=_this->proto_get(_this,buff,len);
    if(_this->proto_matches(_this,proto_from_parent))
    {
        rval=0;
        if(!hl_matched)
            hl_matched=_this->evaluate_own_filters(_this,buff,len);

        applpayload=_this->get_payload(_this,buff,len,&newsize);
        if(_this->outputformat_header)
            _this->outputformat_header(_this,buff, len,&outputstring,&outputlen);
        else
            _this->outputformat_dummy(_this,buff,len-newsize,&outputstring,&outputlen);

        if(applpayload) 
        {
            rval=_this->evaluate_children(_this,applpayload,newsize,_this->proto_get(_this,buff,len),outputstring,outputlen,hl_matched);
        }

    }
    return (rval|hl_matched);
}

void init_genparser(protocolparser *_this)
{
    BOLLOX_LIST_INIT(&(_this->activechildparsers));
    BOLLOX_LIST_INIT(&(_this->childparsers));
    BOLLOX_LIST_INIT(&(_this->parentparsers));
    BOLLOX_LIST_INIT(&(_this->installed_filter_list));
    _this->proto_matches=&proto_matches;
    _this->activate_filter=&activate_filter;
    _this->activate=&activate;
    _this->deactivate=&deactivate;
    _this->evaluate=&evaluate;
    _this->evaluate_own_filters=&evaluate_own_filters;
    _this->evaluate_children=&evaluate_children;
    _this->get_filter=&get_filter;
    _this->outputformat_dummy=&outputformat_dummy;
//    _this->=&;
}

/*
static protocolparser *find_parser(filterfinder *_this,void *proto, size_t maxlen)
{
    unsigned short type=ntohs(*(unsigned short *)proto);
re_eval:
    if(type<this->min_proto || type>_this->max_proto)
    {
        if(maxlen >=6)
        {
            switch(type)
            {
                case 0x8100:
                    type=ntohs(*(((unsigned short *)proto)+2));
                    maxlen-=2;
                    vlan=ntohl(*(unsigned int *)proto);
                        goto re_eval;
                    break;
                case 0x9100:
                    break;
            }
        }
    }
}
*/
//void parser_add_6(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt)
//void parser_add_5(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt)
//void parser_add_4(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt)
void parser_add_3(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt)
{
    printf("parser_add_3() not implemented\n");
}
void parser_add_udpcp2udp(protocolparser *udpcp,protocolparser *udp)
{
    if(!udpcp || !udp)
        return;
    BOLLOX_LIST_ADD(&(udp->childparsers),&udpcp);
    BOLLOX_LIST_ADD(&(udp->activechildparsers),&udpcp);
    BOLLOX_LIST_ADD(&(udpcp->parentparsers),&udp);

}
void parser_add_2(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt)
{
    protocolparser_list *p;
    protocolparser_list *l1_parserlist;
    protocolparser *l1_parser;
    int i;
    for(p=BOLLOX_LIST_GET_FIRST(&G_parser_list);p;p=BOLLOX_LIST_GET_NEXT(p))
    {
        l1_parserlist=&(p->parser->childparsers);
        for(l1_parserlist=BOLLOX_LIST_GET_FIRST(l1_parserlist);l1_parserlist;l1_parserlist=BOLLOX_LIST_GET_NEXT(l1_parserlist))
        {
            l1_parser=l1_parserlist->parser;
            for(i=0;i<parent_proto_amnt;i++)
            {
                if(l1_parser->proto_matches(l1_parser,parent_protos[i]))
                {
                    if(BOLLOX_LIST_ADD(&(l1_parser->childparsers),&parser))
                    {
                        printf("Failed to add parser for proto 0x%hx\n",parser->proto);
                        return;
                    }
                    if(BOLLOX_LIST_ADD(&(parser->parentparsers),&(l1_parser)))
                    {
                        printf("Failed to add parser for proto 0x%hx\n",parser->proto);
                        //parser_list_del(&(p->parser->childparsers),parser);
                        BOLLOX_LIST_DEL(&(p->parser->childparsers),&parser);
                        return;
                    }
                    BOLLOX_LIST_ADD(&(l1_parser->activechildparsers),&parser);
                    break;
                }
            }
        }
    }
}

void parser_add_1(protocolparser *parser,unsigned short *parent_protos, int parent_proto_amnt)
{
    int i;
    protocolparser_list *p;
    for(p=BOLLOX_LIST_GET_FIRST(&G_parser_list);p;p=BOLLOX_LIST_GET_NEXT(p))
    {
        for(i=0;i<parent_proto_amnt;i++)
        {
            if(p->parser->proto_matches(p->parser,parent_protos[i]))
            {
                if(BOLLOX_LIST_ADD(&(parser->parentparsers),&(p->parser)))
                {
                    printf("Failed to add parser for proto 0x%hx\n",parser->proto);
                    return;
                }
                BOLLOX_LIST_ADD(&(p->parser->childparsers),&parser);
                BOLLOX_LIST_ADD(&(p->parser->activechildparsers),&parser);
                break;
            }
        }
    }
}
void parser_add_0(protocolparser *parser)
{
    int rval;
    if(!G_parser_list_inited)
        BOLLOX_LIST_INIT(&G_parser_list);
    G_parser_list_inited=1;
    if((rval=BOLLOX_LIST_ADD(&G_parser_list,&parser)))
        printf("BOLLOX_LIST_ADD FAILED!\n");
    /*
    rval=({
        protocolparser *_d;
        protocolparser_list *_p=calloc(1,sizeof(*_p));
        if(_p)
        {
            _d=(protocolparser *)(((void **)(_p))+3);
            _p->head=(_p->prev=(&G_parser_list)->head);
            _p->next=_p->head->next;
            _p->head->next=_p;
            memcpy(_d,(parser),sizeof(*_d));
        }
        !_p;
    });
    */
    
}

/*
static int add_parser(filterfinder* _this,  protocolparser *parser,unsigned short proto)
{
    if(_this->regged_parsers>=PROTO_PARSER_MAX_AMOUNT-1)
        return -1;
    if(!_this->min_proto)
    {
        _this->min_proto=proto;
        _this->max_proto=proto;
    }
    
}

struct filterfinder* filterfinder_init()
{
    filterfinder* _this=calloc(1,sizeof(filterfinder));
    if(_this)
    {
        _this->add_parser=&add_parser;
    }
    return _this;
}
*/
