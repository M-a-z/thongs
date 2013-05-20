
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

#include "protocolparser_arp.h"
#include "common.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stddef.h>
/*
static int get_mac(char *filter,char *mac)
{
    int rval;
    unsigned m0,m1,m2,m3,m4,m5;
    short i=1;
    char *pi=(char *)&i;
    if(!filter )
    {
        printf("NULL mac at %s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    if(!*pi)
        rval=sscanf(filter,"%x:%x:%x:%x:%x:%x",&m5,&m4,&m3,&m2,&m1,&m0 );
    else
        rval=sscanf(filter,"%x:%x:%x:%x:%x:%x",&m0,&m1,&m2,&m3,&m4,&m5 );
    if(6!=rval || 255<m0 || 255<m1 || 255<m2 || 255<m3 || 255<m4 || 255<m5)
    {
        printf("Invalid strip mac '%s' given\n",filter);
        return EXIT_FAILURE;
    }
    mac[0]=(unsigned char)m0;
    mac[1]=(unsigned char)m1;
    mac[2]=(unsigned char)m2;
    mac[3]=(unsigned char)m3;
    mac[4]=(unsigned char)m4;
    mac[5]=(unsigned char)m5;
    
    return 0;
}

static int get_vlan(char *filter,unsigned int *vlan)
{
    unsigned int v;
    char *endp;
    v=strtol(filter,&endp,0);
    if(*endp || !*filter)
    {
        return -1;
    }
    *vlan=htonl(v);
    return 0;
}

*/
static void *filter2val(protocolparser *_this,unsigned long long int filnum,char *filter, size_t len)
{
    //char *endp;
    uint16_t i=1;
    switch(filnum)
    {
        /* All UDP header vals are shorts */
        case FILTERFUNC_ARP_SENDER_HWA:
        case FILTERFUNC_ARP_TARGET_HWA:
        {
            uint8_t *mac;
            mac=malloc(6);
            if(mac)
                if(get_mac(filter,mac))
                {
                    free(mac);
                    mac=NULL;
                }
            return mac;
            break;
        }
        case FILTERFUNC_ARP_SENDER_PA:
        case FILTERFUNC_ARP_TARGET_PA:
        {
            uint32_t *val=NULL;
            char tmp[100];
            memcpy(tmp,filter,len);
            tmp[len]='\0';
            val=malloc(sizeof(uint32_t));
            if(val)
            {
                if(!inet_pton(AF_INET,tmp,val))
                {
                    break;
                }
                return val;
            }
            break;

        }
        case FILTERFUNC_ARP_OPERATION_REPLY:
        i++;
        case FILTERFUNC_ARP_OPERATION_REQUEST:
        {
            uint16_t *op;
            op=malloc(2);
            if(op)
            {
                *op=htons(i);
            }
            return op;
            break;
        }
        default:
            break;
    }
    return NULL;
}
static unsigned long long int filter2num(protocolparser *_this,char **filter, size_t *len)
{
    unsigned long long rval = -1LL;
    int typelen=0;
    if(len)
    {
        if(!strncmp("req",*filter,3))
        {
            typelen=4;
            rval=0ULL;
        }
        else if(!strncmp("resp",*filter,4))
        {
            typelen=5;
            rval=1ULL;
        }
        else if(!strncmp("smac",*filter,4))
        {
            typelen=5;
            rval=2ULL;
        }
        else if(!strncmp("dmac",*filter,4))
        {
            typelen=5;
            rval=3ULL;
        }
        else if(!strncmp("sip",*filter,3))
        {
            typelen=4;
            rval=4ULL;
        }
        else if(!strncmp("dip",*filter,3))
        {
            typelen=4;
            rval=5ULL;
        }

    }
    *len-=typelen;
    *filter=(*filter+typelen);
    return rval;
}
static void remove_filter(protocolparser *_this_, char *filter, size_t len)
{
}

static void install_filter(protocolparser *_this_, char *filter, size_t len)
{
    unsigned long long int filnum;
    void *val;
    if(-1LL==(long long int)(filnum=filter2num(_this_,&filter,&len))) 
        return;
    val=filter2val(_this_,filnum,filter,len);
    
    _this_->activate_filter(_this_,_this_->get_filter(_this_,filnum),0,val);
}
/*
 * genparser's activate is Ok.
static void activate(protocolparser *_this __attribute__((unused)))
{
    return;
}
*/
static void *get_payload(protocolparser *_this,void *buff, size_t len, size_t *newlen)
{
    int nlen=len-sizeof(Sarp_frame);
    if(0>nlen)
    {
        *newlen=0;
        return (((char*)buff)+len);
    }
    *newlen=(size_t)nlen;
    return (((char *)buff)+sizeof(Sarp_frame));
}
static proto_filter_func get_filter(struct protocolparser *_this_, unsigned long long int filter_type)
{
    protocolparser_arp *_this=(protocolparser_arp *)_this_;
    if(filter_type>=_this->last_filter)
        return NULL;
    else
        return *(proto_filter_func *)(((char *)_this)+offsetof(protocolparser_arp, filfunc[0])+sizeof(proto_filter_func)*filter_type);
}
static unsigned short proto_get(protocolparser *_this __attribute__((unused)),void *buf __attribute__((unused)), size_t len __attribute__((unused))) 
{
    return -1;
}
static int arp_filter_operation(void *buff,size_t len ,void *value)
{
    Sarp_frame *uf=(Sarp_frame*)buff;
    if(len<sizeof(Sarp_frame) || !value)
        return 0;
    return ((*(uint16_t *)value)==uf->oper);
}
static int arp_filter_thwa(void *buff,size_t len ,void *value)
{
    Sarp_frame *uf=(Sarp_frame*)buff;
    
    if(len<sizeof(Sarp_frame) || !value)
        return 0;
    return (!memcmp(uf->target_hwa,value,6));
}

static int arp_filter_shwa(void *buff,size_t len ,void *value)
{
    Sarp_frame *uf=(Sarp_frame*)buff;
    
    if(len<sizeof(Sarp_frame) || !value)
        return 0;
    return (!memcmp(uf->sender_hwa,value,6));
}
static int arp_filter_spa(void *buff,size_t len ,void *value)
{
    Sarp_frame *uf=(Sarp_frame*)buff;
    if(len<sizeof(Sarp_frame) || !value)
        return 0;
    return ((*(uint32_t *)value)==uf->sender_pa);
}
static int arp_filter_tpa(void *buff,size_t len ,void *value)
{
    Sarp_frame *uf=(Sarp_frame*)buff;
    if(len<sizeof(Sarp_frame) || !value)
        return 0;
    return ((*(uint32_t *)value)==uf->target_pa);
}
char *operstring(uint16_t oper)
{
    if(1==oper)
        return "Request";
    if(2==oper)
        return "Reply";
    return "Unknown";
}

static void outputformat_header(protocolparser *_this,char *buff,size_t bufflen, char **outputstring, size_t *outputlen)
{
    Sarp_frame *afr=(Sarp_frame*)buff;
    int rval;
    char src[34];
    char dst[34];
    uint16_t oper;
    if(!outputlen || !*outputlen || !outputstring || !*outputstring)
        return;
    if(bufflen<sizeof(Sarp_frame))
    {
        _this->outputformat_dummy(_this,buff,bufflen,outputstring,outputlen);
        return;
    }
    oper=ntohs(afr->oper);
    rval=snprintf
    (
        *outputstring,
        *outputlen,
        "ARP: HwType%hu ProtoType=%hu HwLen=%hhu Plen=%hhu Oper=%s(%u) {%02x:%02x:%02x:%02x:%02x:%02x/%s} ==> {%02x:%02x:%02x:%02x:%02x:%02x/%s} ",
        ntohs(afr->hwtype),
        ntohs(afr->ptype),
        afr->hwlen,
        afr->plen,
        operstring(oper),
        oper,
        afr->sender_hwa[0],
        afr->sender_hwa[1],
        afr->sender_hwa[2],
        afr->sender_hwa[3],
        afr->sender_hwa[4],
        afr->sender_hwa[5],
        inet_ntop(AF_INET,&(afr->sender_pa),src,34),
        afr->target_hwa[0],
        afr->target_hwa[1],
        afr->target_hwa[2],
        afr->target_hwa[3],
        afr->target_hwa[4],
        afr->target_hwa[5],
        inet_ntop(AF_INET,&(afr->target_pa),dst,34)
    );

    if(rval==-1 || rval > *outputlen)
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




protocolparser_arp *init_protocolparser_arp()
{
    protocolparser_arp *_this=calloc(1,sizeof(protocolparser_arp));
    if(_this)
    {
        init_genparser(&_this->genparser);
        _this->genparser.proto=0x806; /* ARP */
        //_this->genparser.activate=&activate;
        _this->genparser.get_payload=&get_payload; //here we need our own
        _this->genparser.proto_get=&proto_get;
        _this->genparser.get_filter=&get_filter;
        _this->genparser.install_filter=&install_filter;
        _this->genparser.remove_filter=&remove_filter;
        _this->genparser.filter2val=&filter2val;
        _this->genparser.filter2num=&filter2num;
        _this->genparser.outputformat_header=&outputformat_header;
        _this->last_filter=ARP_FILTERS_AMNT;
        _this->filfunc[FILTERFUNC_ARP_OPERATION_REQUEST]=arp_filter_operation;
        _this->filfunc[FILTERFUNC_ARP_OPERATION_REPLY]=arp_filter_operation;
        _this->filfunc[FILTERFUNC_ARP_SENDER_HWA]=arp_filter_shwa;
        _this->filfunc[FILTERFUNC_ARP_TARGET_HWA]=arp_filter_thwa;
        _this->filfunc[FILTERFUNC_ARP_SENDER_PA]=arp_filter_spa;
        _this->filfunc[FILTERFUNC_ARP_TARGET_PA]=arp_filter_tpa;
    }
    return _this;
}
