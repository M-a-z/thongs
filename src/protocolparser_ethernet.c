
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

#include "protocolparser_ethernet.h"
#include "common.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stddef.h>


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

static void *filter2val(protocolparser *_this,unsigned long long int filnum,char *filter, size_t len)
{
    switch(filnum)
    {
        case 0:
        case 1:
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
        case 2:
        {
            unsigned int *vlan;
            vlan=malloc(4);
            if(vlan)
                if(get_vlan(filter,vlan))
                {
                    free(vlan);
                    vlan=NULL;
                }
            return vlan;
            break;
        }
        default:
            break;
    }
    return NULL;
}
static int proto_matches(protocolparser *_this, unsigned short proto)
{
    return proto==_this->proto;
}

static unsigned long long int filter2num(protocolparser *_this,char **filter, size_t *len)
{
    unsigned long long rval = -1LL;
    int typelen=0;
    if(len)
    {
        if(!strncmp("vlan",*filter,4))
        {
            typelen=5;
            rval=2ULL;
        }
        else if(!strncmp("src",*filter,3))
        {
            typelen=4;
            rval=1ULL;
        }
        else if(!strncmp("dst",*filter,3))
        {
            typelen=4;
            rval=0ULL;
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

static void activate(protocolparser *_this __attribute__((unused)))
{
    /* base filter => always active */
    return;
}
static void *get_payload(protocolparser *_this,void *buff, size_t len, size_t *newlen)
{
    int nlen=len-sizeof(Seth_frame);
    Seth_frame *ef=(Seth_frame*)buff;
    *newlen=0;
    if(nlen<=0)
        return NULL;
    if(nlen>8 && ntohs(ef->ethtype)==0x9100)
        nlen-=8;
    else if(nlen > 4 && ntohs(ef->ethtype)==0x8100)
        nlen-=4;
    *newlen=nlen;
    return (((char *)(ef))+(len-nlen));
}
static proto_filter_func get_filter(struct protocolparser *_this_, unsigned long long int filter_type)
{
    protocolparser_ethernet *_this=(protocolparser_ethernet *)_this_;
    if(filter_type>=_this->last_filter)
        return NULL;
    else
        return *(proto_filter_func *)(((char *)_this)+offsetof(protocolparser_ethernet, filfunc[0])+sizeof(proto_filter_func)*filter_type);
}
static unsigned short proto_get(protocolparser *_this,void *buf, size_t len) 
{
    Seth_frame *ef=(Seth_frame*)buf;
    unsigned short proto;
    if(len<14)
        return -1;
    proto=ntohs(ef->ethtype);
    if(0x9100==proto)
    {
        if(len>=22)
            proto=ntohs(*(((unsigned short *)&(ef->ethtype))+4));
    }
    else if(0x8100 == proto)
    {
        if(len>=18)
            proto=ntohs(*(((unsigned short *)&(ef->ethtype))+2));
    }    
    return proto;
}

static int ethernet_filter_dst(void *buff,size_t len ,void *value)
{
    if(len<6)
        return 0;
    return !memcmp(buff,value,6);
}
static int ethernet_filter_vlan(void *buff,size_t len ,void *value)
{
    if(len<16)
        return 0;
    return !memcmp((((char *)buff+12)),value,4);
}

static const char *vlan_string(unsigned long long int tagging)
{
    if((tagging & 0x00000000ffff0000ULL)==0x0000000081000000ULL)
            return "802.1q";
    if((tagging & 0xffff000000000000ULL) == 0x9100000000000000ULL)
            return "oldQinQ";
    if((tagging & 0xffff000000000000ULL) == 0x88a8000000000000ULL)
            return "QinQ";
    return "unknown_vlan";
}
static unsigned long long vlan_number(unsigned long long int tagging)
{
    if((tagging & 0x00000000ffff0000ULL)==0x0000000081000000ULL)
            return (tagging & 0x000000000000ffffULL);
    if((tagging & 0xffff000000000000ULL) == 0x9100000000000000ULL)
            return (((tagging &0x0000ffff00000000ULL)>>16) | (tagging &0x000000000000ffff));
    if((tagging & 0xffff000000000000ULL) == 0x88a8000000000000ULL)
            return (((tagging &0x0000ffff00000000ULL)>>16) | (tagging &0x000000000000ffff));
    return tagging;
}
static const char *proto_string(unsigned short proto)
{
    switch(proto)
    {
        case 0x800:
            return "IPv4";
            break;
        case 0x806:
            return "ARP";
            break;
        case 0x86dd:
            return "IPv6";
            break;
        default:
            break;
    }
    return "Unknown";
}
#if 0
static void mva_ntohll(unsigned long long *num)
{
    short one=1;
    char *two=(char *)&one;
    if(!*two)
        return;
    two++;
    for(one=0;*(char*)&one<4;one++)
    {
        *two=((char *)num)[7-*(char*)&one];
        ((char *)num)[7-*(char*)&one]=((char *)num)[(int)*(char*)&one];
        ((char *)num)[(int)*(char*)&one]=*two;
    }
}
#endif


static unsigned short get_ethtype_from_tagged_frame(char *hdr_ethtype,int framelen)
{
    char QinQtag[2]={0x88,0xa8};
    char QinQtag_old[2]={0x91,0};
    char VLAN_tag[2]={0x81,0};
    if(framelen>=10)
    {
        if( *(short *)QinQtag == *(short *)hdr_ethtype || *(short *)QinQtag_old  == *(short *)hdr_ethtype )
            return ntohs(  *(short *)(hdr_ethtype+8));
        if( *(short *)VLAN_tag  == *(short *)hdr_ethtype )
            return ntohs(  *(short *)(hdr_ethtype+4));
    }
    else if(framelen>=6)
    {
        /* no QinQ check */
        if( *(short *)VLAN_tag  == *(short *)hdr_ethtype )
            return ntohs(  *(short *)(hdr_ethtype+4));
    }
    return 0;
}

static void outputformat_header(protocolparser *_this,char *buff,size_t bufflen, char **outputstring, size_t *outputlen)
{
    Seth_frame *ef=(Seth_frame*)buff;
    int rval;
    unsigned short hostorder_ethtype;
    if(!outputlen || !*outputlen || !outputstring || !*outputstring)
        return;
    if(bufflen<sizeof(Seth_frame))
    {
        _this->outputformat_dummy(_this,buff,bufflen,outputstring,outputlen);
        return;
    }
    hostorder_ethtype=ntohs(ef->ethtype);
    rval=snprintf
    (
        *outputstring,
        *outputlen,
        "%02x:%02x:%02x:%02x:%02x:%02x < %02x:%02x:%02x:%02x:%02x:%02x %s(0x%04llx) ",
        ef->dmac[0],
        ef->dmac[1],
        ef->dmac[2],
        ef->dmac[3],
        ef->dmac[4],
        ef->dmac[5],
        ef->smac[0],
        ef->smac[1],
        ef->smac[2],
        ef->smac[3],
        ef->smac[4],
        ef->smac[5],
        _this->tagging?vlan_string(_this->tagging):proto_string(hostorder_ethtype),
        _this->tagging?vlan_number(_this->tagging):(unsigned long long)hostorder_ethtype
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
        if(_this->tagging)
        {
            hostorder_ethtype=get_ethtype_from_tagged_frame((char *)&(ef->ethtype),bufflen-offsetof(Seth_frame,ethtype));
            rval=snprintf(*outputstring,*outputlen,"%s(%04hx) ",proto_string(ef->ethtype),ef->ethtype);
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
    }
}

static int ethernet_filter_src(void *buff,size_t len ,void *value)
{
    if(len<12)
        return 0;
    return !memcmp((((char *)buff+6)),value,6);
}

protocolparser_ethernet *init_protocolparser_ethernet()
{
    protocolparser_ethernet *_this=calloc(1,sizeof(protocolparser_ethernet));
    if(_this)
    {
        init_genparser(&_this->genparser);
        _this->genparser.proto=0; /* we can assume all 0 level packets are ethernet - thongs is ethernet sniffer */
        _this->genparser.activate=&activate;
        _this->genparser.get_payload=&get_payload; //here we need our own
        _this->genparser.proto_get=&proto_get;
        _this->genparser.get_filter=&get_filter;
        _this->genparser.install_filter=&install_filter;
        _this->genparser.remove_filter=&remove_filter;
        _this->genparser.filter2val=&filter2val;
        _this->genparser.filter2num=&filter2num;
        _this->genparser.proto_matches=&proto_matches;
        _this->genparser.outputformat_header=&outputformat_header;
        _this->last_filter=ETHERNET_FILTERS_AMNT;
        _this->filfunc[0]=ethernet_filter_dst;
        _this->filfunc[1]=ethernet_filter_src;
        _this->filfunc[2]=ethernet_filter_vlan;
    }
    return _this;
}
