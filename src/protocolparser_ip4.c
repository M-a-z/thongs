
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

#include "protocolparser_ip4.h"
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
    char *endp;
    switch(filnum)
    {
        /* All UDP header vals are shorts */
        case FILTERFUNC_IP4_DST_ADDR:
        case FILTERFUNC_IP4_SRC_ADDR:
        {
            //int rval;
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
//                *val=htonl(*val);
                return val;
            }
            break;
        }
        case FILTERFUNC_IP4_TTL:
        {
            unsigned char *ttl;
            ttl=malloc(1);
            if(ttl)
            {
                *ttl=(unsigned char)strtol(filter,&endp,0);
                if( !*filter || (endp && *endp!=' ' && *endp!= '\n'))
                {
                    printf("paska ttl\n");
                    free(ttl);
                    return NULL;
                }
            }
            return ttl;
            break;
        }
        case FILTERFUNC_IP4_LEN:
        {
            uint16_t *len;
            len=malloc(sizeof(uint16_t));
            if(len)
            {
                *len=(uint16_t)strtol(filter,&endp,0);
                if( !*filter || (endp && *endp!=' ' && *endp!= '\n'))
                {
                    free(len);
                    return NULL;
                }
            }
            *len=htons(*len);
            return len;
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
        if(!strncmp("sip",*filter,3))
        {
            typelen=4;
            rval=1ULL;
        }
        else if(!strncmp("dip",*filter,3))
        {
            typelen=4;
            rval=0ULL;
        }
        else if(!strncmp("ttl",*filter,3))
        {
            typelen=4;
            rval=2ULL;
        }
        else if(!strncmp("len",*filter,3))
        {
            typelen=4;
            rval=3ULL;
        }
        else if(!strncmp("csum",*filter,4))
        {
            typelen=5;
            rval=4ULL;
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
    int nlen=len-sizeof(Sip4_frame);
    //int extrawords;
    Sip4_frame *ef=(Sip4_frame*)buff;
    *newlen=0;
    nlen-=((ef->vhl&0xF)-5)*4;
    if(nlen<=0)
        return NULL;
    *newlen=nlen;
    return (((char *)(ef))+(len-nlen));
}
static proto_filter_func get_filter(struct protocolparser *_this_, unsigned long long int filter_type)
{
    protocolparser_ip4 *_this=(protocolparser_ip4 *)_this_;
    if(filter_type>=_this->last_filter)
        return NULL;
    else
        return *(proto_filter_func *)(((char *)_this)+offsetof(protocolparser_ip4, filfunc[0])+sizeof(proto_filter_func)*filter_type);
}
static unsigned short proto_get(protocolparser *_this,void *buf, size_t len) 
{
    Sip4_frame *ipf=(Sip4_frame*)buf;
    //unsigned short proto;
    if(len<sizeof(Sip4_frame))
        return -1;
    return (unsigned short)ipf->proto;
}
static int ip_filter_saddr(void *buff,size_t len ,void *value)
{
    Sip4_frame *uf=(Sip4_frame*)buff;
    if(len<sizeof(Sip4_frame) || !value)
        return 0;
    return ((*(uint32_t *)value)==uf->sip);
}

static int ip_filter_daddr(void *buff,size_t len ,void *value)
{
    Sip4_frame *uf=(Sip4_frame*)buff;
    
    if(len<sizeof(Sip4_frame) || !value)
        return 0;
    return ((*(uint32_t *)value)==uf->dip);
}
static int ip_filter_ttl(void *buff,size_t len ,void *value)
{
    Sip4_frame *uf=(Sip4_frame*)buff;
    if(len<sizeof(Sip4_frame) || !value)
        return 0;
    return ((*(unsigned char *)value)==uf->ttl);
}
static int ip_filter_len(void *buff,size_t len ,void *value)
{
    Sip4_frame *uf=(Sip4_frame*)buff;
    if(len<sizeof(Sip4_frame) || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->totallen);
}
static int ip_filter_csum(void *buff,size_t len ,void *value)
{
    return 0;
    /*
    Sip4_frame *uf=(Sip4_frame*)buff;
    if(len<sizeof(Sip4_frame) || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->totallen);
    */
}

#define ip4_version(vhl)  (unsigned char) (0xf0&(vhl)>>4)

#define ip4_hdrlen(vhl) (unsigned char) (0xf&(vhl))

static const char *ip4_protostr(unsigned char proto)
{
    switch(proto)
    {
        case 0x11:
            return "UDP";
        default:
            break;
    }
    return "Unknown Proto";
}

static void outputformat_header(protocolparser *_this,char *buff,size_t bufflen, char **outputstring, size_t *outputlen)
{
    Sip4_frame *ifr=(Sip4_frame*)buff;
    int rval;
    char src[34];
    char dst[34];
    unsigned char hdrlen;
    if(!outputlen || !*outputlen || !outputstring || !*outputstring)
        return;
    if(bufflen<sizeof(Sip4_frame))
    {
        _this->outputformat_dummy(_this,buff,bufflen,outputstring,outputlen);
        return;
    }
//    inet_ntop(AF_INET,&(ifr->sip),src,34);
//    inet_ntop(AF_INET,&(ifr->dip),dst,34);
    rval=snprintf
    (
        *outputstring,
        *outputlen,
        "IPv%hhu Hlen=%hhu DS_ECN=0x%02hhx len=0x%04hx id=0x%04hx FlagsFrags=0x%04hx TTL=%u %s(0x%02hhx) csum=0x%04hx %s ==> %s ",
        ip4_version(ifr->vhl),
        (hdrlen=ip4_hdrlen(ifr->vhl)),
        ifr->DS_ECN,
        ntohs(ifr->totallen),
        ntohs(ifr->id),
        ntohs(ifr->FlagsNFrags),
        ifr->ttl,
        ip4_protostr(ifr->proto),
        ifr->proto,
        ntohs(ifr->csum),
        inet_ntop(AF_INET,&(ifr->sip),src,34),
        inet_ntop(AF_INET,&(ifr->dip),dst,34)
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
        if( hdrlen-5 > 0 )
        {
            _this->outputformat_dummy(_this,buff+sizeof(Sip4_frame),(hdrlen-5)*4,outputstring,outputlen);
        }
    }
}




protocolparser_ip4 *init_protocolparser_ip4()
{
    protocolparser_ip4 *_this=calloc(1,sizeof(protocolparser_ip4));
    if(_this)
    {
        init_genparser(&_this->genparser);
        _this->genparser.proto=0x800; /* IPv4 */
        //_this->genparser.activate=&activate;
        _this->genparser.get_payload=&get_payload; //here we need our own
        _this->genparser.proto_get=&proto_get;
        _this->genparser.get_filter=&get_filter;
        _this->genparser.install_filter=&install_filter;
        _this->genparser.remove_filter=&remove_filter;
        _this->genparser.filter2val=&filter2val;
        _this->genparser.filter2num=&filter2num;
        _this->genparser.outputformat_header=&outputformat_header;
        _this->last_filter=IP4_FILTERS_AMNT;
        _this->filfunc[FILTERFUNC_IP4_DST_ADDR]=ip_filter_daddr;
        _this->filfunc[FILTERFUNC_IP4_SRC_ADDR]=ip_filter_saddr;
        _this->filfunc[FILTERFUNC_IP4_TTL]=ip_filter_ttl;
        _this->filfunc[FILTERFUNC_IP4_LEN]=ip_filter_len;
        _this->filfunc[FILTERFUNC_IP4_CSUM]=ip_filter_csum;
    }
    return _this;
}
