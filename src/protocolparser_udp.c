
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

#include "protocolparser_udp.h"
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
    unsigned short *val=NULL;
    switch(filnum)
    {
        /* All UDP header vals are shorts */
        case FILTERFUNC_UDP_DST_PORT:
        case FILTERFUNC_UDP_SRC_PORT:
        case FILTERFUNC_UDP_LEN:
        case FILTERFUNC_UDP_CSUM:
        {
            char *endp;
            val=malloc(sizeof(unsigned short));
            if(val)
            {
                *val=strtol(filter,&endp,0);
                if(!filter || (*endp && *endp != ' ' && *endp != '\n'))
                {
                    free(val);
                    return NULL;
                }
                *val=htons(*val);
            }
            break;
        }
        default:
            break;
    }
    return val;
}
static unsigned long long int filter2num(protocolparser *_this,char **filter, size_t *len)
{
    unsigned long long rval = -1LL;
    int typelen=0;
    if(len)
    {
        if(!strncmp("sport",*filter,5))
        {
            typelen=6;
            rval=1ULL;
        }
        else if(!strncmp("dport",*filter,5))
        {
            typelen=6;
            rval=0ULL;
        }
        else if(!strncmp("len",*filter,3))
        {
            typelen=4;
            rval=2ULL;
        }
        else if(!strncmp("csum",*filter,4))
        {
            typelen=5;
            rval=3ULL;
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
    int nlen=len-sizeof(Sudp_frame);
    Sudp_frame *ef=(Sudp_frame*)buff;
    *newlen=0;
    if(nlen<=0)
        return NULL;
    *newlen=nlen;
    return (((char *)(ef))+(len-nlen));
}
static proto_filter_func get_filter(struct protocolparser *_this_, unsigned long long int filter_type)
{
    protocolparser_udp *_this=(protocolparser_udp *)_this_;
    if(filter_type>=_this->last_filter)
        return NULL;
    else
        return *(proto_filter_func *)(((char *)_this)+offsetof(protocolparser_udp, filfunc[0])+sizeof(proto_filter_func)*filter_type);
}
static unsigned short proto_get(protocolparser *_this,void *buf, size_t len) 
{
    /*
    Seth_frame *ef=(Sudp_frame*)buf;
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
    */
    return 0; // there is no knowledge about contained protocol...
}

static int udp_filter_dport(void *buff,size_t len ,void *value)
{
    Sudp_frame *uf=(Sudp_frame*)buff;
    
    if(len<4 || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->dport);
//    return !memcmp((((char *)buff)+2),value,2);
}
static int udp_filter_len(void *buff,size_t len ,void *value)
{
    Sudp_frame *uf=(Sudp_frame*)buff;
    if(len<6 || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->len);
}
static int udp_filter_csum(void *buff,size_t len ,void *value)
{
    Sudp_frame *uf=(Sudp_frame*)buff;
    if(len<6 || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->len);
}


static int udp_filter_sport(void *buff,size_t len ,void *value)
{
    Sudp_frame *uf=(Sudp_frame*)buff;
    if(len<2 || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->sport);
}

static void outputformat_header(protocolparser *_this,char *buff,size_t bufflen, char **outputstring, size_t *outputlen)
{
    Sudp_frame *uf=(Sudp_frame*)buff;
    int rval;
    if(!outputlen || !*outputlen || !outputstring || !*outputstring)
        return;
    if(bufflen<sizeof(Sudp_frame))
    {
        _this->outputformat_dummy(_this,buff,bufflen,outputstring,outputlen);
        return;
    }
    rval=snprintf
    (
        *outputstring,
        *outputlen,
        "UDP sport=%hu dport=%hu len=%hu csum=0x%04hx ",
        
        ntohs(uf->sport),
        ntohs(uf->dport),
        ntohs(uf->len),
        ntohs(uf->csum)
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




protocolparser_udp *init_protocolparser_udp()
{
    protocolparser_udp *_this=calloc(1,sizeof(protocolparser_udp));
    if(_this)
    {
        init_genparser(&_this->genparser);
        _this->genparser.proto=0x11; /* UDP proto */
//        _this->genparser.activate=&activate;
        _this->genparser.get_payload=&get_payload; //here we need our own
        _this->genparser.proto_get=&proto_get;
        _this->genparser.get_filter=&get_filter;
        _this->genparser.install_filter=&install_filter;
        _this->genparser.remove_filter=&remove_filter;
        _this->genparser.filter2val=&filter2val;
        _this->genparser.filter2num=&filter2num;
        _this->genparser.outputformat_header=&outputformat_header;
        _this->last_filter=UDP_FILTERS_AMNT;
        _this->filfunc[FILTERFUNC_UDP_DST_PORT]=udp_filter_sport;
        _this->filfunc[FILTERFUNC_UDP_SRC_PORT]=udp_filter_dport;
        _this->filfunc[FILTERFUNC_UDP_LEN]=udp_filter_len;
        _this->filfunc[FILTERFUNC_UDP_CSUM]=udp_filter_csum;
    }
    return _this;
}
