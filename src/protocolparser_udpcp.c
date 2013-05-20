
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

#include "protocolparser_udpcp.h"
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
    switch(filnum)
    {
        /* All UDP header vals are shorts */
        case FILTERFUNC_UDPCP_MSGTYPE:
        {
            char *val;
            if((val=malloc(1)))
            {
                if(!strncmp("data",filter,len))
                {
                    *val=0x40; 
                }
                else if(!strncmp("ack",filter,len))
                {
                    *val=0x80;
                }
                else
                {
                    free(val);
                    val=NULL;
                }
            }
            return val;
            break;
        }
        case FILTERFUNC_UDPCP_MSGID:
        case FILTERFUNC_UDPCP_DATALEN:
        case FILTERFUNC_UDPCP_CSUM:
        {
            char *endp;
            uint16_t *msgid;
            msgid=malloc(2);
            if(msgid)
            {
                *msgid=strtol(filter,&endp,0);
                if(!filter || (*endp && *endp != ' ' && *endp != '\n'))
                {
                    free(msgid);
                    return NULL;
                }
                *msgid=htons(*msgid);
            }
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
        if(!strncmp("type",*filter,4))
        {
            typelen=5;
            rval=0ULL;
        }
        else if(!strncmp("msgid",*filter,5))
        {
            typelen=6;
            rval=1ULL;
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
    int nlen=len-sizeof(Sudpcp_frame);
    Sudpcp_frame *ef=(Sudpcp_frame*)buff;
    *newlen=0;
    if(nlen<=0)
        return NULL;
    *newlen=nlen;
    return (((char *)(ef))+(len-nlen));
}
static proto_filter_func get_filter(struct protocolparser *_this_, unsigned long long int filter_type)
{
    protocolparser_udpcp *_this=(protocolparser_udpcp *)_this_;
    if(filter_type>=_this->last_filter)
        return NULL;
    else
        return *(proto_filter_func *)(((char *)_this)+offsetof(protocolparser_udpcp, filfunc[0])+sizeof(proto_filter_func)*filter_type);
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

static int udpcp_filter_msgtype(void *buff,size_t len ,void *value)
{
    Sudpcp_frame *uf=(Sudpcp_frame*)buff;
    
    if(len<sizeof(Sudpcp_frame) || !value)
        return 0;
    return ( (0xc0&uf->magicfield) == *(unsigned char *)value);
}
static int udpcp_filter_len(void *buff,size_t len ,void *value)
{
    Sudpcp_frame *uf=(Sudpcp_frame*)buff;
    if(len<6 || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->payload_len);
}
static int udpcp_filter_msgid(void *buff,size_t len ,void *value)
{
    Sudpcp_frame *uf=(Sudpcp_frame*)buff;
    if(len<6 || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->msgId);
}

static int udpcp_filter_csum(void *buff __attribute__((unused)) ,size_t len __attribute__((unused)) ,void *value __attribute__((unused)) )
{
    return 0;
    /*
    Sudp_frame *uf=(Sudp_frame*)buff;
    if(len<2 || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->sport);
    */
}
static char *msgtypestr(unsigned char magic)
{
    if((magic&0xc0)==0x80)
        return "ack";
    else if((magic&0xc0)==0x40)
        return "data";
    return "unknown";
}
static char *ackmodestr(unsigned char magic)
{
    if(!(magic&0x5))
        return "ack_all";
    else if( (!(magic&0x4)) && (magic&1))
        return "ack_last";
    else if((magic&0x4))
        return "ack_none";
    return "unknown";
}
static char *csuminusestr(unsigned char magic)
{
    if(magic&2)
        return "yes";
    return "no";
}
static void outputformat_header(protocolparser *_this,char *buff,size_t bufflen, char **outputstring, size_t *outputlen)
{
    Sudpcp_frame *uf=(Sudpcp_frame*)buff;
    int rval;
    if(!outputlen || !*outputlen || !outputstring || !*outputstring)
        return;
    if(bufflen<sizeof(Sudpcp_frame))
    {
        _this->outputformat_dummy(_this,buff,bufflen,outputstring,outputlen);
        return;
    }
    rval=snprintf
    (
        *outputstring,
        *outputlen,
        "UDPCP csum=0x%x msgtype=%s(%u%u) vers=%u ackmode=%s use_csum=%s %s reservedbits=0x%x fragamnt=%hu fragno=%hu msgid=0x04%hx payload_len=%hu ",
        ntohl(uf->checksum),
        msgtypestr(uf->magicfield),
        (unsigned int)((uf->magicfield&0x38)>>3),
        (unsigned int)((uf->magicfield&0x80)>>7),
        (unsigned int)((uf->magicfield&0x40)>>6),
        ackmodestr(uf->magicfield),
        csuminusestr(uf->magicfield),
        (uf->res&80)?"ack_packet":"data_packet",
        (unsigned int)((uf->res&0x7F)),
        (uf->fragAmnt),
        (uf->fragNo),
        uf->msgId,
        uf->payload_len
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
int data_looks_udpcp(protocolparser *_this,void *buff, size_t len)
{
    Sudpcp_frame *uf=(Sudpcp_frame *)buff;
    if(len<sizeof(Sudpcp_frame))
        return 0;
    if( (uf->magicfield&0xC0) != 0x80 && (uf->magicfield&0xC0) != 0x40)
        return 0;
    if( ((uf->magicfield&38)>>3) != 2)
        return 0;
    if((uf->res&0x7F))
        return 0;
    if(uf->fragNo>uf->fragAmnt)
        return 0;
    return 1;
}
static int evaluate(protocolparser *_this,void *buff, size_t len, uint32_t proto_from_parent,char *outputstring, size_t outputlen, int hl_matched)
{
    int rval=-5;
    size_t newsize;
    void *applpayload;
    
    if(data_looks_udpcp(_this,buff,len))
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




protocolparser_udpcp *init_protocolparser_udpcp()
{
    protocolparser_udpcp *_this=calloc(1,sizeof(protocolparser_udpcp));
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
        /* Overwrite evaluate with our own evaluate since genparser assumes that upper layer header contains our protocolnumber. This is not true with UDP and UDPCP */
        _this->genparser.evaluate=&evaluate;
        _this->last_filter=UDPCP_FILTERS_AMNT;
        _this->filfunc[FILTERFUNC_UDPCP_MSGTYPE]=udpcp_filter_msgtype;
        _this->filfunc[FILTERFUNC_UDPCP_MSGID]=udpcp_filter_msgid;
        _this->filfunc[FILTERFUNC_UDPCP_DATALEN]=udpcp_filter_len;
        _this->filfunc[FILTERFUNC_UDPCP_CSUM]=udpcp_filter_csum;
    }
    return _this;
}
