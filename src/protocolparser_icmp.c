
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

#include "protocolparser_icmp.h"
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
        case FILTERFUNC_ICMP_TYPE:
        case FILTERFUNC_ICMP_CODE:
        {
            unsigned char *vc;
            char *endp;
            vc=malloc(1);
            if(vc)
            {
                unsigned long tmp;
                tmp=strtol(filter,&endp,0);
                if(tmp>255 || !filter || (*endp && *endp != ' ' && *endp != '\n'))
                {
                    printf("error terror\n");
                    free(vc);
                    vc=NULL;
                }
                else
                    *vc=(unsigned char)tmp;
            }
            return vc;
        }
        case FILTERFUNC_ICMP_CSUM:
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
        case FILTERFUNC_ICMP_REST:
        {
            char *endp;
            uint32_t *v;
            v=malloc(sizeof(uint32_t));
            if(v)
            {
                *v=strtol(filter,&endp,0);
                if(!filter || (*endp && *endp != ' ' && *endp != '\n'))
                {
                    free(v);
                    v=NULL;
                }
                else
                    *v=htonl(*v);
            }
            return v;
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
        if(!strncmp("type",*filter,4))
        {
            typelen=5;
            rval=0ULL;
        }
        else if(!strncmp("code",*filter,4))
        {
            typelen=5;
            rval=1ULL;
        }
        else if(!strncmp("csum",*filter,4))
        {
            typelen=5;
            rval=2ULL;
        }
        else if(!strncmp("rest",*filter,4))
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
    int nlen=len-sizeof(Sicmp_frame);
    Sicmp_frame *ef=(Sicmp_frame*)buff;
    *newlen=0;
    if(nlen<=0)
        return NULL;
    *newlen=nlen;
    return (((char *)(ef))+(len-nlen));
}
static proto_filter_func get_filter(struct protocolparser *_this_, unsigned long long int filter_type)
{
    protocolparser_icmp *_this=(protocolparser_icmp *)_this_;
    if(filter_type>=_this->last_filter)
        return NULL;
    else
        return *(proto_filter_func *)(((char *)_this)+offsetof(protocolparser_icmp, filfunc[0])+sizeof(proto_filter_func)*filter_type);
}
static unsigned short proto_get(protocolparser *_this,void *buf, size_t len) 
{
    /*
    Seth_frame *ef=(Sicmp_frame*)buf;
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

static int icmp_filter_type(void *buff,size_t len ,void *value)
{
    Sicmp_frame *uf=(Sicmp_frame*)buff;
    
    if(len<sizeof(Sicmp_frame) || !value)
        return 0;
    return ((*(unsigned char *)value)==uf->type);
//    return !memcmp((((char *)buff)+2),value,2);
}
static int icmp_filter_code(void *buff,size_t len ,void *value)
{
    Sicmp_frame *uf=(Sicmp_frame*)buff;
    if(len<sizeof(Sicmp_frame) || !value)
        return 0;
    return ((*(unsigned char *)value)==uf->code);
}
static int icmp_filter_csum(void *buff,size_t len ,void *value)
{
    Sicmp_frame *uf=(Sicmp_frame*)buff;
    if(len<sizeof(Sicmp_frame) || !value)
        return 0;
    return ((*(unsigned short *)value)==uf->csum);
}


static int icmp_filter_rest(void *buff,size_t len ,void *value)
{
    Sicmp_frame *uf=(Sicmp_frame*)buff;
    if(len<sizeof(Sicmp_frame) || !value)
        return 0;
    return ((*(unsigned int *)value)==uf->rest);
}
const char *icmptype2str(unsigned char type)
{
    switch(type)
    {
        case 0:
            return "PONG";
            break;
        case 3:
            return "Destination Unreachable";
            break;
        case 4:
            return "Source Quench";
            break;
        case 5:
            return "Redirect Msg";
            break;
        case 6:
            return "Alternate Address";
            break;
        case 8:
            return "PING";
            break;
        case 9:
            return "Router Advert";
            break;
        case 10:
            return "Router Solictation";
            break;
        case 11:
            return "TTL";
            break;
        case 12:
            return "Bad Ip hdr";
            break;
        case 13:
            return "Timestamp";
            break;
        case 14:
            return "Timestamp Reply";
            break;
        case 15:
            return "Info Req";
            break;
        case 16:
            return "Info Resp";
            break;
        case 17:
            return "Addr Mask Req";
            break;
        case 18:
            return "Addr Mask Resp";
            break;
        case 19:
            return "Security";
            break;
        case 20:
        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
        case 27:
        case 28:
        case 29:
            return "Robustness";
            break;
        case 30:
            return "Tracert";
            break;
        case 31:
            return "Datagram conversion error";
            break;
        case 32:
            return "Mobile Host Redir";
            break;
        case 33:
            return "Where-Are-You";
            break;
        case 34:
            return "Here-I-Am";
            break;
        case 35:
            return "Mobile Registration Req";
            break;
        case 36:
            return "Mobile Registration Resp";
            break;
        case 37:
            return "DNS Req";
            break;
        case 38:
            return "DNS Resp";
            break;
        case 39:
            return "SKIP";
            break;
        case 40:
            return "Photuris";
            break;
        case 41:
            return "Experimental Mobility";
            break;
        default:
            break;
    }
    return "Unknown";
}
const char *icmpcode2str(unsigned char type, unsigned char code)
{
    switch(type)
    {
        case 0:
        case 1:
        case 2:
        case 4:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 13:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
        case 27:
        case 28:
        case 30:
        case 31:
        case 32:
        case 33:
        case 34:
        case 35:
        case 36:
        case 37:
        case 38:
        case 39:
        case 40:
        case 41:
            return "";
        case 3:
            switch(code)
            {
                case 0:
                    return "Destination Net Unreachable";
                case 1:
                    return "Destination Host Unreachable";
                case 2:
                    return "Destination Proto Unreachable";
                case 3:
                    return "Destination Port Unreachable";
                case 4:
                    return "Big but Can't Frag (DF flag)";
                case 5:
                    return "Source route failed";
                case 6:
                    return "Destination Net Unknown";
                case 7:
                    return "Destination Host Unknown";
                case 8:
                    return "Source Host Isolated";
                case 9:
                    return "Network Adminstratively Prohibited";
                case 10:
                    return "Host Adminstratively Prohibited";
                case 11:
                    return "Net Unreachable for TOS";
                case 12:
                    return "Host Unreachable for TOS";
                case 13:
                    return "Communication Adminstratively Prohibited";
                case 14:
                    return "Host Precedence Violation";
                case 15:
                    return "Precedence cutoff in effect";
                default:
                    return "UNKNOWN";
            }
        case 5:
            switch(code)
            {
                case 0:
                    return "Redir Datagram for the Net";
                case 1:
                    return "Redir Datagram for the Host";
                case 2:
                    return "Redir Datagram for TOS&Net";
                case 3:
                    return "Redir Datagram for TOS&Host";
                default:
                    return "UNKNOWN";
            }
        case 11:
            switch(code)
            {
                case 0:
                    return "TTL expired";
                case 1:
                    return "Fragment Reassembly time exceeded";
                default:
                    return "UNKNOWN";
            }
        case 12:
            switch(code)
            {
                case 0:
                    return "Pointer indicates the error";
                case 1:
                    return "Missing a required option";
                case 2:
                    return "Bad Lenght";
                default:
                    return "UNKNOWN";
            }
        default:
            break;
    }
    return "Unknown";
}
static void outputformat_header(protocolparser *_this,char *buff,size_t bufflen, char **outputstring, size_t *outputlen)
{
    Sicmp_frame *uf=(Sicmp_frame*)buff;
    int rval;
    if(!outputlen || !*outputlen || !outputstring || !*outputstring)
        return;
    if(bufflen<sizeof(Sicmp_frame))
    {
        _this->outputformat_dummy(_this,buff,bufflen,outputstring,outputlen);
        return;
    }
    rval=snprintf
    (
        *outputstring,
        *outputlen,
        "ICMP type=%s(0x%hhx) code=%s(0x%hhx) csum=0x%04hx rest=0x%08x ",
        icmptype2str(uf->type),
        uf->type,
        icmpcode2str(uf->type,uf->code),
        uf->code,
        ntohs(uf->csum),
        (unsigned int)ntohl(uf->rest)
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




protocolparser_icmp *init_protocolparser_icmp()
{
    protocolparser_icmp *_this=calloc(1,sizeof(protocolparser_icmp));
    if(_this)
    {
        init_genparser(&_this->genparser);
        _this->genparser.proto=0x1; /* ICMP proto */
//        _this->genparser.activate=&activate;
        _this->genparser.get_payload=&get_payload; //here we need our own
        _this->genparser.proto_get=&proto_get;
        _this->genparser.get_filter=&get_filter;
        _this->genparser.install_filter=&install_filter;
        _this->genparser.remove_filter=&remove_filter;
        _this->genparser.filter2val=&filter2val;
        _this->genparser.filter2num=&filter2num;
        _this->genparser.outputformat_header=&outputformat_header;
        _this->last_filter=ICMP_FILTERS_AMNT;
        _this->filfunc[FILTERFUNC_ICMP_TYPE]=icmp_filter_type;
        _this->filfunc[FILTERFUNC_ICMP_CODE]=icmp_filter_code;
        _this->filfunc[FILTERFUNC_ICMP_REST]=icmp_filter_rest;
        _this->filfunc[FILTERFUNC_ICMP_CSUM]=icmp_filter_csum;
    }
    return _this;
}
