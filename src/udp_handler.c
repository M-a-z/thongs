
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

#ifndef _GNU_SOURCE
    #define  _GNU_SOURCE
#endif
#include "udp_handler.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "common.h"
#include <net/if.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <sys/time.h>
#include "pcap_ng_structs.h"

static int prepare_socket(int ifindex, int protocol);

static int start_sockets(udp_handler *_this)
{
    int ifindex=0;
    if(_this->ifname)
        if(!(ifindex=if_nametoindex(_this->ifname)))
        {
            DEBUGPR("Failed to get ifindex for if %s (%s)\n",_this->ifname,strerror(errno));
            DEBUGPR("=> listening all ionterfaces\n");
        }
    if(0>=(_this->sock=prepare_socket(ifindex,_this->protocol)))
    {
        DEBUGPR("Failed to create socket\n");
        return -1;
    }
    return 0;
}


static int prepare_socket(int ifindex, int protocol)
{
    int sock;
//    struct sockaddr_in addr;
    struct sockaddr_ll addr_ll;
    
    
    sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(0>sock)
    {
        EARLY_DBGPR("Failed to open socket\n");
        EARLY_DBGPR("%s\n",strerror(errno));
        return -1;
    }
    if(ifindex || protocol)
    {
        memset(&addr_ll,0,sizeof(addr_ll));

        /* ARP, IP? */
        addr_ll.sll_family=AF_PACKET;
        addr_ll.sll_protocol=protocol;
        addr_ll.sll_ifindex=ifindex;
        DEBUGPR("Attempting to bind proto %d ifindex %d\n",protocol,ifindex);
        if(bind(sock,(const struct sockaddr *)&addr_ll,sizeof(addr_ll)))
        {
            EARLY_DBGPR("bind FAILED! %s\n",strerror(errno));
            close(sock);
            return -1;
        }
        DEBUGPR("Binding succeeded\n");
    }
    DEBUGPR("successfully created socket %d\n",sock);
    return sock;
}



static int waitdata(udp_handler *_this)
{
    int retval;

    FD_ZERO(&(_this->rfds));

    FD_SET(_this->sock, &(_this->rfds));
    VERBOSE_DEBUGPR("falling in select\n");
reselect:
    retval = select(_this->sock+1, &(_this->rfds), NULL, NULL, NULL);
    fflush(G_logfile);
    VERBOSE_DEBUGPR("select returned %d\n",retval);
    if (retval == -1)
    {
        if(errno == EINTR)
            goto reselect;
        if(errno == EAGAIN)
            goto reselect;
        else
            DEBUGPR("select FAILED! (%s)\n",strerror(errno));
        return -1;
    }
    return 0;
}

static int read_bs(udp_handler *_this,protocolparser *protofilter )
{
    static int gtmodalreadyfailed=0;
    int readsocks=0;
    //int i;
    int rcvd;
    int retval=0;
    char rcvbuff[1500];
    //time_t tim;

    if(FD_ISSET(_this->sock, &(_this->rfds)))
    {
        readsocks++;

rerecv:
        if(0>(rcvd=recv(_this->sock,rcvbuff,1500,0)))
        {
            int err=errno;
            if(EINTR!=err)
            {
                DEBUGPR("Recv error! %s\n", strerror(err)); 
                retval=_this->sock;
            }
            else
                goto rerecv;

        }
        else if(rcvd)
        {
            char *wrpoint;
            SPcapNgEnchancedPacketBlock *pkgstart;
            int filewrbs;
            int freespace=0;
            int paddingneed=0;

                    
            if(protofilter && ! protofilter->evaluate(protofilter,rcvbuff,rcvd,0,NULL /* no output string needed => NULL buff */,0/* no output needed => output buff size zero */,0))
            {
                /* filter set and not matched => ignore */
                DEBUGPR("Dropping package not matching filter.\n");
            //    _this->bufferhandler->update_writepoint(_this->bufferhandler,wrpoint,0,&filewrbs);
                return retval;
            }

            switch(rcvd%4)
            {
                case 0:
                    break;
                case 1:
                    rcvbuff[rcvd+paddingneed]=0;
                    paddingneed++;
                case 2:
                    rcvbuff[rcvd+paddingneed]=0;
                    paddingneed++;
                case 3:
                    rcvbuff[rcvd+paddingneed]=0;
                    paddingneed++;
                    break;
                default:
                    break;
            }

            wrpoint=_this->bufferhandler->get_writepoint(_this->bufferhandler,&freespace);
            if(!wrpoint)
            {
                DEBUGPR("Wituiks män!\n");
                out(-1);
            }
            if(freespace<rcvd+PCAP_NG_HEADERSPACE+paddingneed)
            {
                DEBUGPR("Dropping package - cannot write that long data\n");
                _this->bufferhandler->update_writepoint(_this->bufferhandler,wrpoint,0,&filewrbs);
            }
            else
            {
                pkgstart=(SPcapNgEnchancedPacketBlock *)wrpoint;
                pkgstart->block_type=6;
                pkgstart->block_total_len=rcvd+PCAP_NG_HEADERSPACE_EXT+paddingneed;
                pkgstart->interface_id=0;
                struct timeval tv;
                if(gettimeofday(&tv, NULL))
                {
                    if(!gtmodalreadyfailed)
                    {
                        DEBUGPR("Failed to gettime (%s)\n",strerror(errno));
                        gtmodalreadyfailed=1;
                    }
                }
                else
                {
                    uint64_t tmp;
                    tmp=(uint64_t)tv.tv_usec+(uint64_t)1000000*(uint64_t)tv.tv_sec;
                    pkgstart->timestamp_hi=(uint32_t)((0xFFFFFFFF00000000ULL&tmp)>>32);
                    pkgstart->timestamp_lo=(uint32_t)(0xFFFFFFFFULL&tmp);
                }
                pkgstart->cap_len=pkgstart->packet_len=rcvd;
                memcpy(wrpoint+sizeof(SPcapNgEnchancedPacketBlock),rcvbuff,rcvd+paddingneed);
                memcpy(wrpoint+sizeof(SPcapNgEnchancedPacketBlock)+rcvd+paddingneed,&pkgstart->block_total_len,sizeof(uint32_t));
                _this->bufferhandler->update_writepoint(_this->bufferhandler,wrpoint,rcvd+PCAP_NG_HEADERSPACE_EXT+paddingneed,&filewrbs);
            }

        }
        else
            perror("rcvd returned 0!\n");       
    }
    return retval;
}

void prepare_printbuffer(udp_handler *_this,printptrhandler *bhandler)
{
    _this->bufferhandler=bhandler;
}
void identify_protocol(udp_handler *_this,char *proto)
{
    int protolen;
    if(!proto)
        return;
    protolen=strlen(proto);
    if(protolen>=3)
    {
        uint32_t *tmp=(uint32_t *)proto;
        if(*tmp==*(uint32_t *)"ip4")
            _this->protocol=htons(ETH_P_IP);
        else if(*tmp==*(uint32_t *)"ip6")
            _this->protocol=htons(ETH_P_IPV6);
        else if(*tmp==*(uint32_t *)"arp")
            _this->protocol=htons(ETH_P_ARP);
        else if(!strcmp(proto,"vlan"))
            _this->protocol=htons(ETH_P_8021Q);
#ifdef ETH_P_PAUSE
        else if(!strcmp(proto,"pause"))
            _this->protocol=htons(ETH_P_PAUSE);
#endif
        else
            DEBUGPR("Unknown protocol (%s)!\n",proto);
    }
}

static int read_portcfgfile(udp_handler *_this,FILE *cf)
{
    int rval;
    char *line;
    if(_this->protocol && _this->ifname)
        return 0;
    rewind(cf);
    DEBUGPR("Searching protocol/ifname from cfg file\n");
    while(1)
    {
        int found=0;
        if(!_this->protocol)
            if(1==(rval=fscanf(cf,"protocol=%a[^\n]\n",&line)))
            {
                found=1;
                DEBUGPR("Detected protocol from config file (%s)\n",line);
                identify_protocol(_this,line);
                DEBUGPR("proto set to %d\n",_this->protocol);
                free(line);
            }
        if(!_this->ifname)
            if(1==(rval=fscanf(cf,"ifname=%a[^\n]\n",&line)))
            {
                found=1;
                DEBUGPR("Detected ifname rom config file (%s)\n",line);
                _this->ifname=line;
            }

        if(EOF == rval || ( !found && (rval=fscanf(cf,"%*a[^\n]\n"))))
        {
            break;
        }
    }

    return 0;
}

udp_handler *init_udphandler()
{
    udp_handler *_this=calloc(1,sizeof(udp_handler));
    if(_this)
    {
        memset(_this,0,sizeof(udp_handler));
        _this->waitdata=&waitdata;
        _this->read_bs=&read_bs;
        _this->prepare_printbuffer=&prepare_printbuffer;
//        _this->add_port=&add_port;
        //_this->get_portamnt=&get_portamnt;
        _this->start_sockets=&start_sockets;
        _this->read_portcfgfile=&read_portcfgfile;
    }
    return _this;
}

