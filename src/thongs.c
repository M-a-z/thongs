
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
#include <ncurses.h>
#include <panel.h>
#include "syscomform.h"
#include "displayhandler.h"
#include "common.h"
#include "stringfilters.h"
#include "bshandler.h"
#include "udp_handler.h"
#include <getopt.h>
#include <unistd.h>
#include <sched.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <net/if.h>
#include <pthread.h>
#include "cexplode.h"
#include <signal.h>
#include "tgt_commander.h"
#include "shitemsgparser.h"
#include "msgloadermenu.h"
#include "pcap_ng_structs.h"
#include "protocolparser_ethernet.h"
#include "protocolparser_ip4.h"
#include "protocolparser_udp.h"
#include "protocolparser_udpcp.h"
#include "protocolparser_arp.h"
#include "protocolparser_icmp.h"

#define IP4_PARENT_PROTO_AMNT 1
#define UDP_PARENT_PROTO_AMNT 1

#define LINE_MAX_LEN 5000
extern void identify_protocol(udp_handler *_this,char *proto);

/* We use fscanf specifier %a (to make fscanf allocate space for read string) which is gnu extension */

protocolparser *G_eth_parser = NULL;
protocolparser *G_ip4_parser = NULL;
protocolparser *G_icmp_parser = NULL;
protocolparser *G_udp_parser = NULL;
protocolparser *G_udpcp_parser = NULL;
protocolparser *G_arp_parser = NULL;

static int filter_before_file=0;


static struct option long_options[] =
{
    {"config", required_argument,  0, 'c'},
    {"debug", required_argument,  0, 'd'},
    {"editor",  required_argument, 0, 'e'},
    {"earlyfilter", no_argument, 0, 'E'},
    {"file" , required_argument, 0, 'f'},
    {"protocol" , required_argument, 0, 'p'},
    {"interface" , required_argument, 0, 'i'},
    {"version",  no_argument, 0, 'v'},
    {"help",  no_argument, 0, 'h'},
    {0,0,0,0}
};




typedef struct user_commands
{
    int pause;
    int end;
    int show_help;
    int show_form;
    int scroll_mode;
    char *editor;
    int scrollcmd;
}user_commands;



#define NEXTBSD(bsd) ((rcvprints *) (((char *)(bsd)) + (((rcvprints*)(bsd))->datasize) ))
//+ (ALIGN_SIZE-(((rcvprints*)(bsd))->datasize)%ALIGN_SIZE) ))


//static void * start_editor(void *params) __attribute__((unused));

pthread_mutex_t G_condmutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t G_cond=PTHREAD_COND_INITIALIZER;

static int G_NOFILTERS=0;
FILE *G_logfile=NULL;

int G_USE_FILE=0;
char G_CURRENT_UDP_FILE_NAME[1024];
//FILE *G_outfile=NULL;

static char *G_exename;
pthread_t G_tid=0;
int G_filewriter_running=0;
int G_bs1_wrsize=0;
int G_bs2_wrsize=0;
int G_bs1filewrneeded=0;
int G_bs2filewrneeded=0;

static void print_usage()
{
    EARLY_DBGPR("\nUsage:\n\n\n");
    EARLY_DBGPR("%s <options>\n\n",G_exename);
    EARLY_DBGPR(HELP_PRINT);
}

void *UDPreaderthread(void *arg)
{
    /* do UDP reading here */
    udp_handler *hand=(udp_handler *)arg;
    pthread_cleanup_push(&udp_file_flush,arg);
    
    signal(SIGTERM,&out);
    signal(SIGINT,&out);
    signal(SIGSTOP,SIG_IGN);
    while(1)
    {
        int bsfail=0;
        if(hand->waitdata(hand))
        {
            DEBUGPR("something went vituiksi\n");
            return NULL;
        }
        if((bsfail=hand->read_bs(hand,(filter_before_file)?G_eth_parser:NULL)))
        {
            DEBUGPR("UDPreader - read_bs FAILED %d!\n",bsfail);
            continue;
        }
    }
    pthread_cleanup_pop(1);
    return NULL;
}
typedef struct editorthreadparam{ int *mode; char *editor; char *logname; sdisplayhandler *dh;}editorthreadparam;

static void * start_editor(void *params)
{
    char command[1000];
    editorthreadparam *p=(editorthreadparam*)params;
    snprintf(command,999,"%s '%s'",p->editor,p->logname);
    DEBUGPR("executing editor command %s\n",command);
    command[999]='\0';
    endwin();
    system(command);
	cbreak();
	keypad(stdscr, TRUE);		/* I need that nifty F1 	*/
    update_panels();
    doupdate();
    timeout(10);
    noecho();
    //p->dh->magic(p->dh);
    *(p->mode)=0;
    free(p);
    return NULL;
}

static protocolparser *get_parser_by_proto(char **proto,size_t *len)
{
    protocolparser *p=NULL;
    if(*len>3)
    {
        if(!strncmp("eth",*proto,3))
        {
            p=G_eth_parser;
            *len-=4;
            *proto=(*proto+4);
        }
        else if(!strncmp("ip4",*proto,3))
        {
            p=G_ip4_parser;
            *len-=4;
            *proto=(*proto+4);
        }
        else if(!strncmp("udpcp",*proto,5))
        {
            p=G_udpcp_parser;
            *len-=6;
            *proto=(*proto+6);
        }
        else if(!strncmp("udp",*proto,3))
        {
            p=G_udp_parser;
            *len-=4;
            *proto=(*proto+4);
        }
        else if(!strncmp("icmp",*proto,4))
        {
            p=G_icmp_parser;
            *len-=5;
            *proto=(*proto+5);
        }
        else if(!strncmp("arp",*proto,3))
        {
            p=G_arp_parser;
            *len-=4;
            *proto=(*proto+4);
        }
    }
    return p;
}

static void remove_protocol_hl(char *proto,size_t len)
{
    protocolparser *parser;
    if((parser=get_parser_by_proto(&proto,&len)))
    {
        parser->remove_filter(parser,proto,len);
    }
}
static void add_protocol_hl(char *proto,size_t len)
{
    protocolparser *parser;
    if((parser=get_parser_by_proto(&proto,&len)))
    {
        parser->install_filter(parser,proto,len);
    }
}


static void handle_char(int ch,stringfilter *filters,sdisplayhandler *displayhandler,char *filterstring,unsigned *filterindex,user_commands *uc,tgt_commander *commander,smsgloader *scommenu,shitemsgparser *sp,printptrhandler *bhandler)
{
    editorthreadparam *parm;
    //int fsp=0;
    pthread_attr_t attr;

    if(uc->pause)
    {
        switch(ch)
        {
            case PAUSECHAR:
                goto pausechar;
                break;
            case ENDCHAR:
                goto endchar;
                break;
            case KEY_UP:
                uc->scrollcmd=KEY_UP;
                break;
            case KEY_DOWN:
                uc->scrollcmd=KEY_DOWN;
                break;
        }
    }
    else if(uc->scroll_mode)
    {
         return;
    }
    else
        switch(ch)
        {
            case SCROLLCHAR:
            {
                parm=malloc(sizeof(editorthreadparam));
                if(!parm)
                    break;
                if(!G_USE_FILE)
                    break;
                pthread_t tid;
                parm->dh=displayhandler;
                parm->mode=&(uc->scroll_mode);
                parm->editor=uc->editor;
                parm->logname=G_CURRENT_UDP_FILE_NAME;
                uc->scroll_mode=1;

                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);

                if( pthread_create(&tid,&attr,start_editor,parm))
                {
                    DEBUGPR("Failed to launch scroller thread!\n");
                    uc->scroll_mode=0;
                }
                pthread_attr_destroy(&attr);
                break;
            }
            case ENDCHAR:
        //case ENDCHAR2:
endchar:
                uc->end=1;
                break;
            case PAUSECHAR:
pausechar:
                DEBUGPR("Toggling pause %d->%d\n",uc->pause,!uc->pause);
                uc->pause=!uc->pause;
                filters->set_paused(filters,uc->pause);
                bhandler->toggle_scrollmode(bhandler,uc->pause);
                break;
            case FSTR_TOGGLE_CHAR:
                displayhandler->toggle_fstr(displayhandler);
                break;
            case DEFFIND_TOGGLE_CHAR:
                displayhandler->toggle_deffind(displayhandler);
                break;
            case HELPCHAR:
                displayhandler->toggle_help(displayhandler);
                break;
            case ERR:
                break;
            case SCOMMENU_TOGGLE_CHAR:
                displayhandler->toggle_scommenu(displayhandler);
                break;
            case FORM_TOGGLE_CHAR:
                displayhandler->toggle_scom(displayhandler);
                break;
/*            case FORM_SEND_FSP_CHAR:
                fsp=1;
*/
            case FORM_SEND_FCM_CHAR:
            {
                char ifname[IFNAMSIZ+1];
                void *msg;
                uint32_t msglen;
                char *nameptr=&(ifname[0]);
                if(!displayhandler->in_syscommode(displayhandler))
                    break;
                msg=displayhandler->get_built_msg(displayhandler,&msglen,&nameptr);
                if(!msg)
                {
                    DEBUGPR("Could not fetch built msg!\n");
                    break;
                }
                else if(commander)
                    commander->send_msg(commander,msg,msglen,ifname);
            }
            break;
            case 10:
            case KEY_ENTER:
            {
                if(displayhandler->scommenuontop(displayhandler))
                {
                    displayhandler->formhandler->fillform(displayhandler->formhandler,sp,scommenu->get_selected_hidden(scommenu));
                    ungetch(KEY_F(3));
                    break;
                }

                werase(displayhandler->filter_win);
                if(!strcmp(filterstring,"C"))
                {
                    displayhandler->clearlog(displayhandler);
                }
                /*
                if(commander)
                {
                    if(filterstring[0]==COMMAND_STARTCHAR)
                    {
                        goto clear_filterstring;
                        break;
                    }
                }
                */
                if(G_eth_parser)
                {
                    size_t len=strlen(filterstring);
                    if(len>5)
                    {
                        if(filterstring[0]=='<')
                        {
                            remove_protocol_hl(&filterstring[2],len-2);
                        }
                        else if(filterstring[0]=='>')
                        {
                            add_protocol_hl(&filterstring[2],len-2);
                        }
                    }
                }
                if(G_NOFILTERS)
                    break;
                DEBUGPR("adding filter!\n");
                filters->add(filters, filterstring);

//clear_filterstring:
                *filterindex=0;
                filterstring[0]=filterstring[1]='\0',filterstring[2]='\0',filterstring[3]='\0';
                break;
                /* apply filters */
            }
            default:
                if(displayhandler->scommenuontop(displayhandler))
                {
                    scommenu->handle_char(scommenu,ch);
                    break;
                }
                if(displayhandler->in_syscommode(displayhandler) || displayhandler->in_deffindmode(displayhandler))
                {
                    displayhandler->handle_char(displayhandler,ch);
                    break;
                }
                if(G_NOFILTERS)
                    break;
                /* add characters to filter */
                if(ch==KEY_BACKSPACE)
                {
                    DEBUGPR("Backspace detected\n");
                    if(*filterindex)
                    {    
                        filterstring[*filterindex-1]='\0';
                        *filterindex=(*filterindex)-1;
                        wmove(displayhandler->filter_win,0,*filterindex);
                        wclrtoeol(displayhandler->filter_win);
                    }
                }
                else
                {
                    if(*filterindex<1024)
                        (*filterindex)++;
                
                    filterstring[*filterindex-1]=ch;
                    filterstring[*filterindex]='\0';
                    DEBUGPR("Added char '%c' (%d) to filterstring '%s' - index %d\n",(char)ch,ch,filterstring,*filterindex-1);
                    wprintw(displayhandler->filter_win,"%c",ch);
                }
        }

}


//static struct protocolparser *Gactive_parsers[PROTO_PARSER_MAX_AMOUNT]={NULL};

static void display_udpdata(stringfilter *filters,sdisplayhandler *displayhandler,printptrhandler *bufferhandler,user_commands *uc)
{
    int size;
    char *blockstart;
    unsigned linesize;
    char line[LINE_MAX_LEN+1];
    SPcapNgEnchancedPacketBlock *pkgstart;
    //int hl;
    int i;
//    int blockread;
    char * (*blockfetchfunc)(struct printptrhandler *_this,int *size);
    int y,x;
    /* Actually this is screen size */
    unsigned lines;
    int ctr;
    

    if(uc->pause)
    {
        if(!uc->scrollcmd)
            return;
        /* This makes bufferhandler to count lines chars in scrollcmd direction and return a block that fits on screen judging this info */
        getmaxyx(displayhandler->logwin,y,x);
        /* Actually this is screen size */
        lines=y*x;
        VERBOSE_DEBUGPR("Using screen size = 0x%x\n",lines);
        bufferhandler->scroll_set_offset_block(bufferhandler,lines,uc->scrollcmd);
        uc->scrollcmd=0;
        blockfetchfunc=bufferhandler->scroll_get_offset_block;
        wclear(displayhandler->logwin);
    }
    else
        blockfetchfunc=bufferhandler->get_next_readable;

    while((blockstart=(*blockfetchfunc)(bufferhandler,&size)))
    {
  //      char lines_hl_hackwar[1024];
        int max_for_this_line=LINE_MAX_LEN;
        int lineindex=0;
        int hl=0;
        //int linectr=0;
        unsigned char *pkgptr;
//        memset(lines_hl_hackwar,0,sizeof(lines_hl_hackwar));
        pkgstart=(SPcapNgEnchancedPacketBlock *)blockstart;
        lineindex=snprintf(line,max_for_this_line,"<%llu>: ",*((unsigned long long int*)&(pkgstart->timestamp_hi)));
        if(max_for_this_line<lineindex)
            continue;
        if(size<pkgstart->cap_len+sizeof(SPcapNgEnchancedPacketBlock))
            continue;
        if(G_eth_parser)
        {
            hl=G_eth_parser->evaluate(G_eth_parser,(((unsigned char *)&(pkgstart->packet_len))+4),pkgstart->cap_len,/* proto from parent */0,line,LINE_MAX_LEN-lineindex,0 /*hl_matched*/);
            line[LINE_MAX_LEN]='\0';
            linesize=strlen(line);
        }
        else
        {
            for(ctr=0,pkgptr=(((unsigned char *)&(pkgstart->packet_len))+4);ctr<pkgstart->cap_len;ctr++)
            {
                unsigned tmp;
                tmp=snprintf(line+lineindex,LINE_MAX_LEN-lineindex,"%02x ",(unsigned)*pkgptr);
                pkgptr++;
                if(tmp>LINE_MAX_LEN-lineindex)
                {
                    line[LINE_MAX_LEN]='\0';
                    line[LINE_MAX_LEN-1]=line[LINE_MAX_LEN-2]=line[LINE_MAX_LEN-3]='.';
                    break;
                }
                lineindex+=tmp;
            }
            linesize=lineindex;
        }
        /*
        if(hl)
        {
            if(LINE_MAX_LEN>lineindex)
                *(line+lineindex)=0x7;
            lineindex++;
        }*/
//            snprintf(line+lineindex,LINE_MAX_LEN-lineindex,"%02x ",(unsigned)*pkgptr);
        /* TODO: Create protocol aware filters */
        if(!filters->filter(filters,line,linesize))
        {
            if(!filters->filter(filters,line,linesize))
            {
                if(hl||(hl=filters->hl(filters,line,linesize)))
                    displayhandler->log_start_hl(displayhandler);
                for(i=0;i<linesize;i++)
                    waddch(displayhandler->logwin,line[i]);
                if(line[i-1]!='\n')
                    waddch(displayhandler->logwin,'\n');
                if(hl)
                    displayhandler->log_end_hl(displayhandler);
                //hl=0;
            }
        }
    }
}
static int argchk(char *arg, unsigned long int lower, unsigned int upper, unsigned long int *value)
{
    char *chkptr;
    unsigned long int retval = 0;
    *value=0;
    if(NULL==arg)
    {
        EARLY_DBGPR("Non numeric arg!\n");
        return -1;
    }
    retval=strtoul(arg,&chkptr,0);
    if(*chkptr!='\0')
    {
        EARLY_DBGPR("Non numeric arg!\n");
        return -1;
    }
    if(retval>upper || retval < lower)
    {
        EARLY_DBGPR("Value %lx not in allowed range!\n",retval);
        return -1;
    }
    *value=retval;
    return 0;

}
/* I should have written scan_string() in same fashion the scan_uint and scan_ip are done... */
static void ucs_from_cfgfile(FILE *cf,user_commands *uc)
{
     char *line;
    int rval;
    unsigned nline=0;
    rewind(cf);
    DEBUGPR("Searching editor name from cfg file\n");

    while(1)
    {
        if(1==(rval=fscanf(cf,"editor=%a[^\n]\n",&line)))
        {
            nline++;
            DEBUGPR("editor %s found from cfg file line %u\n",line,nline);
            if(!uc->editor)
                uc->editor = line;
            break;
        }
        else if(EOF==rval || rval < 0)
            break;
        else if(!(rval=fscanf(cf,"%*a[^\n]\n")))
        {
            nline++;
        }
        else
            break;
    }
}
static void udplog_from_cfgfile(FILE *cf,fileargs *farg)
{
    char *line;
    //unsigned val;
    int rval;
    unsigned nline=0;
    rewind(cf);
    DEBUGPR("Searching udplog name from cfg file\n");

    while(1)
    {
        if(1==(rval=fscanf(cf,"capturefile=%a[^\n]\n",&line)))
        {
            nline++;
            DEBUGPR("capturefile %s found from cfg file line %u\n",line,nline);
            if(!farg->filebasename)
               farg->filebasename = line;
            continue;
        }
        else if(EOF==rval || rval < 0)
            break;
        else if(!(rval=fscanf(cf,"%*a[^\n]\n")))
        {
            nline++;
        }
        else
            break;
    }
    //return NULL;
}

static int filters_from_cfgfile(stringfilter *filters,FILE *cf)
{
    int rval;
    char *filter;
    unsigned nline=0;
    rewind(cf);
    DEBUGPR("Searching filters from cfg file\n");

    while(1)
    {
        if(1==(rval=fscanf(cf,"filter=%a[^\n]\n",&filter)))
        {
            nline++;
            DEBUGPR("Filter string %s found from cfg file line %u\n",filter,nline);
            if(filters->add(filters,filter))
            {
                DEBUGPR("Failed to add filter '%s' from cfgfile line %d\n",filter,nline);
                return -1;
            }
        }
        else if(EOF==rval)
            break;
        else if(!(rval=fscanf(cf,"%*a[^\n]\n")))
        {
            nline++;
        }
        else if(EOF==rval)
            break;
    }
    return 0;
}

uint32_t scan_ip(FILE *cf,char *scanfmt)
{
    char *line;
    int rval;
    rewind(cf);
    while(1)
    {

        if(1==(rval=fscanf(cf,scanfmt,&line)))
        {
            rval=inet_addr(line);
            free(line);
            break;
        }
        else if(EOF == rval || (rval=fscanf(cf,"%*a[^\n]\n")))
        {
            rval=0;
            break;
        }
    }
    return rval;
}
void configfile_getports(FILE *cf, unsigned short *fcmport, unsigned short *fspport)
{
    DEBUGPR("entering configfile_getport():, current fcm=0x%hx, fsp=0x%hx\n",*fcmport,*fspport);
    if(!cf || !fcmport || !fspport)
        return;
    if(!*fcmport)
    {
        rewind(cf);
        *fcmport = (unsigned short)scan_uint(cf,"fcmport=%a[^\n]\n");
    }
    if(!*fspport)
    {
        rewind(cf);
        *fspport = (unsigned short)scan_uint(cf,"fspport=%a[^\n]\n");
    }
    DEBUGPR("leaving configfile_getports():, current fcm=0x%hx, fsp=0x%hx\n",*fcmport,*fspport);

}

void configfile_getips(FILE *cf, uint32_t *fcmip, uint32_t *fspip)
{
    DEBUGPR("entering configfile_getips():, current fcm=0x%x, fsp=0x%x\n",*fcmip,*fspip);
    if(!cf || !fcmip || !fspip)
        return;
    if(!*fcmip)
        *fcmip = scan_ip(cf,"fcmip=%a[^\n]\n");
    if(!*fspip)
        *fspip = scan_ip(cf,"fspip=%a[^\n]\n");
    DEBUGPR("leaving configfile_getips():, current fcm=0x%x, fsp=0x%x\n",*fcmip,*fspip);

}

int main(int argc, char *argv[])
{	
    int c;
	int ch;
    int index;
    //pthread_t tid;
    sockstruct samant;
    stringfilter *filters;
    char *dbglogname=NULL;
    char *udplogname=NULL;
    //FILE *udplogfile=NULL;
    char *cfgfile=NULL;
    FILE *cf=NULL;
    //FILE **arg2;
    char filterstring[1025]={0};
    unsigned filterindex=0;

    unsigned short ip4_parent_proto_list[IP4_PARENT_PROTO_AMNT]={0}; /* ethernet is only parent */
    unsigned short udp_parent_proto_list[UDP_PARENT_PROTO_AMNT]={0x800}; /* ipv4 is only parent */
    sdisplayhandler *displayhandler;
    user_commands uc;
    printptrhandler *bhandler;
    udp_handler *udphandler;
    tgt_commander *commander;
    shitemsgparser *msgfileparser=NULL;
    smsgloader *msgloader;
    char *ptr;
    //char *home=getenv("HOME");
    fileargs farg;
    memset(&farg,0,sizeof(farg));
    displayhandler=sdisplayhandler_init();
    if(!displayhandler)
    {
        EARLY_DBGPR("Failed to allocate displayhandler\n");
        return -1;
    }
    if(!(G_eth_parser=(protocolparser *)init_protocolparser_ethernet()))
    {
        EARLY_DBGPR("Failed to start ethernet protocol parser\n");
        return -1;
    }
    if(!(G_ip4_parser=(protocolparser *)init_protocolparser_ip4()))
    {
        EARLY_DBGPR("Failed to start IPv4 protocol parser\n");
        return -1;
    }
    
    if(!(G_arp_parser=(protocolparser *)init_protocolparser_arp()))
    {
        EARLY_DBGPR("Failed to start ARP protocol parser\n");
        return -1;
    }
    if(!(G_icmp_parser=(protocolparser *)init_protocolparser_icmp()))
    {
        EARLY_DBGPR("Failed to start ICMP protocol parser\n");
        return -1;
    }
    if(!(G_udp_parser=(protocolparser *)init_protocolparser_udp()))
    {
        EARLY_DBGPR("Failed to start UDP protocol parser\n");
        return -1;
    }
    if(!(G_udpcp_parser=(protocolparser *)init_protocolparser_udpcp()))
    {
        EARLY_DBGPR("Failed to start UDPCP protocol parser\n");
        return -1;
    }
    
    parser_add_0(G_eth_parser);

    parser_add_1(G_ip4_parser,ip4_parent_proto_list,IP4_PARENT_PROTO_AMNT);
    G_ip4_parser->activate(G_ip4_parser);
    parser_add_1(G_arp_parser,ip4_parent_proto_list,IP4_PARENT_PROTO_AMNT);
    G_arp_parser->activate(G_arp_parser);

    parser_add_2(G_udp_parser,udp_parent_proto_list,UDP_PARENT_PROTO_AMNT);
    G_udp_parser->activate(G_udp_parser);
    parser_add_2(G_icmp_parser,udp_parent_proto_list,UDP_PARENT_PROTO_AMNT);
    G_udp_parser->activate(G_icmp_parser);

    parser_add_udpcp2udp(G_udpcp_parser,G_udp_parser);
    G_udpcp_parser->activate(G_udpcp_parser);

    commander=init_tgt_commander();
    if(!commander)
    {
        EARLY_DBGPR("Failed to init tgt commander!\n");
    }
    
    memset(&uc,0,sizeof(uc));
    udphandler=init_udphandler();
    if(!udphandler)
    {
        EARLY_DBGPR("Failed to allocate udphandler\n");
        return -1;
    }


    G_exename=argv[0];
    while(-1 != (c = getopt_long(argc, argv, OPTSTRING,long_options,&index)))
    {
        switch(c)
        {
            case 'E':
                filter_before_file=1;
                break;
            case 'e':
            {
                uc.editor=optarg;
                break;
            }
            case 'c':
                if(optarg)
                    cfgfile=optarg;
                break;
            case 'd':
                if(optarg)
                    dbglogname=optarg;
                break;
            case 'i':
                if(optarg)
                {
                    udphandler->ifname=optarg;
                }
                break;
            case 'p':
                /* proto */
                if(optarg)
                {
                    identify_protocol(udphandler,optarg);
                }
                break;
            case 'v':
                EARLY_DBGPR("%s version %s\n",argv[0],VERSION);
                return 0;
                break;
            case '?':
            case 'h':
                EARLY_DBGPR("%s version %s\n",argv[0],VERSION);
                print_usage();
                return 0;
                break;
            case 'f':
            {
                if(optarg)
                {
                    farg.filebasename=udplogname=optarg;
                }
            }
            break;
            default:
                break;
        }
    }

    if(dbglogname)
        if(!(G_logfile=fopen(dbglogname,"w")))
        {
            EARLY_DBGPR("Failed to open logfile '%s' (%s)!\n",dbglogname,strerror(errno));
            return -1;
        }
    if(!cfgfile)
    {
            ptr=calloc(1,26);
            if(ptr)
                snprintf(ptr,25,"%s","/etc/thongs/default.conf");
            cfgfile=ptr;
    }
    if(cfgfile)
    {
        if(!(cf=fopen(cfgfile,"r")))
        {
            EARLY_DBGPR("Failed to open cfgfile '%s' (%s)!\n",cfgfile,strerror(errno));
        }
        else
            if(udphandler->read_portcfgfile(udphandler,cf))
                out(-1);
    }

    if(cf)
    {
        udplog_from_cfgfile(cf,&farg);
        ucs_from_cfgfile(cf,&uc);
        if(!uc.editor)
            uc.editor="gedit";
    }
    if(!farg.filebasename)
    {
        printf("thongs is file based version, -f <filename> or capturefile=<filename> at /etc/thongs/default.conf is REQUIRED!\n");
        return -1;
    }
    strncpy(G_CURRENT_UDP_FILE_NAME,farg.filebasename,1023);
    bhandler=init_printptrhandler(farg.filebasename,0,0);
    if(!bhandler)
    {
        EARLY_DBGPR("Failed to allocate stuff!\n");
        return -1;
    }

    udphandler->prepare_printbuffer(udphandler,bhandler);     

        G_USE_FILE=2;
    if(udphandler->start_sockets(udphandler))
    {
        return -1;
    }
    ptr=calloc(1, 26 /* /etc/thongs/msgtemplates+'\0' */ );
    if(ptr)
    {
        sprintf(ptr,"%s","/etc/thongs/msgtemplates");
        msgfileparser = init_shitemsgparser(ptr);
    }
    
    filters=filterinit(); 
    if(!filters)
    {
        DEBUGPR("Failed to init filters!\n");
        G_NOFILTERS=1;
    }

    signal(SIGSTOP,SIG_IGN);
    signal(SIGTERM,&out);
    signal(SIGINT,&out);
    
    
    DEBUGPR("Enabling ncurses mode...\n");
    displayhandler->ncursesmode_init(displayhandler);
    DEBUGPR("Initializing colours...\n");
    displayhandler->colors_init(displayhandler);
    DEBUGPR("Initializing windows...\n");
    if(displayhandler->windows_init(displayhandler))
    {
        DEBUGPR("Failed to create windows!\n");
        out(-1);
    }
    if(displayhandler->panels_init(displayhandler))
    {
        DEBUGPR("Failed to create panels to handle overlapping windows\n");
        out(-1);
    }
    msgloader=init_smsgloader(displayhandler->menuwin);
    if(!msgloader)
    {
        DEBUGPR("Failed to init msgloader!\n");
        out(-1);
    }
    if(msgfileparser)
        if(msgloader->msgloader_loaditems(msgloader,msgfileparser))
        {
            DEBUGPR("Something went wituiksi!\n");
            out(-1);
        }

    if(displayhandler->scomform_init(displayhandler))
    {
        DEBUGPR("Failed to create form for syscom msgs\n");
        out(-1);
    }

    if(pthread_create(&G_tid,NULL,&UDPreaderthread,  udphandler  ))
    {
        DEBUGPR("Failed to launch UDPlistener thread\n");
        out(0);
    }

    //DEBUGPR("Windows created - statuswin %p, filterwin %p, logwin %p,\n",statuswin,filter_win,logwin);
    filters->set_fstrwin(filters,displayhandler->fstrwin);
    filters->set_statsinfo(filters,displayhandler->statuswin,1);
    wprintw(displayhandler->statuswin,STATUSWIN_PRINT_FMT,samant.sockamnt,0,0,0,"LIVEDISPLAY");
    displayhandler->set_late_properties(displayhandler);
    if(cf && filters_from_cfgfile(filters,cf))
        out(-1);
    if(cf)
        fclose(cf);
//    msgloader->(msgloader,displayhandler->menuwin);
    msgloader->display_menu(msgloader);
    while(!uc.end)
    {
        if(!uc.scroll_mode)
            ch=getch();
        else
            ch=0;
        handle_char(ch,filters,displayhandler,filterstring,&filterindex,&uc,commander,msgloader,msgfileparser,bhandler);
        display_udpdata(filters,displayhandler,bhandler,&uc);
//        if(!uc.scroll_mode && uc.pause<2)
//        {
//            uc.pause*=2;
        if(!uc.scroll_mode)
        {
    		update_panels();
            doupdate();
        }
//        }
    }
    out(0);
	return 0;
}


