
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

#ifndef NIBBLE_COMMIN_H
#define NIBBLE_COMMIN_H

#include <stdio.h>
#include <ncurses.h>
#include <inttypes.h>

//#define debug

#define ALIGN_SIZE 4
#define VERSION "\n0.7   -  )___(\n        (\\___/)\n"
#define OPTSTRING "c:d:Ee:f:i:p:vh?"
#define EARLY_DBGPR printf
/* /altGR + s */
#define SCROLLCHAR (159)
/* ctrl + p */
#define PAUSECHAR (16)
#define HELPWIN_TOGGLE_STR  "F2"
#define HELPCHAR            (KEY_F(2))
#define SYSCOM_TOGGLE_STR   "F3"
#define FORM_TOGGLE_CHAR    (KEY_F(3))
#define DEFFIND_TOGGLE_STR  "F4"
#define DEFFIND_TOGGLE_CHAR (KEY_F(4))
#define FSTR_TOGGLE_STR     "F5"
#define FSTR_TOGGLE_CHAR    (KEY_F(5))
#define SCOMMENU_TOGGLE_STR "F6"
#define SCOMMENU_TOGGLE_CHAR    (KEY_F(6))
/* ESC */
#define ENDCHAR (0x1B) // ESC
/* ctrl+b */
#define FORM_SEND_FCM_CHAR (2)
/* ctrl + n */
#define FORM_SEND_FSP_CHAR (14)

#define COMMAND_STARTCHAR '*'

#define HELP_PRINT \
"Args:\n"\
"    -d --debug             write debug log in file specified as parameter\n" \
"    -p --protocol          protocol to listen (ip4,ip6,arp,vlan,pause)\n" \
"    -E --earlyfilter       apply protocol filter before even writing pkg \n" \
"                           to file and write only matching pkgs\n" \
"    -i --interface         interface to listen \n" \
"    -c --config            use file given as parameter to get default configurations\n" \
"    -f --file              write prints in file given as parameter\n" \
"    -e --editor            editor which is used to open log\n" \
"    -v --version           display version and exit\n" \
"    -h --help              to get this help\n" \
"    -?                     to get this help\n\n" \
"    T.H.O.N.G.S  - Textmode Helper On Network Getting Sniffed \n" \
"    You can add 'exclude' 'include' and 'highlight' filters at runtime, by typing -<excludethis1>,-<excludethis2>,+<includethis1>,!<highlightthis> and pressing enter. (or -<excludethis1> followed by enter, -<excludethis2> followed by enter and so on). Thongs will then scan incoming ethernet frames for filters, and display prints as follows:\n" \
"    If string in print line matches exclude filter, it will not be displayed.\n" \
"    If include filter(s) are set, and no string in line matches any include filters, line is not displayed\n" \
"    Othervice line is displayed.\n" \
"    If string in print line passes include and exlude filters (is displayed), and if it matches highlight filter, then line is printed and coloured.\n" \
"    Filtering does not affect logging.\n\n"

#define HELP_WIN_LEN 120
#define RUNTIME_HELP_PRINT_LINES 45
#define RUNTIME_HELP_PRINT \
    " Raw string filters: \n" \
    " -<str1>,<str2>,..        \t\texclude lines with <str1> or <str2> or ...\n" \
    " +<str1>,<str2>,..        \t\tinclude only lines with <str1> or <str2> or ...\n" \
    " !<str1>,<str2>,..        \t\thighlight lines with <str1> or <str2> or ...\n" \
    " clear                    \t\tclear all raw protocol filters\n" \
    "\n" \
    " Packet matching filters \n" \
    " > <proto> <field> <value>\t\thighlight packets matching filter.\n" \
    " < <proto> <field> <value>\t\tremove installed packet matching filter. (not supported)\n" \
    "   Supported protos: \n" \
    "       eth                    \t\tethernet\n" \
    "       ip4                    \t\tIPv4\n" \
    "       arp                    \t\tARP\n" \
    "       udp                    \t\tUDP\n" \
    "   fields for eth protocol \n" \
    "       dst                    \t\tdestination mac format aa:bb:cc:dd:ee:ff \n"\
    "       src                    \t\tsource mac format aa:bb:cc:dd:ee:ff \n"\
    "       vlan                   \t\tvlan ID\n" \
    "   fields for ip4 protocol \n" \
    "       dip                    \t\tdestination IP in dotted decimal format \n"\
    "       sip                    \t\tsource IP in dotted decimal format \n"\
    "       ttl                    \t\tTTL value\n"\
    "       len                    \t\tTotal Len\n" \
    "       csum                   \t\tChecksum (not supported)\n" \
    "   fields for ARP protocol \n" \
    "       dip                    \t\tdestination IP in dotted decimal format \n"\
    "       sip                    \t\tsource IP in dotted decimal format \n"\
    "       dmac                   \t\tdestination mac in format aa:bb:cc:dd:ee:ff\n"\
    "       smac                   \t\tsource mac in format aa:bb:cc:dd:ee:ff\n" \
    "       req                    \t\tARP packet with response mode (No value needed)\n" \
    "       resp                   \t\tARP packet with response mode (No value needed)\n" \
    "   fields for UDP protocol\n" \
    "       dport                  \t\tdestination port \n"\
    "       sport                  \t\tsource port \n"\
    "       len                    \t\tUDP data lenght\n" \
    "       csum                   \t\tChecksum (not supported)\n" \
    " C                        \t\tclear logwindow\n" \
    " ctrl+p                   \t\tpause/resume\n" \
    " F2-F5                    \t\tbrowse windows\n" \
    " ctrl+b                   \t\tsend ethernet frame when F3 view on\n" \
    " ctrl+f                   \t\tFind values for definitions when definition finder view on\n" \
    " esc                      \t\tquit\n"




#define TIMESTAMPSIZE 26
#define ERRPR DEBUGPR
#define DEBUGPR(foo,args...) { if(NULL!=G_logfile){ fprintf(G_logfile,(foo), ## args ); fflush(G_logfile); } }
#ifdef debug
#define VERBOSE_DEBUGPR DEBUGPR
#else
#define VERBOSE_DEBUGPR(foo,args...) ;
#endif

extern FILE *G_logfile;
void schedule_filewrite(int filewrite,int bs);
void out(int sig);
uint32_t scan_uint(FILE *cf,char *scanfmt);
int get_mac(char *filter,uint8_t *mac);

#endif

