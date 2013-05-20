
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

#ifndef PCAP_NG_STRUCTS_H
#define PCAP_NG_STRUCTS_H

typedef struct SPcapNgSecHdrBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint32_t byte_order_magic;
    uint16_t vermajor;
    uint16_t verminor;
    uint64_t section_len;
    uint32_t block_total_len2;
} __attribute__((packed)) SPcapNgSecHdrBlock;

typedef struct SPcapNgIfDescBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snaplen;
    uint32_t block_total_len2;
} __attribute__((packed)) SPcapNgIfDescBlock;

typedef struct SPcapNgEnchancedPacketBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint32_t interface_id;
    uint32_t timestamp_hi;
    uint32_t timestamp_lo;
    uint32_t cap_len;
    uint32_t packet_len;
} __attribute__((packed)) SPcapNgEnchancedPacketBlock;

typedef struct SPcapNgSimplePacketBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint32_t packet_len;
} __attribute__((packed)) SPcapNgSimplePacketBlock;

#define PCAP_NG_HEADERSPACE (sizeof(SPcapNgSimplePacketBlock)+sizeof(uint32_t))
#define PCAP_NG_HEADERSPACE_EXT sizeof(SPcapNgEnchancedPacketBlock)+sizeof(uint32_t)
//#define PCAP_NG_HEADERSPACE_EXT (8*4)


#endif
