
#common
CFLAGS=-Wall -ggdb -D_GNU_SOURCE
SRC=src/thongs.c src/cexplode.c src/stringfilters.c src/bshandler.c src/tgt_commander.c src/udp_handler.c src/syscomform.c src/displayhandler.c src/definitionfinder.c src/common.c src/shitemsgparser.c src/msgloadermenu.c src/protocolparser.c src/protocolparser_ethernet.c src/protocolparser_ip4.c src/protocolparser_udp.c src/protocolparser_arp.c src/protocolparser_udpcp.c src/protocolparser_icmp.c
LDFLAGS=
#commonstatic
CFLAGS_STATIC=-DNCURSES_STATIC
LDFLAGS_STATIC=-static


#linux
CC=gcc
LIBS=-lpthread -lncurses -lform -lpanel -lmenu
TGT=bin/thongs-sniffer
TGT_STATIC=bin/thongs_static


all: thongs
man: thongs.8.gz

test:
	$(CC) -Wall src/maz_list_test.c -o bin/maz_list_test

thongs: $(SRC)
	$(CC) $(CFLAGS) -o $(TGT) $(SRC) $(LDFLAGS) $(LIBS)

help:
	@echo 'Targets: thongs, testkeys, thongs_static, install, maninstall, clean'

testkeys: src/testkeys.c
	$(CC) $(CFLAGS) src/testkeys.c -o bin/testkeys  $(LIBS)

thongs_static: $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_STATIC) -o $(TGT_STATIC) $(SRC) $(LDFLAGS) $(LDFLAGS_STATIC) $(LIBS)

install: $(TGT) maninstall
	cp $(TGT) /usr/bin/.
	mkdir /etc/thongs

maninstall: thongs.8.gz
	mv thongs.8.gz /usr/share/man/man8/.
	@echo 'man pages installed to /usr/share/man/man8'
	@echo 'consider running mandb or makewhatis to update apropos database'

clean:
	rm -rf $(TGT)
	rm -rf $(TGT_OCT)
	rm -rf $(WINTGT)
	rm -rf bin/testkeys
	rm -rf $(WINTGT_STATIC)
	rm -rf $(TGT_STATIC)
	rm -rf bin/maz_list_test


thongs.8.gz: man/thongs.8
	cp man/thongs.8 thongs.8
	gzip thongs.8
