CONTIKI_PROJECT = smcp-simple

CONTIKI = ../../../../contiki
SMCP = ../../..

include $(SMCP)/contiki-src/Makefile.smcp

CLEAN += *.hex *.elf symbols.c symbols.h

#CFLAGS += -DDEBUG_NONE=1 -DUIP_CONF_LOGGING=1
CFLAGS += -DDEBUG=0 -DNDEBUG=1

#CFLAGS += -DUIP_CONF_LOGGING=0

UIP_CONF_IPV6 = 1
UIP_CONF_RPL = 0

HAVE_BANKING = 0

CFLAGS += -DUIP_CONF_BROADCAST=1

all: $(CONTIKI_PROJECT)

include $(CONTIKI)/Makefile.include

ifeq ($(CC),sdcc)
CFLAGS += --disable-warning 115
endif
