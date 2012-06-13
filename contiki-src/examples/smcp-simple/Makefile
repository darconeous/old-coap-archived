CONTIKI_PROJECT = smcp-simple

CONTIKI = ../../../../contiki
SMCP_ROOT = ../../..

include $(SMCP_ROOT)/contiki-src/Makefile.smcp

CLEAN += *.hex *.elf symbols.c symbols.h

CFLAGS += -DDEBUG=0 -DNDEBUG=1
#CFLAGS += -DUIP_CONF_LOGGING=1

CFLAGS += -DUIP_CONF_RPL=0

#UIP_CONF_IPV6 = 1
#UIP_CONF_RPL = 1

CFLAGS += -DUIP_CONF_BROADCAST=1

all: $(CONTIKI_PROJECT)

include $(CONTIKI)/Makefile.include

ifeq ($(CC),sdcc)
CFLAGS += --disable-warning 115
endif

burn: $(CONTIKI_PROJECT).u

burn-eeprom: $(CONTIKI_PROJECT).u-eep
