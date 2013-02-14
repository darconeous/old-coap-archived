CONTIKI_PROJECT = smcp-complex

ifeq ($(CONTIKI),)
CONTIKI = ../../../../contiki
endif

SMCP_ROOT = ../../..

SMCP_CONF_NODE_ROUTER = 1
SMCP_CONF_EXTRAS = 1
UIP_CONF_IPV6 = 1
#VERBOSE_DEBUG = 0

include $(SMCP_ROOT)/contiki-src/Makefile.smcp

CLEAN += *.hex *.elf symbols.c symbols.h

all: $(CONTIKI_PROJECT)

include $(CONTIKI)/Makefile.include

ifeq ($(CC),sdcc)
CFLAGS += --disable-warning 115
endif

burn: $(CONTIKI_PROJECT).u

burn-eeprom: $(CONTIKI_PROJECT).u-eep
