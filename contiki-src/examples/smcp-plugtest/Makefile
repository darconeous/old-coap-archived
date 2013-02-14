CONTIKI_PROJECT = smcp-plugtest

ifeq ($(CONTIKI),)
CONTIKI = ../../../../contiki
endif

SMCP_ROOT = ../../..

UIP_CONF_IPV6 = 1
UIP_CONF_RPL = 0
SMCP_CONF_NODE_ROUTER = 1
#VERBOSE_DEBUG = 0

include $(SMCP_ROOT)/contiki-src/Makefile.smcp

CONTIKI_SOURCEFILES += plugtest-server.c
APPDIRS += $(SMCP_ROOT)/src/plugtest

ifeq ($(TARGET),avr-raven)
#APPS += raven-webserver
APPS += raven-lcd-interface
endif

CLEAN += *.hex *.elf symbols.c symbols.h

all: $(CONTIKI_PROJECT)

include $(CONTIKI)/Makefile.include

ifeq ($(CC),sdcc)
CFLAGS += --disable-warning 115
endif

burn: $(CONTIKI_PROJECT).u

burn-eeprom: $(CONTIKI_PROJECT).u-eep
