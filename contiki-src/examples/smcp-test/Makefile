CONTIKI_PROJECT = smcp-test

CONTIKI = ../../../../contiki
SMCP = ../../..

include $(SMCP)/contiki-src/Makefile.smcp

CLEAN += *.hex *.elf symbols.c symbols.h

CFLAGS += -g

UIP_CONF_IPV6 = 1

#ifeq ($(TARGET),avr-raven)
#APPS += raven-webserver
#APPS += raven-lcd-interface
#endif

AVRDUDE_OPTIONS=-V
AVRDUDE_OPTIONS+=-B 4
AVRDUDE_PROGRAMMER=dragon_isp
AVRDUDE_PORT=usb

all: $(CONTIKI_PROJECT)

include $(CONTIKI)/Makefile.include

burn: $(CONTIKI_PROJECT).u

burn-eeprom: $(CONTIKI_PROJECT).u-eep
