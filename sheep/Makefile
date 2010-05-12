sbindir ?= $(PREFIX)/sbin

CFLAGS += -g -O2 -Wall -Wstrict-prototypes -I../include
CFLAGS += -D_GNU_SOURCE -DSD_VERSION=\"$(VERSION)\"
LIBS += -lpthread -lcpg -lcfg

PROGRAMS = sheep
SHEEP_OBJS = sheep.o net.o vdi.o group.o store.o work.o ../lib/event.o ../lib/net.o ../lib/logger.o
SHEEP_DEP = $(SHEEP_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

sheep: $(SHEEP_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include $(SHEEP_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY:clean
clean:
	rm -f *.[od] $(PROGRAMS)

.PHONY:install
install: $(PROGRAMS)
	install -d -m 755 $(DESTDIR)$(sbindir)
	install -m 755 $(PROGRAMS) $(DESTDIR)$(sbindir)
