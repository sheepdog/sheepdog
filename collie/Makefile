sbindir ?= $(PREFIX)/sbin

CFLAGS += -g -O2 -Wall -Wstrict-prototypes -I../include
CFLAGS += -D_GNU_SOURCE
LIBS += -lpthread -lcrypto -lcpg

PROGRAMS = collie
COLLIE_OBJS = collie.o net.o vdi.o group.o store.o work.o ../lib/event.o ../lib/net.o ../lib/logger.o
COLLIE_DEP = $(COLLIE_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

collie: $(COLLIE_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include $(COLLIE_DEP)

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
