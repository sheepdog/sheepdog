sbindir ?= $(PREFIX)/sbin

CFLAGS += -g -O2 -Wall -Wstrict-prototypes -I../include
CFLAGS += -D_GNU_SOURCE
LIBS += -lncurses

PROGRAMS = shepherd
SHEPHERD_OBJS = shepherd.o treeview.o ../lib/event.o ../lib/net.o ../lib/logger.o
SHEPHERD_DEP = $(SHEPHERD_OBJS:.o=.d)

.PHONY:all
all: $(PROGRAMS)

shepherd: $(SHEPHERD_OBJS)
	$(CC) $^ -o $@ $(LIBS)

-include $(SHEPHERD_DEP)

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
