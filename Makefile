CC		= gcc
DEBUG		= -g
CFLAGS		= $(RPM_OPT_FLAGS) -Wall -pedantic -D_GNU_SOURCE -fPIC
SHARED		= -shared 
DESTDIR 	= /
prefix  	= /usr
bindir  	= $(prefix)/bin
plibdir 	= /lib/security
sysconfdir	= /etc

all: pam_mount.so pmhelper

pam_mount.so: pam_mount.c pam_mount.h misc.o readconfig.o converse.o
	$(CC) $(CFLAGS) $(SHARED) -o pam_mount.so pam_mount.c misc.o readconfig.o converse.o

pmhelper: pmhelper.c pam_mount.h misc.o
	$(CC) $(CFLAGS) -o pmhelper pmhelper.c misc.o

misc.o: misc.c pam_mount.h
	$(CC) $(CFLAGS) -c misc.c

readconfig.o: readconfig.c pam_mount.h
	$(CC) $(CFLAGS) -c readconfig.c

converse.o: converse.c
	$(CC) $(CFLAGS) -c converse.c

install: all
	install -m 0755 pmhelper \
		$(DESTDIR)$(bindir)/pmhelper
	install -m 0755 pam_mount.so \
		$(DESTDIR)/$(plibdir)/pam_mount.so
	[ -f $(DESTDIR)/$(sysconfdir)/pam_mount.conf ] || \
	install -m 0644 pam_mount.conf $(DESTDIR)$(sysconfdir)/pam_mount.conf

clean:
	rm -f pmhelper *.so *.o

test: pam_mount.c pam_mount.h misc.o readconfig.o
	$(CC) $(CFLAGS) -lpam -o pam_mount pam_mount.c misc.o readconfig.o

