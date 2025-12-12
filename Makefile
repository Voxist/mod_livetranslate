MODNAME=mod_livetranslate
CC=gcc
CFLAGS=`pkg-config --cflags freeswitch libwebsockets` -g -ggdb -O2 -Wall -Werror
LDFLAGS=`pkg-config --libs freeswitch libwebsockets` -shared

all: $(MODNAME).so

$(MODNAME).so: $(MODNAME).c ws_client.c
	$(CC) $(CFLAGS) -fPIC -o $@ $^ $(LDFLAGS)

install:
	install -m 755 $(MODNAME).so /usr/lib/freeswitch/mod/

clean:
	rm -f *.so *.o
