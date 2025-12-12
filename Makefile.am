include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_livetranslate

mod_LTLIBRARIES = mod_livetranslate.la
mod_livetranslate_la_SOURCES  = mod_livetranslate.c ws_client.c
mod_livetranslate_la_CFLAGS   = $(AM_CFLAGS)
mod_livetranslate_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_livetranslate_la_LDFLAGS  = -avoid-version -module -no-undefined -shared `pkg-config --libs libwebsockets`
