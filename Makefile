all: dist

SRCS := $(wildcard *.py) $(wildcard cli/*.py) $(wildcard remote/*.py) $(wildcard services/*.py) LICENSE requirements.txt

dist: iosRsdTunnel.tar.xz


iosRsdTunnel.tar.xz:  $(SRCS)
	tar -cJf iosRsdTunnel.tar.xz $(SRCS)