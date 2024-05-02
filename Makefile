all: dist

MODULE := ios_rsd_tunnel
SRCS := $(wildcard $(MODULE)/*.py) $(wildcard $(MODULE)/cli/*.py) $(wildcard $(MODULE)/remote/*.py) $(wildcard $(MODULE)/services/*.py) $(MODULE)/LICENSE requirements.txt

dist: iosRsdTunnel.tar.xz

clean:
	rm iosRsdTunnel.tar.xz

iosRsdTunnel.tar.xz:  $(SRCS)
	tar -cJf iosRsdTunnel.tar.xz $(SRCS)
