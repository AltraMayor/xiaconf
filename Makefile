LIBXIA_DIR=libxia
XIP_DIR=xip
NWPD_DIR=nwpd
ETC_FILES=etc-production


all: libxia xip nwpd

libxia:
	make -C $(LIBXIA_DIR)

xip:
	make -C $(XIP_DIR)

nwpd:
	make -C $(NWPD_DIR)

install: libxia xip
	install -o root -g root -m 700 $(XIP_DIR)/xip /sbin
	install -o root -g root -m 644 $(LIBXIA_DIR)/libxia.so.0.0 /usr/lib
	install -o root -g root -m 700 $(NWPD_DIR)/nwpd /sbin
	ldconfig
	cp -r $(ETC_FILES)/xia /etc
	mkdir -p /etc/xia/hid/prv
	mkdir /etc/xia/hid/tmp
	chown root:root -R /etc/xia
	chmod 700 -R /etc/xia
	chmod 755 /etc/xia
	chmod 644 /etc/xia/principals

remove:
	rm -rf /etc/xia /sbin/xip /usr/lib/libxia.so.0.0
	ldconfig

cscope:
	cscope -b -q -R -Ikernel-include -Iinclude -sxip -slibxia -stestlibxia

clean:
	make -C $(XIP_DIR) clean
	make -C $(LIBXIA_DIR) clean
	make -C $(NWPD_DIR) clean


.PHONY: clean libxia xip cscope nwpd
