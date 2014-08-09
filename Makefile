target=hytelnetd

all: $(target)

$(target): main.cpp ptypes/*.cxx
	g++ -L. $^ -lpthread -o $@

clean:
	rm -f $(target)

install:
	cp hy_tty.cfg /etc/
	cp hyteld  /etc/init.d/hyteld
	cp $(target)     /opt/
	chmod +x /etc/init.d/hyteld
	chmod +x /opt/$(target)
	/sbin/chkconfig --add hyteld
	/sbin/chkconfig --list | grep hyteld

uninstall:
	rm -f /etc/hy_tty.cfg
	rm -f /etc/init.d/hyteld
	rm -f /opt/$(target)

#	ngcbs yjdlzyyd
start:
	service hyteld start

stop:
	-killall hytelnetd
	-fuser -k /dev/ttyz7
	
enable:
	chkconfig hyteld on
	
disable:
	chkconfig hyteld off


rebuild: stop uninstall $(target) install start

.PHONY: all clean install uninstall
