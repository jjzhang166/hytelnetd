#!/bin/sh

rm -f /etc/hy_tty.cfg
rm -f /etc/init.d/hyteld
rm -f /opt/hytelnetd
rm -f /opt/hy_setup.cfg
rm -f /usr/lib/libptypes.so.21
rm -f /usr/lib/libptypes.so

cp ./etc/hy_tty.cfg /etc/
cp ./etc/init.d/hyteld /etc/init.d/
cp ./opt/hytelnetd /opt/
cp ./opt/hy_setup.cfg /opt/
cp ./usr/lib/* /usr/lib/

chmod +x /etc/init.d/hyteld
chmod +x /opt/hytelnetd

/sbin/chkconfig --add hyteld
/sbin/chkconfig --list | grep hyteld
