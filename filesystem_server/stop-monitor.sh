ps -ef|grep filesystem_monitor_server|grep -v grep|cut -c 9-15|xargs kill -9
ps -ef|grep vol.py|grep -v grep|cut -c 9-15|xargs kill -9
qemu-nbd -d /dev/nbd0
qemu-nbd -d /dev/nbd1
qemu-nbd -d /dev/nbd2
modprobe -r nbd
