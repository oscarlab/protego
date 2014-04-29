obj-m += procmodule.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

helper:
	gcc -g -o proc_setuid_writer proc_setuid_writer.c
	gcc -g -o proc_mount_writer proc_mount_writer.c
	gcc -g -o proc_bind_writer proc_bind_writer.c
	gcc -g -o proc_pppd_writer proc_bind_writer.c
	cp proc_setuid_writer /etc/
	cp proc_mount_writer /etc/
	cp proc_bind_writer /etc/
	cp proc_pppd_writer /etc/
	