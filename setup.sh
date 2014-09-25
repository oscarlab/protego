#!/bin/bash

PWD=`pwd`
#Install packages to compile kernel
sudo apt-get install fakeroot build-essential crash kexec-tools makedumpfile kernel-wedge
sudo apt-get build-dep linux
sudo apt-get install git-core libncurses5 libncurses5-dev libelf-dev asciidoc binutils-dev

#Download source
git clone https://github.com/oscarlab/protego.git

#Kernel Compile and Install
cd protego/linux-stable
make menuconfig
export CONCURRENCY_LEVEL=4
make-kpkg clean
make-kpkg --initrd kernel_image kernel_headers
cd ..
sudo dpkg -i linux-*.deb

#Install the helper binaries
cd proc_plugin
sudo make helper
cd ../shadow-4.1.5
./configure
make plogin
cd ../xtables-addons-1.46
./configure
make && sudo make install

#Add the startup commands

echo "iptables -A OUTPUT -j RAWSOCKET --allow icmp --icmp_type echo_request" > /etc/init.d/protego_startup.sh
echo "iptables -A OUTPUT -j RAWSOCKET --deny_all" >> /etc/init.d/protego_startup.sh

echo "nohup python $PWD/progs/daemon.py &" >> /etc/init.d/protego_startup.sh
chmod a+x /etc/init.d/protego_startup.sh
update-rc.d protego_startup.sh defaults 100

#Reboot the system in protego kernel
sudo reboot
