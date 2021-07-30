(Note: OASIS needs to run on a bare-metal machine with a customized OS, and there would be a VM installed. If your current Ubuntu does not match with the following requirement or you do not want to disturb your current working environment, you can create a new partition and install a new Ubuntu there. Then your machine becomes a dual-boot Ubuntu system, do the following things in the new Ubuntu. It's also okay to skip the step if there is no confliction.)

# Requirement & Preparation
Host OS: Ubuntu 18.04; Kernel version: linux 5.4.X.

[Install kvm and its related virt-manager toolchain](https://linuxize.com/post/how-to-install-kvm-on-ubuntu-18-0)

[Install a VM with linux 5.4.X using virt-manager](https://www.tecmint.com/create-virtual-machines-in-kvm-using-virt-manager/4/)

# Re-compile OASIS kernel source code and install it in the host OS.
## get source code
```
git clone https://github.com/jqhong/onsite/tree/main/linux-hwe-5.3.0
```
## install the required compilers and other tools
```
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev
```
## configuring the kernel
```
cd linux-hwe-5.3.0
cp -v /boot/config-$(uname -r) .config
make menuconfig 
```
In make menuconfig, load and save the new .config file, then exit
## compile the linux kernel as debian packages
```
make -j8 deb-pkg
```
four *.deb packages would be generated, check in the upper folder

## install the new kernel
```
sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb 
sudo dpkg -i linux-image-5.3.18-dbg_5.3.18-1_amd64.deb
sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb   
sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb 
```
    
## reboot and enter the new kernel 5.3.18
During boot procedure, remember to select Advanced options for ..., then select 5.3.18.

you may want update /etc/default/grub or /boot/grub/grub.cfg to make the 5.3.18 as the default kernel whenever reboot. To avoid the above sumbersome selectings. 

# Get the oasis dependent kernel module and install.
```
cd ~/Dcouments
git clone https://github.com/jqhong/onsite/tree/main/elf-module
cd elf-module
make
sudo insmod ld.ko
```
# Get the customized loader and re-compile
```
cd ~/Documents
mkdir glibc-2.27
cd glibc-2.27
git clone https://github.com/jqhong/onsite/tree/master/glibc-2.27
mkdir build-glibc
../glibc-2.27/configure --prefix=/usr/local/lib/glibc-testing
make -j6 CFLAGS="-O2 -U_FORTIFY_SOURCE -fno-stack-protector"
```
# Test onsite mode 
cd ~/Documents
```
git clone https://github.com/jqhong/onsite/tree/main/launcher
cd launcher 
gcc hello.c -o hello
cd ana
./compile.sh
ln -s -f hello testtest
cd ../
./hello 0x0
```
If the program exits smoothly and with "In onsite Mode, dump Target: " on sccreen, oasis in installed successfully.