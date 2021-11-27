This repo contains OASIS customized kernel ./linux-hwe-5.3.0/, OASIS libraries ./oasis_lib/, a dependent kernel module ./elf_module/, and a customized linker ./glibc-2.27/. 

(Note: OASIS needs to run on a bare-metal machine with a customized OS, and there would be a VM installed. If your current Ubuntu does not match with the following requirement or you do not want to disturb your current working environment, you can create a new partition and install a new Ubuntu there. Then your machine becomes a dual-boot Ubuntu system, do the following things in the new Ubuntu. It's also okay to skip the step if there is no confliction.)

# Requirement & Preparation
Host OS: Ubuntu 18.04; Kernel version: linux 5.4.X.

binutils: 2.30

gcc:7.5.0

[Install kvm and its related virt-manager toolchain](https://linuxize.com/post/how-to-install-kvm-on-ubuntu-18-04/)


[Install a VM with linux 5.4.X using virt-manager](https://www.tecmint.com/create-virtual-machines-in-kvm-using-virt-manager/4/)

```
git clone https://github.com/jqhong/onsite.git
```

# Compile OASIS kernel and install.

## install the required compilers and other tools
```
sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev
```
## configuring the kernel
confirm *CONFIG_X86_SMAP is not set* in the .config file. if *CONFIG_X86_SMAP = y*, change it to *CONFIG_X86_SMAP = n*.
```
cd onsite/linux-hwe-5.3.18
grep CONFIG_X86_SMAP .config
```  
load and save the .config file, then exit.
```
make menuconfig 
```
## compile the linux kernel as debian packages
```
make -j8 deb-pkg
cd ../ && ls -la
```
There would be four *.deb packages generated.

## install the new kernel
```
sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb 
sudo dpkg -i linux-image-5.3.18-dbg_5.3.18-1_amd64.deb
sudo dpkg -i linux-libc-dev_5.3.18-1_amd64.deb   
sudo dpkg -i linux-headers-5.3.18_5.3.18-1_amd64.deb 
```
    
## reboot and enter into the new kernel 5.3.18
During boot procedure, remember to select Advanced options for ..., then select 5.3.18.

you may want update /etc/default/grub or /boot/grub/grub.cfg to make the 5.3.18 as the default kernel whenever reboot, to avoid the above troublesome selectings. 

## disable ASLR permanently
[reference](https://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization)
Add a file /etc/sysctl.d/01-disable-aslr.conf containing:
```
kernel.randomize_va_space = 0
```
## disable pti through boot option
add 'nopti' after 'quite splash' in /etc/default/grub, then 
```
sudo update-grub2
```
# Install oasis kernel module ld.ko
```
cd elf-module
```
## In elf.c, update oasis_lib_path, load_eld_library, & elf_core_dump. 

1. load_elf_library & elf_core_dump, find their addresses from System.map and modify in elf.c line 120 and line 141 accordingly. 
```
sudo less /boot/Sysem.map-$(uname -r)
```
2. oasis_lib_path in line 93, change it to "path/to/onsite/oasis_lib/"
3. ensure the .so files in oasis_lib have X permission. if not, use the compile.sh in each sub-folder to re-generate *.so

## compile & install
```
make && sudo insmod ld.ko
```

# Compile the customized linker
```
cd ../
git clone -b master https://github.com/jqhong/onsite.git
cd glibc-2.27
mkdir build-glibc
cd build-glibc/
../glibc-2.27/configure --prefix=/usr/local/lib/glibc-testing
make -j6 CFLAGS="-O2 -U_FORTIFY_SOURCE -fno-stack-protector"
```
