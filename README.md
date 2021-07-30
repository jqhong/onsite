(Note: OASIS needs to run on a bare-metal machine with a customized host OS, and there would be a VM installed. If your current Ubuntu does not mathc with the following requirement or you do not want to disturb your current working environment, you can create a new partition and install a new Ubuntu there. Then your machine becomes a dual-boot Ubuntu system, do the following things in the new Ubuntu. It's also okay to skip the step if there is no confliction.)
1. Preparation
OASIS needs to run on a bare-metal machine with 
    OS: Ubuntu 18.04 
    Kernel: linux 5.4.X
Install kvm and its related virt-manager toolchain: https://linuxize.com/post/how-to-install-kvm-on-ubuntu-18-0
Install a VM with linux 5.4.X using virt-manager: https://www.tecmint.com/create-virtual-machines-in-kvm-using-virt-manager/4/

2. Get OASIS kernel source code and re-compile the source code. Install the new kernel in the host OS.
    # get source code
    git clone https://github.com/jqhong/onsite/tree/main/linux-hwe-5.3.0
    
    # install the required compilers and other tools
    sudo apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev

    # configuring the kernel
    cd linux-hwe-5.3.0
    cp -v /boot/config-$(uname -r) .config
    make menuconfig ##Load the save the new .config file, then exit

    #compile the linux kernel as debian packages
    make -j8 deb-pkg ##four *.deb packages would be generated, check in the
    upper folder

    #install the new kernel
    sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb 
    sudo dpkg -i linux-image-5.3.18-dbg_5.3.18-1_amd64.deb
    sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb   
    sudo dpkg -i linux-image-5.3.18_5.3.18-1_amd64.deb 

    #reboot and enter the new kernel 5.3.18
    during boot procedure, remember to select Advanced options for ..., then select 5.3.18.
    you may want update /etc/default/grub or /boot/grub/grub.cfg to make the 5.3.18 as the default kernel whenever reboot. To avoid the above sumbersome selectings. 

3. Get the oasis dependent kernel module and install.
    cd ~/Dcouments
    git clone https://github.com/jqhong/onsite/tree/main/elf-module
    cd elf-module
    make
    sudo insmod ld.ko

4. Get the customized loader and re-compile
    cd ~/Documents
    mkdir glibc-2.27
    cd glibc-2.27
    git clone https://github.com/jqhong/onsite/tree/master/glibc-2.27
    mkdir build-glibc
    ../glibc-2.27/configure --prefix=/usr/local/lib/glibc-testing
    make -j6 CFLAGS="-O2 -U_FORTIFY_SOURCE -fno-stack-protector"
