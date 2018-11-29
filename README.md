# linux-safe-module
A linux kernel module for securely hide and deposit files in system level.

## Usage
### Kernel Module
- modify `safe.h` to your requirements
  ```c
  #define SECRET_FILE "safe" //the directory name
  #define SAFE_DIR "/home/xytao/safe" //the directory absoulute path
  #define SAFE_PARENT_DIR "/home/xytao" //its parent's absolute path
  #define ALLOWED_UID 1000  //your UID (use `echo $UID` to find out yours)
  #define DEFAULT_PASS "12345" //the pre-shared password
  #define SAFE_APP_LOCATION "/opt/safebox/safebox" //the absolute path of allowed application
  ```
- Compile the module
  ```shell
  make
  ```
- Install the Module
  ```shell
  sudo insmod safeko.ko
  ```
- Automatically load the module on boot
  ```shell
  sudo cp safeko.ko /lib/modules/$(uname -r)/kernel/initrd/
  echo 'safeko' | sudo tee -a /etc/modules
  sudo depmod
  ```
  Then reboot, it should take effect.

- Remove module
  ```shell
  sudo rmmod safeko.ko
  ```
### Netlink Client in Userspace
- Compile
  ```shell
  gcc netlink-client.c -o netlink-client
  ```
- Set it to path in order to use with [linux-safe-desktop](https://github.com/taoxinyi/linux-safe-desktop)
  ```shell
  sudo ln -s $(pwd)/netlink-client /usr/bin/netlink-client
  ```
