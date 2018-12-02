# linux-safe-module
A linux kernel module for securely hiding and depositing files in system level.

When the safe directory is set, only the allowed user using the allowed application can access the safe directory, and others cannot access this directory in system level, including `cd`, `ls`, `open`, `ln`, `mv`, `rename`, `rm`...

For write and read file, it will encrypt and decrypt the buffer seamlessly using **RC4** Key-scheduling algorithm (KSA) for **Substitution Cipher**. Therefore, the actual data stored on disk will be encrypted, but the allowed user will have no knowledge of it when access the file since the read process will automatically encrypt it and pass the plain buffer to the application layer.

Tested on Ubuntu 14.04 (4.4.0-31) and Ubuntu 16.04 (4.13.0-36).
## Supported System Calls
### open
- open
- create
- openat
### read
- read
- pread64
### write
- write
- pwrite64
### link
- link
- linkat
- symlink
- symlinkat
### unlink
- unlink
- unlinkat
### dir
- mkdir
- chdir
### stat
- stat
- lstat
- newfstatat
### others
- rename
- getdents

## Usage
### Kernel Module
- modify `safe.h` to your requirements
  ```c
  //the absolute path of its parent directory
  #define SAFE_PARENT_PATHNAME "/home/xytao"
  //the directory's filename
  #define SAFE_FILENAME "safe"
  //allowed UID (use `echo $UID` to find out yours)
  #define ALLOWED_UID 1000
  //the pre-shared password
  #define DEFAULT_PASS "12345"
  //the absolute path of allowed application
  #define SAFE_APP_LOCATION "/opt/safebox/safebox"

  ```
- Compile the module
  ```shell
  make
  ```
  Recommend to install libelf-dev on Ubuntu 16.04 first
  ```shell
  sudo apt-get install libelf-dev
  ```
  in order to prevent the following warning:
  ```shell
   "Cannot use CONFIG_STACK_VALIDATION=y, please install libelf-dev, libelf-devel or elfutils-libelf-devel"
  ```
- Install the module
  ```shell
  sudo insmod safeko.ko
  ```
- Automatically load the module on boot
  ```shell
  sudo cp safeko.ko /lib/modules/$(uname -r)/kernel/drivers/
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
