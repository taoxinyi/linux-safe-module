#ifndef SAFE
#define SAFE
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/fs_struct.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>

#include "zeroevil/zeroevil.h"
#include "tools/tools.h"

#define SAFE_PARENT_PATHNAME "/home/xytao"
#define SAFE_FILENAME "safe"

#define ALLOWED_UID 1000
#define NETLINK_USER 31
#define DEFAULT_PASS "12345"
#define SAFE_APP_LOCATION "/opt/safebox/safebox"

/* create && open && close*/
asmlinkage long fake_creat(const char __user *pathname, umode_t mode);
asmlinkage long (*real_creat)(const char __user *filename, umode_t mode);

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*real_open)(const char __user *filename, int flags, umode_t mode);

asmlinkage long fake_openat(int dfd, const char __user *filename, int flags, umode_t mode);
asmlinkage long (*real_openat)(int dfd, const char __user *filename, int flags, umode_t mode);

asmlinkage long fake_close(unsigned int fd);
asmlinkage long (*real_close)(unsigned int fd);

/* read & write */
asmlinkage long fake_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*real_read)(unsigned int fd, char __user *buf, size_t count);

asmlinkage long fake_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos);
asmlinkage long (*real_pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos);

asmlinkage long fake_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*real_write)(unsigned int fd, char __user *buf, size_t count);

asmlinkage long fake_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
asmlinkage long (*real_pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos);

/* link & unlink */
asmlinkage long fake_link(const char __user *oldname, const char __user *newname);
asmlinkage long (*real_link)(const char __user *oldname, const char __user *newname);

asmlinkage long fake_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
asmlinkage long (*real_linkat)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);

asmlinkage long fake_symlink(const char __user *old, const char __user *new);
asmlinkage long (*real_symlink)(const char __user *oldname, const char __user *newname);

asmlinkage long fake_symlinkat(const char __user *oldname, int newdfd, const char __user *newname);
asmlinkage long (*real_symlinkat)(const char __user *oldname, int newdfd, const char __user *newname);

asmlinkage long fake_unlink(const char __user *pathname);
asmlinkage long (*real_unlink)(const char __user *pathname);

asmlinkage long fake_unlinkat(int dfd, const char __user *pathname, int flag);
asmlinkage long (*real_unlinkat)(int dfd, const char __user *pathname, int flag);

/* dir */
asmlinkage long fake_chdir(const char __user *filename);
asmlinkage long (*real_chdir)(const char __user *filename);

asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode);
asmlinkage long (*real_mkdir)(const char __user *pathname, umode_t mode);

/* rename */
asmlinkage long fake_rename(const char __user *oldname, const char __user *newname);
asmlinkage long (*real_rename)(const char __user *oldname, const char __user *newname);

/* stat */
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*real_stat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);

asmlinkage long fake_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*real_lstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);

asmlinkage long fake_newfstatat(int dfd, const char __user *filename,struct stat __user *statbuf, int flag);
asmlinkage long (*real_newfstatat)(int dfd, const char __user *filename,struct stat __user *statbuf, int flag);

/* getdents */
asmlinkage long fake_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
asmlinkage long (*real_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
#endif
