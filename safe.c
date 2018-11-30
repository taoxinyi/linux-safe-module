#include "safe.h"

MODULE_LICENSE("GPL");

char SAFE_DIR_SLASH[PATH_MAX];
char SAFE_DIR_NO_SLASH[PATH_MAX];

char SAFE_PARENT_DIR_SLASH[PATH_MAX];
char SAFE_PARENT_DIR_NO_SLASH[PATH_MAX];

struct sock *nl_sk = NULL;
struct Message *message;
unsigned long **sct;
int opened_file_count = 0;

bool is_process_valid(struct task_struct *ts)
{
    char f[PATH_MAX];
    f[0] = '\0';
    while (ts->pid != 1)
    {
        get_filename_from_struct_file(ts->mm->exe_file, f);
        if (!strcmp(f, SAFE_APP_LOCATION))
            return true;
        ts = ts->parent;
    }
    return false;
}
bool is_user_valid(void)
{

    return current_uid().val == ALLOWED_UID;
}
bool is_target(char *path)
{
    return !strcmp(path, SAFE_DIR_NO_SLASH) ||
           !strncmp(path, SAFE_DIR_SLASH, strlen(SAFE_DIR_SLASH));
}
static void on_receive(struct sk_buff *skb)
{

    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    int res;
    struct task_struct *task;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = sizeof(struct Message);
    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;
    message = (struct Message *)nlmsg_data(nlh);

    if (is_process_valid(get_struct_task_from_pid(pid)))
    {
        if (!strcmp(message->filename, SAFE_DIR_SLASH) ||
            !strcmp(message->filename, SAFE_DIR_NO_SLASH))
            message->type = strcmp(message->password, DEFAULT_PASS);
        else
            message->type = -2;
    }
    else
        message->type = -1;

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    memcpy(nlmsg_data(nlh), message, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}
int init_netlink(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = on_receive,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk)
        return -10;
    else
    {
        printk(KERN_INFO "Init Finished\n");
        return 0;
    }
}
void set_safedir(void)
{ //absolute path of safe directory ending without /
    strcpy(SAFE_DIR_NO_SLASH, SAFE_PARENT_PATHNAME);
    strcat(SAFE_DIR_NO_SLASH, "/");
    strcat(SAFE_DIR_NO_SLASH, SAFE_FILENAME);

    //absolute path of safe directory ending with /
    strcpy(SAFE_DIR_SLASH, SAFE_DIR_NO_SLASH);
    strcat(SAFE_DIR_SLASH, "/");

    //absolute path of safe parent directory ending without /
    strcpy(SAFE_PARENT_DIR_NO_SLASH, SAFE_PARENT_PATHNAME);

    //absolute path of safe parent directory ending without /
    strcpy(SAFE_PARENT_DIR_SLASH, SAFE_PARENT_PATHNAME);
    strcat(SAFE_PARENT_DIR_SLASH, "/");
}
int init_module(void)
{
    fm_alert("%s\n", "The linux-safe-module is installed!");
    if (init_netlink() < 0)
        printk(KERN_ALERT "Error creating socket.\n");
    set_safedir();
    sct = get_sct();
    disable_wp();

    HOOK_SCT(sct, link);
    HOOK_SCT(sct, linkat);
    HOOK_SCT(sct, symlink);
    HOOK_SCT(sct, symlinkat);
    HOOK_SCT(sct, unlink);
    HOOK_SCT(sct, unlinkat);

    HOOK_SCT(sct, getdents);
    HOOK_SCT(sct, chdir);
    HOOK_SCT(sct, mkdir);
    HOOK_SCT(sct, rename);
    HOOK_SCT(sct, lstat);
    HOOK_SCT(sct, stat);
    HOOK_SCT(sct, newfstatat);

    HOOK_SCT(sct, open);
    HOOK_SCT(sct, creat);
    HOOK_SCT(sct, openat);
    HOOK_SCT(sct, close);
    HOOK_SCT(sct, pread64);
    HOOK_SCT(sct, pwrite64);
    HOOK_SCT(sct, read);
    HOOK_SCT(sct, write);

    enable_wp();

    return 0;
}

void cleanup_module(void)
{
    netlink_kernel_release(nl_sk);
    disable_wp();

    UNHOOK_SCT(sct, link);
    UNHOOK_SCT(sct, linkat);
    UNHOOK_SCT(sct, symlink);
    UNHOOK_SCT(sct, symlinkat);
    UNHOOK_SCT(sct, unlink);
    UNHOOK_SCT(sct, unlinkat);

    UNHOOK_SCT(sct, getdents);
    UNHOOK_SCT(sct, chdir);
    UNHOOK_SCT(sct, mkdir);
    UNHOOK_SCT(sct, rename);
    UNHOOK_SCT(sct, lstat);
    UNHOOK_SCT(sct, stat);
    UNHOOK_SCT(sct, newfstatat);
    UNHOOK_SCT(sct, open);
    UNHOOK_SCT(sct, creat);
    UNHOOK_SCT(sct, openat);
    UNHOOK_SCT(sct, close);
    UNHOOK_SCT(sct, pread64);
    UNHOOK_SCT(sct, pwrite64);
    UNHOOK_SCT(sct, read);
    UNHOOK_SCT(sct, write);
    enable_wp();

    fm_alert("%s\n", "Farewell the World!");

    return;
}

asmlinkage long fake_link(const char __user *oldname, const char __user *newname)
{
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_struct_task(current, newname, full_new);
    get_simplified_path_from_struct_task(current, oldname, full_old);
    if ((is_target(full_old) || is_target(full_new)))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] link: from-%s to-%s\n", full_old, full_new);
        else
        {
            fm_alert("[Invaild] link: from-%s to-%s, pid:%d ,uid:%d\n", full_old, full_new, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_link(oldname, newname);
}
asmlinkage long fake_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)
{
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_directory_fd(newdfd, current, newname, full_new);
    get_simplified_path_from_directory_fd(olddfd, current, oldname, full_old);
    if ((is_target(full_old) || is_target(full_new)))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] linkat: from-%s to-%s\n", full_old, full_new);
        else
        {
            fm_alert("[Invaild] linkat: from-%s to-%s, pid:%d ,uid:%d\n", full_old, full_new, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_linkat(olddfd, oldname, newdfd, newname, flags);
}
asmlinkage long fake_symlink(const char __user *old, const char __user *new)
{
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_struct_task(current, new, full_new);
    get_simplified_path_from_struct_task(current, old, full_old);
    if ((is_target(full_old) || is_target(full_new)))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] symlink: from-%s to-%s\n", full_old, full_new);
        else
        {
            fm_alert("[Invaild] symlink: from-%s to-%s, pid:%d ,uid:%d\n", full_old, full_new, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_symlink(old, new);
}
asmlinkage long fake_symlinkat(const char __user *oldname, int newdfd, const char __user *newname)
{
    char full_new[PATH_MAX];
    char full_old[PATH_MAX];
    get_simplified_path_from_struct_task(current, newname, full_new);
    get_simplified_path_from_directory_fd(newdfd, current, oldname, full_old);
    if ((is_target(full_old) || is_target(full_new)))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] symlinkat: from-%s to-%s\n", full_old, full_new);
        else
        {
            fm_alert("[Invaild] symlinkat: from-%s to-%s, pid:%d ,uid:%d\n", full_old, full_new, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_symlinkat(oldname, newdfd, newname);
}
asmlinkage long fake_unlink(const char __user *pathname)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current, pathname, full);
    if (is_target(full) && is_user_valid())
    {
        if (is_process_valid(current))
            fm_alert("[Vaild] unlink: %s\n", full);
        else
        {
            fm_alert("[Invaild] unlink: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_unlink(pathname);
}
asmlinkage long fake_unlinkat(int dfd, const char __user *pathname, int flag)
{
    char full[PATH_MAX];
    get_simplified_path_from_directory_fd(dfd, current, pathname, full);
    if (is_target(full) && is_user_valid())
    {
        if (is_process_valid(current))
            fm_alert("[Vaild] unlinkat: %s\n", full);
        else
        {
            fm_alert("[Invaild] unlinkat: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_unlinkat(dfd, pathname, flag);
}

asmlinkage long fake_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            char *decrypted = kmalloc(count, GFP_KERNEL);
            single_encrypt(DEFAULT_PASS, buf, decrypted, count);
            mm_segment_t old_fs;
            old_fs = get_fs();
            set_fs(KERNEL_DS);
            long ret = real_pwrite64(fd, decrypted, count, pos);
            set_fs(old_fs);
            fm_alert("[Vaild] pwrite64:%s\n", path);
            return ret;
        }
        else
        {
            fm_alert("[Invaild] pwrite64: %s, pid:%d, uid:%d\n", path, current->pid, current_uid().val);
            return -28;
        }
    }

    return real_pwrite64(fd, buf, count, pos);
}
asmlinkage long fake_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            long ret = real_pread64(fd, buf, count, pos);
            single_decrypt(DEFAULT_PASS, buf, buf, ret);
            fm_alert("[Vaild] pread64:%s\n", path);
            return ret;
        }
        else
        {
            fm_alert("[Invaild] pread64: %s, pid:%d, uid:%d\n", path, current->pid, current_uid().val);
            return -28;
        }
    }

    return real_pread64(fd, buf, count, pos);
}

asmlinkage long fake_read(unsigned int fd, char __user *buf, size_t count)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            long ret = real_read(fd, buf, count);
            single_decrypt(DEFAULT_PASS, buf, buf, ret);
            fm_alert("[Vaild] read:%s\n", path);
            return ret;
        }
        else
        {
            fm_alert("[Invaild] read: %s, pid:%d, uid:%d\n", path, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_read(fd, buf, count);
}
asmlinkage long fake_write(unsigned int fd, const char __user *buf, size_t count)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            char *decrypted = kmalloc(count, GFP_KERNEL);
            single_encrypt(DEFAULT_PASS, buf, decrypted, count);
            mm_segment_t old_fs;
            old_fs = get_fs();
            set_fs(KERNEL_DS);
            long ret = real_write(fd, decrypted, count);
            set_fs(old_fs);
            fm_alert("[Vaild] write:%s\n", path);
            return ret;
        }
        else
        {
            fm_alert("[Invaild] write: %s, pid:%d, uid:%d\n", path, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_write(fd, buf, count);
}

asmlinkage long fake_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current, filename, full);
    if (is_target(full))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] lstat: %s\n", full);
        else
        {
            fm_alert("[Invaild] mkdir: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_lstat(filename, statbuf);
}
asmlinkage long fake_newfstatat(int dfd, const char __user *filename, struct stat __user *statbuf, int flag)
{
    char full[PATH_MAX];
    get_simplified_path_from_directory_fd(dfd, current, filename, full);
    if (is_target(full) && is_user_valid())
    {
        if (is_process_valid(current))
            fm_alert("[Vaild] newfstatat: %s\n", full);
        else
        {
            fm_alert("[Invaild] newfstatat: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_newfstatat(dfd, filename, statbuf, flag);
}
asmlinkage long fake_rename(const char __user *oldname, const char __user *newname)
{
    char full_old[PATH_MAX];
    char full_new[PATH_MAX];
    get_simplified_path_from_struct_task(current, oldname, full_old);
    get_simplified_path_from_struct_task(current, newname, full_new);

    if ((is_target(full_old) || is_target(full_new)))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] rename: from-%s to-%s\n", full_old, full_new);
        else
        {
            fm_alert("[Invaild] rename: from-%s to-%s, pid%d, uid%d\n", full_old, full_new, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_rename(oldname, newname);
}

asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current, pathname, full);
    if (is_target(full))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] mkdir: %s\n", full);
        else
        {
            fm_alert("[Invaild] mkdir: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_mkdir(pathname, mode);
}
asmlinkage long fake_creat(const char __user *pathname, umode_t mode)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current, pathname, full);
    if (is_target(full))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            long ret = real_creat(pathname, mode);
            if (ret > 0)
            { //open succeeded
                opened_file_count++;
                fm_alert("[Vaild] creat: %s\n", full);
                fm_alert("[Vaild] files: %d\n", opened_file_count);
            }
            return ret;
        }
        else
        {
            fm_alert("[Invaild] creat: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_creat(pathname, mode);
}
asmlinkage long fake_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{

    char full[PATH_MAX];
    get_simplified_path_from_directory_fd(dfd, current, filename, full);
    if (is_target(full))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            long ret = real_openat(dfd, filename, flags, mode);
            if (ret > 0)
            { //openat succeeded
                opened_file_count++;
                fm_alert("[Vaild] openat: %s\n", full);
                fm_alert("[Vaild] files: %d\n", opened_file_count);
            }
            return ret;
        }
        else
        {
            fm_alert("[Invaild] openat: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_openat(dfd, filename, flags, mode);
}
asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current, filename, full);
    if (is_target(full))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            long ret = real_open(filename, flags, mode);
            if (ret > 0)
            { //open succeeded
                opened_file_count++;
                fm_alert("[Vaild] open: %s\n", full);
                fm_alert("[Vaild] files: %d\n", opened_file_count);
            }
            return ret;
        }
        else
        {
            fm_alert("[Invaild] open: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_open(filename, flags, mode);
}
asmlinkage long fake_close(unsigned int fd)
{
    char path[PATH_MAX];
    get_filename_from_fd(current, fd, path);
    if (is_target(path))
    {
        if (is_process_valid(current) && is_user_valid())
        {
            long ret = real_close(fd);
            if (ret == 0)
            { //close succeeded
                opened_file_count--;
                fm_alert("[Vaild] close: %s,fd:%d\n", path, fd);
                fm_alert("[Vaild] files: %d\n", opened_file_count);
            }
            return ret;
        }
        else
        {
            fm_alert("[Invaild] close: %s, pid:%d, uid:%d\n", path, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_close(fd);
}
asmlinkage long fake_chdir(const char __user *filename)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current, filename, full);
    if (is_target(full))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] chdir: %s\n", full);
        else
        {
            fm_alert("[Invaild] chdir: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_chdir(filename);
}
asmlinkage long fake_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    char full[PATH_MAX];
    get_simplified_path_from_struct_task(current, filename, full);
    if (is_target(full))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] stat: %s\n", full);
        else
        {
            fm_alert("[Invaild] getdents: %s, pid:%d, uid:%d\n", full, current->pid, current_uid().val);
            return -28;
        }
    }
    return real_stat(filename, statbuf);
}

asmlinkage long
fake_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
    char pathname[PATH_MAX];
    get_filename_from_fd(current, fd, pathname);
    long ret;
    ret = real_getdents(fd, dirent, count);
    if (is_target(pathname))
    {
        if (is_process_valid(current) && is_user_valid())
            fm_alert("[Vaild] getdents: %s\n", pathname);
        else
        {
            fm_alert("[Invaild] getdents: %s, pid:%d, uid:%d\n", pathname, current->pid, current_uid().val);
            return 0;
        }
    }
    if (!strcmp(pathname, SAFE_PARENT_DIR_NO_SLASH) || !strcmp(pathname, SAFE_PARENT_DIR_SLASH))
    {
        ret = remove_dent(SAFE_FILENAME, dirent, ret);
        fm_alert("[Invaild] getdents: %s, pid:%d, uid:%d\n", pathname, current->pid, current_uid().val);
    }
    return ret;
}
