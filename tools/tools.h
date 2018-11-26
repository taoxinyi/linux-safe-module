#ifndef TOOLS
#define TOOLS
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/crypto.h>
#include <linux/dirent.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
struct NODE
{
    char *s;
    struct NODE *nex;
    struct NODE *pre;
};
typedef struct Message
{
    char filename[4096];
    char password[128];
    int type;
} Message;
int get_simpified_path(const char *absolute_path, char *simplified_path);
int aes_encrypt(u8 *key, u8 *src, u8 *dst, int size);
void aes_decrypt(u8 *key, u8 *src, u8 *dst, int size);
int single_encrypt(char *key, char *src, char *dst, long length);
int single_decrypt(char *key, char *src, char *dst, long length);
int get_filename_from_struct_path(struct path *filepath, char *filename);
int get_filename_from_struct_file(struct file *file, char *filename);
struct file *get_struct_file_from_fd(struct task_struct *ts, unsigned int fd);
int get_filename_from_fd(struct task_struct *ts, unsigned int fd, char *filename);
int get_current_working_dir(struct task_struct *ts, char *dir_path);
int *get_absolute_path(struct task_struct *ts, const char *filename, char *absolute_path);
struct task_struct *get_struct_task_from_pid(int pid);
int get_simplified_path_from_struct_task(struct task_struct *ts, const char *filename, char *absolute_path);
int get_simplified_path_from_directory_fd(int dfd, struct task_struct *ts, const char *filename, char *absolute_path);

#endif
