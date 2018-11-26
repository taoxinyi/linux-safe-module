#include "tools.h"


#define AES_BLOCK_SIZE 16
#define N 256

/**
 * @brief Get the filename (absolute) from struct path
 * 
 * @param filepath  the struct path
 * @param filename  the pointer of the filename, must allocate memory before calling it
 * @return int      whether the function succeeds
 */
int get_filename_from_struct_path(struct path *filepath, char *filename)
{   
    char *buf = (char *)__get_free_page(GFP_KERNEL);
    char *tmp_filename;
    if (!buf)
        return -1;
    tmp_filename = dentry_path_raw(filepath->dentry, buf, PATH_MAX - 1);
    
    if (IS_ERR(tmp_filename))
    {
        free_page((unsigned long)buf);
        return -1;
    }
    strcpy(filename, tmp_filename);
    free_page((unsigned long)buf);
    return 0;
}

/**
 * @brief Get the filename (absolute) from struct file
 * 
 * @param file      the struct file
 * @param filename  the pointer of the filename, must allocate memory before calling it
 * @return int      whether the function succeeds
 */
int get_filename_from_struct_file(struct file *file, char *filename)
{
    struct path filepath = file->f_path;
    return get_filename_from_struct_path(&filepath, filename);
}
/**
 * @brief Get the struct file from file descriptor fd in struct task_struct ts
 * 
 * @param ts                the struct task_struct  
 * @param fd                the file descriptor in ts
 * @return struct file*     the struct file
 */
struct file* get_struct_file_from_fd(struct task_struct *ts, unsigned int fd)
{   
    struct files_struct *files = ts->files;
    spin_lock(&files->file_lock);
    struct file *file = fcheck_files(files, fd);
    if (!file)
    {
        spin_unlock(&files->file_lock);
        return NULL;
    }
    spin_unlock(&files->file_lock);
    return file;
    
}

/**
 * @brief Get the filename from file descriptor fd in struct task_struct ts
 * 
 * @param ts        the struct task_struct
 * @param fd        the file descriptor in ts
 * @param filename  the pointer of the filename, must allocate memory before calling it
 * @return int      whether the function succeeds
 */
int get_filename_from_fd(struct task_struct *ts, unsigned int fd, char *filename)
{   
    struct file *file = get_struct_file_from_fd(ts, fd);
    if (!file)
        return -1;
    return get_filename_from_struct_file(file, filename);
    return 0;
}

/**
 * @brief Get the current working dir pathname from struct task_struct
 * 
 * @param ts        the struct task_struct
 * @param dir_path  the pointer of the directory pathname, must allocate memory before calling it
 * @return int      whether the function succeeds
 */
int get_current_working_dir(struct task_struct *ts, char *dir_path)
{
    struct path pwd;
    get_fs_pwd(ts->fs, &pwd);
    return get_filename_from_struct_path(&pwd, dir_path);
}
/**
 * @brief Get the absolute path from struct task_struct and given filename
 * 
 * @param ts                the struct task_struct
 * @param filename          the filename
 * @param absolute_path     the absolute path result
 * @return int*             whether the function succeeds
 */
int *get_absolute_path(struct task_struct *ts, const char *filename, char *absolute_path)
{

    if (!filename)
    { //filename error,return \0
        absolute_path[0] = '\0';
        return 0;
    }
    else if (filename[0] == '/') //already absolute path
    {
        strcpy(absolute_path, filename);
        return 0;
    }
    else
    { //relative path
        absolute_path[0] = '\0';
        get_current_working_dir(ts, absolute_path);
        if (absolute_path[strlen(absolute_path) - 1] != '/') //not endwith '/'
            strcat(absolute_path, "/");                      //add '/'
        strcat(absolute_path, filename);
        return 0;
    }
}
/**
 * @brief Get the simpified path from a absolutepath
 * 
 * @param absolute_path     the absolute path
 * @param simplified_path   the simplified path result
 * @return int              whether the function succeeds 
 */     
int get_simpified_path(const char *absolute_path,char *simplified_path)
{
    struct NODE *head = (struct NODE *)kmalloc(sizeof(struct NODE), GFP_KERNEL);
    head->nex = NULL;
    head->pre = NULL;
    struct NODE *tail = head;

    int i = 0;
    while (absolute_path[i++] != '\0')
    {
        int j = 0;
        char temp[PATH_MAX];
        while ((absolute_path[i] != '/') && (absolute_path[i] != '\0'))
        {
            temp[j++] = absolute_path[i++];
        }
        temp[j] = '\0';

        struct NODE *p = (struct NODE *)kmalloc(sizeof(struct NODE), GFP_KERNEL);
        p->s = (char *)kmalloc(strlen(temp) + 1, GFP_KERNEL);
        strcpy(p->s, temp);

        tail->nex = p;
        p->pre = tail;
        tail = tail->nex;
        p->nex = NULL;
    }

    struct NODE *p = head;
    while (p->nex != NULL)
    {
        if (strcmp(p->nex->s, "..") == 0)
        {
            if (p->pre == NULL)
            {
                struct NODE *q = p->nex;
                p->nex = p->nex->nex;
                if (p->nex->nex != NULL)
                {
                    p->nex->nex->pre = p;
                }
                kfree(q);
            }
            else
            {
                p = p->pre;
                struct NODE *q = p->nex;
                p->nex = q->nex->nex;
                if (q->nex->nex != NULL)
                {
                    q->nex->nex->pre = p;
                }
                struct NODE *k = q->nex;
                kfree(q);
                kfree(k);
            }
        }
        else if (strcmp(p->nex->s, ".") == 0)
        {
            struct NODE *q = p->nex;
            if (q->nex != NULL)
            {
                p->nex = q->nex;
                q->nex->pre = p;
                kfree(q);
            }
            else
            {
                p->nex = NULL;
                kfree(q);
            }
        }
        else
            p = p->nex;
        
    }
    struct NODE *a = head->nex;
    simplified_path[0] = '\0';
    while (a != NULL)
    {
        strcat(simplified_path, "/");
        strcat(simplified_path, a->s);
        a = a->nex;
    }
    return 0;
}

/**
 * @brief Get the simplified path from struct task and filename (either relative or absolute)
 * 
 * @param ts                the struct task_struct
 * @param filename          the filename
 * @param absolute_path     the absolute path result, must allocate memory before calling it
 * @return int              whether the function succeeds
 */
int get_simplified_path_from_struct_task(struct task_struct *ts,const char*filename,char* absolute_path)
{
    get_absolute_path(ts, filename, absolute_path);
    return get_simpified_path(absolute_path,absolute_path);
}
/**
 * @brief Get the simplified path from struct task and directory's file descriptor and filename (either relative or absolute)
 * 
 * @param dfd               the directory's file descriptor
 * @param ts                the struct task_struct
 * @param filename          the filename
 * @param absolute_path     the absolute path result, must allocate memory before calling it
 * @return int              whether the function succeeds
 */
int get_simplified_path_from_directory_fd(int dfd, struct task_struct *ts, const char *filename, char *absolute_path)
{
    if (filename[0] == '/')//already absolute
        strcpy(absolute_path, filename);
    else
    {   //relative
        get_filename_from_fd(ts, dfd, absolute_path);//directory path
        if (absolute_path[strlen(absolute_path) - 1] != '/') //not endwith '/'
            strcat(absolute_path, "/");                      //add '/'
        strcat(absolute_path, filename);
    }
    return get_simpified_path(absolute_path, absolute_path);
}
struct task_struct *get_struct_task_from_pid(int pid)
{
    struct pid *pid_struct;
    pid_struct = find_get_pid(pid);
    return pid_task(pid_struct, PIDTYPE_PID);
}
void swap_two_array(unsigned char *a, unsigned char *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}
int KSA(char *key, unsigned char *S, int n)
{

    int len = strlen(key);
    int j = 0;
    int i;
    for (i = 0; i < n; i++)
        S[i] = i;

    unsigned char tmp;
    for (i = 0; i < n; i++)
    {
        j = (j + S[i] + key[i % len]) % n;
        swap_two_array(&S[i],&S[j]);
    }

    return 0;
}
int get_encrypted(char *key, unsigned char *encrypted)
{
    KSA(key, encrypted, N);
    return 0;
}
int get_decrypted(char *key, unsigned char *decrypted)
{
    unsigned char S[N];
    int i;
    KSA(key, S, N);
    for (i = 0; i < N; i++)
        decrypted[S[i]] = i;
    return 0;
}
int single_encrypt(char *key, char *src, char *dst, long len)
{
    unsigned char encrypted[N];
    long i;
    get_encrypted(key, encrypted);
    for (i = 0; i < len; i++)
        dst[i] = encrypted[((unsigned char)src[i])];
    return 0;
}
int single_decrypt(char *key, char *src, char *dst, long len)
{
    unsigned char decrypted[N];
    long i;
    get_decrypted(key, decrypted);
    for (i = 0; i < len; i++)
        dst[i] = decrypted[((unsigned char)src[i])];
    return 0;
}

int aes_encrypt(unsigned char *key, unsigned char *src, unsigned char *dst, int size)
{
    struct crypto_cipher *tfm;
    tfm = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
    crypto_cipher_setkey(tfm, key, 32);
    unsigned char *plain = src;
    unsigned char *enc = dst;
    int count = size / AES_BLOCK_SIZE;
    int mod = size % AES_BLOCK_SIZE;
    if (mod > 0)
        count++;
    int i;
    for (i = 0; i < count; i++)
    {
        crypto_cipher_encrypt_one(tfm, enc, plain);
        plain += AES_BLOCK_SIZE;
        enc += AES_BLOCK_SIZE;
    }
    crypto_free_cipher(tfm);

    return count * AES_BLOCK_SIZE;
}
void aes_decrypt(unsigned char *key, unsigned char *src, unsigned char *dst, int size)
{
    struct crypto_cipher *tfm;
    tfm = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
    crypto_cipher_setkey(tfm, key, 32);
    unsigned char *plain = dst;
    unsigned char *enc = src;
    int count = size / AES_BLOCK_SIZE;
    int i;

    for (i = 0; i < count; i++)
    {
        crypto_cipher_decrypt_one(tfm, plain, enc);
        plain += AES_BLOCK_SIZE;
        enc += AES_BLOCK_SIZE;
    }
    crypto_free_cipher(tfm);
}
