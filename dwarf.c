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


/*
 * function declarations
 */
// dwarf
int kptr_unrestrict(void);
int parse_kdwarf_args(char *in, void *out);
int parse_kdwarf_ftrace(char *in, char *tok, void *out);

// file
void file_close(struct file *fp);
struct file *file_open(const char *path, int flags, int rights);
int buf_to_file(char *path, char *content);
int file_read(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size);
int file_size(struct file *fp);
int file_sync(struct file *fp);
int file_to_buf(char *path, char *out);
int file_write(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size);

// ftrace
int ftrace_available_tracers(void *out);
int ftrace_tracing(void *out);

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    char *in = kmalloc(256, GFP_KERNEL);
    void *out = kmalloc(256, GFP_KERNEL);
    int ret;

    ret = strncpy_from_user(in, (void *) regs->regs[0], HANDLER_BUF_SIZE);

    if (ret > 0) {
        printk(KERN_INFO "dwarf -> execve: %s\n", in);
        if (strcmp(in, "kdwarf") == 0) {
            ret = strncpy_from_user(in, (char *) regs->regs[1], HANDLER_BUF_SIZE);
            printk(KERN_INFO "dwarf -> parsing args: %s\n", in);
            parse_kdwarf_args(in, out);
            ret = copy_to_user((void *) regs->regs[2], out, HANDLER_BUF_SIZE);
        }
    }
    kfree(in);
    kfree(out);
    /* A dump_stack() here will give a stack backtrace */
    return 0;
}

int parse_kdwarf_args(char *in, void *out) {
    char *tok, *buf;
    unsigned long valx;

    tok = kstrdup(in, GFP_KERNEL);
    buf = strsep(&tok, " ");
    if (buf != NULL) {
        if (strcmp(buf, "available") == 0) {
            sprintf(out, "1 %s %s %s %s", utsname()->sysname, utsname()->version,
                utsname()->release, utsname()->machine);
        } else if (strcmp(buf, "kallsyms_lookup_name") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                valx = kallsyms_lookup_name(buf);
                memcpy(out, (uintptr_t*) &valx, sizeof(uintptr_t));
            }
        } else if (strcmp(buf, "ftrace") == 0) {
            parse_kdwarf_ftrace(buf, tok, out);
        }
    }

    kfree(tok);

    return 0;
}

int parse_kdwarf_ftrace(char *buf, char *tok, void *out) {
    buf = strsep(&tok, " ");
    if (buf != NULL) {
        if (strcmp(buf, "tracing") == 0) {
            ftrace_tracing(out);
        } else if (strcmp(buf, "tracers") == 0) {
            ftrace_available_tracers(out);
        }
    }
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
                printk(KERN_INFO "dwarf -> write res: %i", ret);
                file_sync(fp);
            }
        }
        file_close(fp);
    }
    return 0;
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
        return NULL;
    }
    return filp;
}

int file_read(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

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

int file_to_buf(char *path, char *out) {
    char *buf;
    int size;
    struct file *fp = file_open(path, O_RDONLY, 0);

    printk(KERN_INFO "dwarf -> open -> %s", path);
    if (fp != NULL) {
        size = file_size(fp);
        printk(KERN_INFO "dwarf -> open size -> %i", size);

        buf =  kmalloc(size, GFP_KERNEL);
        if (buf != NULL) {
            file_read(fp, 0, buf, size);
            printk(KERN_INFO "dwarf -> readed -> %s", buf);
            memcpy(out, buf, size);
            kfree(buf);
        }
        file_close(fp);
    }

    return 0;
}

int buf_to_file(char *path, char *content) {
    struct file *fp = file_open(path, O_WRONLY, 0);
    if (fp != NULL) {
        file_write(fp, 0, "0", strlen("0"));
        file_sync(fp);
        file_close(fp);
    }
    return 0;
}

void file_close(struct file *fp) {
    filp_close(fp, NULL);
}

int file_size(struct file *fp) {
    return vfs_llseek(fp, 0, SEEK_END);
}

int file_sync(struct file *fp) {
    vfs_fsync(fp, 0);
    return 0;
}

/**
 * ftrace
 */
int ftrace_available_tracers(void *out) {
    return file_to_buf("/sys/kernel/debug/tracing/available_tracers", out);
}

int ftrace_tracing(void *out) {
    return file_to_buf("/sys/kernel/debug/tracing/tracing_on", out);
}

static int __init dwarf_init(void) {
    int ret;

    kptr_unrestrict();
    printk(KERN_INFO "dwarf -> sys execve: 0x%p", (void *) kallsyms_lookup_name("SyS_execve"));

    execve_probe.pre_handler = handler_pre;
    execve_probe.addr = (kprobe_opcode_t *) kallsyms_lookup_name("SyS_execve");

    ret = register_kprobe(&execve_probe);
    if (ret < 0) {
        printk(KERN_INFO "dwarf -> cannot register probe on execve, returned %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "dwarf -> planted execve kprobe at %p\n", execve_probe.addr);
    return 0;
}


static void __exit dwarf_end(void) {
    unregister_kprobe(&execve_probe);
    printk(KERN_INFO "dwarf ->kprobe at %p unregistered\n", execve_probe.addr);
}

module_init(dwarf_init);
module_exit(dwarf_end);
MODULE_LICENSE("GPL");