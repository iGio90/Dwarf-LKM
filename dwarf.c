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
int file_size(char *path);
int file_sync(struct file *fp);
int file_to_buf(char *path, char *out);
int file_write(struct file *fp, unsigned long long offset, unsigned char *data, unsigned int size);

// ftrace
int _ftrace_enabled(void *out);
int ftrace_available_tracers(void *out);
int ftrace_opt(void *out);
int ftrace_set_current_events(char *events);
int ftrace_set_current_filters(char *filters);
int ftrace_set_current_pid(char *pid);
int ftrace_set_current_tracer(char *tracer);
int ftrace_set_enabled(char *enabled);
int ftrace_set_opt(char *opt);
int ftrace_set_tracing(char *tracing);
int ftrace_tracing(void *out);

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
        } else if (strcmp(buf, "ftrace") == 0) {
            return parse_kdwarf_ftrace(buf, tok, out);
        }
    }

    kfree(ttok);
    return 0;
}

int parse_kdwarf_ftrace(char *buf, char *tok, void *out) {
    buf = strsep(&tok, " ");
    if (buf != NULL) {
        if (strcmp(buf, "enabled") == 0) {
            return _ftrace_enabled(out);
        } else if (strcmp(buf, "tracing") == 0) {
            return ftrace_tracing(out);
        } else if (strcmp(buf, "opt") == 0) {
            return ftrace_opt(out);
        } else if (strcmp(buf, "tracers") == 0) {
            return ftrace_available_tracers(out);
        } else if (strcmp(buf, "setevents") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                return ftrace_set_current_events(buf);
            }
        } else if (strcmp(buf, "setfilters") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                return ftrace_set_current_filters(buf);
            }
        } else if (strcmp(buf, "setpid") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                return ftrace_set_current_pid(buf);
            }
        } else if (strcmp(buf, "settracer") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                return ftrace_set_current_tracer(buf);
            }
        } else if (strcmp(buf, "setenabled") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                return ftrace_set_enabled(buf);
            }
        } else if (strcmp(buf, "setopt") == 0) {
            buf = strsep(&tok, " ");
            if (buf != NULL) {
                return ftrace_set_opt(buf);
            }
        } else if (strcmp(buf, "trace") == 0) {
            return ftrace_set_tracing("1");
        } else if (strcmp(buf, "stop") == 0) {
            ftrace_set_tracing("0");
            return ftrace_set_current_tracer("nop");
        }
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

int file_to_buf(char *path, char *out) {
    int size, ret;
    struct file *fp = file_open(path, O_RDONLY, 0);

    if (fp != NULL) {
        size = file_size(path);
        if (!size) {
            size = HANDLER_BUF_SIZE * 4;
        }

        ret = file_read(fp, 0, out, size);
        file_close(fp);
    }

    return ret;
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

int file_size(char *path) {
    struct kstat stat;
    mm_segment_t oldfs;
    int error;

    oldfs = get_fs();
    set_fs(get_ds());

    error = vfs_stat(path, &stat);
    set_fs(oldfs);

    if (!error) {
        return stat.size;
    }
    return -1;
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

/**
 * ftrace
 */
int _ftrace_enabled(void *out) {
    return file_to_buf("/proc/sys/kernel/ftrace_enabled", out);
}

int ftrace_available_tracers(void *out) {
    return file_to_buf("/sys/kernel/debug/tracing/available_tracers", out);
}

int ftrace_tracing(void *out) {
    return file_to_buf("/sys/kernel/debug/tracing/tracing_on", out);
}

int ftrace_opt(void *out) {
    return file_to_buf("/sys/kernel/debug/tracing/trace_options", out);
}

int ftrace_set_current_events(char *events) {
    return buf_to_file("/sys/kernel/debug/tracing/set_event", events);
}

int ftrace_set_current_filters(char *filters) {
    return buf_to_file("/sys/kernel/debug/tracing/set_ftrace_filter", filters);
}

int ftrace_set_current_pid(char *pid) {
    buf_to_file("/sys/kernel/debug/tracing/set_event_pid", pid);
    return buf_to_file("/sys/kernel/debug/tracing/set_ftrace_pid", pid);
}

int ftrace_set_current_tracer(char *tracer) {
    return buf_to_file("/sys/kernel/debug/tracing/current_tracer", tracer);
}

int ftrace_set_enabled(char *enabled) {
    return buf_to_file("/proc/sys/kernel/ftrace_enabled", enabled);
}

int ftrace_set_opt(char *opt) {
    return buf_to_file("/sys/kernel/debug/tracing/trace_options", opt);
}

int ftrace_set_tracing(char *tracing) {
    return buf_to_file("/sys/kernel/debug/tracing/tracing_on", tracing);
}

static int __init dwarf_init(void) {
    int ret;

    kptr_unrestrict();
    disable_selinux();

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