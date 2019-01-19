My kernel module for ARM / ARM64 to get some help from the kernel while debugging analysing userspace malware / apps packed.
The logic is simple and could sound stupid as it's my first work on the linux kernel.
I'm hijacking execve syscall, it give us 3 arguments which we can parse and do stuffs if conditions are met.
To provide data back to the user space program (dwarf debugger) we allocate a buffer which we provide in the 3rd argument.
This buffer is feeded by the kernel with the needed data.

The final goal is to expose api to Dwarf debugger to use ftrace and kprobes dynamically from within a debugging session.
It obviously required a kernel with modules enabled which flags to disable signature and maps verification as it's meant to works
on different system maps.