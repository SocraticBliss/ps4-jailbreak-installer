#include <ps4.h>

#include "fw_defines.h"

#define FW_505

#define X86_CR0_WP (1 << 16)

#define JOIN_HELPER(x, y) x##y
#define JOIN(x, y) JOIN_HELPER(x, y)

#define TYPE_PAD(size) char JOIN(_pad_, __COUNTER__)[size]
#define TYPE_VARIADIC_BEGIN(name) name { union {
#define TYPE_BEGIN(name, size) name { union { TYPE_PAD(size)
#define TYPE_END(...) }; } __VA_ARGS__
#define TYPE_FIELD(field, offset) struct { TYPE_PAD(offset); field; }

#define KSLIDE(offset) (void *)(kbase + offset);
#define KDATA(slide, name, type) type *name = KSLIDE(slide);

TYPE_BEGIN(struct sysent, 0x30);
	TYPE_FIELD(uint32_t sy_narg, 0x00);
	TYPE_FIELD(void *sy_call, 0x08);
	TYPE_FIELD(uint16_t sy_auevent, 0x10);
	TYPE_FIELD(uint64_t sy_systrace_args_func, 0x18);
	TYPE_FIELD(uint32_t sy_entry, 0x20);
	TYPE_FIELD(uint32_t sy_return, 0x24);
	TYPE_FIELD(uint32_t sy_flags, 0x28);
	TYPE_FIELD(uint32_t sy_thrcnt, 0x2C);
TYPE_END();

/* Structures */
struct auditinfo_addr {
	char useless[184];
};

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;		// effective user id
	uint32_t cr_ruid;		// real user id
	uint32_t useless2;
	uint32_t useless3;
	uint32_t cr_rgid;		// real group id
	uint32_t useless4;
	void *useless5;
	void *useless6;
	void *cr_prison;		// jail(2)
	void *useless7;
	uint32_t useless8;
	void *useless9[2];
	void *useless10;
	struct auditinfo_addr useless11;
	uint32_t *cr_groups;	// groups
	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    void *fd_rdir;
    void *fd_jdir;
};

struct proc {
	char useless[64];
	struct ucred *p_ucred;
	struct filedesc *p_fd;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

/* Attributes */
static inline __attribute__((always_inline)) void *curthread(void) {
	uint64_t td;
	__asm__ ("movq %0, %%gs:0" : "=r" (td) : : "memory");
	return (void*)td;
}

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}

/* Common */
uint64_t __readmsr(unsigned long __register) 
{
	uint32_t __edx;
	uint32_t __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

void notify(char *message)
{
	char buffer[512];
	sprintf(buffer, "%s\n\n\n\n\n\n\n", message);
	sceSysUtilSendSystemNotificationWithText(0x81, buffer);
}

/* Globals */
uint64_t xfast;
uint64_t prison0;
uint64_t rootvnode;
uint64_t sysent_off;

void **got_prison0;
void **got_rootvnode;

/* Functions */
int callforhelp(struct thread *td, void *uap)
{
	struct ucred *cred;
	struct filedesc *fd;

	td = curthread();
	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
		
	return 0;
}

uint64_t get_kbase()
{
    uint32_t edx, eax;
    __asm__ ("rdmsr" : "=d"(edx), "=a"(eax) : "c"(0xC0000082));
    return ((((uint64_t)edx) << 32) | (uint64_t)eax) - xfast;
}

void install_syscall(uint32_t n, void *func) 
{
	uint8_t *kbase = (uint8_t *)get_kbase();

	KDATA(sysent_off, sysents, struct sysent);
	
    struct sysent *p = &sysents[n];
    memset(p, NULL, sizeof(struct sysent));
    p->sy_narg = 8;
    p->sy_call = func;
    p->sy_thrcnt = 1;
}

int kpayload(struct thread *td)
{
	struct ucred *cred;
	struct filedesc *fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void *kernel_base = &((uint8_t *)__readmsr(0xC0000082))[-xfast];
	uint8_t *kernel_ptr = (uint8_t *)kernel_base;
	got_prison0 =   (void **)&kernel_ptr[prison0];
	got_rootvnode = (void **)&kernel_ptr[rootvnode];

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process
	
	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
	// 112 is international help number :)
    install_syscall(112, callforhelp);
	
	// Restore write protection
	writeCr0(cr0);
	
	return 0;
}

int get_fw_version()
{
    uint64_t name = 0x400000001;
    char kstring[64];
    size_t kstring_len = 64;

    sysctl((int *)&name, 2, kstring, &kstring_len, NULL, 0);
    char *split = strtok(kstring, " ");
    int split_len = strlen(split);

    int major = strtol(split + split_len - 6, NULL, 10);
    int minor = strtol(split + split_len - 3, NULL, 10);

    int fw_version = major * 100 + minor / 10;
    return fw_version;
}
// return: 505


int _main(struct thread *td)
{
	initKernel();
	initLibc();
	initNetwork();
	initPthread();
		
	int ver = get_fw_version();
	switch (ver) {
	case 505:
		xfast = KERN_505_XFAST_SYSCALL;
		prison0 = KERN_505_PRISON_0;
		rootvnode = KERN_505_ROOTVNODE;
		sysent_off = KERN_505_SYSENTS;
		break;
	case 501:
		xfast = KERN_501_XFAST_SYSCALL;
		prison0 = KERN_501_PRISON_0;
		rootvnode = KERN_501_ROOTVNODE;
		sysent_off = KERN_501_SYSENTS;
		break;
	case 500:
		xfast = KERN_500_XFAST_SYSCALL;
		prison0 = KERN_500_PRISON_0;
		rootvnode = KERN_500_ROOTVNODE;
		sysent_off = KERN_500_SYSENTS;
		break;
	case 474:
		xfast = KERN_474_XFAST_SYSCALL;
		prison0 = KERN_474_PRISON_0;
		rootvnode = KERN_474_ROOTVNODE;
		sysent_off = KERN_474_SYSENTS;
		break;
	case 455:
		xfast = KERN_455_XFAST_SYSCALL;
		prison0 = KERN_455_PRISON_0;
		rootvnode = KERN_455_ROOTVNODE;
		sysent_off = KERN_455_SYSENTS;
		break;
	case 405:
		xfast = KERN_405_XFAST_SYSCALL;
		prison0 = KERN_405_PRISON_0;
		rootvnode = KERN_405_ROOTVNODE;
		sysent_off = KERN_405_SYSENTS;
		break;
	case 355:
		xfast = KERN_355_XFAST_SYSCALL;
		prison0 = KERN_355_PRISON_0;
		rootvnode = KERN_355_ROOTVNODE;
		sysent_off = KERN_355_SYSENTS;
		break;
	case 350:
		xfast = KERN_350_XFAST_SYSCALL;
		prison0 = KERN_350_PRISON_0;
		rootvnode = KERN_350_ROOTVNODE;
		sysent_off = KERN_350_SYSENTS;
		break;
	default:
		break;
	}
	
	syscall(11, kpayload, td);
	
	initSysUtil();
	
	notify("jailbreak syscall 112 installed\ndial 112 to jailbreak");
	
	return 0;
}