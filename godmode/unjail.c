/*
*
*        _       _________ ______            _______  _______  _______  ______   _______  _______
*       ( \      \__   __/(  ___ \ |\     /|(  ___  )(       )(  ____ \(  ___ \ (  ____ )(  ____ \|\     /|
*       | (         ) (   | (   ) )| )   ( || (   ) || () () || (    \/| (   ) )| (    )|| (    \/| )   ( |
*       | |         | |   | (__/ / | (___) || |   | || || || || (__    | (__/ / | (____)|| (__    | | _ | |
*       | |         | |   |  __ (  |  ___  || |   | || |(_)| ||  __)   |  __ (  |     __)|  __)   | |( )| |
*       | |         | |   | (  \ \ | (   ) || |   | || |   | || (      | (  \ \ | (\ (   | (      | || || |
*       | (____/\___) (___| )___) )| )   ( || (___) || )   ( || (____/\| )___) )| ) \ \__| (____/\| () () |
*       (_______/\_______/|/ \___/ |/     \|(_______)|/     \|(_______/|/ \___/ |/   \__/(_______/(_______)
*
*
*
*/

#include "unjail.h"

#define FW_505

#define KERN_455_XFAST_SYSCALL		   0x3095D0
#define __prison0_455                  0x10399B0
#define __rootvnode_455                0x21AFA30
#define __printf_455                   0x17F30
#define KERN_505_XFAST_SYSCALL		   0x1C0
#define __prison0_501                  0x10986A0                         
#define __rootvnode_501                0x22C19F0
#define __printf_501                   0x435C70
#define KERN_505_XFAST_SYSCALL		   0x1C0
#define __prison0_505                  0x10986A0                         
#define __rootvnode_505                0x22C1A70
#define __printf_505                   0x436040

// Get Kernel Base Offset.
unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}

static inline int memcmp(const void *s1, const void *s2, size_t len) {
	size_t i;
	const unsigned char *p1 = (const unsigned char *)s1;
	const unsigned char *p2 = (const unsigned char *)s2;

	for (i = 0; i < len; i++)
		if (p1[i] != p2[i])
			return p1[i] - p2[i];

	return 0;
}

// Unjail 4.05
void *unjail(struct thread *td) {
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void *kernel_base = 0;
	uint64_t __prison0 = 0;
	uint64_t __rootvnode = 0;

	// Kernel base resolving followed by kern_printf resolving
	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		if (!memcmp((char*)(kernel_base + __printf_505), (char[12]) { 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D }, 12)) {
			__prison0 = __prison0_505;
			__rootvnode = __rootvnode_505;
		}
		else if (!memcmp((char*)(kernel_base + __printf_501), (char[12]) { 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D }, 12)) {
			__prison0 = __prison0_501;
			__rootvnode = __rootvnode_501;
		}
	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		if (!memcmp((char*)(kernel_base + __printf_455), (char[12]) { 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D }, 12)) {
			__prison0 = __prison0_455;
			__rootvnode = __rootvnode_455;
		}
	}

	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 = (void**)&kernel_ptr[__prison0];
	void** got_rootvnode = (void**)&kernel_ptr[__rootvnode];

	cred->cr_uid              = 0;
	cred->cr_ruid             = 0;
	cred->cr_rgid             = 0;
	cred->cr_groups[0]        = 0;
	cred->cr_prison           = *got_prison0;
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
	return 0;
}