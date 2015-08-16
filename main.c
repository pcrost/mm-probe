#define _GNU_SOURCE

#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

static bool segfaulted;

#define PAGE_SIZE (sysconf(_SC_PAGE_SIZE))
#define PAGE_MASK (~(uintptr_t)(PAGE_SIZE - 1))

static void segv_handler(int signo, siginfo_t *info, void *opaque)
{
    mcontext_t *ctx = &((ucontext_t *)opaque)->uc_mcontext;

    if (signo == SIGSEGV) {
        int i;

        fprintf(stderr, "segfaulted addr is %p\n", info->si_addr);
        mprotect((uintptr_t)info->si_addr & PAGE_MASK, 1,
                 PROT_READ | PROT_WRITE);
        perror("unprotecting segafaulted addess");
        segfaulted = true;
    }
}

static void check_access(void *address, bool fault_expected)
{
    int *iptr = (int *)address;
    int readback;
    int checkval = 0xDEADBEEF;

    segfaulted = false;
    
    fprintf(stderr, "testing address %p = %x\n", iptr, checkval);
    *iptr = checkval;
    readback = *iptr;
    if (readback != checkval) {
        fprintf(stderr, "readback of %p, exp: %x act: %x\n",
                checkval, readback);
        exit(1);
    }

    if (segfaulted != fault_expected) {
        fprintf(stderr, "unexpected fault status, exp:%s act: %s\n",
                fault_expected ? "Y" : "N", segfaulted ? "Y" : "N");
        exit(1);
    }
}

#define UNPROTECTED_PAGE_LOC    ((1 << 12) * 20)
#define REMAPPED_PAGE_LOC       ((1 << 12) * 54)

int main(void)
{
    void *mapping, *mapsmall;

    struct sigaction segv_action = {
        .sa_sigaction = segv_handler,
        .sa_flags = SA_SIGINFO,
    };

    sigaction(SIGSEGV, &segv_action, NULL);

    fprintf(stderr, "hello world\n");

    mapping = mmap(NULL, 1ull << 32, PROT_NONE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    perror("big PROT_NONE mmap:");
    fprintf(stderr, "mapping at %p\n", mapping);

    mprotect(mapping + UNPROTECTED_PAGE_LOC, PAGE_SIZE, PROT_WRITE);
    perror("mark of big mmap PROT_WRITE");

    mapsmall = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    perror("little PROT_RW mmap");

    mremap(mapsmall, PAGE_SIZE, PAGE_SIZE, MREMAP_MAYMOVE | MREMAP_FIXED,
           mapping + REMAPPED_PAGE_LOC);
    perror("little map mremap");

    check_access(mapping + UNPROTECTED_PAGE_LOC, false);    
    check_access(mapping + REMAPPED_PAGE_LOC, false);
    check_access(mapping + (UNPROTECTED_PAGE_LOC +
                            REMAPPED_PAGE_LOC) / 2, true);
    check_access(mapping + (UNPROTECTED_PAGE_LOC +
                            REMAPPED_PAGE_LOC), true);
    check_access(mapping + (UNPROTECTED_PAGE_LOC +
                            REMAPPED_PAGE_LOC) / 2, false);
    check_access(mapping + (UNPROTECTED_PAGE_LOC +
                            REMAPPED_PAGE_LOC), false);
    check_access(mapping + UNPROTECTED_PAGE_LOC, false);    
    check_access(mapping + REMAPPED_PAGE_LOC, false);
}
