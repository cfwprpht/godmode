
#include "syscall.h"

extern "C" {
#include "unjail.h"
}

#define LIBRARY_IMPL (1)
#include "GODMODE.h"

// Unjail this process.
void freedom(void) {
	struct thread td;
	syscall(11, (void *)&unjail, &td);
}

// Do we need to sumon a comet ?
PRX_INTERFACE int Kamehameha(void) {
	int uid = syscall(24);
	if (uid != 0) freedom();
	return 0;
}