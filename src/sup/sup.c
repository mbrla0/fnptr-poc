#include "sup.h"
#include <errno.h>
#include <sys/ptrace.h>

int read_errno()
{
	return errno;
}

void clear_errno()
{
	errno = 0;
}
