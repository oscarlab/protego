#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_setuid_policies.h"

int main(int argc, char* argv[])
{
	struct bind_info bind;
	size_t filedesc;
	int len;
	if(argc < 4)
	{
		usage();
		return -1;
	}
	else
	{
		printf("\nArgc is %d\n",argc);
	}
	bind.port = atoi(argv[1]);
	bind.user = atoi(argv[2]);
	bind.path = argv[3];

    filedesc = open("/proc/policy/bind", O_WRONLY);
    if(filedesc < 0)
        return -1;

    if((len = write(filedesc, (char *)(&bind), sizeof(bind), NULL)) != sizeof(bind))
    {
        printf("There was an error writing to /proc/policy/bind : %d\n",len);
        return -1;
    }
    close(filedesc);

    return 0;
}

int usage()
{
	printf("\nproc_bind_writer <port> <user_id> <path>\n");
}
