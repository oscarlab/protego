#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_setuid_policies.h"

int main(int argc, char* argv[])
{
	struct fstab_info fstab;
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
	fstab.source = argv[1];
	fstab.dest = argv[2];
	fstab.is_user = atoi(argv[3]);

    filedesc = open("/proc/policy/mount", O_WRONLY);
    if(filedesc < 0)
        return -1;

    if((len = write(filedesc, (char *)(&fstab), sizeof(fstab), NULL)) != sizeof(fstab))
    {
        printf("There was an error writing to /proc/policy/setuid : %d\n",len);
        return -1;
    }
    close(filedesc);

    return 0;
}

int usage()
{
	printf("\nproc_mount_writer <source> <destination> <is_user>\n");
}
