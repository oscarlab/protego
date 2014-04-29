#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_setuid_policies.h"

int main(int argc, char* argv[])
{
	struct sudoers_info sudoer;
	size_t filedesc;
	int len;
	if(argc < 6)
	{
		usage();
		return -1;
	}
	else
	{
		printf("\nArgc is %d\n",argc);
	}
	sudoer.original_uid = atoi(argv[1]);
	sudoer.runas_uid = atoi(argv[2]);
	sudoer.commands = argv[3];
	sudoer.nopass = atoi(argv[4]);
	sudoer.sudoedit = atoi(argv[5]);

    filedesc = open("/proc/policy/setuid", O_WRONLY);
    if(filedesc < 0)
        return -1;

    if((len = write(filedesc, (char *)(&sudoer), sizeof(sudoer), NULL)) != sizeof(sudoer))
    {
        printf("There was an error writing to /proc/policy/setuid : %d\n",len);
        return -1;
    }
    close(filedesc);

    return 0;
}

int usage()
{
	printf("\nproc_setuid_writer <original_id> <runas_id> <commands> <is_nopass> <is_sudoedit>\n");
}
