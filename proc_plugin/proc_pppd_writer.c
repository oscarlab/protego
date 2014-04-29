#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_setuid_policies.h"

int main(int argc, char* argv[])
{
	size_t filedesc;
	int len;
	if(argc < 2)
	{
		usage();
		return -1;
	}
	else
	{
		printf("\nArgc is %d\n",argc);
	}
	pppd_defaultroute = atoi(argv[1]);

    filedesc = open("/proc/policy/pppd", O_WRONLY);
    if(filedesc < 0)
        return -1;

    if((len = write(filedesc, (char *)(&pppd_defaultroute), sizeof(pppd_defaultroute), NULL)) != sizeof(pppd_defaultroute))
    {
        printf("There was an error writing to /proc/policy/pppd : %d\n",len);
        return -1;
    }
    close(filedesc);

    return 0;
}

int usage()
{
	printf("\nproc_pppd_writer <isDefaultRoute>\n");
}
