#ifndef __USER_SETUID_POLICIES_H__
#define __USER_SETUID_POLICIES_H__


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#define LIST_SIZE 8
#define LIST_SIZE 16

struct sudoers_info
{
	/* User who is allowed to execute sudo  - should not be invalid*/
	int original_uid;
	/* user to which su is allowed  - can be invalid*/
	int runas_uid;
	/* comma separated commands that user can execute  - can be null to indicate all commands*/
	char *commands;
	/* is NOPASSWD flag mentioned?*/
	int nopass;
	/* is sudoedit flag mentioned?*/
	int sudoedit;

	char list_head[LIST_SIZE]; /* kernel's list structure */
};

struct fstab_info
{
	char *source;
	char *dest;
	int is_user;
	char list_head[LIST_SIZE]; /* kernel's list structure */
};

struct bind_info
{
	int port;
	int user;
	char *path;
	char list_head[LIST_SIZE]; /* kernel's list structure */
};

int pppd_defaultroute;

#endif /* __USER_SETUID_POLICIES_H__ */
