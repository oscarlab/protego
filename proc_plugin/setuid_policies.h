#ifndef __SETUID_POLICIES_H__
#define __SETUID_POLICIES_H__

#include "uidgid.h"
#include <linux/list.h>
struct sudoers_info
{
  /* User who is allowed to execute sudo  - should not be invalid*/
  kuid_t original_uid;
  /* user to which su is allowed  - can be invalid*/
  kuid_t runas_uid;
  /* comma separated commands that user can execute  - can be null to indicate all commands*/
  char* commands;
  /* is NOPASSWD flag mentioned?*/
  int nopass;

  struct list_head list; /* kernel's list structure */
};

struct fstab_info
{
	char* source;
	char* dest;
	int is_user;
    struct list_head list; /* kernel's list structure */
};
#endif /* __SETUID_POLICIES_H__ */
