#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/setuid_policies.h>

#define MAX_LEN       4096
int setuid_read_info( char *page, char **start, off_t off,int count, int *eof, void *data );
int setuid_write_info( struct file *filp, const char __user *buff,unsigned long len, void *data );
int mount_read_info( char *page, char **start, off_t off,int count, int *eof, void *data );
int mount_write_info( struct file *filp, const char __user *buff,unsigned long len, void *data );
int bind_read_info( char *page, char **start, off_t off,int count, int *eof, void *data );
int bind_write_info( struct file *filp, const char __user *buff,unsigned long len, void *data );
int pppd_read_info( char *page, char **start, off_t off,int count, int *eof, void *data );
int pppd_write_info( struct file *filp, const char __user *buff,unsigned long len, void *data );

static struct proc_dir_entry *policy_dir, *setuid_entry, *mount_entry, *bind_entry, *pppd_entry;
struct sudoers_info *sudoers_head = NULL;
struct fstab_info *fstab_head = NULL;
struct bind_info *bind_head = NULL;
int pppd_defaultroute = 1;

static int __init init_module(void)
{
	int ret = 0;

	/* create the dir policy/ */
	policy_dir = proc_mkdir("policy", NULL);
	/* create the setuid/ and mount/ directories */
	setuid_entry = create_proc_entry("setuid", 0640, policy_dir);
	mount_entry = create_proc_entry("mount", 0640, policy_dir);
	bind_entry = create_proc_entry("bind", 0640, policy_dir);
	pppd_entry = create_proc_entry("pppd", 0640, policy_dir);

	setuid_entry->read_proc = setuid_read_info;
	setuid_entry->write_proc = setuid_write_info;
	mount_entry->read_proc = mount_read_info;
	mount_entry->write_proc = mount_write_info;
	bind_entry->read_proc = bind_read_info;
	bind_entry->write_proc = bind_write_info;
	pppd_entry->read_proc = pppd_read_info;
	pppd_entry->write_proc = pppd_write_info;
//	printk(KERN_INFO "procEntry created.\n");
//	printk(KERN_INFO "List size is %lu.\n",sizeof(struct list_head));

	return ret;
}

void cleanup_module( void )
{
	struct sudoers_info *tmp;
	struct fstab_info *tmpfs;
	struct bind_info *tmpbind;
	struct list_head *pos, *q;
    remove_proc_entry("setuid", policy_dir);
    remove_proc_entry("mount", policy_dir);
    remove_proc_entry("bind", policy_dir);
    remove_proc_entry("pppd", policy_dir);
    remove_proc_entry("policy", NULL);
	printk(KERN_INFO "procEntry unloaded.\n");
	if(sudoers_head != NULL)
	{
		list_for_each_safe(pos, q, &sudoers_head->list){
			tmp = list_entry(pos, struct sudoers_info, list);
			list_del(pos);
			vfree(tmp->commands);
			vfree(tmp);
		}
	}
	if(fstab_head != NULL)
	{
		list_for_each_safe(pos, q, &fstab_head->list){
			tmpfs = list_entry(pos, struct fstab_info, list);
			list_del(pos);
			vfree(tmpfs->source);
			vfree(tmpfs->dest);
			vfree(tmpfs);
		}
	}

	if(bind_head != NULL)
	{
		list_for_each_safe(pos, q, &bind_head->list){
			tmpbind = list_entry(pos, struct bind_info, list);
			list_del(pos);
			vfree(tmpbind->path);
			vfree(tmpbind);
		}
	}
}

int setuid_write_info(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
	struct sudoers_info *sudoers_object = (struct sudoers_info *)vmalloc(sizeof(struct sudoers_info));
	char* command;
	memset(sudoers_object, 0, sizeof(struct sudoers_info));
	if(len != sizeof(struct sudoers_info))
	{
//		printk(KERN_INFO "buffer length is not as expected. Expected length is %lu. Received length is %lu\n",sizeof(struct sudoers_info),len);
		return -1;
	}
    if(copy_from_user(sudoers_object, buff, len))
    {
//		printk(KERN_INFO "Copying from user failed.\n");
        return -2;
    }
    command = (char *)vmalloc(strlen(sudoers_object->commands)+1);
	memset(command, 0, strlen(sudoers_object->commands)+1);
    if(copy_from_user(command, sudoers_object->commands, strlen(sudoers_object->commands)+1))
    {
//		printk(KERN_INFO "Copying commands from user failed.\n");
        return -2;
    }
    sudoers_object->commands = command;

//	printk(KERN_INFO "Received data ..... %d,%d,%d,%d,%s.\n",sudoers_object->original_uid,sudoers_object->runas_uid,sudoers_object->nopass,sudoers_object->sudoedit,sudoers_object->commands);
   	INIT_LIST_HEAD(&sudoers_object->list);

   	if(sudoers_head == NULL)
    {
//		printk(KERN_INFO "Head null. configuring head.\n");
    	sudoers_head = sudoers_object;
    }
    else
    {
    	list_add(&(sudoers_object->list), &(sudoers_head->list));
    }

    if(sudoers_head == NULL)
    {
//		printk(KERN_INFO "Head is still null. write failed.\n");
		return -3;
    }

    return len;
}

int setuid_read_info(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct sudoers_info *tmp;
    int len = 0;
    if (off > 0)
    {
        *eof = 1;
        return 0;
    }
//	printk(KERN_INFO "Read called.\n");
	len += sprintf(page, "%s\t%s\t%s\t%s\t\t%s\n", "Original", "RunAs ID", "NOPASSWD", "SUDOEDIT", "Commands");
	if(sudoers_head != NULL)
	{
//		printk(KERN_INFO "Head is NOT null. Printing .... \n");
		len += sprintf(page+len,"%d\t\t%d\t\t%d\t\t%d\t\t%s\n", sudoers_head->original_uid, sudoers_head->runas_uid, sudoers_head->nopass, sudoers_head->sudoedit, sudoers_head->commands);
		list_for_each_entry(tmp, &sudoers_head->list, list)
		{
//			printk(KERN_INFO "Inside list traversal .... \n");
			len += sprintf(page+len,"%d\t\t%d\t\t%d\t\t%d\t\t%s\n", tmp->original_uid, tmp->runas_uid, tmp->nopass, tmp->sudoedit, tmp->commands);
		}
	}
	else
	{
//		printk(KERN_INFO "Head is null.\n");
	}

    return len;
}

int mount_write_info(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
	struct fstab_info *fstab_object = (struct fstab_info *)vmalloc(sizeof(struct fstab_info));
	char *src, *dst;
	memset(fstab_object, 0, sizeof(struct fstab_info));
	if(len != sizeof(struct fstab_info))
	{
//		printk(KERN_INFO "buffer length is not as expected. Expected length is %lu. Received length is %lu\n",sizeof(struct fstab_info),len);
		return -1;
	}
    if(copy_from_user(fstab_object, buff, len))
    {
//		printk(KERN_INFO "Copying from user failed.\n");
        return -2;
    }
    src = (char *)vmalloc(strlen(fstab_object->source)+1);
	memset(src, 0, strlen(fstab_object->source)+1);
    if(copy_from_user(src, fstab_object->source, strlen(fstab_object->source)+1))
    {
//		printk(KERN_INFO "Copying source from user failed.\n");
        return -2;
    }
    fstab_object->source = src;

    dst = (char *)vmalloc(strlen(fstab_object->dest)+1);
	memset(dst, 0, strlen(fstab_object->dest)+1);
    if(copy_from_user(dst, fstab_object->dest, strlen(fstab_object->dest)+1))
    {
//		printk(KERN_INFO "Copying destination from user failed.\n");
        return -2;
    }
    fstab_object->dest = dst;

//    printk(KERN_INFO "Received data ..... %s,%s,%d.\n",fstab_object->source,fstab_object->dest,fstab_object->is_user);
   	INIT_LIST_HEAD(&fstab_object->list);

   	if(fstab_head == NULL)
    {
//		printk(KERN_INFO "Head null. configuring head.\n");
    	fstab_head = fstab_object;
    }
    else
    {
    	list_add(&(fstab_object->list), &(fstab_head->list));
    }

    if(fstab_head == NULL)
    {
//		printk(KERN_INFO "Head is still null. write failed.\n");
		return -3;
    }

    return len;
}

int mount_read_info(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct fstab_info *tmp;
    int len = 0;
    if (off > 0)
    {
        *eof = 1;
        return 0;
    }
//	printk(KERN_INFO "Read called.\n");
	len += sprintf(page, "%s\t%s\t%s\n", "Source", "Destination", "ISUSER");
	if(fstab_head != NULL)
	{
//		printk(KERN_INFO "Head is NOT null. Printing .... \n");
		len += sprintf(page+len,"%s\t%s\t%d\n", fstab_head->source, fstab_head->dest, fstab_head->is_user);
		list_for_each_entry(tmp, &fstab_head->list, list)
		{
//			printk(KERN_INFO "Inside list traversal .... \n");
			len += sprintf(page+len,"%s\t%s\t%d\n", tmp->source, tmp->dest, tmp->is_user);
		}
	}
	else
	{
//		printk(KERN_INFO "Head is null.\n");
	}

    return len;
}

int bind_write_info(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
	struct bind_info *bind_object = (struct bind_info *)vmalloc(sizeof(struct bind_info));
	char* path;
	memset(bind_object, 0, sizeof(struct bind_info));
	if(len != sizeof(struct bind_info))
	{
//		printk(KERN_INFO "buffer length is not as expected. Expected length is %lu. Received length is %lu\n",sizeof(struct bind_info),len);
		return -1;
	}
    if(copy_from_user(bind_object, buff, len))
    {
//		printk(KERN_INFO "Copying from user failed.\n");
        return -2;
    }
    path = (char *)vmalloc(strlen(bind_object->path)+1);
	memset(path, 0, strlen(bind_object->path)+1);
    if(copy_from_user(path, bind_object->path, strlen(bind_object->path)+1))
    {
//		printk(KERN_INFO "Copying path from user failed.\n");
        return -2;
    }
    bind_object->path = path;

//	printk(KERN_INFO "Received data ..... %d,%d,%s.\n",bind_object->port,bind_object->user,bind_object->path);
   	INIT_LIST_HEAD(&bind_object->list);

   	if(bind_head == NULL)
    {
//		printk(KERN_INFO "Head null. configuring head.\n");
    	bind_head = bind_object;
    }
    else
    {
    	list_add(&(bind_object->list), &(bind_head->list));
    }

    if(bind_head == NULL)
    {
//		printk(KERN_INFO "Head is still null. write failed.\n");
		return -3;
    }

    return len;
}

int bind_read_info(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	struct bind_info *tmp;
    int len = 0;
    if (off > 0)
    {
        *eof = 1;
        return 0;
    }
//	printk(KERN_INFO "Read called.\n");
	len += sprintf(page, "%s\t%s\t%s\n", "Port", "User ID", "Path");
	if(bind_head != NULL)
	{
//		printk(KERN_INFO "Head is NOT null. Printing .... \n");
		len += sprintf(page+len,"%d\t\t%d\t\t%s\n", bind_head->port, bind_head->user, bind_head->path);
		list_for_each_entry(tmp, &bind_head->list, list)
		{
			printk(KERN_INFO "Inside list traversal .... \n");
			len += sprintf(page+len,"%d\t\t%d/t/t%s\n", tmp->port, tmp->user, tmp->path);
		}
	}
	else
	{
//		printk(KERN_INFO "Head is null.\n");
	}

    return len;
}

int pppd_write_info(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
	if(len != sizeof(pppd_defaultroute))
	{
//		printk(KERN_INFO "buffer length is not as expected. Expected length is %lu. Received length is %lu\n",sizeof(struct bind_info),len);
		return -1;
	}
    if(copy_from_user(&pppd_defaultroute, buff, len))
    {
//		printk(KERN_INFO "Copying from user failed.\n");
        return -2;
    }
    return len;
}

int pppd_read_info(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    if (off > 0)
    {
        *eof = 1;
        return 0;
    }
//	printk(KERN_INFO "Read called.\n");
	len += sprintf(page, "%s\n", "Default Route");
//		printk(KERN_INFO "Head is NOT null. Printing .... \n");
	len += sprintf(page+len,"%d\n", pppd_defaultroute);
    return len;
}
module_init(init_module);
