#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/dm-ioctl.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include "setuid_policies.h"

#define MAX_LEN       4096
int setuid_read_info( char *page, char **start, off_t off,int count, int *eof, void *data );
int setuid_write_info( struct file *filp, const char __user *buff,unsigned long len, void *data );
int mount_read_info( char *page, char **start, off_t off,int count, int *eof, void *data );
int mount_write_info( struct file *filp, const char __user *buff,unsigned long len, void *data );

static struct proc_dir_entry *policy_dir, *setuid_entry, *mount_entry;
static struct sudoers_info *sudoers_head = NULL;
static struct fstab_info *fstab_head = NULL;

static struct file_operations dmcrypt_byuuid_file_ops;
static struct file_operations dmcrypt_byname_file_ops;
static struct file_operations dmcrypt_bydev_file_ops;

static struct proc_dir_entry *dmcrypt_dir, *dmcrypt_byuuid_entry,
			     *dmcrypt_byname_entry, *dmcrypt_bydev_entry;

static int open_dm_control_file(struct file **file);
static struct file *dm_control = NULL;

int init_module(void)
{
	int ret = 0;

	/* create the dir policy/ */
	policy_dir = proc_mkdir("policy", NULL);
	/* create the setuid/ and mount/ directories */
	setuid_entry = create_proc_entry("setuid", 0640, policy_dir);
	mount_entry = create_proc_entry("mount", 0640, policy_dir);

	ret = open_dm_control_file(&dm_control);
	if (!ret)
	{
		/* create the dir dmcrypt/ */
		dmcrypt_dir = proc_mkdir("dmcrypt", NULL);
		/* create the entries in dmcrypt dir */
		dmcrypt_byuuid_entry = create_proc_entry("by-uuid", 0444, dmcrypt_dir);
		dmcrypt_byname_entry = create_proc_entry("by-name", 0444, dmcrypt_dir);
		dmcrypt_bydev_entry = create_proc_entry("by-dev", 0444, dmcrypt_dir);
	}

	setuid_entry->read_proc = setuid_read_info;
	setuid_entry->write_proc = setuid_write_info;
	mount_entry->read_proc = mount_read_info;
	mount_entry->write_proc = mount_write_info;
	dmcrypt_byuuid_entry->proc_fops = &dmcrypt_byuuid_file_ops;
	dmcrypt_byname_entry->proc_fops = &dmcrypt_byname_file_ops;
	dmcrypt_bydev_entry->proc_fops = &dmcrypt_bydev_file_ops;
	printk(KERN_INFO "procEntry created.\n");
	printk(KERN_INFO "List size is %u.\n",sizeof(struct list_head));

	return ret;
}

void cleanup_module( void )
{
	struct sudoers_info *tmp;
	struct list_head *pos, *q;
    remove_proc_entry("setuid", policy_dir);
    remove_proc_entry("mount", policy_dir);
    remove_proc_entry("policy", NULL);
	if (dm_control)
	{
		remove_proc_entry("by-uuid", dmcrypt_dir);
		remove_proc_entry("by-name", dmcrypt_dir);
		remove_proc_entry("by-dev", dmcrypt_dir);
		remove_proc_entry("dmcrypt", NULL);
		filp_close(dm_control, 0);
	}
	printk(KERN_INFO "procEntry unloaded.\n");
	if(sudoers_head != NULL)
	{
		list_for_each_safe(pos, q, &sudoers_head->list){
			tmp = list_entry(pos, struct sudoers_info, list);
			list_del(pos);
			vfree(tmp);
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
		printk(KERN_INFO "buffer length is not as expected. Expected length is %u. Received length is %lu\n",sizeof(struct sudoers_info),len);
		return -1;
	}
    if(copy_from_user(sudoers_object, buff, len))
    {
		printk(KERN_INFO "Copying from user failed.\n");
        return -2;
    }
    command = (char *)vmalloc(strlen(sudoers_object->commands));
	memset(command, 0, strlen(sudoers_object->commands));
    if(copy_from_user(command, sudoers_object->commands, strlen(sudoers_object->commands)))
    {
		printk(KERN_INFO "Copying commands from user failed.\n");
        return -2;
    }
    sudoers_object->commands = command;

	printk(KERN_INFO "Received data ..... %d,%d,%s.\n",sudoers_object->original_uid,sudoers_object->runas_uid,sudoers_object->commands);
   	INIT_LIST_HEAD(&sudoers_object->list);

   	if(sudoers_head == NULL)
    {
		printk(KERN_INFO "Head null. configuring head.\n");
    	sudoers_head = sudoers_object;
    }
    else
    {
    	list_add_tail(&(sudoers_head->list), &(sudoers_object->list));
    }

    if(sudoers_head == NULL)
    {
		printk(KERN_INFO "Head is still null. write failed.\n");
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
	printk(KERN_INFO "Read called.\n");
	len += sprintf(page, "%s\t%s\t%s\n", "Original", "RunAs ID", "Commands");
	if(sudoers_head != NULL)
	{
		printk(KERN_INFO "Head is NOT null. Printing .... \n");
		len += sprintf(page+len,"%d\t\t%d\t\t%s\n", sudoers_head->original_uid, sudoers_head->runas_uid, sudoers_head->commands);
		list_for_each_entry(tmp, &sudoers_head->list, list)
		{
			printk(KERN_INFO "Inside list traversal .... \n");
			len += sprintf(page+len,"%d\t\t%d\t\t%s\n", tmp->original_uid, tmp->runas_uid, tmp->commands);
		}
	}
	else
	{
		printk(KERN_INFO "Head is null.\n");
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
		printk(KERN_INFO "buffer length is not as expected. Expected length is %u. Received length is %lu\n",sizeof(struct fstab_info),len);
		return -1;
	}
    if(copy_from_user(fstab_object, buff, len))
    {
		printk(KERN_INFO "Copying from user failed.\n");
        return -2;
    }
    src = (char *)vmalloc(strlen(fstab_object->source));
	memset(src, 0, strlen(fstab_object->source));
    if(copy_from_user(src, fstab_object->source, strlen(fstab_object->source)))
    {
		printk(KERN_INFO "Copying source from user failed.\n");
        return -2;
    }
    fstab_object->source = src;

    dst = (char *)vmalloc(strlen(fstab_object->dest));
	memset(dst, 0, strlen(fstab_object->dest));
    if(copy_from_user(dst, fstab_object->dest, strlen(fstab_object->dest)))
    {
		printk(KERN_INFO "Copying destination from user failed.\n");
        return -2;
    }
    fstab_object->dest = dst;

    printk(KERN_INFO "Received data ..... %s,%s,%d.\n",fstab_object->source,fstab_object->dest,fstab_object->is_user);
   	INIT_LIST_HEAD(&fstab_object->list);

   	if(fstab_head == NULL)
    {
		printk(KERN_INFO "Head null. configuring head.\n");
    	fstab_head = fstab_object;
    }
    else
    {
    	list_add_tail(&(fstab_head->list), &(fstab_object->list));
    }

    if(fstab_head == NULL)
    {
		printk(KERN_INFO "Head is still null. write failed.\n");
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
	printk(KERN_INFO "Read called.\n");
	len += sprintf(page, "%s\t%s\t%s\n", "Source", "Destination", "ISUSER");
	if(fstab_head != NULL)
	{
		printk(KERN_INFO "Head is NOT null. Printing .... \n");
		len += sprintf(page+len,"%s\t%s\t%d\n", fstab_head->source, fstab_head->dest, fstab_head->is_user);
		list_for_each_entry(tmp, &fstab_head->list, list)
		{
			printk(KERN_INFO "Inside list traversal .... \n");
			len += sprintf(page+len,"%s\t%s\t%d\n", tmp->source, tmp->dest, tmp->is_user);
		}
	}
	else
	{
		printk(KERN_INFO "Head is null.\n");
	}

    return len;
}

static int open_dm_control_file(struct file **file)
{
	struct file *dm_control;
	printk(KERN_INFO "open_dm_control_file\n");
	dm_control = filp_open("/dev/mapper/control", O_RDONLY, 0);
	if (IS_ERR(dm_control))
	{
		printk(KERN_INFO "CONTROL device not found, probably dm not loaded\n");
		return PTR_ERR(dm_control);
	}
	printk(KERN_INFO "open_dm_control_file done: %llx\n", dm_control);
	*file = dm_control;
	return 0;
}

static int do_dm_ioctl(struct file *dm_control, unsigned int command, struct dm_ioctl *params)
{
	int retval = 0;
	kernel_cap_t *cap = &current_cred()->cap_effective;
	int raised = 0;
	mm_segment_t old_fs = get_fs();

	params->data_start = sizeof(struct dm_ioctl);
	params->version[0] = DM_VERSION_MAJOR;
	params->version[1] = DM_VERSION_MINOR;
	params->version[2] = DM_VERSION_PATCHLEVEL;

	if (!cap_raised(*cap, CAP_SYS_ADMIN))
	{
		cap_raise(*cap, CAP_SYS_ADMIN);
		raised = 1;
	}
	set_fs(KERNEL_DS);
	retval = dm_control->f_op->unlocked_ioctl(dm_control, command, (unsigned long) params);
	set_fs(old_fs);
	if (raised)
		cap_lower(*cap, CAP_SYS_ADMIN);

	return retval;
}

static int dm_list_devices(struct file *dm_control, struct dm_ioctl **params)
{
	int retval, error = 0;
	unsigned int list_params_size = MAX_LEN;
	struct dm_ioctl *list_params;

	printk(KERN_INFO "dm_list_devices\n");
retry:
	printk(KERN_INFO "allocating list_params (size = %u)\n", list_params_size);
	list_params = (struct dm_ioctl *)vmalloc(list_params_size);
	if (list_params == NULL)
	{
		error = -ENOMEM;
		goto out;
	}
	printk(KERN_INFO "allocated list_params (size = %u) = %llx\n", list_params_size, list_params);
	memset(list_params, 0, list_params_size);
	list_params->data_size = list_params_size;
	printk(KERN_INFO "calling ioctl(DM_LIST_DEVICES) on dm_control\n");
	retval = do_dm_ioctl(dm_control, DM_LIST_DEVICES, list_params);
	if (retval < 0)
	{
		printk(KERN_INFO "calling ioctl(DM_LIST_DEVICES) failed on dm_control\n");
		vfree(list_params);
		error = retval;
		goto out;
	}
	if (list_params->flags & DM_BUFFER_FULL_FLAG)
	{
		printk(KERN_INFO "list_params out of buffer\n");
		vfree(list_params);
		list_params_size *= 2;
		goto retry;
	}
	printk(KERN_INFO "calling ioctl(DM_LIST_DEVICES) succeeded on dm_control\n");
	*params = list_params;
	printk(KERN_INFO "dm_list_devices done\n");
out:
	return error;
}

enum dm_info_type {
	DM_INFO_BYUUID,
	DM_INFO_BYNAME,
	DM_INFO_BYDEV,
};

struct dm_info_private {
	int			params_size;
	struct file *		dm_control;
	struct dm_ioctl *	list_params;
	enum dm_info_type	type;
};

static struct seq_operations dm_info_seq_ops;

static int dmcrypt_info_open(struct file *file, enum dm_info_type type)
{
	int retval;
	struct dm_ioctl *list_params = NULL;
	struct dm_info_private *priv;
	struct seq_file *seq;

	retval = dm_list_devices(dm_control, &list_params);
	if (retval)
		goto err;
	printk(KERN_INFO "finish listing device names\n");

	retval = seq_open(file, &dm_info_seq_ops);
	if (retval)
		goto err;

	seq = file->private_data;

	priv = (struct dm_info_private *)vmalloc(MAX_LEN);
	if (priv == NULL)
	{
		retval = -ENOMEM;
		goto err;
	}

	priv->params_size = MAX_LEN;
	priv->dm_control = dm_control;
	priv->list_params = list_params;
	priv->type = type;
	seq->private = priv;
	return 0;
err:
	if (dm_control)
		filp_close(dm_control, 0);
	if (list_params)
		vfree(list_params);
	return retval;
}

static int get_dm_info(struct seq_file *m, struct dm_name_list *nl)
{
	int retval = 0;
	struct dm_info_private *priv = m->private;
	struct dm_ioctl *params = m->private + sizeof(struct dm_info_private);
	int params_size = priv->params_size;
	struct dm_target_spec *dm_target;
	int i;

retry:
	memset(params, 0, params_size - sizeof(struct dm_info_private));
	params->data_size = params_size - sizeof(struct dm_info_private);
	strncpy(params->name, nl->name, DM_NAME_LEN);
	params->flags |= DM_STATUS_TABLE_FLAG;
	printk(KERN_INFO "calling ioctl(DM_TABLE_STATUS) for device %s\n", params->name);
	retval = do_dm_ioctl(priv->dm_control, DM_TABLE_STATUS, params);
	if (retval)
	{
		printk(KERN_INFO "calling ioctl(DM_TABLE_STATUS) failed (%d)\n", retval);
		goto out;
	}
	printk(KERN_INFO "calling ioctl(DM_TABLE_STATUS) suceeded\n");

	if (params->flags & DM_BUFFER_FULL_FLAG)
	{
		printk(KERN_INFO "dm_ioctl param runs out of buffer\n");
		params_size = params_size * 2;
		priv = (struct dm_info_private *)vmalloc(params_size);
		if (priv == NULL)
		{
			retval = -ENOMEM;
			goto out;
		}
		memcpy(priv, m->private, sizeof(struct dm_info_private));
		vfree(m->private);
		m->private = priv;
		params = m->private + sizeof(struct dm_info_private);
		priv->params_size = params_size;
		goto retry;
	}

	dm_target = (void *)params + params->data_start;
	for (i = 0 ; i < params->target_count ; i++)
	{
		printk(KERN_INFO "get dm_target_spec: %d %d %s\n", dm_target->sector_start, dm_target->length, dm_target->target_type);
		printk(KERN_INFO "get dm_target_spec description: %s\n", (char *)dm_target + sizeof(struct dm_target_spec));
		if (strncmp(dm_target->target_type, "crypt", DM_MAX_TYPE_NAME) == 0)
		{
			params->data_start = (void*)dm_target - (void *)params;
			break;
		}
		dm_target = (void *)dm_target + dm_target->next;
	}
out:
	return retval;
}

static void *dm_info_start(struct seq_file *m, loff_t *pos)
{
	int retval;
	struct dm_info_private *priv = m->private;
	struct dm_ioctl *list_params;
	struct dm_name_list *nl;
	printk(KERN_INFO "dm_info_start\n");
	if (!priv)
		return NULL;
	list_params = priv->list_params;
	nl = (void *)list_params + list_params->data_start;
	if (!nl->dev)
		return NULL;
	retval = get_dm_info(m, nl);
	if (retval)
		return NULL;
	printk(KERN_INFO "dm_info_start done\n");
	return nl;
}

static void *dm_info_next(struct seq_file *m, void *v, loff_t *pos)
{
	int retval;
	struct dm_info_private *priv = m->private;
	struct dm_name_list *nl = v;
	printk(KERN_INFO "dm_info_next\n");
	if (!priv || !nl->next)
		return NULL;
	nl = v + nl->next;
	if (!nl->dev)
		return NULL;
	retval = get_dm_info(m, nl);
	if (retval)
		return NULL;
	printk(KERN_INFO "dm_info_next done\n");
	return nl;
}

static int dm_info_show(struct seq_file *m, void *v)
{
	struct dm_info_private *priv = m->private;
	struct dm_ioctl *params;
	printk(KERN_INFO "dm_info_show\n");
	params = (void *)priv + sizeof(struct dm_info_private);
	switch (priv->type)
	{
		case DM_INFO_BYUUID:
			seq_printf(m, "%s", params->uuid);
			break;
		case DM_INFO_BYNAME:
			seq_printf(m, "%s", params->name);
			break;
		case DM_INFO_BYDEV:
			seq_printf(m, "%llu", params->dev);
			break;
	}
	if (params->data_start < params->data_size)
	{
		struct dm_target_spec *dm_target = (void *)params + params->data_start;
		char devname[16];
		char *sector = (void *)dm_target + sizeof(struct dm_target_spec);
		printk(KERN_INFO "get dm_target_spec description: %s\n", sector);
		sscanf(sector, "%*s %*s %*s %s %*s", devname);
		seq_printf(m, " %s", devname);
	}
	seq_printf(m, "\n");
	printk(KERN_INFO "dm_info_show done\n");
	return 0;
}

static void dm_info_stop(struct seq_file *m, void *v)
{
	struct dm_info_private *priv = m->private;
	printk(KERN_INFO "dm_info_stop\n");
	if (priv)
	{
		vfree(priv->list_params);
		vfree(priv);
		m->private = NULL;
		printk(KERN_INFO "dm_info_stop done\n");
	}
}

static struct seq_operations dm_info_seq_ops = {
		.start		= dm_info_start,
		.next		= dm_info_next,
		.show		= dm_info_show,
		.stop		= dm_info_stop,
	};

static int dmcrypt_byuuid_open(struct inode *inode, struct file *file)
{
	return dmcrypt_info_open(file, DM_INFO_BYUUID);

}

static struct file_operations dmcrypt_byuuid_file_ops = {
		.owner		= THIS_MODULE,
		.open		= dmcrypt_byuuid_open,
		.read		= seq_read,
		.llseek		= seq_lseek,
		.release	= seq_release,
	};

static int dmcrypt_byname_open(struct inode *inode, struct file *file)
{
	return dmcrypt_info_open(file, DM_INFO_BYNAME);

}

static struct file_operations dmcrypt_byname_file_ops = {
		.owner		= THIS_MODULE,
		.open		= dmcrypt_byname_open,
		.read		= seq_read,
		.llseek		= seq_lseek,
		.release	= seq_release,
	};

static int dmcrypt_bydev_open(struct inode *inode, struct file *file)
{
	return dmcrypt_info_open(file, DM_INFO_BYDEV);

}

static struct file_operations dmcrypt_bydev_file_ops = {
		.owner		= THIS_MODULE,
		.open		= dmcrypt_bydev_open,
		.read		= seq_read,
		.llseek		= seq_lseek,
		.release	= seq_release,
	};


