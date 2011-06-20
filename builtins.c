/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <linux/kd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <linux/loop.h>
#include <dirent.h>
#include <libgen.h>
#include <limits.h>

#include "init.h"
#include "keywords.h"
#include "property_service.h"
#include "devices.h"

#include <private/android_filesystem_config.h>

void add_environment(const char *name, const char *value);
int copy(char *src, char *dst);

extern int init_module(void *, unsigned long, const char *);

static int write_file(const char *path, const char *value)
{
    int fd, ret, len;

    fd = open(path, O_WRONLY|O_CREAT, 0622);

    if (fd < 0)
        return -errno;

    len = strlen(value);

    do {
        ret = write(fd, value, len);
    } while (ret < 0 && errno == EINTR);

    close(fd);
    if (ret < 0) {
        return -errno;
    } else {
        return 0;
    }
}

static int insmod(const char *filename, char *options)
{
    void *module;
    unsigned size;
    int ret;

    module = read_file(filename, &size);
    if (!module)
        return -1;

    ret = init_module(module, size, options);

    free(module);

    return ret;
}

static int setkey(struct kbentry *kbe)
{
    int fd, ret;

    fd = open("/dev/tty0", O_RDWR | O_SYNC);
    if (fd < 0)
        return -1;

    ret = ioctl(fd, KDSKBENT, kbe);

    close(fd);
    return ret;
}

static int __ifupdown(const char *interface, int up)
{
    struct ifreq ifr;
    int s, ret;

    strlcpy(ifr.ifr_name, interface, IFNAMSIZ);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;

    ret = ioctl(s, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        goto done;
    }

    if (up)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    ret = ioctl(s, SIOCSIFFLAGS, &ifr);

done:
    close(s);
    return ret;
}

static void service_start_if_not_disabled(struct service *svc)
{
    if (!(svc->flags & SVC_DISABLED)) {
        service_start(svc, NULL);
    }
}

int do_chdir(int nargs, char **args)
{
    chdir(args[1]);
    return 0;
}

int do_chroot(int nargs, char **args)
{
    chroot(args[1]);
    return 0;
}

int do_class_start(int nargs, char **args)
{
        /* Starting a class does not start services
         * which are explicitly disabled.  They must
         * be started individually.
         */
    service_for_each_class(args[1], service_start_if_not_disabled);
    return 0;
}

int do_class_stop(int nargs, char **args)
{
    service_for_each_class(args[1], service_stop);
    return 0;
}

int do_domainname(int nargs, char **args)
{
    return write_file("/proc/sys/kernel/domainname", args[1]);
}

int do_exec(int nargs, char **args)
{
    return -1;
}

int do_export(int nargs, char **args)
{
    add_environment(args[1], args[2]);
    return 0;
}

int do_hostname(int nargs, char **args)
{
    return write_file("/proc/sys/kernel/hostname", args[1]);
}

int do_ifup(int nargs, char **args)
{
    return __ifupdown(args[1], 1);
}


static int do_insmod_inner(int nargs, char **args, int opt_len)
{
    char options[opt_len + 1];
    int i;

    options[0] = '\0';
    if (nargs > 2) {
        strcpy(options, args[2]);
        for (i = 3; i < nargs; ++i) {
            strcat(options, " ");
            strcat(options, args[i]);
        }
    }

    return insmod(args[1], options);
}

int do_insmod(int nargs, char **args)
{
    int i;
    int size = 0;

    if (nargs > 2) {
        for (i = 2; i < nargs; ++i)
            size += strlen(args[i]) + 1;
    }

    return do_insmod_inner(nargs, args, size);
}

int do_import(int nargs, char **args)
{
    return parse_config_file(args[1]);
}

int do_rmdir(int nargs, char **args)
{
    char *path = NULL;
    int rc = 0;

    if(nargs != 2)
        return -1;

    path = args[1];
    if(rmdir(path))
        return -errno;

    return 0;
}

int do_mkdir(int nargs, char **args)
{
    mode_t mode = 0755;

    /* mkdir <path> [mode] [owner] [group] */

    if (nargs >= 3) {
        mode = strtoul(args[2], 0, 8);
    }

    if (mkdir(args[1], mode)) {
        return -errno;
    }

    if (nargs >= 4) {
        uid_t uid = decode_uid(args[3]);
        gid_t gid = -1;

        if (nargs == 5) {
            gid = decode_uid(args[4]);
        }

        if (chown(args[1], uid, gid)) {
            return -errno;
        }
    }

    return 0;
}

static struct {
    const char *name;
    unsigned flag;
} mount_flags[] = {
    { "noatime",    MS_NOATIME },
    { "nosuid",     MS_NOSUID },
    { "nodev",      MS_NODEV },
    { "nodiratime", MS_NODIRATIME },
    { "ro",         MS_RDONLY },
    { "rw",         0 },
    { "remount",    MS_REMOUNT },
    { "defaults",   0 },
    { 0,            0 },
};


int mount_fs(char *system, char *source, char *target, unsigned flags, char *options)
{
    char tmp[64];
    struct stat info;
    int n;
    int rc = 0;

    INFO("mount_fs %s %s %s %d %s\n",system,source,target,flags,options);
    if (!strncmp(source, "mtd@", 4)) {
        n = mtd_name_to_number(source + 4);
        if (n < 0) {
            return -1;
        }

        sprintf(tmp, "/dev/mtdblock%d", n);
        if (stat(tmp, &info) < 0)
            sprintf(tmp, "/dev/block/mtdblock%d", n);

        INFO("%s is at %s\n",source,tmp);
        if (mount(tmp, target, system, flags, options) < 0)
            return -1;

        DIR *dp;
        struct dirent *ep;
        INFO("After mount lising of %s",target);
        dp = opendir (target);
        if (dp != NULL) {
           while ((ep = readdir (dp)))
           INFO("  %s",ep->d_name);
           (void) closedir (dp);
        } else {
          ERROR("Couldn't open the directory errno: %d",errno);
        }

        return 0;
    } else if (!strncmp(source, "loop@", 5)) {
        int mode, loop, fd;
        struct loop_info info;

        mode = (flags & MS_RDONLY) ? O_RDONLY : O_RDWR;
        fd = open(source + 5, mode);
        rc = -errno;
        if (fd < 0) {
            INFO("Could not open file %s\n",source);
            return rc;
        }

        for (n = 0; ; n++) {
            sprintf(tmp, "/dev/loop%d", n);

            loop = open(tmp, mode);
            rc = -errno;
            if (loop < 0) {
                INFO("Could not open loopback device %s\n",tmp);
                return rc;
            }

            /* if it is a blank loop device */
            if (ioctl(loop, LOOP_GET_STATUS, &info) < 0 && errno == ENXIO) {
                /* if it becomes our loop device */
                if (ioctl(loop, LOOP_SET_FD, fd) >= 0) {
                    close(fd);

                    if (mount(tmp, target, system, flags, options) < 0) {
                        rc = -errno;
                        ioctl(loop, LOOP_CLR_FD, 0);
                        close(loop);
                        INFO("Could not mount loopback %s\n",tmp);
                        return rc;
                    }

                    close(loop);
                    return 0;
                }
            }

            close(loop);
        }

        close(fd);
        INFO("Oups! could not mount!\n");
        ERROR("out of loopback devices");
        return -1;
    } else {
        if(mount(source, target, system, flags, options) < 0) {
            INFO("could not mount filesystem %s (%d)\n",source,errno);
            return -errno;
        }

        return 0;
    }
}

int do_umount(int nargs, char **args)
{
    char *path = NULL;

    if(nargs != 2)
        return -1;

    path = args[1];
    if(umount(path))
        return -errno;

    return 0;
}

/* mount <type> <device> <path> <flags ...> <options> */
int do_mount(int nargs, char **args)
{
    char *source, *target, *system;
    char *options = NULL;
    unsigned flags = 0;
    int n, i;

    for (n = 4; n < nargs; n++) {
        for (i = 0; mount_flags[i].name; i++) {
            if (!strcmp(args[n], mount_flags[i].name)) {
                flags |= mount_flags[i].flag;
                break;
            }
        }

        /* if our last argument isn't a flag, wolf it up as an option string */
        if (n + 1 == nargs && !mount_flags[i].name)
            options = args[n];
    }

    system = args[1];
    source = args[2];
    target = args[3];

    INFO("mount ");
    INFO("     system: %s", system);
    INFO("     source: %s", source);
    INFO("     target: %s", target);
    INFO("      flags: %d", flags);
    INFO("    options: %s", options);

    return mount_fs(system, source, target, flags, options);
}


int do_setkey(int nargs, char **args)
{
    struct kbentry kbe;
    kbe.kb_table = strtoul(args[1], 0, 0);
    kbe.kb_index = strtoul(args[2], 0, 0);
    kbe.kb_value = strtoul(args[3], 0, 0);
    return setkey(&kbe);
}

int do_setprop(int nargs, char **args)
{
    property_set(args[1], args[2]);
    return 0;
}

int do_setrlimit(int nargs, char **args)
{
    struct rlimit limit;
    int resource;
    resource = atoi(args[1]);
    limit.rlim_cur = atoi(args[2]);
    limit.rlim_max = atoi(args[3]);
    return setrlimit(resource, &limit);
}

int do_start(int nargs, char **args)
{
    struct service *svc;
    svc = service_find_by_name(args[1]);
    if (svc) {
        service_start(svc, NULL);
    }
    return 0;
}

int do_stop(int nargs, char **args)
{
    struct service *svc;
    svc = service_find_by_name(args[1]);
    if (svc) {
        service_stop(svc);
    }
    return 0;
}

int do_restart(int nargs, char **args)
{
    struct service *svc;
    svc = service_find_by_name(args[1]);
    if (svc) {
        service_stop(svc);
        service_start(svc, NULL);
    }
    return 0;
}

int do_trigger(int nargs, char **args)
{
    action_for_each_trigger(args[1], action_add_queue_tail);
    drain_action_queue();
    return 0;
}

int do_symlink(int nargs, char **args)
{
    return symlink(args[1], args[2]);
}

int do_sysclktz(int nargs, char **args)
{
    struct timezone tz;

    if (nargs != 2)
        return -1;

    memset(&tz, 0, sizeof(tz));
    tz.tz_minuteswest = atoi(args[1]);
    if (settimeofday(NULL, &tz))
        return -1;
    return 0;
}

int do_write(int nargs, char **args)
{
    return write_file(args[1], args[2]);
}


int copy_dir(char *src, char *dst)
{
    DIR *dp;
    struct stat src_info;
    struct stat dst_info;
    struct dirent *ep;
    int rc = 0;
    char next_dst[PATH_MAX];
    char next_src[PATH_MAX];


    INFO("copy_dir '%s' => '%s'\n",src,dst);
    memset(&src_info,0,sizeof(struct stat));
    memset(&dst_info,0,sizeof(struct stat));
    if (src == NULL)
        return -1;

    if (dst == NULL)
        return -1;

    if (stat(src, &src_info) < 0) {
        ERROR("copy_dir: could not get %s info\n",src);
        return -1;
    }


    if (S_ISDIR(src_info.st_mode) != 1) {
        ERROR("copy_dir: source %s is not a directory (info:%d - %d)!\n",src,src_info.st_mode, S_ISDIR(src_info.st_mode));
        return -1;
    }

    if(stat(dst, &dst_info) < 0) {
        INFO("copy_dir: %s directory does not exist; creating it\n",dst);
// WARNING ZZZZZZ danger patch to force easy access
        if (mkdir(dst, 0775)) {
            ERROR("copy_dir: could not create directory %s; aborting\n",dst);
            return -errno;
        }
    }

    if (chown(dst, src_info.st_uid, src_info.st_gid)) {
        ERROR("copy_dir: could not make source %s and destination %s permission match\n",src,dst);
        return -errno;
    }

    dp = opendir (src);
    if (dp != NULL) {
        while ((ep = readdir (dp))) {
            if(!(strlen(ep->d_name) == 1 && strncmp(ep->d_name,".",1) == 0) &&
               !(strlen(ep->d_name) == 2 && strncmp(ep->d_name,"..",2) == 0) &&
               !(strncmp(ep->d_name,"lost+found",10) == 0)) {
                memset(next_dst,0,PATH_MAX);
                memset(next_src,0,PATH_MAX);
                snprintf(next_dst,PATH_MAX,"%s/%s",dst,ep->d_name);
                snprintf(next_src,PATH_MAX,"%s/%s",src,ep->d_name);
                rc = copy(next_src,next_dst);
                if (rc != 0) {
                    ERROR("copy_dir: aborting copy. Copy failed (%d)\n",rc);
                    return rc;
                }
            } else {
                INFO("Skipping copy of %s/%s\n",src,ep->d_name);
            }
        }
        (void) closedir (dp);
    } else {
        ERROR("copy_dir: couldn't open %s for listing\n",src);
        return -errno;
    }

    return 0;
}


int copy(char *src, char *dst) {
    char *buffer = NULL;
    int rc = 0;
    int fd1 = -1, fd2 = -1;
    struct stat src_info;
    struct stat dst_info;
    int brtw, brtr;
    char *p;
    struct stat test_info;

    INFO("copy: '%s' => '%s'\n",src,dst);
    memset(&src_info,0,sizeof(struct stat));
    memset(&dst_info,0,sizeof(struct stat));
    if (src == NULL)
        return -1;

    if (dst == NULL)
        return -1;

    if (stat(src, &src_info) < 0) {
        ERROR("copy: source %s does not exist\n",src);
        return -1;
    }

    if (S_ISDIR(src_info.st_mode) == 1) {
        ERROR("copy: source %s is a directory handing to copy_dir\n",src);
        return copy_dir(src,dst);
    }

    /* Do not copy files of same size */
    if(stat(dst, &dst_info) == 0)
        if(dst_info.st_size == src_info.st_size) {
            ERROR("Skipping copy %s and %s have the same size (%lld)\n",src, dst, src_info.st_size);
            return 0;
        }

    if ((fd1 = open(src, O_RDONLY)) < 0) {
        ERROR("copy: source %s could not be opened (errno:%d)\n",src,errno);
        goto out_err;
    }

    if ((fd2 = open(dst, O_WRONLY|O_CREAT|O_TRUNC, src_info.st_mode)) < 0) {
        ERROR("copy: destination %s could not be opened (errno:%d)\n",dst,errno);
        goto out_err;
    }

    if (!(buffer = malloc(src_info.st_size))) {
        ERROR("copy: not enough memory to create copy buffer (errno:%d)\n",errno);
        goto out_err;
    }

    p = buffer;
    brtr = src_info.st_size;
    while(brtr) {
        rc = read(fd1, p, brtr);
        if (rc < 0) {
            ERROR("copy: cannot read source %s (errno:%d)\n",src,errno);
            goto out_err;
        }
        if (rc == 0)
            break;
        p += rc;
        brtr -= rc;
    }

    p = buffer;
    brtw = src_info.st_size;
    while(brtw) {
        rc = write(fd2, p, brtw);
        if (rc < 0) {
            ERROR("copy: failed to write to destination %s (errno:%d)\n",dst,errno);
            goto out_err;
        }
        if (rc == 0)
            break;
        p += rc;
        brtw -= rc;
    }


    if(chown(dst, src_info.st_uid, src_info.st_gid) < 0) {
        ERROR("copy: cannot set ownership on destination file %s (uid:%ld, gid:%ld)\n", dst, src_info.st_uid, src_info.st_gid);
        goto out_err;
    }
// WARNING ZZZZZZ danger patch to force easy access
//    if(chmod(dst, src_info.st_mode) < 0) {
    if(chmod(dst, 0775) < 0) {
    	ERROR("copy: cannot set permissions on destination file %s (%o)\n",dst,src_info.st_mode);
        goto out_err;
    }
// trace
    stat(dst, &test_info);
    INFO("chmod: %s(%i) mode_t %o %x \n",dst, errno, test_info.st_mode, test_info.st_mode);

    rc = 0;
    goto out;
out_err:
    printf("copy could not copy to %s\n",dst);
    if(errno > 0)
      rc = -errno;
    else
      rc = -1;
out:
    if (buffer)
        free(buffer);
    if (fd1 >= 0)
        close(fd1);
    if (fd2 >= 0)
        close(fd2);
    return rc;
}

int do_copy(int nargs, char **args)
{
    char *buffer = NULL;
    int rc = 0;
    int fd1 = -1, fd2 = -1;
    struct stat info;
    int brtw, brtr;
    char *p;

    if (nargs != 3)
        return -1;

    return copy(args[1],args[2]);
}

int do_stat(int nargs, char**args)
{
	struct stat test_info;
	int ret_value;

	ret_value = stat(args[1], &test_info);
	INFO("stat: %s, ret=%i errno=%i, mode_t=%o \n", args[1], ret_value, errno, test_info.st_mode);
	return ret_value;
}

int do_chown(int nargs, char **args) {
    /* GID is optional. */
    if (nargs == 3) {
        if (chown(args[2], decode_uid(args[1]), -1) < 0)
            return -errno;
    } else if (nargs == 4) {
        if (chown(args[3], decode_uid(args[1]), decode_uid(args[2])))
            return -errno;
    } else {
        return -1;
    }
    return 0;
}

static mode_t get_mode(const char *s) {
    mode_t mode = 0;
    while (*s) {
        if (*s >= '0' && *s <= '7') {
            mode = (mode<<3) | (*s-'0');
        } else {
            return -1;
        }
        s++;
    }
    return mode;
}

int do_chmod(int nargs, char **args) {
    mode_t mode = get_mode(args[1]);
    if (chmod(args[2], mode) < 0) {
        return -errno;
    }
    return 0;
}

int do_loglevel(int nargs, char **args) {
    if (nargs == 2) {
        log_set_level(atoi(args[1]));
        return 0;
    }
    return -1;
}

int do_device(int nargs, char **args) {
    int len;
    char tmp[64];
    char *source = args[1];
    int prefix = 0;

    if (nargs != 5)
        return -1;
    /* Check for wildcard '*' at the end which indicates a prefix. */
    len = strlen(args[1]) - 1;
    if (args[1][len] == '*') {
        args[1][len] = '\0';
        prefix = 1;
    }
    /* If path starts with mtd@ lookup the mount number. */
    if (!strncmp(source, "mtd@", 4)) {
        int n = mtd_name_to_number(source + 4);
        if (n >= 0) {
            snprintf(tmp, sizeof(tmp), "/dev/mtd/mtd%d", n);
            source = tmp;
        }
    }
    add_devperms_partners(source, get_mode(args[2]), decode_uid(args[3]),
                          decode_uid(args[4]), prefix);
    return 0;
}

int do_update(int nargs, char **args) {
    char *src = NULL;
    char *src_fs = NULL;
    char *dst = NULL;
    char *dst_fs = NULL;
    mode_t mode = 0755;
    struct stat info;
    int rc = 0;

    if(nargs != 5)
       return -1;

    memset(&info,0,sizeof(struct stat));
    src_fs = args[1];
    src = args[2];
    dst_fs = args[3];
    dst = args[4];

    INFO("update: src:(%s %s) dst:(%s %s)\n",src,src_fs,dst,dst_fs);

    INFO("update: 1/3 mkdir\n");
    if(mkdir("/update",mode))
        goto error;
    if(mkdir("/update/src",mode))
        goto error;
    if(mkdir("/update/dst",mode))
        goto error;

    INFO("update: 2/3 mount\n");
    if(mount_fs(src_fs,src,"/update/src",MS_RDONLY,""))
        goto error;

    if(mount_fs(dst_fs,dst,"/update/dst",0,""))
        goto error;

    /* Do the copy */
    INFO("update: 3/3 copy\n");
    rc = copy("/update/src", "/update/dst");
    if(rc == 0)
        goto done;
    else
        INFO("Update failed (rc=%d)",rc);

error:
    INFO("update error!");
    rc = -errno;
    goto cleanup;

done:
    INFO("Update completed successfully\n");

cleanup:
    umount("/update/dst");
    umount("/update/src");
    rmdir("/update/dst");
    rmdir("/update/src");
    rmdir("/update");
    return rc;
}
