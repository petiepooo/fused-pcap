/*
 * main.c
 * fused-pcap
 *
 * Copyright (C) 2014 Peter Nelson, All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as publised
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * without any warranty, without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU GPL for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, you may write to the Free Software Foundation,
 * Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define FUSE_USE_VERSION	26

static const char *fusedPcapVersion = "0.0.1a";

//#include <sys/types.h>
//#include <sys/xattr.h>
#include <sys/stat.h>
//#include <sys/statvfs.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
//#include <strings.h>
#include <errno.h>
//#include <assert.h>
//#include <dirent.h>
#include <fuse.h>

// GLOBAL VARIABLES

// path to real pcap files
char *pcapDirectory;

// FUSE CALLBACKS

static int callback_getattr(const char *path, struct stat *stData)
{
  //TODO: finish
  (void)path;
  (void)stData;
  return -EROFS;
}

static int callback_readlink(const char *path, char *buffer, size_t size)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)size;
  return -EROFS;
}

static int callback_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fillInfo)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)filler;
  (void)offset;
  (void)fillInfo;
  return -EROFS;
}

static int callback_mknod(const char *path, mode_t mode, dev_t rdev)
{
  //TODO: finish
  (void)path;
  (void)mode;
  (void)rdev;
  return -EROFS;
}

static int callback_mkdir(const char *path, mode_t mode)
{
  //TODO: finish
  (void)path;
  (void)mode;
  return -EROFS;
}

static int callback_unlink(const char *path)
{
  //TODO: finish
  (void)path;
  return -EROFS;
}

static int callback_rmdir(const char *path)
{
  //TODO: finish
  (void)path;
  return -EROFS;
}

static int callback_symlink(const char *from, const char *to)
{
  //TODO: finish
  (void)from;
  (void)to;
  return -EROFS;
}

static int callback_rename(const char *from, const char *to)
{
  //TODO: finish
  (void)from;
  (void)to;
  return -EROFS;
}

static int callback_link(const char *from, const char *to)
{
  //TODO: finish
  (void)from;
  (void)to;
  return -EROFS;
}

static int callback_chmod(const char *path, mode_t mode)
{
  //TODO: finish
  (void)path;
  (void)mode;
  return -EROFS;
}

static int callback_chown(const char *path, uid_t uid, gid_t gid)
{
  //TODO: finish
  (void)path;
  (void)uid;
  (void)gid;
  return -EROFS;
}

static int callback_truncate(const char *path, off_t size)
{
  //TODO: finish
  (void)path;
  (void)size;
  return -EROFS;
}

static int callback_utime(const char *path, struct utimbuf *timeBuffer)
{
  //TODO: finish
  (void)path;
  (void)timeBuffer;
  return -EROFS;
}

static int callback_open(const char *path, struct fuse_file_info *fileInfo)
{
  //TODO: finish
  (void)path;
  (void)fileInfo;
  return -EROFS;
}

static int callback_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)size;
  (void)offset;
  (void)fileInfo;
  return -EROFS;
}

static int callback_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)size;
  (void)offset;
  (void)fileInfo;
  return -EROFS;
}

static int callback_statfs(const char *path, struct statvfs *status)
{
  //TODO: finish
  (void)path;
  (void)status;
  return -EROFS;
}

static int callback_release(const char *path, struct fuse_file_info *fileInfo)
{
  //TODO: finish
  (void)path;
  (void)fileInfo;
  return -EROFS;
}

static int callback_fsync(const char *path, int dummy, struct fuse_file_info *fileInfo)
{
  //TODO: finish
  (void)path;
  (void)dummy;
  (void)fileInfo;
  return -EROFS;
}

static int callback_access(const char *path, int mode)
{
  //TODO: finish
  (void)path;
  (void)mode;
  return -EROFS;
}

static int callback_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  //TODO: finish
  (void)path;
  (void)name;
  (void)value;
  (void)flags;
  return -EROFS;
}

static int callback_getxattr(const char *path, const char *name, char *value, size_t size)
{
  //TODO: finish
  (void)path;
  (void)name;
  (void)value;
  (void)size;
  return -EROFS;
}

static int callback_listxattr(const char *path, char *list, size_t size)
{
  //TODO: finish
  (void)path;
  (void)list;
  (void)size;
  return -EROFS;
}

static int callback_removexattr(const char *path, const char *name)
{
  //TODO: finish
  (void)path;
  (void)name;
  return -EROFS;
}


struct fuse_operations callbackOperations = {
  .getattr     = callback_getattr,
  .readlink    = callback_readlink,
  .readdir     = callback_readdir,
  .mknod       = callback_mknod,
  .mkdir       = callback_mkdir,
  .symlink     = callback_symlink,
  .rename      = callback_rename,
  .unlink      = callback_unlink,
  .rmdir       = callback_rmdir,
  .link        = callback_link,
  .chmod       = callback_chmod,
  .chown       = callback_chown,
  .truncate    = callback_truncate,
  .utime       = callback_utime,
  .open        = callback_open,
  .read        = callback_read,
  .write       = callback_write,
  .statfs      = callback_statfs,
  .release     = callback_release,
  .fsync       = callback_fsync,
  .access      = callback_access,
  .setxattr    = callback_setxattr,
  .getxattr    = callback_getxattr,
  .listxattr   = callback_listxattr,
  .removexattr = callback_removexattr
};

static void usage(const char *progname)
{
  fprintf(stdout,
"Usage: %s pcapdirpath mountpoint [-h | -v | -o opt1[,opt2]...]\n"
"\n"
"options:\n"
"  clustersize=X - block reads until X processes have connected to and read from the same file (default 1)\n"
"  blockslack=X - number of blocks to allow between leading and lagging reads in a cluster (default TBD)\n"
"  filesize=X - size of file returned in fstat() call, K, M, G, T, and P suffixes allowed (default 512T)\n"
"  clusterabend=X - how to handle premature closure of cluster member's read handle (0=err, 1=eof, 2=ignore) (default=0)\n"
"  clustermode=X - how to distribute packets between cluster members (0=vlan+ip+port, 1=vlan, 2=ip, 3=vlan+ip, 4=ip+port) (default=0)\n"
"\n", progname);
}

enum {
  MY_FUSE_OPT_KEY_HELP,
  MY_FUSE_OPT_KEY_VERSION
};

static int parseMountOptions(void *data, const char *arg, int key, struct fuse_args *arguments)
{
  switch (key) {
  case FUSE_OPT_KEY_NONOPT:
    if (pcapDirectory == NULL) {
      pcapDirectory = strdup(arg);
      return 0;
    }
    break;
  case FUSE_OPT_KEY_OPT:
    //TODO: handle my options here
    break;
  case MY_FUSE_OPT_KEY_HELP:
    usage(arguments->argv[0]);
    exit(0);
  case MY_FUSE_OPT_KEY_VERSION:
    fprintf(stdout, "fused_pcap version %s\n", fusedPcapVersion);
    exit(0);
  default:
    usage(arguments->argv[0]);
    exit(1);
  }
  return 1;
}

static struct fuse_opt fusedPcapOptions[] = {
  FUSE_OPT_KEY("-h",        MY_FUSE_OPT_KEY_HELP),
  FUSE_OPT_KEY("--help",    MY_FUSE_OPT_KEY_HELP),
  FUSE_OPT_KEY("-v",        MY_FUSE_OPT_KEY_VERSION),
  FUSE_OPT_KEY("--version", MY_FUSE_OPT_KEY_VERSION),
  FUSE_OPT_END
};

int main (int argc, char *argv[])
{
  struct fuse_args fuseArgs = FUSE_ARGS_INIT(argc, argv);

  if ((fuse_opt_parse(&fuseArgs, &pcapDirectory, fusedPcapOptions, parseMountOptions)) != 0) {
    fprintf(stderr, "%s: invalid arguments\n", argv[0]);
    exit(1);
  }

  if (pcapDirectory == NULL) {
    fprintf(stderr, "%s: missing pcap source directory\n", argv[0]);
    exit(1);
  }

#if FUSE_VERSION >= 26
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations, NULL);
#else
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations);
#endif
}



