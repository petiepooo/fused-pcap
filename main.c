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
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
//#include <strings.h>
#include <errno.h>
//#include <assert.h>
//#include <dirent.h>
#include <fuse.h>

// DEFAULT VALUES AND CONSTRAINTS

// range and default slack between slowest and fastest cluster member in blocks
#define DEFAULT_BLOCK_SLACK 256
#define MIN_BLOCK_SLACK 1
#define MAX_BLOCK_SLACK 1024

// MAX members in a cluster
#define MAX_CLUSTER_SIZE 32

// default pcap filesize is two exabytes
#define DEFAULT_PCAP_FILESIZE 1024LL * 1024 * 1024 * 1024 * 1024 * 1024 * 2
// minimum is 1, maximum is however much an "off_t" type can hold

// enumerated and default cluster modes
enum {
  CLUSTER_MODE_VLAN_IP_PORT,
  CLUSTER_MODE_VLAN,
  CLUSTER_MODE_IP,
  CLUSTER_MODE_VLAN_IP,
  CLUSTER_MODE_IP_PORT
};
#define DEFAULT_CLUSTER_MODE CLUSTER_MODE_VLAN_IP_PORT

// enumerated and default cluster abnormal end behaviors
enum {
  CLUSTER_ABEND_EOF_ALL_AT_EOF,
  CLUSTER_ABEND_ERR_ALL_AT_EOF,
  CLUSTER_ABEND_IMMEDIATE_EOF_ALL,
  CLUSTER_ABEND_IMMEDIATE_ERROR_ALL,
  CLUSTER_ABEND_IGNORE
};
#define DEFAULT_CLUSTER_ABEND CLUSTER_ABEND_EOF_ALL_AT_EOF

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
"  filesize=X - size of file returned in fstat() call, K, M, G, T, and P suffixes allowed (default 512T)\n"
"  clustersize=X - block reads until X processes have connected to and read from the same file (default 1)\n"
"  clustermode=X - how to distribute packets between cluster members (0=vlan+ip+port, 1=vlan, 2=ip, 3=vlan+ip, 4=ip+port) (default=0)\n"
"  clusterabend=X - how to handle premature closure of cluster member's read handle (0=err, 1=eof, 2=ignore) (default=0)\n"
"  blockslack=X - number of blocks to allow between leading and lagging reads in a cluster (default TBD)\n"
"\n", progname);
}

enum {
  FUSED_PCAP_OPT_KEY_HELP,
  FUSED_PCAP_OPT_KEY_VERSION,
};

struct fusedPcapConfig_s {
  off_t pcapfilesize;
  char *filesize;
  int clustersize;
  int clustermode;
  int clusterabend;
  int blockslack;
} fusedPcapConfig;

#define FUSED_PCAP_OPT(t, p, v) { t, offsetof(struct fusedPcapConfig_s, p), v }

static struct fuse_opt fusedPcapOptions[] = {
  FUSED_PCAP_OPT("filesize=%s",     filesize,     0),
  FUSED_PCAP_OPT("clustersize=%i",  clustersize,  0),
  FUSED_PCAP_OPT("clustermode=%i",  clustermode,  0),
  FUSED_PCAP_OPT("clusterabend=%i", clusterabend, 0),
  FUSED_PCAP_OPT("blockslack=%i",   blockslack,   0),

  FUSE_OPT_KEY("-h",        FUSED_PCAP_OPT_KEY_HELP),
  FUSE_OPT_KEY("--help",    FUSED_PCAP_OPT_KEY_HELP),
  FUSE_OPT_KEY("-v",        FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_KEY("--version", FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_END
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
    fprintf(stdout, "FUSE_OPT_KEY_OPT: %s", arg);
    break;
  case FUSED_PCAP_OPT_KEY_HELP:
    usage(arguments->argv[0]);
    exit(0);
  case FUSED_PCAP_OPT_KEY_VERSION:
    fprintf(stdout, "fused_pcap version %s\n", fusedPcapVersion);
    exit(0);
  default:
    usage(arguments->argv[0]);
    exit(1);
  }
  return 1;
}

int main (int argc, char *argv[])
{
  struct fuse_args fuseArgs = FUSE_ARGS_INIT(argc, argv);
  off_t multiplier;

//fprintf(stderr, "pcapfilesize=%lld\nfilesize=%s\nclustersize=%d\nclustermode=%d\nclusterabend=%d\nblockslack=%d\n", (long long int) fusedPcapConfig.pcapfilesize, fusedPcapConfig.filesize, fusedPcapConfig.clustersize, fusedPcapConfig.clustermode, fusedPcapConfig.clusterabend, fusedPcapConfig.blockslack);

  if ((fuse_opt_parse(&fuseArgs, &fusedPcapConfig, fusedPcapOptions, parseMountOptions)) == -1) {
    fprintf(stderr, "%s: invalid arguments\n", argv[0]);
    exit(1);
  }

  // convert and validate filesize option
  if (fusedPcapConfig.filesize == NULL)
    fusedPcapConfig.pcapfilesize = DEFAULT_PCAP_FILESIZE;
  else {
    multiplier = 1;
    switch (fusedPcapConfig.filesize[strlen(fusedPcapConfig.filesize) - 1]) {
    case 'K':
    case 'k':
      multiplier = 1024ll;
      break;
    case 'M':
    case 'm':
      multiplier = 1024ll * 1024;
      break;
    case 'G':
    case 'g':
      multiplier = 1024ll * 1024 * 1024;
      break;
    case 'T':
    case 't':
      multiplier = 1024ll * 1024 * 1024 * 1024;
      break;
    case 'P':
    case 'p':
      multiplier = 1024ll * 1024 * 1024 * 1024 * 1024;
      break;
    default:
      break;
    }
//fprintf(stderr, " multiplier=%lld\n filesize=%s\n", (long long int) multiplier, fusedPcapConfig.filesize);
    if (multiplier > 1)
      fusedPcapConfig.filesize[strlen(fusedPcapConfig.filesize) - 1] = '\0';
    fusedPcapConfig.pcapfilesize = atoll(fusedPcapConfig.filesize) * multiplier;
    if (fusedPcapConfig.pcapfilesize < multiplier) {
      fprintf(stderr, "%s: filesize option out of range (1..2^63-1)\n", argv[0]);
      if (fusedPcapConfig.pcapfilesize != 0 && fusedPcapConfig.filesize[0] != '-')
        fprintf(stderr, "Congratulations! you overflowed a 64-bit integer.\n");
      exit(1);
    }
  }
  
//fprintf(stderr, "pcapfilesize=%lld\nfilesize=%s\nclustersize=%d\nclustermode=%d\nclusterabend=%d\nblockslack=%d\n", (long long int) fusedPcapConfig.pcapfilesize, fusedPcapConfig.filesize, fusedPcapConfig.clustersize, fusedPcapConfig.clustermode, fusedPcapConfig.clusterabend, fusedPcapConfig.blockslack);
  // validate all other options
  if (fusedPcapConfig.clustersize == 0)
    fusedPcapConfig.clustersize = 1;
  else if (fusedPcapConfig.clustersize < 0 || fusedPcapConfig.clustersize > 32) {
    fprintf(stderr, "%s: clustersize option out of range (1..%d)\n", argv[0], MAX_CLUSTER_SIZE);
    exit(1);
  }
  if (fusedPcapConfig.clustermode < CLUSTER_MODE_VLAN_IP_PORT || fusedPcapConfig.clustermode > CLUSTER_MODE_IP_PORT) {
    fprintf(stderr, "%s: clustermode option out of range (%d..%d)\n", argv[0], CLUSTER_MODE_VLAN_IP_PORT, CLUSTER_MODE_IP_PORT);
    exit(1);
  }
  if (fusedPcapConfig.clusterabend < CLUSTER_ABEND_EOF_ALL_AT_EOF || fusedPcapConfig.clusterabend > CLUSTER_ABEND_IGNORE) {
    fprintf(stderr, "%s: clusterabend option out of range (%d..%d)\n", argv[0], CLUSTER_ABEND_EOF_ALL_AT_EOF, CLUSTER_ABEND_IGNORE);
    exit(1);
  }
  if (fusedPcapConfig.blockslack == 0)
    fusedPcapConfig.blockslack = DEFAULT_BLOCK_SLACK;
  else if (fusedPcapConfig.blockslack < MIN_BLOCK_SLACK || fusedPcapConfig.blockslack > MAX_BLOCK_SLACK) {
    fprintf(stderr, "%s: blockslack option out of range (%d..%d)\n", argv[0], MIN_BLOCK_SLACK, MAX_BLOCK_SLACK);
    exit(1);
  }
//fprintf(stderr, "pcapfilesize=%lld\nfilesize=%s\nclustersize=%d\nclustermode=%d\nclusterabend=%d\nblockslack=%d\n", (long long int) fusedPcapConfig.pcapfilesize, fusedPcapConfig.filesize, fusedPcapConfig.clustersize, fusedPcapConfig.clustermode, fusedPcapConfig.clusterabend, fusedPcapConfig.blockslack);

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



