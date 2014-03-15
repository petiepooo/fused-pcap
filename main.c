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
#define _FILE_OFFSET_BITS	64

static const char *fusedPcapVersion = "0.0.2a";

#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
//#include <sys/xattr.h>
//#include <sys/statvfs.h>
#include <errno.h>
//#include <assert.h>
#include <dirent.h>
#include <fuse.h>

// DEFAULT VALUES AND CONSTRAINTS

// range and default slack between slowest and fastest cluster member in blocks
#define DEFAULT_BLOCK_SLACK 2048
#define MIN_BLOCK_SLACK 1
#define MAX_BLOCK_SLACK 1048576

// MAX members in a cluster
#define MAX_CLUSTER_SIZE 32

// default pcap filesize is two exabytes
#define DEFAULT_PCAP_FILESIZE 1024LL * 1024 * 1024 * 1024 * 1024 * 1024 * 2
// minimum is 1, maximum is however much an "off_t" type can hold

// enumerated and default cluster modes
enum {
  CLUSTER_MODE_INVALID,
  CLUSTER_MODE_VLAN,
  CLUSTER_MODE_IP,
  CLUSTER_MODE_VLAN_IP,
  CLUSTER_MODE_IP_PORT,
  CLUSTER_MODE_VLAN_IP_PORT
};
#define DEFAULT_CLUSTER_MODE CLUSTER_MODE_VLAN_IP_PORT

// enumerated and default cluster abnormal end behaviors
enum {
  CLUSTER_ABEND_INVALID,
  CLUSTER_ABEND_EOF_ALL_AT_EOF,
  CLUSTER_ABEND_ERR_ALL_AT_EOF,
  CLUSTER_ABEND_IMMEDIATE_EOF_ALL,
  CLUSTER_ABEND_IMMEDIATE_ERROR_ALL,
  CLUSTER_ABEND_IGNORE
};
#define DEFAULT_CLUSTER_ABEND CLUSTER_ABEND_EOF_ALL_AT_EOF

// GLOBAL VARIABLES

// path to real pcap files
static struct {
  char pcapDirectory[PATH_MAX + 1];
  char mountDirectory[PATH_MAX + 1];
  int debug;
} fusedPcapGlobal;

// FUSE CALLBACKS

static int fused_pcap_getattr(const char *path, struct stat *stData)
{
  char mountPath[PATH_MAX + 1];
  
  //TODO: finish
  (void)path;
  (void)stData;

  //TODO: handle fused-pcap virtual files

  //TODO: strip option subdirs, locate true path
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, path);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "getattr calling stat for %s\n", mountPath);

  if (stat(mountPath, stData) == -1) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "stat returned error");
    return -errno;
  }

  //stData->st_mode &= !0222;
  return 0;
}

static int fused_pcap_readlink(const char *path, char *buffer, size_t size)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)size;
  return -EROFS;
}

static int fused_pcap_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fillInfo)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)filler;
  (void)offset;
  (void)fillInfo;
  return -EROFS;
}

static int fused_pcap_mknod(const char *path, mode_t mode, dev_t rdev)
{
  //TODO: finish
  (void)path;
  (void)mode;
  (void)rdev;
  return -EROFS;
}

static int fused_pcap_mkdir(const char *path, mode_t mode)
{
  //TODO: finish
  (void)path;
  (void)mode;
  return -EROFS;
}

static int fused_pcap_unlink(const char *path)
{
  //TODO: finish
  (void)path;
  return -EROFS;
}

static int fused_pcap_rmdir(const char *path)
{
  //TODO: finish
  (void)path;
  return -EROFS;
}

static int fused_pcap_symlink(const char *from, const char *to)
{
  //TODO: finish
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_rename(const char *from, const char *to)
{
  //TODO: finish
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_link(const char *from, const char *to)
{
  //TODO: finish
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_chmod(const char *path, mode_t mode)
{
  //TODO: finish
  (void)path;
  (void)mode;
  return -EROFS;
}

static int fused_pcap_chown(const char *path, uid_t uid, gid_t gid)
{
  //TODO: finish
  (void)path;
  (void)uid;
  (void)gid;
  return -EROFS;
}

static int fused_pcap_truncate(const char *path, off_t size)
{
  //TODO: finish
  (void)path;
  (void)size;
  return -EROFS;
}

static int fused_pcap_utime(const char *path, struct utimbuf *timeBuffer)
{
  //TODO: finish
  (void)path;
  (void)timeBuffer;
  return -EROFS;
}

static int fused_pcap_open(const char *path, struct fuse_file_info *fileInfo)
{
  char mountPath[PATH_MAX];
  int ret;

  //TODO: check flags for inappropriate values
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, path);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "open calling open for %s\n", mountPath);
  ret = open(mountPath, fileInfo->flags);
  if (ret == -1)
    return -errno;
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "fd %x stored in fuse_file_info for %s\n", ret, mountPath);
  fileInfo->fh = ret;
  return 0;
}

static int fused_pcap_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  off_t offRes;
  ssize_t sizeRes;

  //TODO: finish
  (void)path;
  
  offRes = lseek(fileInfo->fh, offset, SEEK_SET);
  if (offRes != offset)
    return -errno;

  sizeRes = read(fileInfo->fh, buffer, size);
  if (sizeRes == -1)
    return -errno;

  return sizeRes;
}

static int fused_pcap_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  //TODO: finish
  (void)path;
  (void)buffer;
  (void)size;
  (void)offset;
  (void)fileInfo;
  return -EROFS;
}

static int fused_pcap_statfs(const char *path, struct statvfs *status)
{
  //TODO: finish
  (void)path;
  (void)status;
  return -EROFS;
}

static int fused_pcap_release(const char *path, struct fuse_file_info *fileInfo)
{
  int ret;

  //TODO: finish
  (void)path;
  ret = close(fileInfo->fh);
  if (ret == -1)
    return -errno;
  return ret;
}

static int fused_pcap_fsync(const char *path, int dummy, struct fuse_file_info *fileInfo)
{
  //TODO: finish
  (void)path;
  (void)dummy;
  (void)fileInfo;
  return -EROFS;
}

static int fused_pcap_access(const char *path, int mode)
{
  //TODO: finish
  (void)path;
  (void)mode;
  return -EROFS;
}

static int fused_pcap_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  //TODO: finish
  (void)path;
  (void)name;
  (void)value;
  (void)flags;
  return -EROFS;
}

static int fused_pcap_getxattr(const char *path, const char *name, char *value, size_t size)
{
  //TODO: finish
  (void)path;
  (void)name;
  (void)value;
  (void)size;
  return -EROFS;
}

static int fused_pcap_listxattr(const char *path, char *list, size_t size)
{
  //TODO: finish
  (void)path;
  (void)list;
  (void)size;
  return -EROFS;
}

static int fused_pcap_removexattr(const char *path, const char *name)
{
  //TODO: finish
  (void)path;
  (void)name;
  return -EROFS;
}


struct fuse_operations callbackOperations = {
  .getattr     = fused_pcap_getattr,
  .readlink    = fused_pcap_readlink,
  .readdir     = fused_pcap_readdir,
  .mknod       = fused_pcap_mknod,
  .mkdir       = fused_pcap_mkdir,
  .symlink     = fused_pcap_symlink,
  .rename      = fused_pcap_rename,
  .unlink      = fused_pcap_unlink,
  .rmdir       = fused_pcap_rmdir,
  .link        = fused_pcap_link,
  .chmod       = fused_pcap_chmod,
  .chown       = fused_pcap_chown,
  .truncate    = fused_pcap_truncate,
  .utime       = fused_pcap_utime,
  .open        = fused_pcap_open,
  .read        = fused_pcap_read,
  .write       = fused_pcap_write,
  .statfs      = fused_pcap_statfs,
  .release     = fused_pcap_release,
  .fsync       = fused_pcap_fsync,
  .access      = fused_pcap_access,
  .setxattr    = fused_pcap_setxattr,
  .getxattr    = fused_pcap_getxattr,
  .listxattr   = fused_pcap_listxattr,
  .removexattr = fused_pcap_removexattr
};

static void usage(const char *progname)
{
  fprintf(stdout,
"Usage: %s [-h | -v | -o opt[,opt[...]] pcapdirpath mountpoint\n"
"\n"
"%s options:\n"
"    -o filesize=N          set size of file returned in fstat() call, K, M, G, T, and P suffixes allowed (default 2048P)\n"
"    -o clustersize=N       block reads until N processes have connected to and read from the same file (default 1)\n"
"    -o clustermode=N       set distribution of packets to cluster members (1=vlan, 2=ip, 3=vlan+ip, 4=ip+port, 5=vlan+ip+port) (default=5)\n"
"    -o clusterabend=N      set handling of premature closure of a member's read handle (1=eof, 2=err, 3=imm_eof, 4-imm_err, 5=ign) (default=1)\n"
"    -o blockslack=N        set number of blocks to allow between leading and lagging reads in a cluster (default 2048)\n"
"\n", progname, progname);
}

// OPTION HANDLING

enum {
  FUSED_PCAP_OPT_KEY_HELP,
  FUSED_PCAP_OPT_KEY_VERSION,
  FUSED_PCAP_OPT_KEY_DEBUG,
};

struct fusedPcapConfig_s {
  off_t filesize;
  int clustersize;
  int clustermode;
  int clusterabend;
  int blockslack;
} fusedPcapConfig;

struct fusedPcapInputs_s {
  char *filesize;
  char *clustermode;
  char *clusterabend;
  char *clustersize;
  char *blockslack;
  int help;
} fusedPcapInputs;

#define FUSED_PCAP_OPT(t, p, v) { t, offsetof(struct fusedPcapInputs_s, p), v }

static struct fuse_opt fusedPcapOptions[] = {
  FUSED_PCAP_OPT("filesize=%s",     filesize,     0),
  FUSED_PCAP_OPT("clustermode=%s",  clustermode,  0),
  FUSED_PCAP_OPT("clustersize=%s",  clustersize,  0),
  FUSED_PCAP_OPT("clusterabend=%s", clusterabend, 0),
  FUSED_PCAP_OPT("blockslack=%s",   blockslack,   0),

  FUSE_OPT_KEY("-h",        FUSED_PCAP_OPT_KEY_HELP),
  FUSE_OPT_KEY("--help",    FUSED_PCAP_OPT_KEY_HELP),
  FUSE_OPT_KEY("-v",        FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_KEY("--version", FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_KEY("debug",     FUSED_PCAP_OPT_KEY_DEBUG),
  FUSE_OPT_KEY("-d",        FUSED_PCAP_OPT_KEY_DEBUG),

  FUSE_OPT_END
};

static int parseMountOptions(void *data, const char *arg, int key, struct fuse_args *arguments)
{
  switch (key) {
  case FUSE_OPT_KEY_NONOPT:
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSE_PARAM: %s\n", arg);
    if (fusedPcapGlobal.pcapDirectory[0] == '\0') {
      realpath(arg, fusedPcapGlobal.pcapDirectory);
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "normalized to %s\n", fusedPcapGlobal.pcapDirectory);
      return 0;
    }
    else if (fusedPcapGlobal.mountDirectory[0] == '\0') {
      strncpy(fusedPcapGlobal.mountDirectory, arg, PATH_MAX);
      return 1;
    }
    else {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "(parameter %s ignored)\n", arg);
      return 0;
    }
    break;
  case FUSE_OPT_KEY_OPT:
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSE_OPT: %s\n", arg);
    break;
  case FUSED_PCAP_OPT_KEY_HELP:
    fusedPcapInputs.help = 1;
    usage(basename(arguments->argv[0]));
    return fuse_opt_add_arg(arguments, "-ho");
  case FUSED_PCAP_OPT_KEY_VERSION:
    fprintf(stdout, "%s version %s\n", basename(arguments->argv[0]), fusedPcapVersion);
    exit(0);
  case FUSED_PCAP_OPT_KEY_DEBUG:
    fusedPcapGlobal.debug = 1;
    fprintf(stderr, "FUSE_OPT: %s, debug enabled\n", arg);
    break;
  default:
    usage(arguments->argv[0]);
    exit(1);
  }
  return 1;
}

void convertValidateFilesize(const char *progname, off_t *size /*output*/, char *input)
{
  if (input == NULL) {
    *size = DEFAULT_PCAP_FILESIZE;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "filesize=0x%016llx\n", (long long int)*size);
  }
  else {
    off_t multiplier;

    multiplier = 1ll;
    switch (input[strlen(input)]) {
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

    *size = atoll(input) * multiplier;
    if (*size < multiplier) {
      fprintf(stderr, "%s: filesize option out of range (1..2^63-1)\n", progname);
      if (*size != 0 && input[0] != '-')
        fprintf(stderr, "Congratulations! you overflowed a 64-bit integer.\n");
      exit(1);
    }
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: filesize=%s (0x%016llx)\n", input, (long long int)*size);
  }
}

void convertValidateClustersize(const char *progname, int *size /*output*/, const char *input)
{
  if (input == 0) {
    *size = 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "clustersize=%d\n", *size);
  }
  else {
    *size = atoi(input);
    if (*size < 1 || *size > MAX_CLUSTER_SIZE) {
      fprintf(stderr, "%s: clustersize option out of range (1..%d)\n", progname, MAX_CLUSTER_SIZE);
      exit(1);
    }
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clustersize=%d\n", *size);
  }
}

void convertValidateClustermode(const char *progname, int *mode /*output*/, const char *input)
{
  if (input == 0) {
    *mode = DEFAULT_CLUSTER_MODE;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "clustermode=%d\n", *mode);
  }
  else {
    *mode = atoi(input);
    if (*mode < CLUSTER_MODE_VLAN || *mode > CLUSTER_MODE_VLAN_IP_PORT) {
      fprintf(stderr, "%s: clustermode option out of range (%d..%d)\n", progname, CLUSTER_MODE_VLAN, CLUSTER_MODE_VLAN_IP_PORT);
      exit(1);
    }
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clustermode=%d\n", *mode);
  }
}

void convertValidateClusterabend(const char *progname, int *action /*output*/, const char *input)
{
  if (input == 0) {
    *action = DEFAULT_CLUSTER_ABEND;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "clusterabend=%d\n", *action);
  }
  else {
    *action = atoi(input);
    if (*action < CLUSTER_ABEND_EOF_ALL_AT_EOF || *action > CLUSTER_ABEND_IGNORE) {
      fprintf(stderr, "%s: clusterabend option out of range (%d..%d)\n", progname, CLUSTER_ABEND_EOF_ALL_AT_EOF, CLUSTER_ABEND_IGNORE);
      exit(1);
    }
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clusterabend=%d\n", *action);
  }
}

void convertValidateBlockslack(const char *progname, int *slack /*output*/, const char *input)
{
  if (input == 0) {
    *slack = DEFAULT_BLOCK_SLACK;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "blockslack=%d\n", *slack);
  }
  else {
    *slack = atoi(input);
    if (*slack < MIN_BLOCK_SLACK || *slack > MAX_BLOCK_SLACK) {
      fprintf(stderr, "%s: blockslack option out of range (%d..%d)\n", progname, MIN_BLOCK_SLACK, MAX_BLOCK_SLACK);
      exit(1);
    }
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: blockslack=%d\n", *slack);
  }
}

int main (int argc, char *argv[])
{
  struct fuse_args fuseArgs = FUSE_ARGS_INIT(argc, argv);
  //struct fuse_args moreArgs = FUSE_ARGS_INIT(0, NULL);

  if ((fuse_opt_parse(&fuseArgs, &fusedPcapInputs, fusedPcapOptions, parseMountOptions)) == -1) {
    fprintf(stderr, "%s: invalid arguments\n", argv[0]);
    return 1;
  }
  if (!fusedPcapInputs.help)
  {

    //TODO: add read-only option if needed
    //fuse_opt_add_arg (&moreArgs, "-oro");
    //fuse_opt_parse(&moreArgs, &fusedPcapConfig, fusedPcapOptions, parseMountOptions);

    // convert and validate options
    convertValidateFilesize(argv[0], &fusedPcapConfig.filesize, fusedPcapInputs.filesize);
    convertValidateClustermode(argv[0], &fusedPcapConfig.clustermode, fusedPcapInputs.clustermode);
    convertValidateClustersize(argv[0], &fusedPcapConfig.clustersize, fusedPcapInputs.clustersize);
    convertValidateClusterabend(argv[0], &fusedPcapConfig.clusterabend, fusedPcapInputs.clusterabend);
    convertValidateBlockslack(argv[0], &fusedPcapConfig.blockslack, fusedPcapInputs.blockslack);

    if (fusedPcapGlobal.pcapDirectory[0] == '\0') {
      fprintf(stderr, "%s: missing pcap source directory\n", argv[0]);
      return 1;
    }

    //TODO: validate source directory parameter

    if (fusedPcapGlobal.debug)
      fprintf(stderr, "Parameters validated, calling fuse_main()\n");
  }

#if FUSE_VERSION >= 26
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations, NULL);
#else
  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations);
#endif
}



