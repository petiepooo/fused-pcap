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

static const char *fusedPcapVersion = "0.0.4a";

#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <sys/statvfs.h>
#include <errno.h>
//#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <syslog.h>
#include <fuse.h>

// DEFAULT VALUES AND CONSTRAINTS

// range and default slack between slowest and fastest cluster member in blocks
#define DEFAULT_BLOCK_SLACK 2048
#define MIN_BLOCK_SLACK 1
#define MAX_BLOCK_SLACK 1048576

// MAX members in a cluster
#define MAX_CLUSTER_SIZE 32
#define MAX_NUM_CLUSTERS 4

// number of linked list nodes or residual files to add when exhausted
#define SLAB_ALLOC_COUNT 64
#define SPECIAL_FILE_COUNT 32

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
#define DEFAULT_CLUSTER_ABEND CLUSTER_ABEND_IMMEDIATE_EOF_ALL

// GLOBAL STRUCTURES

static struct fusedPcapGlobal_s {
  char pcapDirectory[PATH_MAX + 1];
  char mountDirectory[PATH_MAX + 1];
  int debug;
  long pageSize;
} fusedPcapGlobal;

static struct fusedPcapConfig_s {
  off_t filesize;
  int clustersize;
  int clustermode;
  int clusterabend;
  int blockslack;
  int keepcache;
} fusedPcapConfig;

struct packet_link_s {
  char *offset;
  int size;
  int block;
  struct packet_link_s *next;
  struct packet_link_s *free;
};

// this mutes protects the array below: used to track instances in a cluster
// this mutex should never be held for long (no blocking calls)
// can be locked while instanceMutex is held
static pthread_mutex_t clusterMutex = PTHREAD_MUTEX_INITIALIZER;

struct clusterBuffer_s {
  char *begin;
  char *oldest;
  char *next;
  char *read;
  char *end;
};

static struct fusedPcapCluster_s {
  char *shortPath;
  struct fusedPcapInstance_s *instance[MAX_CLUSTER_SIZE];
  struct packet_link_s *free;
  struct packet_link_s *slabs;
  pthread_mutex_t readThreadMutex;  // blocking
  pthread_spinlock_t queueHeadSpin;   // non-blocking
  struct clusterBuffer_s buf;
  struct fusedPcapConfig_s config;
  int fd;
  //bitfields
  uint32_t fullyPopulated: 1;
  uint32_t memberError: 1;
} fusedPcapClusters[MAX_NUM_CLUSTERS];

// this mutes protects the array below: used to track residual special files
// this mutex should never be held for long (no blocking calls)
static pthread_mutex_t residualMutex = PTHREAD_MUTEX_INITIALIZER;

static struct fusedPcapResidual_s {
  uint16_t pid[MAX_CLUSTER_SIZE];
  char *lastFile;
  char *thisFile;
  char *nextFile;
  char *endFile;
  char *abendPid;
  char *pathPrefix;
  char *mountPath;
  struct fusedPcapConfig_s config;
} fusedPcapResidual[SPECIAL_FILE_COUNT]; 

// this mutex protects the array below; pid indicates whether an entry is free or not.
// this mutex should never be held for long (no blocking calls)
// should never attempt lock while clusterMutex is held (will cause deadlock)
static pthread_mutex_t instanceMutex = PTHREAD_MUTEX_INITIALIZER;

static struct fusedPcapInstance_s {
  off_t readOffset;
  off_t outputOffset;
  struct packet_link_s *queue;
  struct packet_link_s *free;
  struct fusedPcapCluster_s *cluster;
  char *shortPath; // allocated with strdup; must be freed when pid cleared
  char *readFile;  // allocated with strdup; must be freed when file closed
  int member;
  int fd;
  pid_t pid;
  struct fusedPcapConfig_s config;
  struct stat stData;
  char endFile[PATH_MAX + 1];
  // bitfields
  union {
    uint32_t bits;
    struct {
      uint32_t clusterMember: 8;
      uint32_t normalEnding: 1;
      uint32_t fileEndEof: 1;
      uint32_t fileEndErr: 1;
      uint32_t abortEof: 1;
      uint32_t abortErr: 1;
      uint32_t nonblocking: 1;
    };
  };
} fusedPcapInstances[MAX_CLUSTER_SIZE];

struct fusedPcapDirectory_s {
  char *pathPrefix; // allocated with strdup; must be freed when pid cleared
  DIR *fd;
  struct fusedPcapResidual_s *residual;
};

// SUPPORT FUNCTIONS

static void printConfigStruct(struct fusedPcapConfig_s *config)
{
  fprintf(stderr, "  %s: 0x%016llx\n  %s: %d  %s: %d\n  %s: %d  %s: %d  %s\n",
          "filesize", (long long int) config->filesize,
          "clustersize", config->clustersize,
          "clustermode", config->clustermode,
          "clusterabend", config->clusterabend,
          "blockslack", config->blockslack,
          config->keepcache ? "keepcache" : "");
}

static int convertValidateFilesize(struct fusedPcapConfig_s *config /*output*/, const char *input)
{
  const char *suffix;
  off_t multiplier;

  if (input == NULL)
    config->filesize = DEFAULT_PCAP_FILESIZE;

  else {
    suffix = input;
    while (isdigit(suffix[0]))
      suffix++;
    switch (suffix[0]) {
    case '\0':
    case '/':
      multiplier = 1ll;
      break;
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
      return 1;
      break;
    }

    config->filesize = multiplier * atoll(input);
    if (config->filesize < multiplier)
      return 1;
    if (fusedPcapGlobal.debug) {
      char value[32];
      memset(value, '\0', 32);
      strncpy(value, input, strchr(input, '/') ? (strchr(input, '/') - input) & 31ll : 31);
      fprintf(stderr, "FUSED_PCAP_OPT: filesize=%s (0x%016zx)\n", value, config->filesize);
    }
  }
  return 0;
}

static int convertValidateClustersize(struct fusedPcapConfig_s *config /*output*/, const char *input)
{
  if (input == 0)
    config->clustersize = 1;
  else {
    config->clustersize = atoi(input);
    if (config->clustersize < 1 || config->clustersize > MAX_CLUSTER_SIZE)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clustersize=%d\n", config->clustersize);
  }
  return 0;
}

static int convertValidateClustermode(struct fusedPcapConfig_s *config /*output*/, const char *input)
{
  if (input == 0)
    config->clustermode = DEFAULT_CLUSTER_MODE;
  else {
    config->clustermode = atoi(input);
    if (config->clustermode < CLUSTER_MODE_VLAN || config->clustermode > CLUSTER_MODE_VLAN_IP_PORT)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clustermode=%d\n", config->clustermode);
  }
  return 0;
}

static int convertValidateClusterabend(struct fusedPcapConfig_s *config /*output*/, const char *input)
{
  if (input == 0)
    config->clusterabend = DEFAULT_CLUSTER_ABEND;
  else {
    config->clusterabend = atoi(input);
    if (config->clusterabend < CLUSTER_ABEND_EOF_ALL_AT_EOF || config->clusterabend > CLUSTER_ABEND_IGNORE)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: clusterabend=%d\n", config->clusterabend);
  }
  return 0;
}

static int convertValidateBlockslack(struct fusedPcapConfig_s *config /*output*/, const char *input)
{
  if (input == 0)
    config->blockslack = DEFAULT_BLOCK_SLACK;
  else {
    config->blockslack = atoi(input);
    if (config->blockslack < MIN_BLOCK_SLACK || config->blockslack > MAX_BLOCK_SLACK)
      return 1;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "FUSED_PCAP_OPT: blockslack=%d\n", config->blockslack);
  }
  return 0;
}

static int convertValidateKeepcache(struct fusedPcapConfig_s *config /*output*/, const char *input)
{
  config->keepcache = 1;
  return 0;
}

static struct {
  const char *string;
  int (* function)(struct fusedPcapConfig_s *, const char *);
} optionDirs[] = {
  { "..filesize=",     convertValidateFilesize }, 
  { "..clustersize=",  convertValidateClustersize },
  { "..clustermode=",  convertValidateClustermode },
  { "..clusterabend=", convertValidateClusterabend },
  { "..blockslack=",   convertValidateBlockslack },
  { "..keepcache",     convertValidateKeepcache },
};
static int numOptionDirs = 6;

static char *specialFiles[] = {
  "..status",
  "..abend",
  "..last",
  "..current",
  "..next",
  "..pids",
  "..end",
};
static int numSpecialFiles = 7;

static int parsePath(const char *path, struct fusedPcapConfig_s *config, const char **mountPath, const char **filename, const char **specialFile, const char **endFile)
{
  // any parameters other than path can be NULL if not used
  // mountPath will point to the directory separator following any option directories
  //    if mountPath == path, there were option directories
  //    if mountPath == NULL, there were only option directories, so treat mountPath as "/"
  // filename will point to the last directory separator in path
  //    if filename == NULL, there were only option directories, so treat filename as "/"
  // specialFile will point to the last directory separator if the file matches one of the special file names
  //    if specialFile == NULL, the filename isn't a special file
  // endFile will point to the start of the endfile's name
  //    if the path ends with .. then it will point to the terminating NUL char
  //    if some characters of the ending file are present, it will point to the first character of the ending file
  //    in either case, it will be two characters past the .. substring
  //    if endFile == NULL, there is no .. in the filename or it starts with .. but isn't a special file or option directory
  // To process just the starting file, the caller will have to determine if endFile is set
  //    the caller can compute the starting file length based on pointer subtraction
  //    eg: s = calloc (endFile - file - 1, 1); strncpy(s, endFile - file - 2, file);
  //    the caller can safely assume that the endFile[-2] is a valid memory location and can set that to NUL if not const
  int i;
  const char *delimiter;

  if (mountPath)
    *mountPath = NULL;
  if (filename)
    *filename = NULL;
  if (specialFile)
    *specialFile = NULL;
  if (endFile)
    *endFile = NULL;

  memcpy(config, &fusedPcapConfig, sizeof(struct fusedPcapConfig_s));

  // assert: path[0] is a directory separator
  if (path == NULL || path[0] != '/')
    return 1;
  delimiter = path;

  do {
    //for (i=0; i<sizeof(optionDirs); i++) {
    for (i=0; i<numOptionDirs; i++) {
      if (strncmp(optionDirs[i].string, delimiter + 1, strlen(optionDirs[i].string)) == 0) {
        if (config && optionDirs[i].function(config, delimiter + strlen(optionDirs[i].string) + 1) != 0)
          return 1;
        delimiter = strchr(delimiter + 3, '/');
        break;
      }
    }
  } while (delimiter && i < numOptionDirs);

  if (delimiter == NULL)
     return 0;
  if (mountPath)
    *mountPath = delimiter;

  delimiter = strrchr(delimiter, '/');
  if (filename)
    *filename = delimiter;
  if (delimiter[1] == '\0')
    return 0;
 
  if (specialFile) {
    for (i=0; i<numSpecialFiles; i++) {
      if (strcmp(specialFiles[i], delimiter + 1) == 0) {
        *specialFile = delimiter;
        return 0;
      }
    }
  }
 
  if (endFile) {
    *endFile = strstr(delimiter, "..");
    if (*endFile)
      *endFile += 2;
  }
  return 0;
}

static struct fusedPcapResidual_s *getResidual(const struct fusedPcapConfig_s *config, const char *mountPath)
{
  struct fusedPcapResidual_s *residual;
  int i;

  residual = NULL;
  if (config == NULL)
    return NULL;

  pthread_mutex_lock(&residualMutex);

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "residual structure search with clustersize=%d, path %s\n", config->clustersize, mountPath);
  //search for a matching config and, if not NULL, path
  for (i=1; i<SPECIAL_FILE_COUNT; i++) {
    if (memcmp(&(fusedPcapResidual[i].config), config, sizeof(struct fusedPcapConfig_s)) == 0) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "residual structure found at offset %d\n", i);
      residual = &fusedPcapResidual[i];
      break;
    }
    else if (fusedPcapResidual[i].config.filesize == 0) {
      residual = &fusedPcapResidual[i];
      memcpy(&residual->config, config, sizeof(struct fusedPcapConfig_s));
      break;
    }
  }

  if (i == SPECIAL_FILE_COUNT) {
    //TODO: grow the size
  }

  if (mountPath) {
    if (residual->mountPath)
      free(residual->mountPath);
    residual->mountPath = strdup(mountPath);
  }

  pthread_mutex_unlock(&residualMutex);
  return residual;
}

static int getResidualIndex(struct fusedPcapResidual_s *residual)
{
  int i;
  for (i=1; i<SPECIAL_FILE_COUNT; i++)
    if (residual == &fusedPcapResidual[i])
      return i;
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "RESIDUAL OVERRUN! getResidualIndex: %p, main array: %p\n", residual, fusedPcapResidual);
  return 0;
}

static int closeInstance(struct fusedPcapInstance_s *instance)
{
  int i;
  struct fusedPcapResidual_s *residual;
  struct fusedPcapCluster_s *cluster;
  struct packet_link_s *slab;
  struct packet_link_s *head;
  int ret;

  ret = 0;

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "instance %p - clearing\n", instance);
  pthread_mutex_lock(&instanceMutex);

  residual = getResidual(&instance->config, NULL);
  if (residual) {
    for (i=0; i<MAX_CLUSTER_SIZE - 1 && residual->pid[i]; i++)
      if (residual->pid[i] == instance->pid)
        break;
    for (   ; i<MAX_CLUSTER_SIZE - 1 && residual->pid[i]; i++)
      residual->pid[i] = residual->pid[i+1];
    residual->pid[i] = 0;
  }

  if (instance->readFile)
    free(instance->readFile);
  if (instance->config.clustersize > 1 && instance->cluster) {
    cluster = instance->cluster;
    pthread_mutex_lock(&clusterMutex);
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "instance %p - removing from cluster %p member %d\n", instance, cluster, instance->member);
    cluster->instance[instance->member] = NULL;
    for (i=0; i<instance->config.clustersize; i++)
      if (cluster->instance[i])
        break;
    if (i >= instance->config.clustersize) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "instance %p - last instance removed, clearing cluster too\n", instance);
      if (cluster->fd)
        ret = close(cluster->fd);
      if (cluster->shortPath)
        free(cluster->shortPath);
      pthread_mutex_destroy(&cluster->readThreadMutex);
      pthread_spin_destroy(&cluster->queueHeadSpin);
      if (fusedPcapGlobal.debug) {
        head = cluster->free;
        i = 0;
        while (head) {
          i++;
          head = head->free;
        }
        fprintf(stderr, "instance %p - %d free links in cluster free list\n", instance, i);
      }
      slab = cluster->slabs;
      i = 0;
      while (slab) {
        i++;
        head = slab;
        slab = slab->next;
        free(head);
      }
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "instance %p - %d memory slabs freed from cluster\n", instance, i);
      memset(cluster, '\0', sizeof(struct fusedPcapCluster_s));
    }
    pthread_mutex_unlock(&clusterMutex);
  }
  else {
    if (instance->fd)
      ret = close(instance->fd);
  }
  //if (instance->shortPath)
    //free(instance->shortPath);
  memset(instance, '\0', sizeof(struct fusedPcapInstance_s));
  pthread_mutex_unlock(&instanceMutex);
  return ret;
}

static struct fusedPcapInstance_s *populateInstance(const char *shortPath, struct fusedPcapConfig_s *config)
{
  struct fuse_context *context;
  struct fusedPcapInstance_s *instance;
  struct fusedPcapCluster_s *cluster;
  struct packet_link_s *next;
  int i;

  cluster = NULL;
  context = fuse_get_context();

  //need to protect fusedPcapInstances array allocation with mutex
  pthread_mutex_lock(&instanceMutex);
  for (i=0; i<MAX_CLUSTER_SIZE; i++)
    if (fusedPcapInstances[i].pid == 0)
      break;
  if (i == MAX_CLUSTER_SIZE)
    return NULL;
  instance = &fusedPcapInstances[i];
  instance->pid = context->pid;
  //once pid is non-zero, other threads will skip the entry, so release mutex while we finish
  pthread_mutex_unlock(&instanceMutex);

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "instance %p - populating struct for %s [%d]\n", instance, shortPath, context->pid);

  memcpy(&instance->config, config, sizeof(struct fusedPcapConfig_s));

  instance->readOffset = 0ll;
  instance->outputOffset = 0ll;
  instance->endFile[0] = '\0';
  instance->bits = 0;

  if (config->clustersize == 1) {
    if (instance->shortPath)
      free(instance->shortPath);
    //NOTE: if strdup fails, this is set to NULL; always verify before dereferencing
    instance->shortPath = strdup(shortPath);
  }

  else {
    pthread_mutex_lock(&clusterMutex);
    for (i=0; i<MAX_NUM_CLUSTERS; i++) {
      cluster = &fusedPcapClusters[i];
      if (cluster->shortPath && strcmp(cluster->shortPath, shortPath) == 0 &&
          memcmp(&cluster->config, config, sizeof(struct fusedPcapConfig_s)) == 0)
        break; // found cluster that matches shortPath and config
    }
    if (i < MAX_NUM_CLUSTERS) {  // found a matching shortPath and config
      cluster = &fusedPcapClusters[i];
      for (i=0; i<config->clustersize; i++)
        if (cluster->instance[i] == NULL)
          break;
      if (i < config->clustersize) {
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "instance %p - to cluster %p as member %d\n", instance, cluster, i);
        instance->cluster = cluster;
        instance->member = i;
        instance->shortPath = cluster->shortPath;
        cluster->instance[i] = instance; // last change for thread safety
        if (i + 1 == config->clustersize)
          cluster->fullyPopulated = 1;
      }

      else {
        closeInstance(instance);
        instance = NULL;
      }

    }
    else {
      for (i=0; i<MAX_NUM_CLUSTERS; i++)
        if (fusedPcapClusters[i].shortPath == NULL)
          break;
      if (i < MAX_NUM_CLUSTERS) {  // found a free cluster offset
        cluster = &fusedPcapClusters[i];
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "instance %p - populating new cluster at %p as member 0\n", instance, cluster);
        pthread_mutex_init(&cluster->readThreadMutex, NULL);
        pthread_spin_init(&cluster->queueHeadSpin, 0);
        instance->cluster = cluster;
        instance->member = 0;
        memcpy(&cluster->config, config, sizeof(struct fusedPcapConfig_s));
        cluster->shortPath = strdup(shortPath);
        instance->shortPath = cluster->shortPath;
        cluster->instance[0] = instance; // last change for thread safety
        cluster->slabs = calloc(SLAB_ALLOC_COUNT, sizeof(struct packet_link_s));
        if (cluster->slabs) {
          cluster->free = next = cluster->slabs + 1;
          for (i=2; i<SLAB_ALLOC_COUNT; i++) { // first used by slabs, last has free=NULL
            next = next->free = next + 1;
          }
          if (fusedPcapGlobal.debug)
            fprintf(stderr, "instance %p - new slab at %p\n", instance, cluster->slabs);
        }
      }

      else {
        // TODO: no room at the inn
        closeInstance(instance);
        instance = NULL;
      }

    }
    pthread_mutex_unlock(&clusterMutex);
  }

  return instance;
}

static struct fusedPcapInstance_s *findInstance(void)
{
  struct fuse_context *context;
  int i;

  //this is read-only, no need to protect with a mutex
  context = fuse_get_context();
  for (i=0; i<MAX_CLUSTER_SIZE; i++)
    if (fusedPcapInstances[i].pid == context->pid)
      return &fusedPcapInstances[i];
  return NULL;
}

static inline void setInstance(struct fuse_file_info *fileInfo, struct fusedPcapInstance_s *instance)
{
  fileInfo->fh = (uint64_t)instance;  //masking only, no mutex needed
}

static inline struct fusedPcapInstance_s *getInstance(struct fuse_file_info *fileInfo)
{
  return (struct fusedPcapInstance_s *)fileInfo->fh;  //masking only, no mutex needed
}

static inline void setDirectory(struct fuse_file_info *fileInfo, struct fusedPcapDirectory_s *directory)
{
  fileInfo->fh = (uint64_t)directory;  //masking only, no mutex needed
}

static inline struct fusedPcapDirectory_s *getDirectory(struct fuse_file_info *fileInfo)
{
  return (struct fusedPcapDirectory_s *)fileInfo->fh;  //masking only, no mutex needed
}

// FUSE CALLBACKS

static void *fused_pcap_init(struct fuse_conn_info *conn)
{
  (void) conn;
  syslog(LOG_INFO, "fused_pcap initialized");
  return NULL;
}

static void fused_pcap_destroy(void *privateData)
{
  (void) privateData;
  syslog(LOG_INFO, "fused_pcap exiting");
}

static int fused_pcap_getattr(const char *path, struct stat *stData)
{
  struct fusedPcapConfig_s fileConfig;
  struct fusedPcapInstance_s *instance;
  struct fusedPcapResidual_s *residual;
  const char *mountPath;
  const char *filename;
  const char *specialFile;
  const char *endFile;
  char statPath[PATH_MAX];
  int length;

  if (parsePath(path, &fileConfig, &mountPath, &filename, &specialFile, &endFile))
    return -ENOENT;
  if (fusedPcapGlobal.debug && path != mountPath)
    printConfigStruct(&fileConfig);

  if (mountPath == NULL || specialFile) {

    stData->st_uid = geteuid();
    stData->st_gid = getegid();
    stData->st_nlink = 1;
    stData->st_blocks = 1;
    stData->st_ino = 99999;

    if (specialFile) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "getattr call detected %s is a special file\n", path);

      residual = getResidual(&fileConfig, NULL);
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "getResidual returned %p\n", residual);

      stData->st_size = fusedPcapGlobal.pageSize;
      stData->st_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;
      if (strcmp(specialFile, "/..status") == 0)
        return 0;
      if (residual->lastFile && strcmp(specialFile, "/..last") == 0)
        return 0;
      if (residual->thisFile && strcmp(specialFile, "/..current") == 0)
        return 0;
      if (residual->nextFile && strcmp(specialFile, "/..next") == 0)
        return 0;
      if (residual->abendPid && strcmp(specialFile, "/..abend") == 0)
        return 0;
      if (residual->pid[0] && strcmp(specialFile, "/..pids") == 0)
        return 0;
      if (residual->endFile && strcmp(specialFile, "/..end") == 0) {
        stData->st_size = strlen(residual->endFile);
        stData->st_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        return 0;
      }
      return -ENOENT;
    }
    else {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "getattr call detected %s is a special directory\n", path);
      stData->st_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH | S_IXUSR | S_IXGRP | S_IXOTH;
      return 0;
    }
  }

  snprintf(statPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, mountPath);
  if (endFile) {
    if (endFile[0]) {
      length = filename - mountPath + strlen(fusedPcapGlobal.pcapDirectory) + 1;
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "getattr using ending file instead of start file (len=%d\n", length);
    }
    else {
      length = endFile - mountPath + strlen(fusedPcapGlobal.pcapDirectory) - 2;
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "getattr detected empty ending file, truncating start file to %d\n", length);
    }
    if (length > PATH_MAX)
      return -EINVAL;
    statPath[length] = '\0';
    strncat(statPath, endFile, PATH_MAX - length);
  }

  // lookup calling pid, check if file is already opened
  instance = findInstance();
  if (instance && instance->shortPath && strcmp(mountPath, instance->shortPath) == 0) {
    // if it is, we need to return the cached attributes, as we may have
    // altered its virtual size or it may no longer exist.
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "getattr using cached stData for %s\n", mountPath);
    memcpy(stData, &instance->stData, sizeof(struct stat));
    return 0;
  }

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "getattr calling stat for %s\n", statPath);
  if (stat(statPath, stData) == -1) {
    return -errno;
  }

  stData->st_mode = stData->st_mode & ~(S_IWUSR | S_IWGRP | S_IWOTH);
  if (S_ISREG(stData->st_mode))
  if (endFile) {
    if (endFile[0]) {
      //TODO: compute sum (less extra headers) of files between filename and endFile
      stData->st_size *= 4;
    }
    else
      stData->st_size = fileConfig.filesize;
  }

  return 0;
}

static int fused_pcap_readlink(const char *path, char *buffer, size_t size)
{
  const char *mountPath;

  parsePath(path, NULL, &mountPath, NULL, NULL, NULL);
  if (mountPath)
    if (readlink(mountPath, buffer, size) == -1)
      return -errno;
  return 0;
}

static int fused_pcap_opendir(const char *path, struct fuse_file_info *fileInfo)
{
  char openDirPath[PATH_MAX + 1];
  struct fusedPcapDirectory_s *dirInfo;
  //struct fusedPcapConfig_s fileConfig;
  const char *mountPath;
  struct fusedPcapConfig_s config;

  if (parsePath(path, &config, &mountPath, NULL, NULL, NULL))
    return -ENOENT;
  if (fusedPcapGlobal.debug && path != mountPath)
    printConfigStruct(&config);

  dirInfo = malloc(sizeof(struct fusedPcapDirectory_s));
  if (dirInfo == NULL)
    return -ENOMEM;
  dirInfo->pathPrefix = strdup(path);
  dirInfo->residual = getResidual(&config, NULL);
  if (dirInfo->residual == NULL)
    return -ENOMEM;

  if (! mountPath)
    mountPath = "/";
  snprintf(openDirPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, mountPath);

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "opendir call opening %s\n", openDirPath);
  dirInfo->fd = opendir(openDirPath);
  if (dirInfo->fd == NULL) {
    free(dirInfo);
    return -errno;
  }
  setDirectory(fileInfo, dirInfo);

  return 0;
}

static int fused_pcap_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fileInfo)
{
  char fillerPath[PATH_MAX + 1];
  struct dirent *entry;
  struct stat status;
  struct fusedPcapDirectory_s *dirInfo;
  struct fusedPcapConfig_s *config;

  (void)path;  // should not use if flag_nopath is set
  (void)offset;

  dirInfo = getDirectory(fileInfo);
  while ((entry = readdir(dirInfo->fd)) != NULL) {
    memset(&status, 0, sizeof(struct stat));
    status.st_ino = entry->d_ino;
    status.st_mode = entry->d_type << 12;

    if (fusedPcapGlobal.debug)
      fprintf(stderr, "readdir call sending file %s to filler callback\n", entry->d_name);
    if (filler(buffer, entry->d_name, &status, 0))
      break;
  }

  memset(&status, 0, sizeof(struct stat));
  status.st_uid = geteuid();
  status.st_gid = getegid();
  status.st_nlink = 1;
  status.st_blocks = 1;
  status.st_ino = 99999;

  status.st_size = fusedPcapGlobal.pageSize;
  status.st_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;

  snprintf(fillerPath, PATH_MAX, "..status");
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
  filler(buffer, fillerPath,  &status, 0);

  if (dirInfo->residual->lastFile) {
    snprintf(fillerPath, PATH_MAX, "..last");
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
    filler(buffer, fillerPath,  &status, 0);
  }
  if (dirInfo->residual->thisFile) {
    snprintf(fillerPath, PATH_MAX, "..current");
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
    filler(buffer, fillerPath,  &status, 0);
  }
  if (dirInfo->residual->nextFile) {
    snprintf(fillerPath, PATH_MAX, "..next");
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
    filler(buffer, fillerPath,  &status, 0);
  }
  if (dirInfo->residual->abendPid) {
    snprintf(fillerPath, PATH_MAX, "..abend");
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
    filler(buffer, fillerPath,  &status, 0);
  }
  if (dirInfo->residual->pid[0]) {
    snprintf(fillerPath, PATH_MAX, "..pids");
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
    filler(buffer, fillerPath,  &status, 0);
  }
  if (dirInfo->residual->endFile) {
    snprintf(fillerPath, PATH_MAX, "..end");
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
    filler(buffer, fillerPath,  &status, 0);
  }

  status.st_size = 1;
  status.st_mode = S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO;

  config = &(dirInfo->residual->config);
  snprintf(fillerPath, PATH_MAX, "..filesize=%lli", (long long int)config->filesize);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
  filler(buffer, fillerPath,  &status, 0);
  snprintf(fillerPath, PATH_MAX, "..clustersize=%d", config->clustersize);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
  filler(buffer, fillerPath,  &status, 0);
  snprintf(fillerPath, PATH_MAX, "..clustermode=%d", config->clustermode);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
  filler(buffer, fillerPath,  &status, 0);
  snprintf(fillerPath, PATH_MAX, "..clusterabend=%d", config->clusterabend);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
  filler(buffer, fillerPath,  &status, 0);
  snprintf(fillerPath, PATH_MAX, "..blockslack=%d", config->blockslack);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "readdir call sending %s to filler callback\n", fillerPath);
  filler(buffer, fillerPath,  &status, 0);
  if (config->keepcache)
    filler(buffer, "..keepcache",  &status, 0);

  return 0;
}

static int fused_pcap_releasedir(const char *path, struct fuse_file_info *fileInfo)
{
  struct fusedPcapDirectory_s *dirInfo;
  DIR *fd;

  (void)path;  // should not use if flag_nopath is set

  dirInfo = getDirectory(fileInfo);
  fd = dirInfo->fd;
  if (dirInfo->pathPrefix)
    free(dirInfo->pathPrefix);
  free(dirInfo);

  if (closedir(fd) != 0)
    return -errno;
  return 0;
}

static int fused_pcap_create(const char *path, mode_t mode, struct fuse_file_info *fileInfo)
{
  struct fusedPcapConfig_s fileConfig;
  struct fusedPcapResidual_s *residual;
  const char *specialFile;
  const char *mountPath;

  (void)mode;
 
  if (parsePath(path, &fileConfig, &mountPath, NULL, &specialFile, NULL))
    return -ENOENT;

  if (specialFile && strcmp(specialFile, "/..end") == 0) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "create call attempt on allowed special file %s\n", specialFile);
    //TODO:

    residual = getResidual(&fileConfig, mountPath);
    if (!residual)
      return -EMFILE;

    if (! residual->endFile)
      residual->endFile = strdup("");
    //if fh is a small number, it's the index into residual, and it's path is the filename
    fileInfo->fh = getResidualIndex(residual);
    return 0;
  }

  return -EROFS;
}

static int fused_pcap_mknod(const char *path, mode_t mode, dev_t rdev)
{
  (void)path;
  (void)mode;
  (void)rdev;
  return -EROFS;
}

static int fused_pcap_mkdir(const char *path, mode_t mode)
{
  (void)path;
  (void)mode;
  return -EROFS;
}

static int fused_pcap_unlink(const char *path)
{
  struct fusedPcapConfig_s fileConfig;
  const char *mountPath;
  const char *specialFile;
  struct fusedPcapResidual_s *residual;

  if (parsePath(path, &fileConfig, &mountPath, NULL, &specialFile, NULL))
    return -ENOENT;

  if (! specialFile || strcmp(specialFile, "/..end") != 0)
    return -EROFS;

  residual = getResidual(&fileConfig, mountPath);
  if (residual) {
    if (residual->endFile)
      free(residual->endFile);
    residual->endFile = NULL;
    return 0;
  }
  return -EINVAL;
}

static int fused_pcap_rmdir(const char *path)
{
  (void)path;
  return -EROFS;
}

static int fused_pcap_symlink(const char *from, const char *to)
{
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_rename(const char *from, const char *to)
{
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_link(const char *from, const char *to)
{
  (void)from;
  (void)to;
  return -EROFS;
}

static int fused_pcap_chmod(const char *path, mode_t mode)
{
  (void)path;
  (void)mode;
  return -EROFS;
}

static int fused_pcap_chown(const char *path, uid_t uid, gid_t gid)
{
  (void)path;
  (void)uid;
  (void)gid;
  return -EROFS;
}

static int fused_pcap_truncate(const char *path, off_t size)
{
  struct fusedPcapConfig_s fileConfig;
  const char *mountPath;
  const char *specialFile;
  struct fusedPcapResidual_s *residual;

  if (size != 0)
    return -EFBIG;

  if (parsePath(path, &fileConfig, &mountPath, NULL, &specialFile, NULL))
    return -ENOENT;

  if (! specialFile || strcmp(specialFile, "/..end") != 0)
    return -EROFS;

  residual = getResidual(&fileConfig, mountPath);
  if (residual) {
    if (residual->endFile)
      free(residual->endFile);
    residual->endFile = strdup("");
    return 0;
  }
  return -EINVAL;
}

static int fused_pcap_utimens(const char *path, const struct timespec timeSpec[2])
{
  (void)path;
  (void)timeSpec;
  return -EROFS;
}

static int fused_pcap_open(const char *path, struct fuse_file_info *fileInfo)
{
  char openPath[PATH_MAX];
  struct fusedPcapConfig_s fileConfig;
  struct fusedPcapInstance_s *instance;
  struct fusedPcapResidual_s *residual;
  struct fuse_context *context;
  const char *mountPath;
  const char *filename;
  const char *specialFile;
  const char *endFile;
  int length;
  int i;
  int fd;
  
  fd = -1;

  if (parsePath(path, &fileConfig, &mountPath, &filename, &specialFile, &endFile))
    return -ENOENT;
  if (mountPath == NULL || filename == NULL)
    return -ENOENT;
  if (fusedPcapGlobal.debug && path != mountPath)
    printConfigStruct(&fileConfig);

  if (fileInfo->flags & (O_CREAT | O_WRONLY) && (specialFile == NULL || strcmp(specialFile, "/..end") != 0)) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "open call detected O_CREAT or O_WRONLY flags in %x, returning EROFS\n", fileInfo->flags);
    return -EROFS;
  }

  if (specialFile) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "open call attempt to open special file %s\n", specialFile);
    //TODO:

    residual = getResidual(&fileConfig, mountPath);
    if (!residual)
      return -EMFILE;

    //if fh is a small number, it's the index into residual, and it's path is the filename
    fileInfo->fh = getResidualIndex(residual);
    return 0;
  }

  snprintf(openPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, mountPath);
  if (endFile) {
    length = endFile - mountPath + strlen(fusedPcapGlobal.pcapDirectory) - 2;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "open call detected ending file, truncating openPath at offset %d\n", length);
    if (length > PATH_MAX)
      return -ENAMETOOLONG;
    openPath[length] = '\0';
  }

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "open call calling open() for path %s\n", openPath);
  fd = open(openPath, fileInfo->flags);
  if (fd == -1)
    return -errno;

  // read first few bytes, verify it's a pcap, rewind to beginning of file

  fileInfo->direct_io = 1;
  fileInfo->nonseekable = 1;
  if (fileConfig.keepcache)
    fileInfo->keep_cache = 1;

  instance = populateInstance(mountPath, &fileConfig);
  if (!instance) {
    close(fd);
    return -ENOMEM;
  }

  if (stat(openPath, &instance->stData) == -1) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "open call failing on stat() for %s\n", openPath);
    closeInstance(instance);
    return -errno;
  }
  instance->stData.st_size = instance->config.filesize;
  instance->fd = fd;
  if (instance->cluster)
    instance->cluster->fd = fd;

  if (endFile)
    snprintf(instance->endFile, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, endFile);

  instance->readFile = strdup(openPath);
  instance->nonblocking = ((fileInfo->flags | O_NONBLOCK) == O_NONBLOCK);
  setInstance(fileInfo, instance);

  residual = getResidual(&fileConfig, filename);
  if (residual) {
    pthread_mutex_lock(&residualMutex);
    context = fuse_get_context();
    for (i=0; i<MAX_CLUSTER_SIZE; i++)
      if (residual->pid[i] == 0)
        break;
    if (i < MAX_CLUSTER_SIZE) {
      residual->pid[i] = context->pid;
    }
    if (residual->thisFile) {
      if (residual->lastFile)
        free(residual->lastFile);
      residual->lastFile = residual->thisFile;
    }
    residual->thisFile = strdup(openPath);
    pthread_mutex_unlock(&residualMutex);
  }

  return 0;
}

static int readSpecialFile(char *buffer, size_t size, off_t offset, struct fusedPcapResidual_s *residual)
{
  int i;
  int len;

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "read call (special file) - residual at %p, mountPath is %s\n", residual, residual->mountPath);

  if (offset)
    return 0;

  if (residual->mountPath && strcmp(residual->mountPath, "/..status") == 0) {
    strncpy(buffer, "********** This is my special wonder-file ...\n", size); //TODO
    //snprintf(buffer, size, "%s\n"%s\n",
      //"",
      //"",
      //...,
      //...);
    return strlen(buffer);
  }
  if (residual->mountPath && strcmp(residual->mountPath, "/..last") == 0)
    if (residual->lastFile && residual->lastFile[0])
      return snprintf(buffer, size, "%s\n", residual->lastFile);
  if (residual->mountPath && strcmp(residual->mountPath, "/..current") == 0)
    if (residual->thisFile && residual->thisFile[0])
      return snprintf(buffer, size, "%s\n", residual->thisFile);
  if (residual->mountPath && strcmp(residual->mountPath, "/..next") == 0)
    if (residual->nextFile && residual->nextFile[0])
      return snprintf(buffer, size, "%s\n", residual->nextFile);
  if (residual->mountPath && strcmp(residual->mountPath, "/..pids") == 0) {
    buffer[0] = '\0';
    for (i=0; i<MAX_CLUSTER_SIZE && residual->pid[i] != 0; i++) {
      len = strnlen(buffer, size - 16); //strlen excludes terminating NUL
      snprintf(buffer + len, size - len, "%d\n", residual->pid[i]);
    }
    return strlen(buffer);
  }
  if (residual->mountPath && strcmp(residual->mountPath, "/..end") == 0)
    if (residual->endFile && residual->endFile[0])
      return snprintf(buffer, size, "%s\n", residual->endFile);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "READ CALL (special file) failed to match!  last: %s  this: %s  next: %s\n", residual->lastFile, residual->thisFile, residual->nextFile);
  return -EINVAL;
}

static int nextPcapAvailable(int *newFd)
{
  (void)newFd;

  //TODO: check if new file exists, read the first 24 bytes, and return true if it's a pcap

  return 0;
}

static int fillClusterBuffer(struct fusedPcapCluster_s *cluster, int readSize)
{
  int i;
  int length;
  int sizeRes;
  struct clusterBuffer_s *buf;
  struct packet_link_s *link;
  int newFd;

  buf = &cluster->buf;

  if (buf->begin == NULL) {
    length = fusedPcapGlobal.pageSize * cluster->config.blockslack;
    buf->begin = malloc(length);
    if (buf->begin == NULL)
      return -ENOMEM;
    buf->end = buf->begin + length;
    buf->read = buf->begin;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "fillClusterBuffer - %d bytes allocated at %p\n", length, buf->begin);

    //TODO: read the first page in
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "fillClusterBuffer - attempting to read %ld bytes from fd %d to %p\n", fusedPcapGlobal.pageSize, cluster->fd, buf->read);
    sizeRes = read(cluster->fd, buf->read, fusedPcapGlobal.pageSize);
    if (sizeRes == -1)
      return -errno;
    //if (sizeRes < 24)
      //return -EINVAL;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "fillClusterBuffer - %d bytes read to address %p, magic number: %x\n", sizeRes, buf->read, *((unsigned *)buf->begin));
    buf->read = buf->begin + sizeRes;

    //TODO: verify it's a pcap
    if ((((unsigned *)buf->begin)[0] != 0xa1b2c3d4 && ((unsigned *)buf->begin)[0] != 0xa1b23c4d) || ((unsigned *)buf->begin)[1] != 0x00040002) {
      free(buf->begin);
      buf->begin = NULL;
      return -EINVAL;
    }

    //add a link to each cluster member to copy the header
    for (i=0; i<cluster->config.clustersize; i++) {
      link = cluster->free;
      cluster->free = link->free;
      memset((void *)link, '\0', sizeof(struct packet_link_s));
      link->offset = buf->begin;
      link->size = 24;
      pthread_mutex_lock(&clusterMutex);
      if (cluster->instance[i]) {
        //assert(cluster->instance[i]->queue == NULL);
        cluster->instance[i]->queue = link;
      }
      pthread_mutex_unlock(&clusterMutex);
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "fillClusterBuffer - cluster member %d got header link (%d bytes at %p)\n", i, link->size, link->offset);
    }
    buf->next = buf->begin + 24;
  }

  // pointers into clusterBuffer:
  // | <--begin (also what is freed when done)
  // | (available)
  // | <--oldest (pulled from cluster member queues
  // | (in queues)
  // | <--next (start of next packet to process (may not be complete)
  // | (partial packet, if present)
  // | <--read (where next read is going to put data (size: end-read)
  // | (available to be filled by read)
  // | <--end (buffer + sizeof(buffer), precomputed for ease
  //
  // or, if rolled around:
  // | <--begin
  // | (in queues)
  // | <--next
  // | (partial packet, if present)
  // | <--read
  // | (available to be filled by read)
  // | <--oldest
  // | (in queues)
  // | (unused, if partial packet previously copied to begin)
  // | <--end
  //
  // when updating oldest, lower is older, but above read is older than below read
  // if ((oldest<read && read<test) || ((oldest<read || read<test) && test<oldest)) oldest=test;

  do {
    
    //find instance that's the furthest behind
    buf->oldest = buf->read;
    for (i=0; i<cluster->config.clustersize; i++) {
      link = NULL;
      pthread_mutex_lock(&clusterMutex);
      if (cluster->instance[i])
        link = cluster->instance[i]->queue;
      pthread_mutex_unlock(&clusterMutex);
      if (link) {
        if ((buf->oldest <= buf->read && buf->read < link->offset) ||
           ((buf->oldest <= buf->read || buf->read < link->offset) &&
            link->offset < buf->oldest)) {
          buf->oldest = link->offset;
          if (fusedPcapGlobal.debug)
            fprintf(stderr, "fillClusterBuffer - member %d has oldest: %p, read: %p, end: %p, link: %p\n", i, buf->oldest, buf->read, buf->end, link ? link->offset : NULL);
        }
      }
    }

    //if there's room, move partial packet to beginning of the buffer
    if (buf->read + fusedPcapGlobal.pageSize - 1 >= buf->end) {
      length = buf->read - buf->next;
      if (buf->oldest - buf->begin >= length) {
        //TODO: assert(buf->begin + length < buf->next) //memcpy with overlapping ranges is undefined
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "fillClusterBuffer - moving partial packet of %d bytes from %p to start\n", length, buf->next);
        memcpy(buf->begin, buf->next, length);
        buf->next = buf->begin;
        buf->read = buf->begin + length;
      }
    }

    //determine how many bytes are available
    if (buf->read < buf->oldest)
      length = buf->oldest - buf->read;
    else
      length = buf->end - buf->read;
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "fillClusterBuffer - available length before adjustment is %d\n", length);

    //only read lengths that are multiples of pagesize and less or equal to what client requested
    if (length > readSize)
      length = readSize;
    else
      length &= ~(fusedPcapGlobal.pageSize - 1);

    //whoops! nowhere to put anything..
    if (length <= 0) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "fillClusterBuffer - giving other readers a chance to catch up...\n");
        return 0;
    }

    //TODO: try to read
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "fillClusterBuffer - reading %d bytes to %p\n", length, buf->read);
    sizeRes = read(cluster->fd, buf->read, length);
    if (sizeRes == -1)
      return -errno;

    // if at EOF, determine what to do
    if (sizeRes == 0) {
      pthread_mutex_lock(&clusterMutex);
        for (i=0; i<cluster->config.clustersize; i++) {
          if (cluster->instance[i] == NULL || cluster->instance[i]->queue)
            break;
        }
      pthread_mutex_unlock(&clusterMutex);

      if (i != cluster->config.clustersize) {
        if (cluster->instance[i]) {  // fell out because queue isn't empty
          if (fusedPcapGlobal.debug)
            fprintf(stderr, "fillClusterBuffer - read returned 0 bytes, not all queues empty\n");
          return 0;
        }

        else {  // fell out because instance is gone
          if (!cluster->memberError) {
            if (fusedPcapGlobal.debug)
              fprintf(stderr, "FILLCLUSTERBUFFER - detected abnormal end to one of the instances!!\n");
            cluster->memberError = 1;
          }
          return 0;
        }
      }

      else { // all queues are empty, check for ..end, newer files, etc.
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "fillClusterBuffer - read returned 0 bytes, all queues are empty, checking for new file\n");
        if (nextPcapAvailable(&newFd)) {
          close(cluster->fd);
          cluster->fd = newFd;
        }

        // nothing to do, try again in a bit
        return 0;
      }
return 0;
    }

    //TODO: other counters here?
    buf->read += sizeRes;

    if (fusedPcapGlobal.debug)
      fprintf(stderr, "fillClusterBuffer - read %d bytes, next read point is %p\n", sizeRes, buf->read);
    return 0;
  } while (1);
}

static struct packet_link_s *getFreeLink(struct fusedPcapCluster_s *cluster)
{
  struct packet_link_s *link;
  int i;

  if (cluster->free == NULL) {
    link = calloc(SLAB_ALLOC_COUNT, sizeof(struct packet_link_s));
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "getFreeLink - allocated new slab %p\n", link);
    if (link) {
      //struct packet_link_s *oldfree = cluster->free;  // if adding to rather than initializing
      link->next = cluster->slabs;
      cluster->slabs = link;
      cluster->free = link = cluster->slabs + 1;
      for (i=2; i<SLAB_ALLOC_COUNT; i++) // first used by slabs, last has free=NULL
        link = link->free = link + 1;
    }
    else {
      syslog(LOG_ERR, "getFreeLink could not allocate another slab");
      exit(1);
    }
  }

  link = cluster->free;
  cluster->free = link->free;
  memset(link, '\0', sizeof(struct packet_link_s));
  return link;
}

static void parsePackets(struct fusedPcapCluster_s *cluster, struct packet_link_s *newlink[])
{
  struct packet_link_s *link;
  struct packet_link_s *tail;
  int i;
  int size;

  //TODO: parse the packets, adding links to members' queues, allocating queue links as needed
  //size = cluster->buf.read - cluster->buf.next;
  if (cluster->buf.read - cluster->buf.next < 16)
    return;
  size = ((unsigned *)cluster->buf.next)[2];
  size += 16;
  //TODO:  WARNING!!! buffer overrun here if .next is too close to .end...

  while (size <= cluster->buf.read - cluster->buf.next) {

    //TODO: determine which instance it should be sent to
    i = (unsigned long long)cluster->buf.next / 8 % cluster->config.clustersize;

    if (cluster->instance[i]) {
      link = getFreeLink(cluster);
      //TODO: populate it's fields
      link->next = NULL;
      link->size = size;
      link->offset = cluster->buf.next;

      if (fusedPcapGlobal.debug)
        fprintf(stderr, "parsePackets - adding %d bytes at %p to member %d newlink\n", link->size, link->offset, i);
      if (newlink[i]) {
        tail = newlink[i];
        while (tail->next)
          tail = tail->next;
        tail->next = link;
      }
      else
        newlink[i] = link;
    }

    (cluster->buf.next) += size;
    if (cluster->buf.read - cluster->buf.next < 16)
      return;
    size = ((unsigned *)cluster->buf.next)[2]; 
    size += 16;
  }
}


static int fillClusterQueues(struct fusedPcapInstance_s *instance, int readSize)
{
  struct packet_link_s *lastlink[MAX_CLUSTER_SIZE];
  struct packet_link_s *newlink[MAX_CLUSTER_SIZE];
  struct packet_link_s *lastfree;
  struct packet_link_s *freehead;
  struct fusedPcapCluster_s *cluster;
  int clustersize;
  int i;
  int count;

  // assert: we hold read Mutex, can modify cluster lists and instance lists other than the first link  
  cluster = instance->cluster;

  do {
    if ((i = fillClusterBuffer(cluster, readSize)) != 0)
      return i;

    clustersize = instance->config.clustersize;
    for (i=0; i<clustersize; i++) {

      // find the last link in the list (where we'll append new ones)
      lastlink[i] = NULL;
      pthread_mutex_lock(&clusterMutex);

      if (cluster->instance[i]) {
        lastlink[i] = cluster->instance[i]->queue;

        if (cluster->memberError) {
          if (cluster->config.clusterabend == CLUSTER_ABEND_IMMEDIATE_ERROR_ALL)
            cluster->instance[i]->abortErr = 1;
          if (cluster->config.clusterabend == CLUSTER_ABEND_IMMEDIATE_EOF_ALL)
            cluster->instance[i]->abortEof = 1;
          if (cluster->config.clusterabend == CLUSTER_ABEND_ERR_ALL_AT_EOF)
            cluster->instance[i]->fileEndErr = 1;
          if (cluster->config.clusterabend == CLUSTER_ABEND_EOF_ALL_AT_EOF)
            cluster->instance[i]->fileEndEof = 1;
        }
      }
      if (lastlink[i])
        while (lastlink[i]->next)
          lastlink[i] = lastlink[i]->next;

      // move any free links (except the first) from the instance to the cluster
      freehead = NULL;
      count = 0;
      if (cluster->instance[i])
        freehead = cluster->instance[i]->free;

      pthread_mutex_unlock(&clusterMutex);

      if (freehead) {
        lastfree = freehead->free;
        while (lastfree && lastfree->free) {
          lastfree = lastfree->free;
          count++;
        }
        if (lastfree) { // move links between freehead->free and lastfree to beginning of cluster free list
          lastfree->free = cluster->free;
          cluster->free = freehead->free;
          freehead->free = NULL;
        }
      }

      // initialize the array of new links to be added
      newlink[i] = NULL;

      if (fusedPcapGlobal.debug)
        fprintf(stderr, "fillClusterQueue - cluster %p index %d lastlink %p freehead %p (freed %d links)\n", cluster, i, lastlink[i], freehead, count);
    }

    // before we go any further, check if we should abort
    if (instance->abortErr)
      return -EIO;
    if (instance->abortEof)
      return -EOF;

    parsePackets(cluster, newlink);

    for (i=0; i<clustersize; i++) {
      if (newlink[i] && cluster->instance[i]) {
        pthread_spin_lock(&cluster->queueHeadSpin);
        if (lastlink[i] && cluster->instance[i]->queue)
          lastlink[i]->next = newlink[i];
        else {
          cluster->instance[i]->queue = newlink[i];
        }
        pthread_spin_unlock(&cluster->queueHeadSpin);
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "fillClusterQueue - cluster member %d: adding newlink %p to end of chain\n", i, newlink[i]);
      }
    }

    if (instance->queue)
      return 0;

    if (instance->nonblocking)
      return -EAGAIN;
    usleep(10000);
    if (fuse_interrupted())
      return -EINTR;
    if (instance->abortErr)
      return -EIO;

  } while (1);
}

static int readClusteredFile(char *buffer, size_t size, off_t offset, struct fusedPcapInstance_s *instance)
{
  int clustersize;
  int count;
  int i;
  struct timespec timeSpec;
  int earlyBreak;

  count = 0;
  clustersize = instance->config.clustersize;

  if (fusedPcapGlobal.debug && instance->cluster && ! instance->cluster->fullyPopulated)
    fprintf(stderr, "instance %p - clustersize: %d, blocking on fullyPopulated flag\n", instance, clustersize);
  while (! instance->cluster->fullyPopulated) {
    if (instance->nonblocking)
      return -EAGAIN;
    usleep(10000);
    count++;
    if (fuse_interrupted())
      return -EINTR;
    if (instance->abortErr)
      return -EIO;
  }
  if (fusedPcapGlobal.debug && count)
    fprintf(stderr, "instance %p - fullyPopulated flag detected, proceeding with read after %d checks\n", instance, count);

  earlyBreak = 0;
  while (instance->queue == NULL) {
    count = 1;

    if (clock_gettime(CLOCK_REALTIME, &timeSpec) == -1)
      if (fusedPcapGlobal.debug && count)
        fprintf(stderr, "instance %p - cluster %p clock_gettime() returned %d\n", instance, instance->cluster, errno);
    if ((timeSpec.tv_nsec += 5000000ll) >= 1000000000ll) {
      timeSpec.tv_nsec -= 1000000000ll;
      timeSpec.tv_sec += 1l;
    }

    if (fusedPcapGlobal.debug)
      fprintf(stderr, "instance %p - cluster %p grabbing read mutex (timeout %zd.%ld)\n", instance, instance->cluster, timeSpec.tv_sec, timeSpec.tv_nsec);
    while (pthread_mutex_timedlock(&instance->cluster->readThreadMutex, &timeSpec) == ETIMEDOUT) {
      if (fuse_interrupted())
        return -EINTR;
      if (instance->queue != NULL) { // recheck as we may have gotten more blocks while waiting
        if (fusedPcapGlobal.debug)
          fprintf(stderr, "instance %p - cluster %p breaking out without read mutex after try %d, queue points to %p\n", instance, instance->cluster, count, instance->queue);
        earlyBreak++;
        break;
      }

      if ((timeSpec.tv_nsec += 10000000ll) >= 1000000000ll) {
        timeSpec.tv_nsec -= 1000000000ll;
        timeSpec.tv_sec += 1l;
      }
      count++;
    }
    if (earlyBreak)
      break;

    if (fusedPcapGlobal.debug)
      fprintf(stderr, "instance %p - cluster %p grabbed read mutex on try %d, queue points to %p\n", instance, instance->cluster, count, instance->queue);
    if (instance->queue == NULL) // recheck as we may have gotten more blocks while waiting
      i = fillClusterQueues(instance, size);

    //we got some blocks while we were waiting; release and continue
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "instance %p - cluster %p releasing read mutex\n", instance, instance->cluster);
    pthread_mutex_unlock(&instance->cluster->readThreadMutex);
    if (i < 0)
      return i;
    break;
  }

  // if we still have no blocks, must be at EOF
  if (instance->queue == NULL)
    return 0;

  if (size < instance->queue->size) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "instance %p - link address %p, sending %zu bytes from offset %p (partial packet)\n", instance, instance->queue, size, instance->queue->offset);
    memcpy(buffer, instance->queue->offset, size);
    instance->queue->size -= size;
    instance->queue->offset += size;
    return size;
  }

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "instance %p - link address %p, sending %d bytes from offset %p\n", instance, instance->queue, instance->queue->size, instance->queue->offset);
  memcpy(buffer, instance->queue->offset, instance->queue->size);
  //TODO: make this mutex per instance instead of per cluster
  pthread_spin_lock(&instance->cluster->queueHeadSpin);
  instance->queue->free = instance->free;
  instance->free = instance->queue;
  instance->queue = instance->queue->next;
  pthread_spin_unlock(&instance->cluster->queueHeadSpin);

  return instance->free->size;
}
  
static int readSingleFile(char *buffer, size_t size, off_t offset, struct fusedPcapInstance_s *instance)
{
  ssize_t sizeRes;
  struct fusedPcapResidual_s *residual;

  if (fusedPcapGlobal.debug)
    fprintf(stderr, "read call (single) -from offset %zu on fd %d\n", offset, instance->fd);
  //offRes = lseek(instance->fd, offset, SEEK_SET);
  //if (offRes != offset)
    //return -errno;

  sizeRes = read(instance->fd, buffer, size);
  if (sizeRes == -1)
    return -errno;
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "read call (single) -returned %zu\n", sizeRes);

  instance->readOffset += sizeRes;
  instance->outputOffset += sizeRes;

  if (sizeRes == 0) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "read call (single) - EOF detected, comparing %s and %s\n", instance->readFile, instance->endFile);

    if (instance->endFile && strcmp(instance->readFile, instance->endFile) == 0) {
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "read call (single) - EOF detected on ending file, returning 0 bytes\n");
      instance->normalEnding = 1;
      instance->config.filesize = instance->readOffset;
    }

    do {
      if (1) { //TODO: nextFileReady()) 
        //TODO: refactor into a separate function
        if (instance->fileEndEof) {
          if (fusedPcapGlobal.debug)
            fprintf(stderr, "read call (single) - setting cluster member %d to abort before next read with EOF\n", instance->clusterMember);
          //TODO: adjust instance's cached stData filesize?
          instance->abortEof = 1;
        }
        else if (instance->fileEndErr) {
          if (fusedPcapGlobal.debug)
            fprintf(stderr, "read call (single) - aborting cluster member %d at EOF before next read\n", instance->clusterMember);
          return -EIO;
        }
        else {
          if (fusedPcapGlobal.debug)
            fprintf(stderr, "TODO: close current file, open next, and continue\n");
          residual = getResidual(&instance->config, NULL);
          pthread_mutex_lock(&residualMutex);
          if (residual) {
            if (residual->lastFile)
              free(residual->lastFile);
            residual->lastFile = residual->thisFile;
            residual->thisFile = residual->nextFile;
              //residual->nextFile = getNextFile(residual->thisFile);
          }
          pthread_mutex_unlock(&residualMutex);
          //close(instance->fd);
          //instance->fd = open(nextFilePath, fileEntry->flags);
          //instance->readOffset = 0ll;
          //free readFile string and dup from nextFilePath
          //discard pcap header from new file

          //read again
        }
      }

      else if (0) { //TODO: (! non-blocking)
        //block until more available (or just wait a few and retry) //TODO: figure out how to determine more is available
        // return -EIO;
      }
    } while (0);//TODO: sizeRes == 0);
  }

  return sizeRes;
}

static int fused_pcap_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  struct fusedPcapInstance_s *instance;

  (void)path;  // should not use if flag_nopath is set

  if (fileInfo->fh < SPECIAL_FILE_COUNT)
    return readSpecialFile(buffer, size, offset, &fusedPcapResidual[fileInfo->fh]);

  instance = getInstance(fileInfo);
  if (instance == NULL)
    return -EBADF;  // fuse fd passed between pids, or process forked? look up based on name and offset?
  //if (fileEntry->readOffset != offset)
    //EINVAL? offset not suitably aligned

  //TODO: refactor into a standalone function
  if (instance->abortEof) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "read call - aborting cluster member %d before read with EOF\n", instance->clusterMember);
    instance->config.filesize = instance->readOffset;
    instance->normalEnding = 1;
    return -EOF;
  }
  if (instance->abortErr) {
    if (fusedPcapGlobal.debug)
      fprintf(stderr, "read call - aborting cluster member %d before read with ENOENT\n", instance->clusterMember);
    instance->normalEnding = 1;
    return -EIO;
  }

  if (instance->config.clustersize > 1)
    return readClusteredFile(buffer, size, offset, instance);
  return readSingleFile(buffer, size, offset, instance);
}

static int fused_pcap_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
  struct fusedPcapResidual_s *residual;

  (void)path;  // should not use if flag_nopath is set
  (void)buffer;

  if (fileInfo->fh >= SPECIAL_FILE_COUNT)
    return -EROFS;
  if (offset > 0)
    return -EINVAL;
  if (size >= PATH_MAX)
    return -EFBIG;

  residual = &fusedPcapResidual[fileInfo->fh];
  if (residual->endFile)
    free(residual->endFile);
  residual->endFile = strndup(buffer, size);
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "write call - wrote endFile of %s\n", residual->endFile);
  return size;
}

static int fused_pcap_statfs(const char *path, struct statvfs *status)
{
  if (fusedPcapGlobal.debug)
    fprintf(stderr, "statfs call - receiving statfs for %s\n", path);
  if (statvfs(fusedPcapGlobal.pcapDirectory, status) != 0)
    return -errno;
  status->f_blocks = status->f_blocks - status->f_bfree;
  status->f_bfree = status->f_bavail = 0;
  return 0;
}

static int fused_pcap_release(const char *path, struct fuse_file_info *fileInfo)
{
  struct fusedPcapInstance_s *instance;
  int i;

  //TODO: finish
  (void)path;  // should not use if flag_nopath is set
  //fileEntry = (struct fileEntry_t *)fileInfo->fh;
  //if (fileEntry->fd)
    //ret = close(fileEntry->fd);
  //if (! fileEntry->normalEnding)
    //for (each fileEntry structure in the cluster) {
      //switch (fileEntry->config.clusterabend) {
      //case CLUSTER_ABEND_EOF_ALL_AT_EOF:
        //fileEntry->fileEndEof = 1;
        //break;
      //case CLUSTER_ABEND_ERR_ALL_AT_EOF:
        //fileEntry->fileEndEof = 1;
        //break;
      //case CLUSTER_ABEND_IMMEDIATE_EOF_ALL:
        //fileEntry->abortEof = 1;
        //break;
      //case CLUSTER_ABEND_IMMEDIATE_ERROR_ALL:
        //fileEntry->abortErr = 1;
        //break;
      //case CLUSTER_ABEND_IGNORE:
        //break;
      //};
    //};
  //};
  //remove fileEntry from cluster index;
  //if (last fileEntry in clusterIndex)
    //clear clusterIndex

  if (fileInfo->fh < SPECIAL_FILE_COUNT)
    return 0;

  instance = getInstance(fileInfo);
  if (instance == NULL) {
    return -EBADF;  // fuse fd passed between pids, or process forked? look up based on name and offset?
  }

  if (instance->cluster && ! instance->normalEnding) {
    pthread_mutex_lock(&clusterMutex);
    switch (instance->config.clusterabend) {
    case CLUSTER_ABEND_EOF_ALL_AT_EOF:
      for (i=0; i<instance->config.clustersize; i++)
        if (instance->cluster->instance[i])
          instance->cluster->instance[i]->fileEndEof = 1;
      break;
    case CLUSTER_ABEND_ERR_ALL_AT_EOF:
      for (i=0; i<instance->config.clustersize; i++)
        if (instance->cluster->instance[i])
          instance->cluster->instance[i]->fileEndErr = 1;
      break;
    case CLUSTER_ABEND_IMMEDIATE_EOF_ALL:
      for (i=0; i<instance->config.clustersize; i++)
        if (instance->cluster->instance[i])
          instance->cluster->instance[i]->abortEof = 1;
      break;
    case CLUSTER_ABEND_IMMEDIATE_ERROR_ALL:
      for (i=0; i<instance->config.clustersize; i++)
        if (instance->cluster->instance[i])
          instance->cluster->instance[i]->abortErr = 1;
      break;
    case CLUSTER_ABEND_IGNORE: //TODO: need to tell other members not to wait or assign queue links
      break;
    default:
      syslog(LOG_ERR, "invalid clusterabend value detected during release");
      break;
    }
    pthread_mutex_unlock(&clusterMutex);
  }

  return closeInstance(instance);
}

static int fused_pcap_fsync(const char *path, int dummy, struct fuse_file_info *fileInfo)
{
  (void)path;  // should not use if flag_nopath is set
  (void)dummy;
  (void)fileInfo;
  if (fileInfo->fh < SPECIAL_FILE_COUNT)
    return 0;
  return -EROFS;
}

static int fused_pcap_access(const char *path, int mode)
{
  struct fusedPcapConfig_s fileConfig;
  const char *mountPath;
  const char *filename;
  const char *specialFile;
  const char *endFile;
  char accessPath[PATH_MAX];
  int length;

  if (parsePath(path, &fileConfig, &mountPath, &filename, &specialFile, &endFile))
    return -ENOENT;
  if (fusedPcapGlobal.debug && path != mountPath)
    printConfigStruct(&fileConfig);

  if (specialFile) {
    //TODO: anthing else we need to do here?
    return 0;
  }

  snprintf(accessPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, mountPath);
  if (endFile) {
    if (endFile[0]) {
      length = filename - mountPath + strlen(fusedPcapGlobal.pcapDirectory) + 1;
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "access call - ending file detected, using it instead of start file (len=%d\n", length);
    }
    else {
      length = endFile - mountPath + strlen(fusedPcapGlobal.pcapDirectory) - 2;
      if (fusedPcapGlobal.debug)
        fprintf(stderr, "access call - empty ending file detected, truncating start file to %d\n", length);
    }
    if (length > PATH_MAX)
      return -EINVAL;
    accessPath[length] = '\0';
    strncat(accessPath, endFile, PATH_MAX - length);
  }

  if (access(accessPath, mode) == -1)
    return -errno;

  return 0;
}

#ifdef HAVE_SETXATTR
static int fused_pcap_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  (void)path;
  (void)name;
  (void)value;
  (void)flags;
  return -EROFS;
}

static int fused_pcap_getxattr(const char *path, const char *name, char *value, size_t size)
{
  char mountPath[PATH_MAX + 1];
  struct fusedPcapConfig_s fileConfig;
  char *shortPath;
  //char *endFile;
  int response;

  (void)name;
  (void)value;
  (void)size;

  if (reapConfigDirs(path, &shortPath, &fileConfig))
    return -ENOENT;
  if (fusedPcapGlobal.debug)
    printConfigStruct(&fileConfig);

  if (isSpecialFile(shortPath))
    return 0;  // extended attributes are not aupported on virtual files

  separateEndingFile(&shortPath, &shortPath);

  if (! shortPath)
    shortPath = "/";
  snprintf(mountPath, PATH_MAX, "%s%s", fusedPcapGlobal.pcapDirectory, shortPath);

  response = lgetxattr(mountPath, name, value, size);
  if (response == -1)
    return -errno;
  return response;
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
  (void)path;
  (void)name;
  return -EROFS;
}
#endif


struct fuse_operations callbackOperations = {
  .init        = fused_pcap_init,
  .destroy     = fused_pcap_destroy,
  .getattr     = fused_pcap_getattr,
  .access      = fused_pcap_access,
  .readlink    = fused_pcap_readlink,
  .opendir     = fused_pcap_opendir,
  .readdir     = fused_pcap_readdir,
  .releasedir  = fused_pcap_releasedir,
  .create      = fused_pcap_create,
  .mknod       = fused_pcap_mknod,
  .mkdir       = fused_pcap_mkdir,
  .symlink     = fused_pcap_symlink,
  .unlink      = fused_pcap_unlink,
  .rmdir       = fused_pcap_rmdir,
  .rename      = fused_pcap_rename,
  .link        = fused_pcap_link,
  .chmod       = fused_pcap_chmod,
  .chown       = fused_pcap_chown,
  .truncate    = fused_pcap_truncate,
  .utimens     = fused_pcap_utimens,
  .open        = fused_pcap_open,
  .read        = fused_pcap_read,
  .write       = fused_pcap_write,
  .statfs      = fused_pcap_statfs,
  .release     = fused_pcap_release,
  .fsync       = fused_pcap_fsync,
#ifdef HAVE_SETXATTR
  .setxattr    = fused_pcap_setxattr,
  .getxattr    = fused_pcap_getxattr,
  .listxattr   = fused_pcap_listxattr,
  .removexattr = fused_pcap_removexattr,
#endif
#if FUSE_MAJOR_VERSION > 2 || ( FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION >= 9 )
  .flag_nopath = 1,
#endif
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
  FUSED_PCAP_OPT_KEY_HO,
  FUSED_PCAP_OPT_KEY_VERSION,
  FUSED_PCAP_OPT_KEY_DEBUG,
  FUSED_PCAP_OPT_KEY_KEEPCACHE,
};

static struct fusedPcapInputs_s {
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
  FUSE_OPT_KEY("-ho",       FUSED_PCAP_OPT_KEY_HO),
  FUSE_OPT_KEY("-v",        FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_KEY("--version", FUSED_PCAP_OPT_KEY_VERSION),
  FUSE_OPT_KEY("debug",     FUSED_PCAP_OPT_KEY_DEBUG),
  FUSE_OPT_KEY("-d",        FUSED_PCAP_OPT_KEY_DEBUG),
  FUSE_OPT_KEY("keepcache", FUSED_PCAP_OPT_KEY_KEEPCACHE),

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
  case FUSED_PCAP_OPT_KEY_KEEPCACHE:
    fusedPcapConfig.keepcache = 1;
    return 0;
    break;
  case FUSED_PCAP_OPT_KEY_HELP:
    fusedPcapInputs.help = 1;
    usage(basename(arguments->argv[0]));
    return fuse_opt_add_arg(arguments, "-ho");
  case FUSED_PCAP_OPT_KEY_HO:
    fusedPcapInputs.help = 1;
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

int main (int argc, char *argv[])
{
  struct fuse_args fuseArgs = FUSE_ARGS_INIT(argc, argv);

  if ((fuse_opt_parse(&fuseArgs, &fusedPcapInputs, fusedPcapOptions, parseMountOptions)) == -1) {
    fprintf(stderr, "%s: invalid arguments\n", argv[0]);
    return 1;
  }
  if (!fusedPcapInputs.help)
  {

    // convert and validate options
    if (convertValidateFilesize(&fusedPcapConfig, fusedPcapInputs.filesize)) {
      fprintf(stderr, "%s: filesize option out of range (1..2^63-1)\n", argv[0]);
      if (fusedPcapConfig.filesize != 0 && fusedPcapInputs.filesize[0] != '-')
        fprintf(stderr, "Congratulations! you overflowed a 64-bit integer.\n");
      return 1;
    }
    if (convertValidateClustermode(&fusedPcapConfig, fusedPcapInputs.clustermode)) {
      fprintf(stderr, "%s: clustermode option out of range (%d..%d)\n", argv[0], CLUSTER_MODE_VLAN, CLUSTER_MODE_VLAN_IP_PORT);
      return 1;
    }
    if (convertValidateClustersize(&fusedPcapConfig, fusedPcapInputs.clustersize)) {
      fprintf(stderr, "%s: clustersize option out of range (1..%d)\n", argv[0], MAX_CLUSTER_SIZE);
      return 1;
    }
    if (convertValidateClusterabend(&fusedPcapConfig, fusedPcapInputs.clusterabend)) {
      fprintf(stderr, "%s: clusterabend option out of range (%d..%d)\n", argv[0], CLUSTER_ABEND_EOF_ALL_AT_EOF, CLUSTER_ABEND_IGNORE);
      return 1;
    }
    if (convertValidateBlockslack(&fusedPcapConfig, fusedPcapInputs.blockslack)) {
      fprintf(stderr, "%s: blockslack option out of range (%d..%d)\n", argv[0], MIN_BLOCK_SLACK, MAX_BLOCK_SLACK);
      return 1;
    }

    if (fusedPcapGlobal.pcapDirectory[0] == '\0') {
      fprintf(stderr, "%s: missing pcap source directory\n", argv[0]);
      return 1;
    }

    //TODO: validate source directory parameter

    // retrieve the system pagesize, verify that it's a power of 2, save it
    fusedPcapGlobal.pageSize = sysconf(_SC_PAGESIZE);
    if (fusedPcapGlobal.pageSize <= 0) {
      fprintf(stderr, "%s: warning: pagesize invalid, assuming 4k\n", argv[0]);
      fusedPcapGlobal.pageSize = 4096;
    }
    else if (fusedPcapGlobal.pageSize & (fusedPcapGlobal.pageSize - 1)) { // more than one bit set?
      fprintf(stderr, "%s: PAGESIZE is not a power of 2\n", argv[0]);
      return 1;
    }

    if (fusedPcapGlobal.debug) {
      fprintf(stderr, "PAGESIZE: %ld\n", fusedPcapGlobal.pageSize);
      printConfigStruct(&fusedPcapConfig);
      fprintf(stderr, "Parameters validated, calling fuse_main()\n");
    }

    openlog(NULL, LOG_PID, LOG_DAEMON);
  }

  return fuse_main(fuseArgs.argc, fuseArgs.argv, &callbackOperations, NULL);
}



