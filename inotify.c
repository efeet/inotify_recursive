#define _GNU_SOURCE   
#include "libraries_include.h"
#include "enum_ip_inter.h"
 
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)                                                                           
                                                                                                              
/* logMessage() flags */                                                                                      
#define VB_BASIC 1      /* Basic messages */                                                                  
#define VB_NOISY 2      /* Verbose messages */     
static int verboseMask;

   //Variables para Socket
    int sock = 0, sock_send = 0;
    char hostname[256];
    char ipconsole[256];
    char allIps[PATH_MAX];
    int justkill = 0;
                                                                                  
static int checkCache = 0;                                                                                                                                                                        
static int readBufferSize = 0;   
static FILE *logfp = NULL; //Variable para abrir archivo de Log.

static int inotifyReadCnt = 0;

static const int INOTIFY_READ_BUF_LEN = (100 * (sizeof(struct inotify_event) + NAME_MAX + 1));

static char **rootDirPaths; /* List of pathnames supplied on command line */
static int numRootDirs;     /* Number of pathnames supplied on command line */
static int ignoreRootDirs;  /* Number of command-line pathnames that
                               we've ceased to monitor */

static struct stat *rootDirStat; // stat(2) structures for croot directories 

static void logMessage(int vb_mask, const char *format, ...)
{
    va_list argList;
    if ((vb_mask == 0) || (vb_mask & verboseMask)) {
	fprintf(logfp,"%s : ",currTimeLog());
        va_start(argList, format);
        vfprintf(logfp, format, argList);
        va_end(argList);
	fprintf(logfp," \n");
    }
}

static void displayInotifyEvent(struct inotify_event *ev)
{
    if (ev->cookie > 0)
        logMessage(VB_NOISY, "cookie = %4d; ", ev->cookie);
    
    if (ev->mask & IN_ISDIR)
        logMessage(VB_NOISY, "mask = IN_ISDIR ");

    if (ev->mask & IN_CREATE)
        logMessage(VB_NOISY, "mask = IN_CREATE ");

    if (ev->mask & IN_DELETE_SELF)
        logMessage(VB_NOISY, "mask = IN_DELETE_SELF ");

    if (ev->mask & IN_MOVE_SELF)
        logMessage(VB_NOISY, "mask = IN_MOVE_SELF ");
    if (ev->mask & IN_MOVED_FROM)
        logMessage(VB_NOISY, "mask = IN_MOVED_FROM ");
    if (ev->mask & IN_MOVED_TO)
        logMessage(VB_NOISY, "mask = IN_MOVED_TO ");

    if (ev->mask & IN_IGNORED)
        logMessage(VB_NOISY, "mask = IN_IGNORED ");
    if (ev->mask & IN_Q_OVERFLOW)
        logMessage(VB_NOISY, "mask = IN_Q_OVERFLOW ");
    if (ev->mask & IN_UNMOUNT)
        logMessage(VB_NOISY, "mask = IN_UNMOUNT ");
    
    if (ev->mask & IN_ATTRIB)
        logMessage(VB_NOISY, "mask = IN_ATTRIB ");
    
    /*if (ev->mask & IN_OPEN)
        logMessage(VB_NOISY, "mask = IN_OPEN ");
    
    if (ev->mask & IN_MODIFY)
	logMessage(VB_NOISY, "mask = IN_MODIFY ");
    
    if (ev->mask & IN_CLOSE_WRITE)
	logMessage(VB_NOISY, "mask = IN_CLOSE_WRITE ");*/

    if (ev->len > 0)
        logMessage(VB_NOISY, "Event Name = %s", ev->name);
}

static void CheckPerm(char fullPathPerm[PATH_MAX])
{
    char sendBuff[PATH_MAX], clearsendBuff[PATH_MAX];    //Sockects
    int sock_inits;
    struct stat buf_stat;
   
    stat(fullPathPerm, &buf_stat);
    if(buf_stat.st_mode & S_IWOTH){
      for (sock_inits=1; sock_inits<4; sock_inits++){
	logMessage(0,"Intento %d de conexion de Socket...",sock_inits);
	sock = OS_ConnectPort(514,ipconsole);
	if( sock > 0 ){
	  logMessage(0,"Conexion Exitosa.");
	  break;
	}	    
      }
      snprintf(sendBuff, sizeof(sendBuff),"%s|%s|%sWARN|Write Perm Others Users|%s\r\n",currTime(), hostname, allIps, fullPathPerm); //Construir mensaje
      sock_send = write(sock, sendBuff, strlen(sendBuff)); //Envio a socket.
      if( sock_send < 0 )
	logMessage(0,"Error al enviar a Socket.");
      logMessage(0,"---->Objeto Con Escritura Publica=%s",fullPathPerm);
      bzero(fullPathPerm,PATH_MAX);
      strcpy(fullPathPerm, clearsendBuff);
      bzero(sendBuff,PATH_MAX);
      strcpy(sendBuff, clearsendBuff);
      OS_CloseSocket(sock);
      OS_CloseSocket(sock_send);
    }
}

/***********************************************************************/
/* Data structures and functions for the watch list cache */
/* We use a very simple data structure for caching watched directory
   paths: a dynamically sized array that is searched linearly. Not
   efficient, but our main goal is to demonstrate the use of inotify. */
struct watch {
    int wd;                     /* Watch descriptor (-1 if slot unused) */
    char path[PATH_MAX];        /* Cached pathname */
};

struct watch *wlCache = NULL;   /* Array of cached items */
static int cacheSize = 0;       /* Current size of the array */

/* Deallocate the watch cache */
static void freeCache(void)
{
    free(wlCache);
    cacheSize = 0;
    wlCache = NULL;
}

/* Check that all pathnames in the cache are valid, and refer
   to directories */
static void checkCacheConsistency(void)
{
    int failures, j;
    struct stat sb;

    failures = 0;
    for (j = 0; j < cacheSize; j++) {
        if (wlCache[j].wd >= 0) {
            if (lstat(wlCache[j].path, &sb) == -1) {
                logMessage(0,
                        "checkCacheConsistency: stat: "
                        "[slot = %d; wd = %d] %s: %s\n",
                        j, wlCache[j].wd, wlCache[j].path, strerror(errno));
                failures++;
        } else if (!S_ISDIR(sb.st_mode)) {
            logMessage(0, "checkCacheConsistency: %s is not a directory\n",wlCache[j].path);
                    exit(EXIT_FAILURE);
            }
        }
    }

    if (failures > 0)
        logMessage(VB_NOISY, "checkCacheConsistency: %d failures\n",failures);
}

/* Check whether the cache contains the watch descriptor 'wd'.
   If found, return the slot number, otherwise return -1. */
static int findWatch(int wd)
{
    int j;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd == wd)
            return j;

    return -1;
}

/* Find and return the cache slot for the watch descriptor 'wd'.
   The caller expects this watch descriptor to exist.  If it does not,
   there is a problem, which is signaled by the -1 return. */
static int findWatchChecked(int wd)
{
    int slot;

    slot = findWatch(wd);

    if (slot >= 0)
        return slot;

    logMessage(0, "Could not find watch %d\n", wd);
}

/* Mark a cache entry as unused */
static void markCacheSlotEmpty(int slot)
{
    //logMessage(VB_NOISY,"        markCacheSlotEmpty: slot = %d;  wd = %d; path = %s\n",slot, wlCache[slot].wd, wlCache[slot].path);

    wlCache[slot].wd = -1;
    wlCache[slot].path[0] = '\0';
}

/* Find a free slot in the cache */
static int findEmptyCacheSlot(void)
{
    int j;
    const int ALLOC_INCR = 10;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd == -1)
            return j; 

    /* No free slot found; resize cache */
    cacheSize += ALLOC_INCR;

    wlCache = realloc(wlCache, cacheSize * sizeof(struct watch));
    if (wlCache == NULL)
        errExit("realloc");

    for (j = cacheSize - ALLOC_INCR; j < cacheSize; j++)
        markCacheSlotEmpty(j);

    return cacheSize - ALLOC_INCR;      /* Return first slot in
                                           newly allocated space */
}

/* Add an item to the cache */
static int addWatchToCache(int wd, const char *pathname)
{
    int slot;

    slot = findEmptyCacheSlot();

    wlCache[slot].wd = wd;
    strncpy(wlCache[slot].path, pathname, PATH_MAX);

    return slot;
}

/* Return the cache slot that corresponds to a particular pathname,
   or -1 if the pathname is not in the cache */
static int pathnameToCacheSlot(const char *pathname)
{
    int j;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd >= 0 && strcmp(wlCache[j].path, pathname) == 0)
            return j;

    return -1;
}

/* Is 'pathname' in the watch cache? */
static int pathnameInCache(const char *pathname)
{
    return pathnameToCacheSlot(pathname) >= 0;
}

/* Duplicate the pathnames supplied on the command line, perform
   some sanity checking along the way */
static void copyRootDirPaths(char *argv[])
{
    char **p;
    int j, k;
    struct stat sb;

    p = argv;
    numRootDirs = 0;

    printf("->Backup\n");
    /* Count the number of root paths, and check that the paths are valid */
    for (p = argv; *p != NULL; p++) {
        /* Check that command-line arguments are directories */
        printf("->Valor de p=%s\n",*p);
        if (lstat(*p, &sb) == -1) {
            fprintf(stderr, "lstat() failed on '%s'\n", *p);
            printf("Error lstat()\n");
            exit(EXIT_FAILURE);
        }
        if (! S_ISDIR(sb.st_mode)) {
            fprintf(stderr, "'%s' is not a directory\n", *p);
            printf("Error No es un directorio\n");
            exit(EXIT_FAILURE);
        }
        numRootDirs++;
    }

    /* Create a copy of the root directory pathnames */
    rootDirPaths = calloc(numRootDirs, sizeof(char *));
    if (rootDirPaths == NULL)
        errExit("calloc");

    rootDirStat = calloc(numRootDirs, sizeof(struct stat));
    if (rootDirPaths == NULL)
        errExit("calloc");

    for (j = 0; j < numRootDirs; j++) {
      printf("->Inicia argv[j]=%s\n",argv[j]);
        rootDirPaths[j] = strdup(argv[j]);
        printf("rootDirPaths[j]=%s\n",rootDirPaths[j]);
        if (rootDirPaths[j] == NULL)
            errExit("strdup");
        if (lstat(argv[j], &rootDirStat[j]) == -1)
            errExit("lstat");

        for (k = 0; k < j; k++) {
            if ((rootDirStat[j].st_ino == rootDirStat[k].st_ino) && (rootDirStat[j].st_dev == rootDirStat[k].st_dev)) {
                fprintf(stderr, "Duplicate filesystem objects: %s, %s\n",argv[j], argv[k]);
                exit(EXIT_FAILURE);
            }
        }
    }
    printf("ignoreRootDirs=%d\n",ignoreRootDirs);
    ignoreRootDirs = 0;
}

/* Return the address of the element in 'rootDirPaths' that points
   to a string matching 'path', or NULL if there is no match */
static char ** findRootDirPath(const char *path)
{
    int j;

    for (j = 0; j < numRootDirs; j++)
	//Si rootDirPaths es diferente de NULL y path y rootDirPaths[j] es igual.
        if (rootDirPaths[j] != NULL && strcmp(path, rootDirPaths[j]) == 0)
            return &rootDirPaths[j];

    return NULL;
}

/* Is 'path' one of the pathnames that was listed on the command line? */
static int isRootDirPath(const char *path)
{
    return findRootDirPath(path) != NULL;
}

/* We've ceased to monitor a root directory pathname (probably because it
   was renamed), so zap this pathname from the root path list */
static void zapRootDirPath(const char *path)
{
    char **p;

    printf("zapRootDirPath: %s\n", path);

    p = findRootDirPath(path);
    if (p == NULL) {
        fprintf(stderr, "zapRootDirPath(): path not found!\n");
        exit(EXIT_FAILURE);
    }

    *p = NULL;
    ignoreRootDirs++;
    if (ignoreRootDirs == numRootDirs) {
        fprintf(stderr, "No more root paths left to monitor; bye!\n");
        exit(EXIT_SUCCESS);
    }
}

/***********************************************************************/
/* Below is a function called by nftw() to traverse a directory tree.
   The function adds a watch for each directory in the tree. Each
   successful call to this function should return 0 to indicate to
   nftw() that the tree traversal should continue. */
/* The usual hack for nftw()...  We can't pass arguments to the
   function invoked by nftw(), so we use these global variables to
   exchange information with the function. */
static int dirCnt;      /* Count of directories added to watch list */
static int ifd;         /* Inotify file descriptor */

static int traverseTree(const char *pathname, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
    int wd, slot, flags;

    if (! S_ISDIR(sb->st_mode))
        return 0;               /* Ignore nondirectory files */

    /* Create a watch for this directory */
    flags = IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_ATTRIB;
    //| IN_OPEN | IN_MODIFY | IN_CLOSE_WRITE;

    if (isRootDirPath(pathname))
        flags |= IN_MOVE_SELF;

    wd = inotify_add_watch(ifd, pathname, flags | IN_ONLYDIR);
    if (wd == -1) {
        logMessage(VB_NOISY, "inotify_add_watch: %s: %s",pathname, strerror(errno));
        if (errno == ENOENT)
            return 0;
        else
            exit(EXIT_FAILURE);
    }

    if (findWatch(wd) >= 0) {
        /* This watch descriptor is already in the cache;
           nothing more to do. */
        logMessage(VB_NOISY, "WD %d already in cache (%s)", wd, pathname);
        return 0;
    }

    dirCnt++;
    /* Cache information about the watch */
    slot = addWatchToCache(wd, pathname);
    /* Print the name of the current directory */
    logMessage(VB_NOISY, "    traverseTree-> : wd = %d [cache slot: %d]; %s",wd, slot, pathname);
    return 0;
}

/* Add the directory in 'pathname' to the watch list of the inotify
   file descriptor 'inotifyFd'. The process is recursive: watch items
   are also created for all of the subdirectories of 'pathname'.
   Returns number of watches/cache entries added for this subtree. */
static int watchDir(int inotifyFd, const char *pathname)
{
    dirCnt = 0;
    ifd = inotifyFd;
    
    if (nftw(pathname, traverseTree, 20, FTW_PHYS) == -1)
        logMessage(VB_NOISY,
                "nftw: %s: %s (directory probably deleted before we "
                "could watch)", pathname, strerror(errno));
    return dirCnt;
}

/* Add watches and cache entries for a subtree, logging a message
   noting the number entries added. */
static void watchSubtree(int inotifyFd, char *path)
{
    int cnt;
    cnt = watchDir(inotifyFd, path);
    logMessage(VB_NOISY, "    watchSubtree: %s: %d entries added",path, cnt);
}

/***********************************************************************/
/* The directory oldPathPrefix/oldName was renamed to
   newPathPrefix/newName. Fix up cache entries for
   oldPathPrefix/oldName and all of its subdirectories
   to reflect the change. */
static void rewriteCachedPaths(const char *oldPathPrefix, const char *oldName, const char *newPathPrefix, const char *newName)
{
    char fullPath[PATH_MAX], newPrefix[PATH_MAX];
    char newPath[PATH_MAX];
    size_t len;
    int j;

    snprintf(fullPath, sizeof(fullPath), "%s/%s", oldPathPrefix, oldName);
    snprintf(newPrefix, sizeof(newPrefix), "%s/%s", newPathPrefix, newName);
    len = strlen(fullPath);

    logMessage(0, "Rename: %s ==> %s", fullPath, newPrefix);

    for (j = 0; j < cacheSize; j++) {
        if (strncmp(fullPath, wlCache[j].path, len) == 0 &&
                    (wlCache[j].path[len] == '/' ||
                     wlCache[j].path[len] == '\0')) {
            snprintf(newPath, sizeof(newPath), "%s%s", newPrefix,&wlCache[j].path[len]);
            strncpy(wlCache[j].path, newPath, PATH_MAX);
            logMessage(0, "  rewriteCachedPaths -> wd %d [cache slot %d] ==> %s",wlCache[j].wd, j, newPath);
        }
    }
}

/* Zap watches and cache entries for directory 'path' and all of its
   subdirectories. Returns number of entries that we (tried to) zap,
   or -1 if an inotify_rm_watch() call failed. */
static int zapSubtree(int inotifyFd, char *path)
{
    size_t len;
    int j;
    int cnt;
    char *pn;

    logMessage(0, "Zapping subtree: %s", path);

    len = strlen(path);
    pn = strdup(path);

    cnt = 0;

    for (j = 0; j < cacheSize; j++) {
        if (wlCache[j].wd >= 0) {
            if (strncmp(pn, wlCache[j].path, len) == 0 &&
                    (wlCache[j].path[len] == '/' ||
                     wlCache[j].path[len] == '\0')) {

                logMessage(0,"    removing watch: wd = %d (%s)",wlCache[j].wd, wlCache[j].path);

                if (inotify_rm_watch(inotifyFd, wlCache[j].wd) == -1) {
                    logMessage(0, "inotify_rm_watch wd = %d (%s): %s",wlCache[j].wd, wlCache[j].path, strerror(errno));
                    cnt = -1;
                    break;
                }

                markCacheSlotEmpty(j);
                cnt++;
            }
        }
    }
    free(pn);
    return cnt;
}

/* When the cache is in an unrecoverable state, we discard the current
   inotify file descriptor ('oldInotifyFd') and create a new one (returned
   as the function result), and zap and rebuild the cache.
   If 'oldInotifyFd' is -1, this is the initial build of the cache, or an
   explicitly requested cache rebuild, so we are a little less verbose,
   and we reset 'reinitCnt'.  */
static int reinitialize(int oldInotifyFd)
{
    int inotifyFd;
    static int reinitCnt;
    int cnt, j;

    if (oldInotifyFd >= 0) {
        close(oldInotifyFd);

        reinitCnt++;
        logMessage(0, "Reinitializing cache and inotify FD (reinitCnt = %d)",reinitCnt);
    } else {
        logMessage(0, "Initializing cache");
        reinitCnt = 0;
    }

    inotifyFd = inotify_init();
    if (inotifyFd == -1)
        errExit("inotify_init");

    logMessage(0, "    new inotifyFd = %d", inotifyFd);

    freeCache();

    for (j = 0; j < numRootDirs; j++)
        if (rootDirPaths[j] != NULL)
            watchSubtree(inotifyFd, rootDirPaths[j]);

    cnt = 0;
    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd >= 0)
            cnt++;

    if (oldInotifyFd >= 0)
        logMessage(0, "Rebuilt cache with %d entries", cnt);

    return inotifyFd;
}

/* Process the next inotify event in the buffer specified by 'buf'
   and 'bufSize'. In most cases, a single event is consumed, but
   if there is an IN_MOVED_FROM+IN_MOVED_TO pair that share a cookie
   value, both events are consumed.
   Returns the number of bytes in the event(s) consumed from 'buf'.  */
static size_t processNextInotifyEvent(int *inotifyFd, char *buf, int bufSize, int firstTry)
{
    char fullPath[PATH_MAX];
    struct inotify_event *ev;
    size_t evLen;
    int evCacheSlot;

    ev = (struct inotify_event *) buf;
    
    displayInotifyEvent(ev);
    
    if (ev->wd != -1 && !(ev->mask & IN_IGNORED)) {
        evCacheSlot = findWatchChecked(ev->wd);
        //Elimina todo el monitor y lo vuelve a inicializar...
        if (evCacheSlot == -1) {
           /* Cache reached an inconsistent state */
           *inotifyFd = reinitialize(*inotifyFd);
           /* Discard all remaining events in current read() buffer */
           return INOTIFY_READ_BUF_LEN;
        }
    }
    
    evLen = sizeof(struct inotify_event) + ev->len;

    if ((ev->mask & IN_ISDIR) && (ev->mask & (IN_CREATE | IN_MOVED_TO))) {
        snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);	
        logMessage(0, "Directory creation on wd %d: %s",ev->wd, fullPath);
        if (!pathnameInCache(fullPath))
            watchSubtree(*inotifyFd, fullPath);

    } else if (ev->mask & IN_DELETE_SELF) {
        logMessage(0, "Clearing watchlist item %d (%s)",ev->wd, wlCache[evCacheSlot].path);

        if (isRootDirPath(wlCache[evCacheSlot].path))
            zapRootDirPath(wlCache[evCacheSlot].path);

        markCacheSlotEmpty(evCacheSlot);
            /* No need to remove the watch; that happens automatically */
    } else if ((ev->mask & (IN_MOVED_FROM | IN_ISDIR)) == (IN_MOVED_FROM | IN_ISDIR)) {
        struct inotify_event *nextEv;
        nextEv = (struct inotify_event *) (buf + evLen);
        if (((char *) nextEv < buf + bufSize) &&
                (nextEv->mask & IN_MOVED_TO) &&
                (nextEv->cookie == ev->cookie)) {

            int nextEvCacheSlot;

            nextEvCacheSlot = findWatchChecked(nextEv->wd);

            if (nextEvCacheSlot == -1) {
                /* Cache reached an inconsistent state */
                *inotifyFd = reinitialize(*inotifyFd);
                /* Discard all remaining events in current read() buffer */
                return INOTIFY_READ_BUF_LEN;
            }

            rewriteCachedPaths(wlCache[evCacheSlot].path, ev->name,wlCache[nextEvCacheSlot].path, nextEv->name);

            evLen += sizeof(struct inotify_event) + nextEv->len;

        } else if (((char *) nextEv < buf + bufSize) || !firstTry) {
            logMessage(VB_NOISY, "MOVED_OUT: %p %p",wlCache[evCacheSlot].path, ev->name);
            logMessage(VB_NOISY, "firstTry = %d; remaining bytes = %d",firstTry, buf + bufSize - (char *) nextEv);
            snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);

            if (zapSubtree(*inotifyFd, fullPath) == -1) {
                /* Cache reached an inconsistent state */
                *inotifyFd = reinitialize(*inotifyFd);
                /* Discard all remaining events in current read() buffer */
                return INOTIFY_READ_BUF_LEN;
            }

        } else {
            logMessage(VB_NOISY, "HANGING IN_MOVED_FROM");
            return -1;  /* Tell our caller to do another read() */
        }

    } else if (ev->mask & IN_Q_OVERFLOW) {
        static int overflowCnt = 0;
        overflowCnt++;
        logMessage(0, "Queue overflow (%d) (inotifyReadCnt = %d)",overflowCnt, inotifyReadCnt);
        *inotifyFd = reinitialize(*inotifyFd);
        /* Discard all remaining events in current read() buffer */
        evLen = INOTIFY_READ_BUF_LEN;
    } else if (ev->mask & IN_UNMOUNT) {
        logMessage(0, "Filesystem unmounted: %s",wlCache[evCacheSlot].path);
        markCacheSlotEmpty(evCacheSlot);
            /* No need to remove the watch; that happens automatically */
    } else if (ev->mask & IN_MOVE_SELF && isRootDirPath(wlCache[evCacheSlot].path)) {
        logMessage(0, "Root path moved: %s",wlCache[evCacheSlot].path);
        zapRootDirPath(wlCache[evCacheSlot].path);
        if (zapSubtree(*inotifyFd, wlCache[evCacheSlot].path) == -1) {
            /* Cache reached an inconsistent state */
            *inotifyFd = reinitialize(*inotifyFd);
            /* Discard all remaining events in current read() buffer */
            return INOTIFY_READ_BUF_LEN;
        }
    } else if(ev->mask & IN_ATTRIB){
	snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);
	  CheckPerm(fullPath);
    }
    if (checkCache)
        checkCacheConsistency();

    return evLen;
}

static void alarmHandler(int sig)
{
    return;             /* Just interrupt read() */
}

/* Read a block of events from the inotify file descriptor, 'inotifyFd'.
   Process the events relating to directories in the subtree we are
   monitoring, in order to keep our cached view of the subtree in sync
   with the filesystem. */
static void processInotifyEvents(int *inotifyFd)
{
    char buf[INOTIFY_READ_BUF_LEN] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    //char buf[PATH_MAX + sizeof(struct inotify_event) + 1];
    ssize_t numRead, nr;
    char *evp;
    size_t cnt;
    int evLen;
    int firstTry;
    int j;
    struct sigaction sa;

    /* SIGALRM handler is designed simply to interrupt read() */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = alarmHandler;
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, NULL) == -1)
        errExit("sigaction");

    firstTry = 1;

    /* Read some events from inotify file descriptor */
    cnt = (readBufferSize > 0) ? readBufferSize : INOTIFY_READ_BUF_LEN;
    numRead = read(*inotifyFd, buf, cnt);
    if (numRead == -1)
        errExit("read");
    if (numRead == 0) {
        fprintf(stderr, "read() from inotify fd returned 0!");
        exit(EXIT_FAILURE);
    }

    inotifyReadCnt++;
    //Imprime los eventos como los va leyendo y los bytes en los enventos.
    //logMessage(VB_NOISY,"\n==========> Read %d: got %zd bytes\n", inotifyReadCnt, numRead);

    /* Process each event in the buffer returned by read() */
    for (evp = buf; evp < buf + numRead - 16; ) {
        evLen = processNextInotifyEvent(inotifyFd, evp, buf + numRead - evp, firstTry);

        if (evLen > 0) {
            evp += evLen;
            firstTry = 1;
        } else {
          
            struct sigaction sa;
            int savedErrno;
            firstTry = 0;

            numRead = buf + numRead - evp;

            /* Shuffle remaining bytes to start of buffer */
            for (j = 0; j < numRead; j++)
                printf("905 -  FOR: Valores J=%d, buf=%s[j], evp=%s[j]\n",j,buf[j],evp[j]);
                buf[j] = evp[j];

            /* Do a read with timeout, to allow next events (if any) to arrive */
            sa.sa_flags = 0;
            sigemptyset(&sa.sa_mask);
            sa.sa_handler = alarmHandler;

            ualarm(2000, 0);

            nr = read(*inotifyFd, buf + numRead, INOTIFY_READ_BUF_LEN - numRead);

            savedErrno = errno; /* In case ualarm() should change errno */
            ualarm(0, 0);       /* Cancel alarm */
            errno = savedErrno;

            if (nr == -1 && errno != EINTR)
                errExit("read");
            if (nr == 0) {
                fprintf(stderr, "read() from inotify fd returned 0!");
                exit(EXIT_FAILURE);
            }

            if (errno != -1) {
                numRead += nr;
                inotifyReadCnt++;
                logMessage(VB_NOISY,"\n==========> SECONDARY Read %d: got %zd bytes",inotifyReadCnt, nr);
            } else {                    /* EINTR */
                logMessage(VB_NOISY,
                       "\n==========> SECONDARY Read got nothing");
            }
            evp = buf;          /* Start again at beginning of buffer */
        }
    }
}

static int LoadValues(char *config_file)
{
    FILE *fvalues;
    char line[1024 + 1];
    char *token, *token2, buf[12];
    char *parameters[] = { "logpath", "pidpath" , "logverbose" , "ipconsole" , "paths" }; 
    char **argv2 = malloc(2*sizeof(char *));
    size_t argc2 = 0;
    int fd, n, max_watches;
    
    fd = open("/proc/sys/fs/inotify/max_user_watches", O_RDONLY);
    if (fd < 0) {
        perror("No se puede abrir /proc/sys/fs/inotify/max_user_watches");
        exit(1);
    }

    if ( (n = read(fd, buf, sizeof(buf) - 1)) < 0) {
        perror("No se puede leer() /proc/sys/fs/inotify/max_user_watches");
        exit(1);
    }
    
    buf[n] = 0;
    max_watches = atoi(buf) - 256;
    printf("Numero de Archivos a monitorear = /proc/sys/fs/inotify/max_user_watches: %d\n",max_watches);
    printf("Por cada 65000 archivos, se restan 256\n");
    if (max_watches <= 0) {
        printf("Numero de Rutas Incorrecto: ");
        printf(buf);
        printf("\n");
        return 1;
    }
    
    fvalues = fopen(config_file, "r");
    
    while( fgets(line, 1024, fvalues) != NULL ){
        token = strtok(line, "\t =\n\r");
        if( token != NULL && token[0] != '#' ){
	  if(justkill == 0){
	    if(!strncmp(token, parameters[0], sizeof(parameters[0]))){ //Cargamos parametro de archivo de LOG.
	      token = strtok( NULL, "\t =\n\r");
	      logfp = fopen(token, "w+"); 
	      if (logfp == NULL)
		errExit("fopen");
	      setbuf(logfp, NULL);
	    }  
	    if(!strncmp(token, parameters[1], sizeof(parameters[1]))){ //Cargamos parametro de archivo PID.
	      id_t pid = getpid();
	      token = strtok( NULL, "\t =\n\r");
	      FILE *fpid = fopen(token, "w"); 
	      if (!fpid){
		perror("Archivo PID Error\n");
		exit(EXIT_FAILURE);
	      }
	      fprintf(fpid, "%d\n", pid);
	      fclose(fpid);
	    }
	    if(!strncmp(token, parameters[2], sizeof(parameters[2]))){ //Cargamos parametro de Verbose de Log.
	      token = strtok( NULL, "\t =\n\r");
	      verboseMask = atoi(token);
	      logMessage(VB_BASIC,"Log establecido como Basico...");
	      logMessage(VB_NOISY,"Log establecido como Ruidoso...");
	    }
	    if(!strncmp(token, parameters[3], sizeof(parameters[3]))){ //Cargamos parametro de la IP de Consola que recibe mensajes.
	      token = strtok( NULL, "\t =\n\r");
	      strncpy(ipconsole, token, sizeof(ipconsole)-1 );
	      ipconsole[sizeof(ipconsole)-1] = '\0';
	    }
	    if(!strncmp(token, parameters[4], sizeof(parameters[4]))){ //Cargamos parametros de las rutas a monitorear.
	      token = strtok( NULL, "\n\r");
	      token2 = strtok( token, "|");
	      while(token2 != NULL){
		argv2[argc2++] = token2;	      
		token2 = strtok( NULL, "|");
	      }
	      argv2[argc2] = NULL;
	      copyRootDirPaths(argv2);
	    }
	  }
	  else{
	    int getpid = 0;
	    char killagent[PATH_MAX];
	    if(!strncmp(token, parameters[1], sizeof(parameters[1]))){ //Cargamos el parametro de PID para matar el proceso.
	      token = strtok( NULL, "\t =\n\r");
	      FILE *fpid = fopen(token, "r");
	      if (!fpid){
		perror("Archivo PID Error\n");
		exit(EXIT_FAILURE);
	      }
	      fscanf(fpid, "%d", &getpid);
	      if(!kill(getpid, SIGKILL)){
		fclose(fpid);
		return 0;
	      }
	      else{
		fclose(fpid);
		return -1;
	      }
	    }
	  }
	}
    }     
    return 0;
}


int main(int argc, char *argv[])
{
    fd_set rfds;
    int inotifyFd, opt, gload, cfgvalida=0, controla1;
    char* token, *token2;
    char namecfg[11]="inotify.cfg";
    
    if (optind >= argc){
        printf("Error Inicial\n");
	exit(EXIT_FAILURE);
    }
    
    if ( argc < 3){
      printf("Error de uso: %s\n",argv[0]);
      exit(EXIT_FAILURE);
    }
    
    char *p = malloc(strlen(argv[2] + 1));
    
    while ((opt = getopt(argc, argv, "c:k")) != -1) {
      switch (opt) {
	case 'c':
	  strcpy(p, argv[2]);
	  printf("Ruta de configuracion: %s\n",argv[2]);
	  token = strtok(p,"\n\r");
	  token2 = strtok(token, "/");
	  while(token2 != NULL){
	    if(!strncmp(token2, namecfg, sizeof(namecfg))){
		cfgvalida = 1;
		break;
	    }
	    else{
	      token2 = strtok(NULL, "/");
	      cfgvalida = 0;
	    }
	  }
	  if(cfgvalida == 1){
	    gload = LoadValues(argv[2]);
	    if( gload != 0 ){
	      errExit("ErrValues");
	    }
	  } else {
	      printf("error: cfg file not found\n");
	      exit(1);
	  }
	break;
	case 'k':
	  justkill = 1;
	  printf("Terminado proceso\n");
	   gload = LoadValues(argv[2]);
	   if( gload == 0 )
	     errExit("Terminando proceso iNotify Agent ");
	   else
	     errExit("Problemas para terminar proceso iNotify Agent");
	break;
	default:
	  printf("1-Error de uso: %s\n",argv[0]);
	  exit(EXIT_FAILURE);
      }
    }
    
    inotifyFd = reinitialize(-1);
    fflush(stdout);
    
    struct numera_data ips = get_interfaces();
    for(controla1 = 0; controla1 < ips.nInterfaces; controla1++)
	{
	  strcat(allIps, prt_interfaces(controla1));
	  strcat(allIps,"|");
	}
    
    gethostname(hostname, sizeof(hostname));
    hostname[sizeof(hostname) - 1] = '\0';
    
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(inotifyFd, &rfds);
        if (FD_ISSET(inotifyFd, &rfds)){
            processInotifyEvents(&inotifyFd);
	}
    }
    exit(EXIT_SUCCESS);
}