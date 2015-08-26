/**
 * by eFeet
 * @_eFeet_ (twitter)
 * https://github.com/efeet
 */
#define _GNU_SOURCE   
#include "libraries_include.h"
#include "enum_ip_inter.h"

#define APP_USAGE "Error de uso: \
		   \nUso: \
		   \n\nIniciar Agente de monitoreo:  -c  inotify.cfg \
		   \nIniciar Agente de monitoreo:  -c  inotify.cfg\n"

/*@errExit - Macro para envio de Mensajes en archivo Log.*/
/*@verboseMask - Variable para indicar nivel de Verbose en log.*/
#define errExit(msg)    do{ \
			logMessage(0, msg); \
			exit(EXIT_FAILURE); \
                        }while (0)

#define VB_BASIC 1      /* Basic messages */                                                                  
#define VB_NOISY 2      /* Verbose messages */  
static int verboseMask;

/* Inicializa socket*/
int sock = 0;
/* Envio de frame por socket.*/
int sock_send = 0;
/*Hostname Server.*/
char hostname[256];
/*Ip console Address.*/
char ipconsole[256];
/*All Ips on Server.*/
char allIps[PATH_MAX];
/*Variable para matar proceso.*/
int justkill = 0;
/*Variable para bandera de Evento de Modificacion.*/
int modifiedband=0;
/*Variable para mostrar cambios en archivos.*/
int showchanges = 0;
/*Variable para almacenar la ruta de log*/
char logpath[PATH_MAX];
                                                                         
static int checkCache = 0;                                                                                                                                                                        
static int readBufferSize = 0;   
static FILE *logfp = NULL; //Variable para abrir archivo de Log.
static FILE *fvalues = NULL; //Variable para abrir archivo de configuracion.

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

static void CheckPerm(char fullPathPerm[PATH_MAX])
{
    char sendBuff[PATH_MAX], clearsendBuff[PATH_MAX];    //Sockects
    int sock_inits;
    struct stat buf_stat;
   
    stat(fullPathPerm, &buf_stat);
    if(buf_stat.st_mode & S_IWOTH){
      for (sock_inits=1; sock_inits<3; sock_inits++){
	logMessage(VB_NOISY,"Intento %d de conexion de Socket...",sock_inits);
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
      //Verificamos el LOG y los rotamos.
      logfp = rotatelog(logpath, logfp);
      setbuf(logfp, NULL);
    }
}

struct watch {
    int wd;                     /* Watch descriptor (-1 if slot unused) */
    char path[PATH_MAX];        /* Cached pathname */
};

struct watch *wlCache = NULL;   /* Array of cached items */
static int cacheSize = 0;       /* Current size of the array */

static void freeCache(void)
{
    free(wlCache);  //Free cache
    cacheSize = 0;
    wlCache = NULL;
}

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
            logMessage(0, "checkCacheConsistency: %s no es un directorio\n",wlCache[j].path);
                    exit(EXIT_FAILURE);
            }
        }
    }

    if (failures > 0)
        logMessage(VB_NOISY, "checkCacheConsistency: %d fallo\n",failures);
}

static int findWatch(int wd)
{
    int j;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd == wd)
            return j;

    return -1;
}

static int findWatchChecked(int wd)
{
    int slot;

    slot = findWatch(wd);

    if (slot >= 0)
        return slot;

    logMessage(0, "No se encuentra watch %d\n", wd);
}

static void markCacheSlotEmpty(int slot)
{
    wlCache[slot].wd = -1;  //Marcado de slot libre.
    wlCache[slot].path[0] = '\0';
}

static int findEmptyCacheSlot(void)
{
    int j;
    const int ALLOC_INCR = 10;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd == -1)
            return j; 

    cacheSize += ALLOC_INCR;

    wlCache = realloc(wlCache, cacheSize * sizeof(struct watch));
    if (wlCache == NULL)
        errExit("realloc");

    for (j = cacheSize - ALLOC_INCR; j < cacheSize; j++)
        markCacheSlotEmpty(j);

    return cacheSize - ALLOC_INCR;
}

static int addWatchToCache(int wd, const char *pathname)
{
    int slot;

    slot = findEmptyCacheSlot();

    wlCache[slot].wd = wd;
    strncpy(wlCache[slot].path, pathname, PATH_MAX);

    return slot;
}

static int pathnameToCacheSlot(const char *pathname)
{
    int j;

    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd >= 0 && strcmp(wlCache[j].path, pathname) == 0)
            return j;

    return -1;
}

static int pathnameInCache(const char *pathname)
{
    return pathnameToCacheSlot(pathname) >= 0;
}

static void copyRootDirPaths(char *argv[])
{
    char **p;
    int j, k;
    struct stat sb;

    p = argv;
    numRootDirs = 0;

    for (p = argv; *p != NULL; p++) {
        if (lstat(*p, &sb) == -1) {
	    logMessage(0, "lstat() fallo en '%s'",*p);
            //fprintf(stderr, "lstat() failed on '%s'\n", *p);
            exit(EXIT_FAILURE);
        }
        if (! S_ISDIR(sb.st_mode)) {
	    logMessage(0, "'%s' no es un directorio", *p);
            //fprintf(stderr, "'%s' is not a directory\n", *p);
            exit(EXIT_FAILURE);
        }
        numRootDirs++;
    }

    rootDirPaths = calloc(numRootDirs, sizeof(char *));
    if (rootDirPaths == NULL)
        errExit("calloc");

    rootDirStat = calloc(numRootDirs, sizeof(struct stat));
    if (rootDirPaths == NULL)
        errExit("calloc");

    for (j = 0; j < numRootDirs; j++) {
        rootDirPaths[j] = strdup(argv[j]);
        if (rootDirPaths[j] == NULL)
            errExit("strdup");
        if (lstat(argv[j], &rootDirStat[j]) == -1)
            errExit("lstat");

        for (k = 0; k < j; k++) {
            if ((rootDirStat[j].st_ino == rootDirStat[k].st_ino) && (rootDirStat[j].st_dev == rootDirStat[k].st_dev)) {
		logMessage(0, "Objeto en FileSystem Duplicado: %s, %s", argv[j], argv[k]);
                exit(EXIT_FAILURE);
            }
        }
    }
    ignoreRootDirs = 0;
}

static char ** findRootDirPath(const char *path)
{
    int j;

    for (j = 0; j < numRootDirs; j++)
	//Si rootDirPaths es diferente de NULL y path y rootDirPaths[j] es igual.
        if (rootDirPaths[j] != NULL && strcmp(path, rootDirPaths[j]) == 0)
            return &rootDirPaths[j];

    return NULL;
}

static int isRootDirPath(const char *path)
{
    return findRootDirPath(path) != NULL;
}

static void zapRootDirPath(const char *path)
{
    char **p;

    p = findRootDirPath(path);
    if (p == NULL) {
	logMessage(0, "zapRootDirPath(): ruta no valida!");
        exit(EXIT_FAILURE);
    }

    *p = NULL;
    ignoreRootDirs++;
    if (ignoreRootDirs == numRootDirs) {
	logMessage(0, "No mas rutas Raiz para monitor; bye!");
        exit(EXIT_SUCCESS);
    }
}

static int dirCnt;      /* Count of directories added to watch list */
static int ifd;         /* Inotify file descriptor */

static int traverseTree(const char *pathname, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
    int wd, slot, flags;

    if (! S_ISDIR(sb->st_mode))
        return 0;               /* Ignore nondirectory files */

    /* Create a watch for this directory */
    flags = IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_DELETE | IN_ATTRIB | IN_OPEN | IN_MODIFY | IN_CLOSE_WRITE;

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
        logMessage(VB_NOISY, "WD %d ya estan en cache (%s)", wd, pathname);
        return 0;
    }

    dirCnt++;
    slot = addWatchToCache(wd, pathname);
    logMessage(VB_NOISY, "-Agregado-> : wd = %d [cache slot: %d]; %s",wd, slot, pathname);
    return 0;
}

static int watchDir(int inotifyFd, const char *pathname)
{
    dirCnt = 0;
    ifd = inotifyFd;
    
    if (nftw(pathname, traverseTree, 20, FTW_PHYS) == -1)
        logMessage(VB_NOISY,
                "nftw: %s: %s (directorio probablemente eliminado antes de "
                "revision)", pathname, strerror(errno));
    return dirCnt;
}

static void watchSubtree(int inotifyFd, char *path)
{
    int cnt;
    cnt = watchDir(inotifyFd, path);
    logMessage(VB_NOISY, "-MonSubDir: %s: %d entradas agregadas",path, cnt);
}

static void rewriteCachedPaths(const char *oldPathPrefix, const char *oldName, const char *newPathPrefix, const char *newName)
{
    char fullPath[PATH_MAX], newPrefix[PATH_MAX];
    char newPath[PATH_MAX];
    size_t len;
    int j;

    snprintf(fullPath, sizeof(fullPath), "%s/%s", oldPathPrefix, oldName);
    snprintf(newPrefix, sizeof(newPrefix), "%s/%s", newPathPrefix, newName);
    len = strlen(fullPath);

    logMessage(VB_NOISY, "Renombrado: %s ==> %s", fullPath, newPrefix);

    for (j = 0; j < cacheSize; j++) {
        if (strncmp(fullPath, wlCache[j].path, len) == 0 &&
                    (wlCache[j].path[len] == '/' ||
                     wlCache[j].path[len] == '\0')) {
            snprintf(newPath, sizeof(newPath), "%s%s", newPrefix,&wlCache[j].path[len]);
            strncpy(wlCache[j].path, newPath, PATH_MAX);
            logMessage(VB_NOISY, "  rewriteCachedPaths -> wd %d [cache slot %d] ==> %s",wlCache[j].wd, j, newPath);
        }
    }
}

static int zapSubtree(int inotifyFd, char *path)
{
    size_t len;
    int j;
    int cnt;
    char *pn;

    logMessage(VB_NOISY, "Liberando SubDir: %s", path);

    len = strlen(path);
    pn = strdup(path);

    cnt = 0;

    for (j = 0; j < cacheSize; j++) {
        if (wlCache[j].wd >= 0) {
            if (strncmp(pn, wlCache[j].path, len) == 0 &&
                    (wlCache[j].path[len] == '/' ||
                     wlCache[j].path[len] == '\0')) {

                logMessage(VB_NOISY,"-eliminando watch: wd = %d (%s)",wlCache[j].wd, wlCache[j].path);

                if (inotify_rm_watch(inotifyFd, wlCache[j].wd) == -1) {
                    logMessage(VB_NOISY, "inotify_rm_watch wd = %d (%s): %s",wlCache[j].wd, wlCache[j].path, strerror(errno));
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

static int reinitialize(int oldInotifyFd)
{
    int inotifyFd;
    static int reinitCnt;
    int cnt, j;

    if (oldInotifyFd >= 0) {
        close(oldInotifyFd);

        reinitCnt++;
        logMessage(0, "Reinicialianzo cache y inotify FD (reinitCnt = %d)",reinitCnt);
    } else {
        logMessage(0, "Inicializando cache");
        reinitCnt = 0;
    }

    inotifyFd = inotify_init();
    if (inotifyFd == -1)
        errExit("inotify_init");

    logMessage(0, "    nuevo inotifyFd = %d", inotifyFd);

    freeCache();

    for (j = 0; j < numRootDirs; j++)
        if (rootDirPaths[j] != NULL)
            watchSubtree(inotifyFd, rootDirPaths[j]);

    cnt = 0;
    for (j = 0; j < cacheSize; j++)
        if (wlCache[j].wd >= 0)
            cnt++;

    if (oldInotifyFd >= 0)
        logMessage(0, " Reconstruccion de cache con %d entradas", cnt);

    return inotifyFd;
}

static size_t processNextInotifyEvent(int *inotifyFd, char *buf, int bufSize, int firstTry)
{
    char fullPath[PATH_MAX];
    struct inotify_event *ev;
    size_t evLen;
    int evCacheSlot;

    ev = (struct inotify_event *) buf;
    
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
        logMessage(0, "Creacion de directorio en wd %d: %s",ev->wd, fullPath);
        if (!pathnameInCache(fullPath))
            watchSubtree(*inotifyFd, fullPath);

    } else if (ev->mask & IN_DELETE_SELF) {
        logMessage(0, "Limpiando watchlist item %d (%s)",ev->wd, wlCache[evCacheSlot].path);

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
            logMessage(VB_NOISY, "primerIntento = %d; remaining bytes = %d",firstTry, buf + bufSize - (char *) nextEv);
            snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);

            if (zapSubtree(*inotifyFd, fullPath) == -1) {
                /* Cache reached an inconsistent state */
                *inotifyFd = reinitialize(*inotifyFd);
                /* Discard all remaining events in current read() buffer */
                return INOTIFY_READ_BUF_LEN;
            }
        } else {
            logMessage(VB_NOISY, "Manejo IN_MOVED_FROM");
            return -1;  /* Tell our caller to do another read() */
        }

    } else if (ev->mask & IN_Q_OVERFLOW) {
        static int overflowCnt = 0;
        overflowCnt++;
        logMessage(0, "Sobrecarga en cola (%d) (inotifyReadCnt = %d)",overflowCnt, inotifyReadCnt);
        *inotifyFd = reinitialize(*inotifyFd);
        /* Discard all remaining events in current read() buffer */
        evLen = INOTIFY_READ_BUF_LEN;
    } else if (ev->mask & IN_UNMOUNT) {
        logMessage(0, "FileSystem Desmontado: %s",wlCache[evCacheSlot].path);
        markCacheSlotEmpty(evCacheSlot);
            /* No need to remove the watch; that happens automatically */
    } else if (ev->mask & IN_MOVE_SELF && isRootDirPath(wlCache[evCacheSlot].path)) {
        logMessage(0, "Ruta Raiz Movida: %s",wlCache[evCacheSlot].path);
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
    } else if(ev->mask & IN_OPEN && modifiedband == 0){
	modifiedband = 1;
    } else if(ev->mask & IN_MODIFY && modifiedband == 1){
	modifiedband = 2;
    } else if(ev->mask & IN_DELETE || ev->mask & IN_CREATE ){
	modifiedband = 0;
    } else if(ev->mask & IN_CLOSE_WRITE && modifiedband == 2 && showchanges == 1){
	snprintf(fullPath, sizeof(fullPath), "%s/%s",wlCache[evCacheSlot].path, ev->name);
	logMessage(0, "Modificacion de contenido en: %s",fullPath);
	modifiedband = 0;
    }
    if (checkCache)
        checkCacheConsistency();

    return evLen;
}

static void alarmHandler(int sig)
{
    return;             /* Just interrupt read() */
}

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
        fprintf(stderr, "read() regreso 0->fd desde inotify!");
        exit(EXIT_FAILURE);
    }

    inotifyReadCnt++;

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
                buf[j] = evp[j];

            /* Do a read with timeout, to allow next events (if any) to arrive */
            sa.sa_flags = 0;
            sigemptyset(&sa.sa_mask);
            sa.sa_handler = alarmHandler;

            ualarm(5000, 0);

            nr = read(*inotifyFd, buf + numRead, INOTIFY_READ_BUF_LEN - numRead);

            savedErrno = errno; /* In case ualarm() should change errno */
            ualarm(0, 0);       /* Cancel alarm */
            errno = savedErrno;

            if (nr == -1 && errno != EINTR)
                errExit("read");
            if (nr == 0) {
                fprintf(stderr, "read() regreso 0->fd desde inotify!");
                exit(EXIT_FAILURE);
            }

            if (errno != -1) {
                numRead += nr;
                inotifyReadCnt++;
                logMessage(VB_NOISY,"\n==========> Scaneo Secundario %d: got %zd bytes",inotifyReadCnt, nr);
            } else {                    /* EINTR */
                logMessage(VB_NOISY,"\n==========> Escaneo Secundario sin nada");
            }
            evp = buf;          /* Start again at beginning of buffer */
        }
    }
}

static int LoadValues()
{
    char line[1024 + 1];
    char *token, *token2, buf[12];
    char *parameters[] = { "logpath", "pidpath" , "logverbose" , "ipconsole" , "paths", "showchanges" }; 
    char **argv2 = malloc(2*sizeof(char *));
    size_t argc2 = 0;
    int max_watches;
    
    max_watches = chk_kernel();
    
    if (max_watches <= 0) {
      printf("\nValor de Kernel incorrecto...\n");
      exit(EXIT_FAILURE);
    }
    
    while( fgets(line, 1024, fvalues) != NULL ){
        token = strtok(line, "\t =\n\r");
        if( token != NULL && token[0] != '#' ){
	  if(justkill == 0){
	    if(!strncmp(token, parameters[0], sizeof(parameters[0]))){
	      token = strtok( NULL, "\t =\n\r");
	      strcpy(logpath, token);
	      logfp = fopen(token, "a+");
	      if (logfp == NULL)
		errExit("Archivo log Error...\n");
	      setbuf(logfp, NULL);
	    }  
	    if(!strncmp(token, parameters[1], sizeof(parameters[1]))){
	      id_t pid = getpid();
	      token = strtok( NULL, "\t =\n\r");
	      FILE *fpid = fopen(token, "w");
	      if (!fpid){
		perror("Archivo pid Error...\n");
		exit(EXIT_FAILURE);
	      }
	      fprintf(fpid, "%d\n", pid);
	      fclose(fpid);
	    }
	    if(!strncmp(token, parameters[2], sizeof(parameters[2]))){
	      token = strtok( NULL, "\t =\n\r");
	      verboseMask = atoi(token);
	      logMessage(VB_BASIC,"Log establecido como Basico...");
	      logMessage(VB_NOISY,"->Log establecido como Ruidoso...");
	      logMessage(0, "ATENCION: El numero de directorios soportados es: %d", max_watches);
	      logMessage(0, "          para modificar este numero, se edita el parametro de kernel");
	      logMessage(0, "          /proc/sys/fs/inotify/max_user_watches");
	    }
	    if(!strncmp(token, parameters[3], sizeof(parameters[3]))){
	      token = strtok( NULL, "\t =\n\r");
	      strncpy(ipconsole, token, sizeof(ipconsole)-1 );
	      ipconsole[sizeof(ipconsole)-1] = '\0';
	    }
	    if(!strncmp(token, parameters[4], sizeof(parameters[4]))){
	      token = strtok( NULL, "\n\r");
	      token2 = strtok( token, "|");
	      while(token2 != NULL){
		argv2[argc2++] = token2;	      
		token2 = strtok( NULL, "|");
	      }
	      argv2[argc2] = NULL;
	      copyRootDirPaths(argv2);
	    }
	    if(!strncmp(token, parameters[5], sizeof(parameters[5]))){
	      token = strtok( NULL, "\t =\n\r");
	      showchanges = atoi(token);
	    }
	  }
	  else{
	    int getpid = 0;
	    char killagent[PATH_MAX];
	    if(!strncmp(token, parameters[1], sizeof(parameters[1]))){
	      token = strtok( NULL, "\t =\n\r");
	      FILE *fpid = fopen(token, "r");
	      if (!fpid){
		perror("Archivo pid Error\n");
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
    
    if (optind >= argc || argc < 3 || argc > 3 ){
      printf(APP_USAGE);
      exit(EXIT_FAILURE);
    }

    fvalues = fopen(argv[2], "r");
    if( fvalues == NULL ){
     printf("Error ruta incorrecta de Archivo inotify.cfg..\n");
     exit(EXIT_FAILURE);
    }
    
    char *p = malloc(strlen(argv[2] + 1));
    
    while ((opt = getopt(argc, argv, "c:k")) != -1) {
      switch (opt) {
	case 'c':
	  strcpy(p, argv[2]);
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
	    gload = LoadValues();
	    if( gload != 0 ){
	      printf("Error en la carga de valores en archivo inotify.cfg..\n");
	      exit(EXIT_FAILURE);
	    }
	  } else {
	      printf("Error archivo inotify.cfg no es valido...\n");
	      exit(EXIT_FAILURE);
	  }
	break;
	case 'k':
	  justkill = 1;
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
	    gload = LoadValues();
	    if( gload != 0 ){
	      printf("Error en la carga de valores en archivo inotify.cfg..\n");
	      exit(EXIT_FAILURE);
	    }
	  } else {
	      printf("Error archivo inotify.cfg no es valido...\n");
	      exit(EXIT_FAILURE);
	  }
	  printf("Matando PID\n");
	  gload = LoadValues();
	  if( gload == 0 ){
	    printf("Exito al matar el pid del Agente..\n");
	    exit(EXIT_SUCCESS);
	  }
	  else {
	    printf("error: No se pudo matar el pid del Agente..");
	    exit(EXIT_FAILURE);
	  }
	break;
	default:
	  printf(APP_USAGE);
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