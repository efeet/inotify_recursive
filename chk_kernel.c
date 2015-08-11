#include "libraries_include.h"
int fd, n, max_watches, i, rem, rest = 0;
char buf[12];

int chk_kernel(void)
{
  fd = open("/proc/sys/fs/inotify/max_user_watches", O_RDONLY);
  if (fd < 0) {
    perror("No se puede abrir /proc/sys/fs/inotify/max_user_watches");
    exit(EXIT_FAILURE);
  }
  if ( (n = read(fd, buf, sizeof(buf) - 1)) < 0) {
    perror("No se puede leer() /proc/sys/fs/inotify/max_user_watches");
    exit(EXIT_FAILURE);
  }
  buf[n] = 0;
  max_watches = atoi(buf);
  for(i=1; i <= max_watches; i++){
    rem = i % 65000;
    if(rem == 0)
      rest+=256;
  }
  printf("Numero de Archivos a monitorear = /proc/sys/fs/inotify/max_user_watches: %d\n",max_watches - rest);
  if (max_watches <= 0) {
    printf("Numero de Rutas Incorrecto: ");
    printf(buf);
    printf("\n");
    return 1;
  }
  return (max_watches - rest);
}