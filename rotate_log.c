#include "libraries_include.h"

int logren1=0;
int logren2=0;
int logren3=0;

int logexist (char *filename)
{
  struct stat   buffer;   
  return (stat (filename, &buffer) == 0);
}

FILE *rotatelog(char logpath[PATH_MAX], FILE *logfp){
  int logsizelimit = 1048576/*104857600*/;
  char rotate[PATH_MAX];
  char rotatelog1[PATH_MAX];
  char rotatelog2[PATH_MAX];
  char rotatelog3[PATH_MAX];
  struct stat st;
  
  stat(logpath, &st);
  
  strcpy(rotate, logpath);
  
  strcpy(rotatelog1, logpath);
  strcat(rotatelog1, ".1");
  strcpy(rotatelog2, logpath);
  strcat(rotatelog2, ".2");
  strcpy(rotatelog3, logpath);
  strcat(rotatelog3, ".3");
  
  if(st.st_size >= logsizelimit){
    if(logexist(rotatelog1)){
      logren1=1;
      if(logexist(rotatelog2)){
	logren2=1;
	if(logexist(rotatelog3)){
	  logren3=1;
	  remove(rotatelog3);
	  rename(rotatelog2, rotatelog3);
	  rename(rotatelog1, rotatelog2);
	  rename(logpath, rotatelog1);
	}
	else{
	  rename(rotatelog2, rotatelog3);
	  rename(rotatelog1, rotatelog2);
	  rename(logpath, rotatelog1);
	}
      }
      else{
	rename(rotatelog1, rotatelog2);
	rename(logpath, rotatelog1);
      }
    }
    else{
      rename(logpath, rotatelog1);
    }
  }
  logfp = freopen(logpath, "a+", stdout);
  return(logfp);
}