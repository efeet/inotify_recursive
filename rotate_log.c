#include "libraries_include.h"

int logren1=0;
int logren2=0, logren3=0;

int logexist (char *filename)
{
  struct stat   buffer;   
  return (stat (filename, &buffer) == 0);
}

void rotatelog(char logpath[PATH_MAX], FILE *logfp){
  int logsizelimit = 1048576/*104857600*/;
  char rotatelog1[PATH_MAX];
  char rotatelog2[PATH_MAX];
  char rotatelog3[PATH_MAX];
  struct stat st;
  int i;
  
  stat(logpath, &st);
  
  strcpy(rotatelog1, logpath);
  strcat(rotatelog1, ".1");
  strcpy(rotatelog2, logpath);
  strcat(rotatelog2, ".2");
  strcpy(rotatelog3, logpath);
  strcat(rotatelog3, ".3");
  
  if(st.st_size >= logsizelimit){
    for(i=1; i<4; i++){
      if(logexist(rotatelog1)){
	logren1=1;
      }
      else{
	if(rename(logpath, rotatelog1) == 0){
	  logfp = freopen(logpath, "a+", stdout);
	  setbuf(logfp, NULL);
	}
      }
      if(logexist(rotatelog2)){
	logren2=1;
      }
      else{
	if(rename(logpath, rotatelog2) == 0){
	  logfp = freopen(logpath, "a+", stdout);
	  setbuf(logfp, NULL);
	}
      }
      if(logexist(rotatelog3)){
	logren3=1;
      }
      else{
	if(rename(logpath, rotatelog3) == 0){
	  logfp = freopen(logpath, "a+", stdout);
	  setbuf(logfp, NULL);
	}
      }
      if(logren1 == 1 && logren2 == 1 && logren3 == 1){
	remove(rotatelog1);
	remove(rotatelog2);
	remove(rotatelog3);
	logren1=0;
	logren2=0;
	logren3=0;
      }
    }
  }
}