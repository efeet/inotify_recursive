#include "libraries_include.h"
#include "curr_time.h"          /* Declares function defined here */

#define BUF_SIZE 1000

char * currTime(void)
{
    static char buf[BUF_SIZE];  /* Nonreentrant */
    time_t t;
    size_t s;
    struct tm *tm;

    t = time(NULL);
    tm = localtime(&t);
    if (tm == NULL)
        return NULL;

    s = strftime(buf,BUF_SIZE,"%Y-%m-%d %T", tm);

    return (s == 0) ? NULL : buf;
}

char * currTimeLog(void)
{
    static char buf[BUF_SIZE];  /* Nonreentrant */
    time_t t;
    size_t s;
    struct tm *tm;

    t = time(NULL);
    tm = localtime(&t);
    if (tm == NULL)
        return NULL;

    s = strftime(buf,BUF_SIZE,"[%m/%d/%Y %T]", tm);

    return (s == 0) ? NULL : buf;
}