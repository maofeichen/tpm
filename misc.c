#include "misc.h"
#include <stdio.h>
#include <sys/time.h>

struct timeval start, stop;

void
printTime(char *s)
{
    time_t rawtime;
	struct tm *timeinfo;

 	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "----------\n%s\nlocal time: %s", s, asctime (timeinfo) );
}

void
printTimeMicroStart()
{
    gettimeofday(&start, NULL);
}

void
printTimeMicroEnd()
{
    gettimeofday(&stop, NULL);
    printf("took %lu microseconds\n", stop.tv_sec - start.tv_sec);
}
