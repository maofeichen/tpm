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
printTimeMicroEnd(double *totalElapse)
{
    double elapsedTime;
    gettimeofday(&stop, NULL);
    elapsedTime = ((stop.tv_sec - start.tv_sec)*1000000L + stop.tv_usec) - start.tv_usec;
    *totalElapse += elapsedTime;
    printf("took %.1f microseconds\n", elapsedTime);
}
