#include "misc.h"
#include <stdio.h>
#include <sys/time.h>

struct timeval start, stop;

void
printTime()
{
    time_t rawtime;
	struct tm *timeinfo;

 	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "local time: %s", asctime (timeinfo) );
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
    printf("tool %lu microseconds\n", stop.tv_sec - start.tv_sec);
}
