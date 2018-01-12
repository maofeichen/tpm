#include "misc.h"
#include <stdio.h>

void
printTime()
{
    time_t rawtime;
	struct tm *timeinfo;

 	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "local time: %s", asctime (timeinfo) );
}
