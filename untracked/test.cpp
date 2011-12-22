#include <unistd.h>
#include <stdio.h>

int main ( int argc, char *argv[] )
{
    char buf[20];
    while (1)
    {
	read(0, buf, sizeof(buf));
	printf ("received %s", buf);
    }
}
