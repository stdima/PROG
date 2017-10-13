#include <stdio.h>

__attribute__((constructor)) void f()
{
    setvbuf(stdout,NULL,_IONBF,0);
}


// gcc -fPIC -shared -Wall -o line_buffer.so line_buffer.c
