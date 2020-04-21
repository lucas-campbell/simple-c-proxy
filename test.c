#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
int main()

{
    char arr[] = {'a','b','c','4','y','\0'};
    char bad[] = {'r','a','d','\0','i','c','L'};

    char *x = arr;
    char *y = bad;

    printf("%c %c\n", x[4], y[4]);
    

    int i;

    //int hash = 0;
    while((i = *x++))
        i++;

    return 0;
}
