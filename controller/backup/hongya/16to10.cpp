#include <stdio.h>   
#include <stdlib.h>//strtol头文件   
#include <string.h>

int main()   
{   
    char p[10]="0xFF";      
    char *str;      
    int i = (int)strtol(p, &str, 16);//十六进制   
    printf("%d\n",i);   
    return 0;      
} 
