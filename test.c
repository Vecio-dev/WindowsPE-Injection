#include <stdio.h>

double f(int a, int b) {
    return a + b;
}

int main() {
    int a = 1;
    a = 1 + 2;

    char* str = "Hello, World!";
    f(a, 2);

    printf("%s\n", str);

    return 0;
}