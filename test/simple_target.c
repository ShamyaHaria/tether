#include <stdio.h>
#include <unistd.h>

// Kept noinline so it has a stable, easy-to-find address for breakpoints.
__attribute__((noinline))
int add(int a, int b) {
    int result = a + b;
    return result;
}

int main(void) {
    printf("simple_target: pid=%d\n", getpid());
    for (int i = 0; i < 5; i++) {
        int sum = add(i, i * 2);
        printf("add(%d, %d) = %d\n", i, i * 2, sum);
        sleep(1);
    }
    printf("simple_target: done\n");
    return 0;
}
