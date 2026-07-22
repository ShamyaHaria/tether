#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NUM_THREADS 3

static pid_t gettid_(void) { return (pid_t)syscall(SYS_gettid); }

// Every thread calls this same function, so a single breakpoint set here
// will trap in whichever thread happens to execute it next -- that's the
// piece that demonstrates breakpoints as shared, process-wide state across
// a multithreaded tracee.
__attribute__((noinline))
int worker(int id) {
    int total = 0;
    for (int i = 0; i < 3; i++) {
        total += id * 10 + i;
        printf("[thread %d / tid %d] iteration %d, total=%d\n", id, gettid_(), i, total);
        sleep(1);
    }
    return total;
}

static void* thread_main(void* arg) {
    long id = (long)arg;
    worker((int)id);
    return NULL;
}

int main(void) {
    printf("threaded_target: pid=%d\n", getpid());
    pthread_t threads[NUM_THREADS];
    for (long i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_main, (void*)i);
        usleep(200000); // stagger clone() calls so events are easy to read
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("threaded_target: all threads done\n");
    return 0;
}
