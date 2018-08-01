#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>

timer_t create_timer(void (*fn)(union sigval), void *arg)
{
        union sigval val = {.sival_ptr = arg};
        struct sigevent event = {
                .sigev_notify = SIGEV_THREAD,
                .sigev_value = val,
                .sigev_notify_function = fn,
                .sigev_notify_attributes = NULL,
        };
        timer_t timer;

        if (timer_create (CLOCK_MONOTONIC, &event, &timer) == -1) {
                perror("timer_create");
                exit(1);
        }

        return timer;
}

void set_timer(timer_t timer, const struct timespec *time, bool repeat)
{
        struct itimerspec spec;
        spec.it_value = *time;
        if (repeat)
                spec.it_interval = *time;
        timer_settime(timer, 0, &spec, NULL);
}
