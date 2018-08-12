#ifndef _TIMER_H
#define _TIMER_H

#include <stdbool.h>
#include <time.h>
#include <signal.h>

extern timer_t create_timer(void (*)(union sigval), void *);
extern void set_timer(timer_t, const struct timespec *, bool);

#endif /* _TIMER_H */
