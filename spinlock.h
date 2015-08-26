#ifndef _SPINLOCK_
#define _SPINLOCK_

typedef uint32_t lock_t;

void acquire_lock(lock_t * lock);
void release_lock(lock_t * lock);

#endif