#ifndef _HELPERS_H_
#define _HELPERS_H_

typedef long (*sched_setaffinity_t)(pid_t pid, const struct cpumask *in_mask);

static sched_setaffinity_t _helper_sched_setaffinity = NULL;

static long helper_sched_setaffinity(pid_t pid, const struct cpumask *in_mask) {
    if (!_helper_sched_setaffinity) {
        _helper_sched_setaffinity = rk_kallsyms_lookup_name("sched_setaffinity");
    }

    return _helper_sched_setaffinity(pid, in_mask);
}

// ALIGN macro is fucked, rounds down to 0 ?? or size ??? i have no fucking idea
#define helper_make_contig(src, size)     \
    memcpy(kmalloc(PAGE_SIZE, GFP_KERNEL), src, size)


// // !! cant be in a func idk why
// #define helper_flush_virt(addr)       \
//     flush_cache_mm(init_mm_ptr);      \
//     flush_tlb_all();                  \
//     _helper_flush_virt(addr);

// // preempt_disable(); here
// #define helper_for_each_cpu(f)        \
//     preempt_disable();                \
//     do {                              \
//         int i;                        \
//         for (i = 0; i < num_online_cpus(); i++) {             \
//             helper_sched_setaffinity(0, get_cpu_mask(i));     \
//             f                         \
//         }                             \
//     } while (0);                      \
//     preempt_enable();

#endif
