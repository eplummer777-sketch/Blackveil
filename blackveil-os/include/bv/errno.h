#ifndef BV_ERRNO_H
#define BV_ERRNO_H

/* Kernel error codes, returned negated (e.g. -BV_ENOMEM). */
#define BV_EPERM    1
#define BV_ENOENT   2
#define BV_ENOMEM   12
#define BV_EFAULT   14
#define BV_EBUSY    16
#define BV_EINVAL   22
#define BV_ENOSPC   28
#define BV_EALREADY 114

static inline const char *bv_strerror(int err)
{
    switch (err < 0 ? -err : err) {
    case 0: return "ok";
    case BV_EPERM: return "not permitted";
    case BV_ENOENT: return "not mapped";
    case BV_ENOMEM: return "out of memory";
    case BV_EFAULT: return "corrupted";
    case BV_EBUSY: return "in use";
    case BV_EINVAL: return "invalid argument";
    case BV_ENOSPC: return "table full";
    case BV_EALREADY: return "already free";
    default: return "unknown error";
    }
}

#endif
