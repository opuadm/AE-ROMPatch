typedef unsigned int u32;
typedef int s32;
typedef long s64;
typedef unsigned long u64;
typedef unsigned short u16;

#define EXPORT __attribute__((visibility("default")))

static long sc(long n, long a, long b, long c, long d, long e)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory", "cc");
    return x0;
}

#define NR_OPENAT 56
#define NR_READ 63
#define NR_PPOLL 73
#define NR_NANOSLEEP 101
#define NR_CLOCK_GETTIME 113
#define AT_FDCWD (-100)
#define O_RDWR 02
#define O_NONBLOCK 04000
#define O_CLOEXEC 02000000
#define POLLIN 1
#define WAIT_NS 200000000L

struct ts {
    long sec, nsec;
};
struct pfd {
    int fd;
    short events, revents;
};

struct hw_module;
struct hw_device;
struct hw_module_methods {
    int (*open)(const struct hw_module *m, const char *id, struct hw_device **dev);
};
struct hw_module {
    u32 tag;
    u16 module_api_version, hal_api_version;
    const char *id, *name, *author;
    struct hw_module_methods *methods;
    void *dso;
    u64 reserved[25];
};
struct hw_device {
    u32 tag, version;
    struct hw_module *module;
    u64 reserved[12];
    int (*close)(struct hw_device *dev);
};
struct sensor_t {
    const char *name, *vendor;
    int version, handle, type;
    float maxRange, resolution, power;
    s32 minDelay;
    u32 fifoReservedEventCount, fifoMaxEventCount;
    const char *stringType, *requiredPermission;
    s64 maxDelay;
    u64 flags;
    void *reserved[2];
};
struct event {
    s32 version, sensor, type, reserved0;
    s64 timestamp;
    float data[16];
    u32 flags, reserved1[3];
};
struct sensors_module {
    struct hw_module common;
    int (*get_sensors_list)(struct sensors_module *m, const struct sensor_t **list);
    int (*set_operation_mode)(unsigned mode);
};
struct poll_device {
    struct hw_device common;
    int (*activate)(struct poll_device *d, int handle, int enabled);
    int (*setDelay)(struct poll_device *d, int handle, s64 ns);
    int (*poll)(struct poll_device *d, struct event *data, int count);
    int (*batch)(struct poll_device *d, int handle, int flags, s64 period_ns, s64 timeout);
    int (*flush)(struct poll_device *d, int handle);
    int (*inject_sensor_data)(struct poll_device *d, const struct event *data);
    int (*register_direct_channel)(struct poll_device *d, const void *mem, int channel);
    int (*config_direct_report)(struct poll_device *d, int sensor, int channel, const void *config);
    void (*reserved_procs[5])(void);
};

#define HANDLE_ACCEL 1
#define GRAVITY 9.80665f

static const struct sensor_t sensors[] = {{
    .name = "AEmulator 3-axis Accelerometer",
    .vendor = "AEmulator",
    .version = 1,
    .handle = HANDLE_ACCEL,
    .type = 1,
    .maxRange = 4.0f * GRAVITY,
    .resolution = 1.0f / 4096.0f,
    .power = 0.2f,
    .minDelay = 10000,
    .stringType = "android.sensor.accelerometer",
    .maxDelay = 1000000,
    .flags = 0,
}};

static struct poll_device dev;
static int g_fd = -1;
static int g_active;
static int g_flush;

static void zero(void *p, unsigned long n)
{
    volatile unsigned char *c = p;
    while (n--)
        *c++ = 0;
}

static s64 now_ns(void)
{
    struct ts t;
    sc(NR_CLOCK_GETTIME, 1, (long)&t, 0, 0, 0);
    return t.sec * 1000000000L + t.nsec;
}

static int get_list(struct sensors_module *m, const struct sensor_t **list)
{
    (void)m;
    *list = sensors;
    return 1;
}

static int set_mode(unsigned mode) { return mode == 0 ? 0 : -22; }

static int d_activate(struct poll_device *d, int handle, int en)
{
    (void)d;
    if (handle != HANDLE_ACCEL)
        return -22;
    __atomic_store_n(&g_active, en ? 1 : 0, __ATOMIC_RELEASE);
    return 0;
}

static int d_delay(struct poll_device *d, int handle, s64 ns)
{
    (void)d;
    (void)ns;
    return handle == HANDLE_ACCEL ? 0 : -22;
}

static int d_batch(struct poll_device *d, int handle, int flags, s64 p, s64 t)
{
    (void)d;
    (void)flags;
    (void)p;
    (void)t;
    return handle == HANDLE_ACCEL ? 0 : -22;
}

static int d_flush(struct poll_device *d, int handle)
{
    (void)d;
    if (handle != HANDLE_ACCEL)
        return -22;
    __atomic_add_fetch(&g_flush, 1, __ATOMIC_ACQ_REL);
    return 0;
}

static int d_inject(struct poll_device *d, const struct event *e)
{
    (void)d;
    (void)e;
    return -38;
}

static int take_flush(void)
{
    int v = __atomic_load_n(&g_flush, __ATOMIC_ACQUIRE);
    while (v > 0)
        if (__atomic_compare_exchange_n(&g_flush, &v, v - 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 1;
    return 0;
}

static int d_poll(struct poll_device *d, struct event *out, int count)
{
    (void)d;
    if (count <= 0)
        return 0;
    if (take_flush()) {
        zero(out, sizeof *out);
        out->version = 3;
        out->type = 0;
        ((s32 *)out->data)[0] = 1;
        ((s32 *)out->data)[1] = HANDLE_ACCEL;
        return 1;
    }
    if (g_fd < 0)
        g_fd = (int)sc(NR_OPENAT, AT_FDCWD, (long)"/dev/aemu_sensors", O_RDWR | O_NONBLOCK | O_CLOEXEC, 0, 0);
    struct ts wait = {0, WAIT_NS};
    if (g_fd < 0) {
        sc(NR_NANOSLEEP, (long)&wait, 0, 0, 0, 0);
        return 0;
    }
    int n = 0;
    while (n < count) {
        s32 rec[4];
        long r = sc(NR_READ, g_fd, (long)rec, sizeof rec, 0, 0);
        if (r != (long)sizeof rec) {
            if (n)
                break;
            struct pfd p = {g_fd, POLLIN, 0};
            if (sc(NR_PPOLL, (long)&p, 1, (long)&wait, 0, 8) <= 0)
                break;
            continue;
        }
        if (!__atomic_load_n(&g_active, __ATOMIC_ACQUIRE) || rec[0] != 1)
            continue;
        struct event *e = out + n++;
        zero(e, sizeof *e);
        e->version = (s32)sizeof *e;
        e->sensor = HANDLE_ACCEL;
        e->type = 1;
        e->timestamp = now_ns();
        e->data[0] = *(float *)&rec[1];
        e->data[1] = *(float *)&rec[2];
        e->data[2] = *(float *)&rec[3];
        ((signed char *)&e->data[3])[0] = 3;
    }
    return n;
}

static int d_close(struct hw_device *h)
{
    (void)h;
    return 0;
}

static int s_open(const struct hw_module *m, const char *id, struct hw_device **out)
{
    (void)id;
    zero(&dev, sizeof dev);
    dev.common.tag = 0x48574454;
    dev.common.version = (1u << 24) | (3u << 16) | 1;
    dev.common.module = (struct hw_module *)m;
    dev.common.close = d_close;
    dev.activate = d_activate;
    dev.setDelay = d_delay;
    dev.poll = d_poll;
    dev.batch = d_batch;
    dev.flush = d_flush;
    dev.inject_sensor_data = d_inject;
    *out = &dev.common;
    return 0;
}

static struct hw_module_methods methods = {s_open};

EXPORT struct sensors_module HMI = {
    .common =
        {
            .tag = 0x484d4f44,
            .module_api_version = 1,
            .hal_api_version = 0,
            .id = "sensors",
            .name = "AEmulator sensors (aerompatch)",
            .author = "aerompatch",
            .methods = &methods,
        },
    .get_sensors_list = get_list,
    .set_operation_mode = set_mode,
};
