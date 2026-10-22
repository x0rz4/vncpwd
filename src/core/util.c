#include "util.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#  include <io.h>
#  include <windows.h>
#  define VNC_ISATTY(f) _isatty(_fileno(f))
#else
#  include <dirent.h>
#  include <unistd.h>
#  define VNC_ISATTY(f) isatty(fileno(f))
#endif

static int lower(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
    return c;
}

int vnc_str_ieq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (lower((unsigned char)*a) != lower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

int vnc_str_istarts(const char *hay, const char *prefix) {
    if (!hay || !prefix) return 0;
    while (*prefix) {
        if (!*hay) return 0;
        if (lower((unsigned char)*hay) != lower((unsigned char)*prefix)) return 0;
        hay++;
        prefix++;
    }
    return 1;
}

int vnc_str_iends(const char *hay, const char *suffix) {
    size_t h, s;
    if (!hay || !suffix) return 0;
    h = strlen(hay);
    s = strlen(suffix);
    if (s > h) return 0;
    return vnc_str_ieq(hay + (h - s), suffix);
}

const char *vnc_str_icontains(const char *hay, const char *needle) {
    size_t nlen;
    if (!hay || !needle) return NULL;
    nlen = strlen(needle);
    if (nlen == 0) return hay;
    for (; *hay; hay++) {
        if (vnc_str_istarts(hay, needle)) return hay;
    }
    return NULL;
}

void vnc_trim(char *s) {
    char *start, *end;
    size_t len;

    if (!s) return;
    start = s;
    while (*start && (unsigned char)*start <= ' ') start++;
    len = strlen(start);
    if (start != s) memmove(s, start, len + 1);
    end = s + len;
    while (end > s && (unsigned char)end[-1] <= ' ') end--;
    *end = 0;
}

int vnc_copy(char *dst, size_t cap, const char *src) {
    size_t len;
    if (!dst || cap == 0) return -1;
    if (!src) {
        dst[0] = 0;
        return 0;
    }
    len = strlen(src);
    if (len >= cap) {
        memcpy(dst, src, cap - 1);
        dst[cap - 1] = 0;
        return -1;
    }
    memcpy(dst, src, len + 1);
    return 0;
}

void vnc_utf8_bom_strip(const char **data, size_t *len) {
    if (!data || !*data || !len) return;
    if (*len >= 3 && (unsigned char)(*data)[0] == 0xef &&
        (unsigned char)(*data)[1] == 0xbb && (unsigned char)(*data)[2] == 0xbf) {
        *data += 3;
        *len -= 3;
    }
}

static int expand_var(const char *name, char *out, size_t outcap) {
#ifdef _WIN32
    DWORD n;
    char buf[1024];
    n = GetEnvironmentVariableA(name, buf, (DWORD)sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return -1;
    return vnc_copy(out, outcap, buf);
#else
    const char *v = getenv(name);
    if (!v) return -1;
    return vnc_copy(out, outcap, v);
#endif
}

int vnc_expand_path(const char *in, char *out, size_t outcap) {
    char tmp[1024];
    char var[128];
    size_t oi = 0, ii = 0;

    if (!in || !out || outcap == 0) return -1;
    tmp[0] = 0;

    if (in[0] == '~' && (in[1] == '/' || in[1] == '\\' || in[1] == 0)) {
        if (expand_var("HOME", tmp, sizeof(tmp)) != 0) {
#ifdef _WIN32
            if (expand_var("USERPROFILE", tmp, sizeof(tmp)) != 0) return -1;
#else
            return -1;
#endif
        }
        if (vnc_copy(out, outcap, tmp) != 0) return -1;
        if (in[1]) {
            size_t used = strlen(out);
            if (vnc_copy(out + used, outcap - used, in + 1) != 0) return -1;
        }
        return 0;
    }

    while (in[ii] && oi + 1 < outcap) {
        if (in[ii] == '%') {
            size_t vi = 0, close = ii + 1;
            while (in[close] && in[close] != '%' && vi + 1 < sizeof(var)) {
                var[vi++] = in[close++];
            }
            var[vi] = 0;
            if (in[close] == '%' && vi > 0) {
                char value[1024];
                if (expand_var(var, value, sizeof(value)) == 0) {
                    size_t vlen = strlen(value);
                    if (oi + vlen + 1 > outcap) return -1;
                    memcpy(out + oi, value, vlen);
                    oi += vlen;
                    ii = close + 1;
                    continue;
                }
            }
        }
        out[oi++] = in[ii++];
    }
    out[oi] = 0;
    return 0;
}

int vnc_file_exists(const char *path) {
    struct stat st;
    if (!path) return 0;
    return stat(path, &st) == 0 && (st.st_mode & S_IFREG) != 0;
}

int vnc_is_tty(FILE *f) {
    if (!f) return 0;
    return VNC_ISATTY(f);
}

size_t vnc_read_file(const char *path, char **out, size_t max_bytes) {
    FILE *f;
    char *buf;
    size_t cap, len = 0;

    if (!path || !out) return (size_t)-1;
    *out = NULL;

    f = fopen(path, "rb");
    if (!f) return (size_t)-1;

    cap = 4096;
    if (max_bytes && cap > max_bytes + 1) cap = max_bytes + 1;
    buf = (char *)malloc(cap);
    if (!buf) {
        fclose(f);
        return (size_t)-1;
    }

    for (;;) {
        size_t n;
        if (len + 1 >= cap) {
            char *grown;
            size_t ncap = cap * 2;
            if (max_bytes && ncap > max_bytes + 1) ncap = max_bytes + 1;
            if (ncap <= cap) break; /* hit the cap */
            grown = (char *)realloc(buf, ncap);
            if (!grown) {
                free(buf);
                fclose(f);
                return (size_t)-1;
            }
            buf = grown;
            cap = ncap;
        }
        n = fread(buf + len, 1, cap - len - 1, f);
        len += n;
        if (n == 0) {
            if (ferror(f)) {
                free(buf);
                fclose(f);
                return (size_t)-1;
            }
            break;
        }
    }
    fclose(f);

    buf[len] = 0;
    *out = buf;
    return len;
}

int vnc_list_dir(const char *dir, const char *suffix, vnc_dir_cb cb, void *ctx) {
    int visited = 0;
    if (!dir || !cb) return 0;

#ifdef _WIN32
    {
        WIN32_FIND_DATAA fd;
        HANDLE h;
        char pattern[1024];
        snprintf(pattern, sizeof(pattern), "%s\\*", dir);
        h = FindFirstFileA(pattern, &fd);
        if (h == INVALID_HANDLE_VALUE) return 0;
        do {
            char full[1024];
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (suffix && !vnc_str_iends(fd.cFileName, suffix)) continue;
            snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
            visited++;
            if (cb(ctx, full)) break;
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    {
        DIR *d;
        struct dirent *ent;
        d = opendir(dir);
        if (!d) return 0;
        while ((ent = readdir(d)) != NULL) {
            char full[1024];
            if (ent->d_name[0] == '.') continue;
            if (suffix && !vnc_str_iends(ent->d_name, suffix)) continue;
            snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
            if (!vnc_file_exists(full)) continue;
            visited++;
            if (cb(ctx, full)) break;
        }
        closedir(d);
    }
#endif
    return visited;
}

void vnc_mask_secret(const char *secret, size_t len, int show, char *out, size_t outcap) {
    size_t i;

    if (!out || outcap == 0) return;
    if (!secret) {
        out[0] = 0;
        return;
    }
    if (show) {
        size_t n = len < outcap - 1 ? len : outcap - 1;
        memcpy(out, secret, n);
        out[n] = 0;
        return;
    }
    if (len == 0) {
        vnc_copy(out, outcap, "(empty)");
        return;
    }
    if (outcap < 16) {
        out[0] = 0;
        return;
    }
    out[0] = secret[0];
    out[1] = '*';
    out[2] = '*';
    out[3] = '*';
    for (i = 4; i < len && i + 8 < outcap; i++) out[i] = '*';
    snprintf(out + i, outcap - i, " (len %u)", (unsigned)len);
}

void vnc_escape(const char *in, size_t len, char *out, size_t outcap) {
    size_t i, o = 0;

    if (!out || outcap == 0) return;
    if (!in) {
        out[0] = 0;
        return;
    }
    for (i = 0; i < len && o + 5 < outcap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c >= 0x20 && c < 0x7f) {
            out[o++] = (char)c;
        } else {
            o += (size_t)snprintf(out + o, outcap - o, "\\x%02x", c);
        }
    }
    out[o] = 0;
}
