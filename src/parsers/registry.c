#include "registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>

static HKEY hive_handle(vnc_hive hive) {
    switch (hive) {
    case VNC_HIVE_CURRENT_USER:  return HKEY_CURRENT_USER;
    case VNC_HIVE_LOCAL_MACHINE: return HKEY_LOCAL_MACHINE;
    case VNC_HIVE_USERS:         return HKEY_USERS;
    default:                     return NULL;
    }
}

static REGSAM view_flag(int view) {
    if (view == 32) return KEY_WOW64_32KEY;
    if (view == 64) return KEY_WOW64_64KEY;
    return 0;
}

int vnc_reg_available(void) { return 1; }

int vnc_reg_read_value(vnc_hive hive, int view, const char *path, const char *name,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       uint32_t *type, char *err, size_t errcap) {
    HKEY key = NULL;
    DWORD dwType = 0;
    DWORD cb = (DWORD)outcap;
    LONG rc;

    if (err && errcap) err[0] = 0;
    if (outlen) *outlen = 0;
    if (type) *type = VNC_REG_NONE;
    if (!path || !name || !out) return VNC_REG_ERR_FAILED;

    rc = RegOpenKeyExA(hive_handle(hive), path, 0, KEY_READ | view_flag(view), &key);
    if (rc != ERROR_SUCCESS) {
        if (err && errcap) {
            snprintf(err, errcap, "cannot open %s (error %ld)", path, (long)rc);
        }
        return (rc == ERROR_FILE_NOT_FOUND) ? VNC_REG_ERR_NOT_FOUND : VNC_REG_ERR_FAILED;
    }

    rc = RegQueryValueExA(key, name, NULL, &dwType, (LPBYTE)out, &cb);
    RegCloseKey(key);

    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_MORE_DATA || rc == ERROR_INSUFFICIENT_BUFFER) {
            return VNC_REG_ERR_TOO_SMALL;
        }
        return VNC_REG_ERR_NOT_FOUND;
    }

    if (type) *type = (uint32_t)dwType;
    /* String types include the terminating NUL in cb. */
    if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ) {
        if (cb > 0 && out[cb - 1] == 0) cb--;
    }
    if (outlen) *outlen = (size_t)cb;
    return VNC_REG_OK;
}

int vnc_reg_read_string(vnc_hive hive, int view, const char *path, const char *name,
                        char *out, size_t outcap, char *err, size_t errcap) {
    size_t len = 0;
    uint32_t type = 0;
    int rc;

    if (!out || outcap == 0) return VNC_REG_ERR_FAILED;
    out[0] = 0;
    rc = vnc_reg_read_value(hive, view, path, name, (uint8_t *)out, outcap - 1,
                            &len, &type, err, errcap);
    if (rc != VNC_REG_OK) return rc;
    if (type != VNC_REG_SZ && type != VNC_REG_EXPAND && type != VNC_REG_BINARY) {
        if (err && errcap) {
            snprintf(err, errcap, "value %s has unexpected registry type %lu",
                     name, (unsigned long)type);
        }
        return VNC_REG_ERR_BAD_TYPE;
    }
    out[len] = 0;
    return VNC_REG_OK;
}

int vnc_reg_read_dword(vnc_hive hive, int view, const char *path, const char *name,
                       uint32_t *out, char *err, size_t errcap) {
    uint8_t buf[8];
    size_t len = 0;
    uint32_t type = 0;
    int rc = vnc_reg_read_value(hive, view, path, name, buf, sizeof(buf),
                                &len, &type, err, errcap);
    if (rc != VNC_REG_OK) return rc;
    if (type != VNC_REG_DWORD || len != 4) return VNC_REG_ERR_BAD_TYPE;
    memcpy(out, buf, 4);
    return 0;
}

/* Returns 1 when the callback asked to stop. */
static int walk_recursive(vnc_hive hive, int view, const char *path,
                          int depth, int max_depth, vnc_reg_visit_fn fn, void *ctx) {
    HKEY key = NULL;
    DWORD index;
    LONG rc;

    if (RegOpenKeyExA(hive_handle(hive), path, 0, KEY_READ | view_flag(view), &key)
            != ERROR_SUCCESS) {
        return 0;
    }

    /* Values of this key.  Read the data with a second query using the size
     * reported by the enumeration; never assume the reported cb is accurate. */
    for (index = 0;; index++) {
        char name[512];
        DWORD name_len = sizeof(name);
        DWORD type = 0;
        DWORD cb = 0;
        uint8_t *data = NULL;
        DWORD got;
        int stop;

        name_len = sizeof(name) - 1;
        rc = RegEnumValueA(key, index, name, &name_len, NULL, &type, NULL, &cb);
        if (rc != ERROR_SUCCESS) break;
        name[name_len] = 0;

        if (cb > 0 && cb < 64 * 1024) {
            got = cb;
            data = (uint8_t *)malloc(got);
            if (data && RegQueryValueExA(key, name, NULL, &type, data, &got) != ERROR_SUCCESS) {
                free(data);
                data = NULL;
                got = 0;
            }
        } else {
            got = 0;
        }

        stop = fn(ctx, path, name, (uint32_t)type, data, (size_t)got);
        free(data);
        if (stop) {
            RegCloseKey(key);
            return 1;
        }
    }

    if (max_depth >= 0 && depth >= max_depth) {
        RegCloseKey(key);
        return 0;
    }

    for (index = 0;; index++) {
        char subkey[512];
        DWORD name_len = sizeof(subkey);
        char child[1024];

        name_len = sizeof(subkey) - 1;
        rc = RegEnumKeyExA(key, index, subkey, &name_len, NULL, NULL, NULL, NULL);
        if (rc != ERROR_SUCCESS) break;
        subkey[name_len] = 0;

        snprintf(child, sizeof(child), "%s\\%s", path, subkey);
        if (walk_recursive(hive, view, child, depth + 1, max_depth, fn, ctx)) {
            RegCloseKey(key);
            return 1;
        }
    }

    RegCloseKey(key);
    return 0;
}

int vnc_reg_walk(vnc_hive hive, int view, const char *root, int max_depth,
                 vnc_reg_visit_fn fn, void *ctx) {
    if (!root || !fn) return VNC_REG_ERR_FAILED;
    walk_recursive(hive, view, root, 0, max_depth, fn, ctx);
    return VNC_REG_OK;
}

#else /* !_WIN32 */

int vnc_reg_available(void) { return 0; }

int vnc_reg_read_value(vnc_hive hive, int view, const char *path, const char *name,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       uint32_t *type, char *err, size_t errcap) {
    (void)hive; (void)view; (void)path; (void)name; (void)out; (void)outcap;
    (void)outlen; (void)type;
    if (err && errcap) snprintf(err, errcap, "registry access requires Windows");
    return VNC_REG_ERR_UNSUPPORTED;
}

int vnc_reg_read_string(vnc_hive hive, int view, const char *path, const char *name,
                        char *out, size_t outcap, char *err, size_t errcap) {
    (void)hive; (void)view; (void)path; (void)name;
    if (out && outcap) out[0] = 0;
    if (err && errcap) snprintf(err, errcap, "registry access requires Windows");
    return VNC_REG_ERR_UNSUPPORTED;
}

int vnc_reg_read_dword(vnc_hive hive, int view, const char *path, const char *name,
                       uint32_t *out, char *err, size_t errcap) {
    (void)hive; (void)view; (void)path; (void)name; (void)out;
    if (err && errcap) snprintf(err, errcap, "registry access requires Windows");
    return VNC_REG_ERR_UNSUPPORTED;
}

int vnc_reg_walk(vnc_hive hive, int view, const char *root, int max_depth,
                 vnc_reg_visit_fn fn, void *ctx) {
    (void)hive; (void)view; (void)root; (void)max_depth; (void)fn; (void)ctx;
    return VNC_REG_ERR_UNSUPPORTED;
}

#endif /* _WIN32 */

const char *vnc_reg_hive_name(vnc_hive hive) {
    switch (hive) {
    case VNC_HIVE_CURRENT_USER:  return "HKEY_CURRENT_USER";
    case VNC_HIVE_LOCAL_MACHINE: return "HKEY_LOCAL_MACHINE";
    case VNC_HIVE_USERS:         return "HKEY_USERS";
    default:                     return "?";
    }
}
