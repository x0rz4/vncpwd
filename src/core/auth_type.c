#include "auth_type.h"
#include "util.h"

#include <string.h>

typedef struct {
    vnc_auth_type type;
    const char   *name;
    const char   *desc;
    int           recoverable;
    vnc_risk      risk;
} auth_meta;

static const auth_meta auth_table[] = {
    { VNC_AUTH_UNKNOWN, "unknown", "authentication type could not be determined",
      0, VNC_RISK_MEDIUM },
    { VNC_AUTH_NONE, "none", "no authentication required (security type 1)",
      0, VNC_RISK_CRITICAL },
    { VNC_AUTH_VNC_PASSWORD, "vnc-password",
      "classic VNC DES challenge, fixed public key, 8 character maximum",
      1, VNC_RISK_HIGH },
    { VNC_AUTH_VENCRYPT, "vencrypt",
      "VeNCrypt TLS negotiation, subtype not recorded",
      0, VNC_RISK_LOW },
    { VNC_AUTH_TLSVNC, "tlsvnc",
      "VeNCrypt TLSVnc: TLS transport with VncAuth credentials inside",
      1, VNC_RISK_MEDIUM },
    { VNC_AUTH_X509VNC, "x509vnc",
      "VeNCrypt X509Vnc: mutual TLS with VncAuth credentials inside",
      1, VNC_RISK_LOW },
    { VNC_AUTH_RA2, "ra2",
      "TigerVNC RSA-AES (RA2), password never leaves the client in recoverable form",
      0, VNC_RISK_LOW },
    { VNC_AUTH_RA2_256, "ra2-256",
      "TigerVNC RSA-AES-256 (RA2_256)",
      0, VNC_RISK_LOW },
    { VNC_AUTH_MSLOGON, "mslogon",
      "UltraVNC MS-Logon against Windows accounts, optionally with a DSM plugin",
      0, VNC_RISK_LOW },
    { VNC_AUTH_WINDOWS, "windows",
      "Windows account authentication (LogonUser), no VNC password stored",
      0, VNC_RISK_LOW },
    { VNC_AUTH_PAM, "pam", "PAM authentication (x11vnc / libvncserver)",
      0, VNC_RISK_LOW },
    { VNC_AUTH_KERBEROS, "kerberos", "Kerberos / GSSAPI authentication",
      0, VNC_RISK_LOW },
    { VNC_AUTH_SSO, "sso", "RealVNC Connect cloud identity / SSO",
      0, VNC_RISK_INFO },
};

const char *vnc_auth_name(vnc_auth_type type) {
    size_t i;
    for (i = 0; i < VNC_ARRAY_LEN(auth_table); i++) {
        if (auth_table[i].type == type) return auth_table[i].name;
    }
    return "unknown";
}

const char *vnc_auth_description(vnc_auth_type type) {
    size_t i;
    for (i = 0; i < VNC_ARRAY_LEN(auth_table); i++) {
        if (auth_table[i].type == type) return auth_table[i].desc;
    }
    return "unknown";
}

vnc_auth_type vnc_auth_from_name(const char *name) {
    size_t i;
    if (!name) return VNC_AUTH_UNKNOWN;
    for (i = 0; i < VNC_ARRAY_LEN(auth_table); i++) {
        if (vnc_str_ieq(name, auth_table[i].name)) return auth_table[i].type;
    }
    return VNC_AUTH_UNKNOWN;
}

int vnc_auth_locally_recoverable(vnc_auth_type type) {
    size_t i;
    for (i = 0; i < VNC_ARRAY_LEN(auth_table); i++) {
        if (auth_table[i].type == type) return auth_table[i].recoverable;
    }
    return 0;
}

vnc_risk vnc_auth_baseline_risk(vnc_auth_type type) {
    size_t i;
    for (i = 0; i < VNC_ARRAY_LEN(auth_table); i++) {
        if (auth_table[i].type == type) return auth_table[i].risk;
    }
    return VNC_RISK_MEDIUM;
}

const char *vnc_risk_name(vnc_risk risk) {
    switch (risk) {
    case VNC_RISK_INFO:     return "info";
    case VNC_RISK_LOW:      return "low";
    case VNC_RISK_MEDIUM:   return "medium";
    case VNC_RISK_HIGH:     return "high";
    case VNC_RISK_CRITICAL: return "critical";
    default:                return "unknown";
    }
}
