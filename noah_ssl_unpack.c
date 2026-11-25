#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>

/* 256-byte lookup table from libprecise.so .rodata @ 0x7da4 */
static const uint8_t TQ_TABLE[256] = {
    0x9c,0x6c,0xcf,0x32,0xe4,0xfc,0xef,0x75,0x3a,0x0f,0x4e,0x09,0xae,0x4f,0x54,0xf7,
    0x9f,0x04,0x7d,0x82,0x5a,0xea,0x25,0xe6,0xde,0x23,0x1e,0x2e,0x2d,0x61,0xbf,0x34,
    0x45,0xb5,0xc0,0x7b,0x62,0x15,0x26,0x51,0x66,0x00,0x0e,0xcc,0xb2,0xc5,0xe3,0x5c,
    0x72,0x31,0x0a,0xe5,0xf4,0x5e,0xc2,0x36,0x6a,0x9d,0xd9,0x56,0xa4,0xe8,0x83,0xcb,
    0x0d,0x55,0x14,0xa5,0x88,0x18,0xe7,0x6f,0xdd,0x8c,0x12,0x91,0x74,0x94,0xd2,0x6d,
    0xeb,0x43,0xc6,0xd5,0xe9,0xce,0x53,0xda,0xb7,0xa0,0x48,0x4c,0x2c,0x2a,0x73,0x87,
    0x35,0x63,0xfd,0x3e,0x68,0x7c,0x71,0x2b,0x7a,0x0c,0x22,0x78,0x01,0x52,0x6e,0xed,
    0xf2,0xc9,0xa7,0xbe,0xf3,0xc4,0x9e,0x44,0x90,0x5d,0xb9,0x1c,0x10,0x79,0x6b,0x8e,
    0x40,0xf0,0xc8,0x98,0x86,0x50,0xe2,0xfa,0x59,0x3f,0x80,0x99,0xbc,0x3d,0x1f,0x46,
    0x77,0xba,0x42,0x93,0xaf,0xf9,0x27,0xd7,0xf6,0x19,0xac,0x5b,0x38,0x97,0x41,0x96,
    0xd3,0xdb,0x1d,0x8a,0xca,0x05,0x85,0x17,0x57,0x84,0x24,0xa6,0x16,0xec,0xb1,0x47,
    0xc3,0xaa,0xf8,0xe0,0xb6,0xfe,0x08,0xd1,0xff,0x89,0x1b,0x95,0x7f,0x21,0x03,0x1a,
    0x4d,0x60,0x29,0x65,0xf5,0xfb,0x69,0x49,0xad,0xab,0x5f,0xd4,0xdc,0x4b,0xd8,0x9b,
    0xd6,0x92,0x3c,0xc1,0x30,0xa3,0xe1,0xb0,0x33,0x67,0x8d,0xee,0xbb,0xa2,0xa9,0x0b,
    0x8f,0x28,0xc7,0x81,0x2f,0x4a,0x07,0x8b,0xb8,0x06,0xcd,0x9a,0x58,0xf1,0x76,0x13,
    0x02,0xa8,0x20,0x3b,0x39,0xa1,0xd0,0x7e,0x11,0xb4,0x70,0x37,0xbd,0x64,0xb3,0xdf
};

static uint32_t g_crc32_tab[256];
static uint16_t g_crc16_tab[256];

static void init_crc_tables(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c32 = i;
        for (int k = 0; k < 8; k++) {
            c32 = (c32 & 1) ? ((c32 >> 1) ^ 0xEDB88320u) : (c32 >> 1);
        }
        g_crc32_tab[i] = c32;

        uint16_t c16 = (uint16_t)(i << 8);
        for (int k = 0; k < 8; k++) {
            c16 = (c16 & 0x8000u) ? (uint16_t)((c16 << 1) ^ 0x1021u) : (uint16_t)(c16 << 1);
        }
        g_crc16_tab[i] = c16;
    }
}

static uint32_t calc_crc32(const uint8_t *buf, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c = g_crc32_tab[(c ^ buf[i]) & 0xFFu] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

static uint16_t calc_crc16_ccitt(const uint8_t *buf, size_t len) {
    uint16_t c = 0;
    for (size_t i = 0; i < len; i++) {
        c = (uint16_t)(g_crc16_tab[((c >> 8) ^ buf[i]) & 0xFFu] ^ (c << 8));
    }
    return c;
}

static uint16_t rd_u16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void mkdirs_w(const wchar_t *path) {
    wchar_t tmp[MAX_PATH * 4];
    size_t len = wcslen(path);
    if (len == 0 || len >= sizeof(tmp) / sizeof(tmp[0])) return;
    wcscpy(tmp, path);
    for (size_t i = 0; i < len; i++) {
        if (tmp[i] == L'/' || tmp[i] == L'\\') {
            if (i == 0 || (i == 2 && tmp[1] == L':')) continue;
            if (i > 0 && tmp[i - 1] == L'\\') continue;
            wchar_t ch = tmp[i];
            tmp[i] = L'\0';
            CreateDirectoryW(tmp, NULL);
            tmp[i] = ch;
        }
    }
    CreateDirectoryW(tmp, NULL);
}

static void ensure_parent_dir_w(const wchar_t *file_path) {
    wchar_t tmp[MAX_PATH * 4];
    wcsncpy(tmp, file_path, sizeof(tmp) / sizeof(tmp[0]) - 1);
    tmp[sizeof(tmp) / sizeof(tmp[0]) - 1] = L'\0';
    wchar_t *slash = wcsrchr(tmp, L'\\');
    wchar_t *fslash = wcsrchr(tmp, L'/');
    if (fslash && (!slash || fslash > slash)) slash = fslash;
    if (slash) {
        *slash = L'\0';
        mkdirs_w(tmp);
    }
}

static char *mb_to_utf8(const char *src, int src_len, UINT cp, int *out_len) {
    int wlen = MultiByteToWideChar(cp, 0, src, src_len, NULL, 0);
    if (wlen <= 0 && cp != 936) {
        cp = 936;
        wlen = MultiByteToWideChar(cp, 0, src, src_len, NULL, 0);
    }
    if (wlen <= 0) {
        char *empty = (char *)malloc(1);
        empty[0] = '\0';
        if (out_len) *out_len = 0;
        return empty;
    }
    wchar_t *wbuf = (wchar_t *)malloc((size_t)(wlen + 1) * sizeof(wchar_t));
    MultiByteToWideChar(cp, 0, src, src_len, wbuf, wlen);
    wbuf[wlen] = L'\0';

    int ulen = WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, NULL, 0, NULL, NULL);
    char *ubuf = (char *)malloc((size_t)(ulen + 1));
    WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, ubuf, ulen, NULL, NULL);
    ubuf[ulen] = '\0';
    free(wbuf);
    if (out_len) *out_len = ulen;
    return ubuf;
}

static wchar_t *utf8_to_wide(const char *src) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
    if (wlen <= 0) {
        wchar_t *e = (wchar_t *)malloc(sizeof(wchar_t));
        e[0] = L'\0';
        return e;
    }
    wchar_t *wbuf = (wchar_t *)malloc((size_t)wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, src, -1, wbuf, wlen);
    return wbuf;
}

static uint8_t *read_entire_file_w(const wchar_t *path, size_t *out_size) {
    FILE *fp = _wfopen(path, L"rb");
    if (!fp) return NULL;
    _fseeki64(fp, 0, SEEK_END);
    int64_t sz = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_SET);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = 0;
    *out_size = got;
    return buf;
}

static int write_entire_file_w(const wchar_t *path, const uint8_t *data, size_t len) {
    ensure_parent_dir_w(path);
    FILE *fp = _wfopen(path, L"wb");
    if (!fp) return -1;
    size_t written = (len > 0) ? fwrite(data, 1, len, fp) : 0;
    fclose(fp);
    return (written == len) ? 0 : -1;
}

static int extract_raw_zip(const wchar_t *ssl_path, const wchar_t *raw_dir, int *out_files, int *out_crc_ok) {
    FILE *fp = _wfopen(ssl_path, L"rb");
    if (!fp) {
        fwprintf(stderr, L"[ERR] Cannot open SSL file: %ls\n", ssl_path);
        return -1;
    }
    _fseeki64(fp, 0, SEEK_END);
    int64_t total_len = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_SET);

    mkdirs_w(raw_dir);
    int file_count = 0;
    int crc_ok = 0;
    int crc_fail = 0;

    while (_ftelli64(fp) + 30 <= total_len) {
        uint8_t sig[4];
        if (fread(sig, 1, 4, fp) != 4) break;
        if (sig[0] == 'P' && sig[1] == 'K' && sig[2] == 1 && sig[3] == 2) {
            break;
        }
        if (!(sig[0] == 'P' && sig[1] == 'K' && sig[2] == 3 && sig[3] == 4)) {
            fwprintf(stderr, L"[ERR] Unexpected ZIP signature at offset 0x%llx\n", (unsigned long long)(_ftelli64(fp) - 4));
            fclose(fp);
            return -1;
        }

        uint8_t hdr[26];
        if (fread(hdr, 1, 26, fp) != 26) {
            fclose(fp);
            return -1;
        }
        uint16_t method = rd_u16(hdr + 4);
        uint32_t crc = rd_u32(hdr + 10);
        uint32_t csz = rd_u32(hdr + 14);
        uint16_t nlen = rd_u16(hdr + 22);
        uint16_t elen = rd_u16(hdr + 24);

        char *name_gbk = (char *)malloc((size_t)nlen + 1);
        if (fread(name_gbk, 1, nlen, fp) != nlen) {
            free(name_gbk);
            fclose(fp);
            return -1;
        }
        name_gbk[nlen] = '\0';
        if (elen > 0) {
            _fseeki64(fp, elen, SEEK_CUR);
        }
        if (method != 0) {
            fprintf(stderr, "[ERR] Unsupported compression method %u for %s\n", method, name_gbk);
            free(name_gbk);
            fclose(fp);
            return -1;
        }

        char *name_utf8 = mb_to_utf8(name_gbk, nlen, 936, NULL);
        free(name_gbk);
        for (char *p = name_utf8; *p; p++) {
            if (*p == '/') *p = '\\';
        }
        wchar_t *wname = utf8_to_wide(name_utf8);
        size_t wlen = wcslen(wname);
        int is_dir = (wlen > 0 && wname[wlen - 1] == L'\\');

        wchar_t out_path[MAX_PATH * 4];
        _snwprintf(out_path, sizeof(out_path) / sizeof(out_path[0]), L"%ls\\%ls", raw_dir, wname);
        free(wname);
        free(name_utf8);

        if (is_dir) {
            mkdirs_w(out_path);
            if (csz > 0) _fseeki64(fp, csz, SEEK_CUR);
        } else {
            uint8_t *payload = (uint8_t *)malloc(csz > 0 ? csz : 1);
            if (csz > 0 && fread(payload, 1, csz, fp) != csz) {
                free(payload);
                fclose(fp);
                return -1;
            }
            uint32_t calc = calc_crc32(payload, csz);
            if (calc != crc) {
                crc_fail++;
                fwprintf(stderr, L"[WARN] CRC32 mismatch for %ls (expected 0x%08x, got 0x%08x)\n", out_path, crc, calc);
            } else {
                crc_ok++;
            }
            if (write_entire_file_w(out_path, payload, csz) != 0) {
                free(payload);
                fclose(fp);
                return -1;
            }
            free(payload);
            file_count++;
        }
    }

    fclose(fp);
    if (crc_fail > 0) return -1;
    *out_files = file_count;
    *out_crc_ok = crc_ok;
    return 0;
}

static int decrypt_one_tq(uint8_t *buf, size_t n, uint32_t offset) {
    uint8_t k0 = (uint8_t)(((offset >> 24) ^ (offset >> 16) ^ (offset >> 8) ^ offset) & 0xFFu);
    size_t s2 = offset & 0xFFu;
    if (s2 < 24) s2 = 24;
    if (n < s2) s2 = n & 0xFFu;

    for (size_t i = 0; i < s2; i++) {
        buf[i] ^= k0;
    }

    if (n < 10 || buf[7] != '"') return -1;
    size_t end_q = 8;
    while (end_q < n && buf[end_q] != '"') end_q++;
    if (end_q >= n) return -1;

    uint16_t crc = calc_crc16_ccitt(buf + 8, end_q - 8);
    uint8_t crc0 = (uint8_t)((crc >> 8) & 0xFFu);
    uint8_t crc1 = (uint8_t)(crc & 0xFFu);

    if (s2 < n) {
        size_t rem = n - s2;
        size_t klen = rem < 8 ? rem : 8;
        uint8_t key[8] = {0};
        if (klen >= 1) key[0] = crc0 ^ crc1;
        if (klen >= 2) key[1] = (uint8_t)((buf[s2] + 0x80) & 0xFFu);
        if (klen >= 3) key[2] = (uint8_t)((buf[s2 + 1] + 0x70) & 0xFFu);
        if (klen >= 4) key[3] = TQ_TABLE[(2u * key[1] + key[2]) & 0xFFu];
        if (klen >= 5) key[4] = (uint8_t)((buf[s2 + 3] + 0x60) & 0xFFu);
        if (klen >= 6) key[5] = (uint8_t)((buf[s2 + 4] + 0x50) & 0xFFu);
        if (klen >= 7) key[6] = key[3] ^ buf[s2 + 5];
        if (klen >= 8) key[7] = key[0] ^ buf[s2 + 6];
        for (size_t i = s2; i < n; i++) {
            buf[i] ^= key[(i - s2) & 7u];
        }
    }
    return 0;
}

typedef struct {
    char *oid;
    char *qid;
    char *kpid;
    char *title;
    char *author;
    char *category;
    char *body;
    char *raw_xml;
} PoemRec;

typedef struct CatBucket {
    char *category;
    int *indices;
    size_t count;
    size_t cap;
    struct CatBucket *next;
} CatBucket;

static uint32_t hash_str(const char *s) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

static char *dup_range(const char *start, size_t len) {
    char *s = (char *)malloc(len + 1);
    memcpy(s, start, len);
    s[len] = '\0';
    return s;
}

static void trim_inplace(char *s) {
    size_t len = strlen(s);
    size_t a = 0;
    while (a < len && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    size_t b = len;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    if (a > 0) memmove(s, s + a, b - a);
    s[b - a] = '\0';
}

static char *extract_attr(const char *xml, const char *tag_prefix, const char *attr_key) {
    const char *t = strstr(xml, tag_prefix);
    if (!t) return dup_range("", 0);
    const char *gt = strchr(t, '>');
    const char *k = strstr(t, attr_key);
    if (!k || (gt && k > gt)) return dup_range("", 0);
    k += strlen(attr_key);
    const char *end = strchr(k, '"');
    if (!end || (gt && end > gt)) return dup_range("", 0);
    return dup_range(k, (size_t)(end - k));
}

static char *extract_cdata_tag(const char *xml, const char *open_prefix, const char *close_tag) {
    const char *t = strstr(xml, open_prefix);
    if (!t) return dup_range("", 0);
    const char *cd = strstr(t, "<![CDATA[");
    if (!cd) return dup_range("", 0);
    cd += 9;
    const char *end = strstr(cd, "]]>");
    if (!end) return dup_range("", 0);
    (void)close_tag;
    return dup_range(cd, (size_t)(end - cd));
}

static char *replace_br_and_trim(const char *raw_body) {
    size_t len = strlen(raw_body);
    char *out = (char *)malloc(len + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; ) {
        if (raw_body[i] == '<' && (raw_body[i + 1] == 'b' || raw_body[i + 1] == 'B') &&
            (raw_body[i + 2] == 'r' || raw_body[i + 2] == 'R')) {
            size_t k = i + 3;
            while (k < len && (raw_body[k] == ' ' || raw_body[k] == '/')) k++;
            if (k < len && raw_body[k] == '>') {
                out[j++] = '\n';
                i = k + 1;
                continue;
            }
        }
        out[j++] = raw_body[i++];
    }
    out[j] = '\0';
    size_t a = 0;
    while (a < j && (out[a] == '\r' || out[a] == '\n')) a++;
    size_t b = j;
    while (b > a && (out[b - 1] == '\r' || out[b - 1] == '\n')) b--;
    if (a > 0) memmove(out, out + a, b - a);
    out[b - a] = '\0';
    return out;
}

static void write_json_str(FILE *fp, const char *s) {
    fputc('"', fp);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"': fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\b': fputs("\\b", fp); break;
            case '\f': fputs("\\f", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if (c < 0x20) {
                    fprintf(fp, "\\u%04x", c);
                } else {
                    fputc(c, fp);
                }
        }
    }
    fputc('"', fp);
}

static void write_tsv_field(FILE *fp, const char *s) {
    for (const char *p = s; *p; p++) {
        if (*p == '\t' || *p == '\n' || *p == '\r') {
            fputc(' ', fp);
        } else {
            fputc(*p, fp);
        }
    }
}

static void build_category_path_w(const wchar_t *cat_root, const char *category_utf8, wchar_t *out_path, size_t max_chars) {
    char *copy = dup_range(category_utf8, strlen(category_utf8));
    for (char *p = copy; *p; p++) {
        if (*p == '/') *p = '\\';
    }
    char clean[4096];
    size_t ci = 0;
    char *seg_start = copy;
    int seg_count = 0;

    while (*seg_start) {
        while (*seg_start == '\\') seg_start++;
        if (!*seg_start) break;
        char *sep = strchr(seg_start, '\\');
        size_t slen = sep ? (size_t)(sep - seg_start) : strlen(seg_start);

        char seg[512];
        if (slen >= sizeof(seg)) slen = sizeof(seg) - 1;
        memcpy(seg, seg_start, slen);
        seg[slen] = '\0';
        for (size_t i = 0; i < slen; i++) {
            char c = seg[i];
            if (c == '<' || c == '>' || c == ':' || c == '"' || c == '|' || c == '?' || c == '*') {
                seg[i] = '_';
            }
        }
        size_t a = 0;
        while (a < slen && (seg[a] == ' ' || seg[a] == '.')) a++;
        size_t b = slen;
        while (b > a && (seg[b - 1] == ' ' || seg[b - 1] == '.')) b--;

        const char *use_seg = (b > a) ? (seg + a) : "_";
        size_t use_len = (b > a) ? (b - a) : 1;
        if (ci + use_len + 8 < sizeof(clean)) {
            if (seg_count > 0) clean[ci++] = '\\';
            memcpy(clean + ci, use_seg, use_len);
            ci += use_len;
            seg_count++;
        }
        if (!sep) break;
        seg_start = sep + 1;
    }
    free(copy);

    if (seg_count == 0) {
        strcpy(clean, "\xE6\x9C\xAA\xE5\x88\x86\xE7\xB1\xBB.txt"); /* 未分类.txt */
    } else {
        memcpy(clean + ci, ".txt", 5);
    }

    wchar_t *wrel = utf8_to_wide(clean);
    _snwprintf(out_path, max_chars, L"%ls\\%ls", cat_root, wrel);
    free(wrel);
}

static int decode_and_export(const wchar_t *raw_dir, const wchar_t *decoded_dir) {
    mkdirs_w(decoded_dir);

    /* Convert info.cfg (GBK -> UTF-8) */
    wchar_t info_in[MAX_PATH * 4], info_out[MAX_PATH * 4];
    _snwprintf(info_in, sizeof(info_in) / sizeof(info_in[0]), L"%ls\\info.cfg", raw_dir);
    _snwprintf(info_out, sizeof(info_out) / sizeof(info_out[0]), L"%ls\\info_utf8.cfg", decoded_dir);
    size_t info_sz = 0;
    uint8_t *info_buf = read_entire_file_w(info_in, &info_sz);
    if (info_buf) {
        int ulen = 0;
        char *u8 = mb_to_utf8((const char *)info_buf, (int)info_sz, 936, &ulen);
        write_entire_file_w(info_out, (const uint8_t *)u8, (size_t)ulen);
        free(u8);
        free(info_buf);
    }

    /* Copy title.gif -> title.png if valid PNG */
    wchar_t title_in[MAX_PATH * 4], title_out[MAX_PATH * 4];
    _snwprintf(title_in, sizeof(title_in) / sizeof(title_in[0]), L"%ls\\title.gif", raw_dir);
    _snwprintf(title_out, sizeof(title_out) / sizeof(title_out[0]), L"%ls\\title.png", decoded_dir);
    size_t title_sz = 0;
    uint8_t *title_buf = read_entire_file_w(title_in, &title_sz);
    if (title_buf) {
        static const uint8_t PNG_MAGIC[8] = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};
        if (title_sz >= 8 && memcmp(title_buf, PNG_MAGIC, 8) == 0) {
            write_entire_file_w(title_out, title_buf, title_sz);
        }
        free(title_buf);
    }

    /* Check topic.math/data */
    wchar_t data_path[MAX_PATH * 4];
    _snwprintf(data_path, sizeof(data_path) / sizeof(data_path[0]), L"%ls\\topic.math\\data", raw_dir);
    size_t total_len = 0;
    uint8_t *data = read_entire_file_w(data_path, &total_len);
    if (!data) {
        wprintf(L"[INFO] No topic.math\\data found; raw files extracted only.\n");
        return 0;
    }
    if (total_len < 20 || memcmp(data, "SYBTSOFTWARE", 12) != 0) {
        fprintf(stderr, "[ERR] topic.math/data does not start with SYBTSOFTWARE\n");
        free(data);
        return -1;
    }

    wchar_t jsonl_path[MAX_PATH * 4], tsv_path[MAX_PATH * 4], txt_path[MAX_PATH * 4], cat_root[MAX_PATH * 4];
    _snwprintf(jsonl_path, sizeof(jsonl_path) / sizeof(jsonl_path[0]), L"%ls\\poems.jsonl", decoded_dir);
    _snwprintf(tsv_path, sizeof(tsv_path) / sizeof(tsv_path[0]), L"%ls\\index.tsv", decoded_dir);
    _snwprintf(txt_path, sizeof(txt_path) / sizeof(txt_path[0]), L"%ls\\poems.txt", decoded_dir);
    _snwprintf(cat_root, sizeof(cat_root) / sizeof(cat_root[0]), L"%ls\\poems_by_category", decoded_dir);
    mkdirs_w(cat_root);

    FILE *f_jsonl = _wfopen(jsonl_path, L"wb");
    FILE *f_tsv = _wfopen(tsv_path, L"wb");
    FILE *f_txt = _wfopen(txt_path, L"wb");
    if (!f_jsonl || !f_tsv || !f_txt) {
        if (f_jsonl) fclose(f_jsonl);
        if (f_tsv) fclose(f_tsv);
        if (f_txt) fclose(f_txt);
        free(data);
        return -1;
    }

    setvbuf(f_jsonl, NULL, _IOFBF, 1 << 20);
    setvbuf(f_tsv, NULL, _IOFBF, 1 << 20);
    setvbuf(f_txt, NULL, _IOFBF, 1 << 20);

    fputs("oid\tqid\tkpid\ttitle\tauthor\tcategory\n", f_tsv);

    size_t rec_cap = 4096;
    size_t rec_count = 0;
    PoemRec *recs = (PoemRec *)malloc(rec_cap * sizeof(PoemRec));

    const size_t HT_SIZE = 8192;
    CatBucket **ht = (CatBucket **)calloc(HT_SIZE, sizeof(CatBucket *));
    int cat_files = 0;

    size_t pos = 0x14;
    int bad = 0;
    size_t total_seen = 0;

    while (pos + 10 <= total_len) {
        uint32_t rec_id = rd_u32(data + pos);
        uint32_t rec_len = rd_u32(data + pos + 6);
        size_t payload_off = pos + 10;
        if (payload_off + rec_len > total_len) {
            fprintf(stderr, "[ERR] Truncated record at 0x%zx (id=%u, len=%u)\n", pos, rec_id, rec_len);
            free(data);
            fclose(f_jsonl);
            fclose(f_tsv);
            fclose(f_txt);
            return -1;
        }

        uint8_t *buf = data + payload_off;
        if (decrypt_one_tq(buf, rec_len, (uint32_t)payload_off) != 0 ||
            rec_len < 7 || memcmp(buf, "<q ", 3) != 0 || memcmp(buf + rec_len - 4, "</q>", 4) != 0) {
            bad++;
            if (bad <= 5) {
                fprintf(stderr, "[ERR] Bad decryption at rec %zu id=%u off=0x%zx\n", total_seen + 1, rec_id, payload_off);
            }
        } else {
            char *xml = mb_to_utf8((const char *)buf, (int)rec_len, 54936, NULL);
            PoemRec r;
            r.oid = extract_attr(xml, "<q ", "oid=\"");
            r.qid = extract_attr(xml, "<q ", "qid=\"");
            r.kpid = extract_attr(xml, "<kp ", "kpid=\"");
            r.title = extract_attr(xml, "<kp ", "name=\"");
            r.author = extract_cdata_tag(xml, "<desc", "</desc>");
            trim_inplace(r.author);
            r.category = extract_cdata_tag(xml, "<an", "</an>");
            trim_inplace(r.category);
            char *raw_qb = extract_cdata_tag(xml, "<qb", "</qb>");
            r.body = replace_br_and_trim(raw_qb);
            free(raw_qb);
            r.raw_xml = xml;

            /* Write JSONL */
            fputs("{\"oid\":", f_jsonl); write_json_str(f_jsonl, r.oid);
            fputs(",\"qid\":", f_jsonl); write_json_str(f_jsonl, r.qid);
            fputs(",\"kpid\":", f_jsonl); write_json_str(f_jsonl, r.kpid);
            fputs(",\"title\":", f_jsonl); write_json_str(f_jsonl, r.title);
            fputs(",\"author\":", f_jsonl); write_json_str(f_jsonl, r.author);
            fputs(",\"category\":", f_jsonl); write_json_str(f_jsonl, r.category);
            fputs(",\"body\":", f_jsonl); write_json_str(f_jsonl, r.body);
            fputs(",\"raw_xml\":", f_jsonl); write_json_str(f_jsonl, r.raw_xml);
            fputs("}\n", f_jsonl);

            /* Write TSV */
            write_tsv_field(f_tsv, r.oid); fputc('\t', f_tsv);
            write_tsv_field(f_tsv, r.qid); fputc('\t', f_tsv);
            write_tsv_field(f_tsv, r.kpid); fputc('\t', f_tsv);
            write_tsv_field(f_tsv, r.title); fputc('\t', f_tsv);
            write_tsv_field(f_tsv, r.author); fputc('\t', f_tsv);
            write_tsv_field(f_tsv, r.category); fputc('\n', f_tsv);

            /* Write TXT */
            fprintf(f_txt, "=== [%s] %s ===\n", r.oid, r.title);
            fprintf(f_txt, "\xE4\xBD\x9C\xE8\x80\x85: %s | \xE5\x88\x86\xE7\xB1\xBB: %s | qid: %s | kpid: %s\n",
                    r.author, r.category, r.qid, r.kpid);
            fputs(r.body, f_txt);
            fputs("\n\n", f_txt);

            if (rec_count == rec_cap) {
                rec_cap *= 2;
                recs = (PoemRec *)realloc(recs, rec_cap * sizeof(PoemRec));
            }
            int idx = (int)rec_count;
            recs[rec_count++] = r;

            /* Group into category hash table */
            uint32_t h = hash_str(r.category) & (HT_SIZE - 1);
            CatBucket *b = ht[h];
            while (b && strcmp(b->category, r.category) != 0) b = b->next;
            if (!b) {
                b = (CatBucket *)malloc(sizeof(CatBucket));
                b->category = dup_range(r.category, strlen(r.category));
                b->cap = 16;
                b->count = 0;
                b->indices = (int *)malloc(b->cap * sizeof(int));
                b->next = ht[h];
                ht[h] = b;
                cat_files++;
            }
            if (b->count == b->cap) {
                b->cap *= 2;
                b->indices = (int *)realloc(b->indices, b->cap * sizeof(int));
            }
            b->indices[b->count++] = idx;
        }

        total_seen++;
        pos = payload_off + rec_len + 8;
    }

    fclose(f_jsonl);
    fclose(f_tsv);
    fclose(f_txt);
    free(data);

    if (bad > 0) {
        fprintf(stderr, "[ERR] %d records failed decryption!\n", bad);
        return -1;
    }

    /* Write poems_by_category */
    for (size_t h = 0; h < HT_SIZE; h++) {
        CatBucket *b = ht[h];
        while (b) {
            wchar_t cat_file[MAX_PATH * 4];
            build_category_path_w(cat_root, b->category, cat_file, sizeof(cat_file) / sizeof(cat_file[0]));
            ensure_parent_dir_w(cat_file);
            FILE *fc = _wfopen(cat_file, L"wb");
            if (fc) {
                for (size_t i = 0; i < b->count; i++) {
                    PoemRec *r = &recs[b->indices[i]];
                    fprintf(fc, "=== [%s] %s ===\n", r->oid, r->title);
                    fprintf(fc, "\xE4\xBD\x9C\xE8\x80\x85: %s | qid: %s | kpid: %s\n", r->author, r->qid, r->kpid);
                    fputs(r->body, fc);
                    fputs("\n\n", fc);
                }
                fclose(fc);
            }
            CatBucket *next = b->next;
            free(b->category);
            free(b->indices);
            free(b);
            b = next;
        }
    }
    free(ht);

    for (size_t i = 0; i < rec_count; i++) {
        free(recs[i].oid);
        free(recs[i].qid);
        free(recs[i].kpid);
        free(recs[i].title);
        free(recs[i].author);
        free(recs[i].category);
        free(recs[i].body);
        free(recs[i].raw_xml);
    }
    free(recs);

    printf("Decoded %zu records (bad=%d), exported %d category files.\n", total_seen, bad, cat_files);
    return 0;
}

/* ========== BaiKssl V5.0 (精装百科) support ========== */

typedef struct {
    uint32_t first_code;
    uint16_t sym_offset;
    uint16_t count;
} BaikHuffLevel;

typedef struct {
    const uint8_t *buf;
    size_t len;
    int max_len;
    BaikHuffLevel levels[32];
} BaikHuffTable;

static void decyclopedical_decrypt(uint8_t *buf, size_t len, const uint8_t key[8]) {
    for (size_t off = 0; off + 8 <= len; off += 8) {
        uint8_t orig[8];
        memcpy(orig, buf + off, 8);
        uint8_t b0 = orig[0] ^ key[0];
        uint8_t b2 = orig[2] ^ key[2] ^ orig[0];
        uint8_t b6 = orig[6] ^ key[6] ^ orig[2];
        uint8_t b1 = orig[1] ^ key[1] ^ orig[6];
        uint8_t b5 = orig[5] ^ key[5] ^ b0;
        uint8_t b3 = orig[3] ^ key[4] ^ orig[1] ^ b2;
        uint8_t b4 = orig[4] ^ key[3];
        uint8_t b7 = orig[7] ^ key[7];
        uint8_t out[8] = {b0, b1, b2, b3, b4, b5, b6, b7};
        for (int k = 0; k < 7; k++) {
            if (out[k] != 0) {
                out[7] ^= out[k];
                break;
            }
        }
        memcpy(buf + off, out, 8);
    }
}

static int baik_huff_init(BaikHuffTable *ht, const uint8_t *buf, size_t len) {
    ht->buf = buf;
    ht->len = len;
    uint16_t first_off = 0;
    for (size_t i = 0; i * 6 + 6 <= len; i++) {
        uint16_t off = rd_u16(buf + i * 6 + 4);
        if (off != 0) {
            first_off = off;
            break;
        }
    }
    int max_len = first_off / 6;
    if (max_len <= 0 || max_len > 32) return -1;
    ht->max_len = max_len;
    for (int i = 0; i < max_len; i++) {
        uint32_t fc = rd_u32(buf + i * 6);
        uint16_t off = rd_u16(buf + i * 6 + 4);
        ht->levels[i].first_code = fc;
        ht->levels[i].sym_offset = off;
        if (off == 0) {
            ht->levels[i].count = 0;
        } else {
            uint16_t next_off = (uint16_t)len;
            for (int j = i + 1; j < max_len; j++) {
                uint16_t noff = rd_u16(buf + j * 6 + 4);
                if (noff != 0) {
                    next_off = noff;
                    break;
                }
            }
            ht->levels[i].count = (next_off >= off) ? (uint16_t)(next_off - off) : 0;
        }
    }
    return 0;
}

static int baik_huff_decode_sym(const BaikHuffTable *ht, const uint8_t *data, size_t n_bits, size_t *bit_pos) {
    uint32_t code = 0;
    for (int len = 1; len <= ht->max_len; len++) {
        if (*bit_pos >= n_bits) return -1;
        size_t bp = (*bit_pos)++;
        int b = (data[bp >> 3] >> (7 - (bp & 7))) & 1;
        code = (code << 1) | (uint32_t)b;
        uint16_t cnt = ht->levels[len - 1].count;
        uint32_t fc = ht->levels[len - 1].first_code;
        if (cnt > 0 && code >= fc && code < fc + cnt) {
            return ht->buf[ht->levels[len - 1].sym_offset + (code - fc)];
        }
    }
    return -1;
}

static int baik_huff_decode_article(
    const BaikHuffTable *ht1, const BaikHuffTable *ht2,
    const uint8_t *comp, size_t comp_len,
    uint8_t **io_buf, size_t *io_cap, size_t *out_len
) {
    size_t bp = 0;
    size_t n_bits = comp_len * 8;
    const BaikHuffTable *cur = ht1;
    size_t len = 0;
    while (bp < n_bits) {
        int s = baik_huff_decode_sym(cur, comp, n_bits, &bp);
        if (s < 0) break;
        if (s == 0x02) {
            cur = (cur == ht1) ? ht2 : ht1;
            continue;
        }
        if (s == 0x0A) break;
        if (len + 1 >= *io_cap) {
            *io_cap *= 2;
            *io_buf = (uint8_t *)realloc(*io_buf, *io_cap);
        }
        (*io_buf)[len++] = (uint8_t)s;
    }
    (*io_buf)[len] = '\0';
    *out_len = len;
    return 0;
}

static int unpack_baik_ssl(const wchar_t *ssl_path, const wchar_t *out_dir) {
    FILE *fp = _wfopen(ssl_path, L"rb");
    if (!fp) {
        fwprintf(stderr, L"[ERR] Cannot open SSL file: %ls\n", ssl_path);
        return 1;
    }
    mkdirs_w(out_dir);

    uint8_t hdr[64];
    if (fread(hdr, 1, 64, fp) != 64 || memcmp(hdr, "BaiKssl\0", 8) != 0) {
        fprintf(stderr, "[ERR] Invalid BaiKssl header.\n");
        fclose(fp);
        return 1;
    }

    uint8_t keyA[8];
    for (int i = 0; i < 8; i++) {
        keyA[i] = hdr[4 * i] ^ hdr[4 * i + 1] ^ hdr[4 * i + 2] ^ hdr[4 * i + 3];
    }
    uint16_t hdr_size = rd_u16(hdr + 16);

    char ver[8] = {0}, ts[24] = {0}, raw_title[32] = {0};
    memcpy(ver, hdr + 8, 4);
    memcpy(ts, hdr + 18, 20);
    memcpy(raw_title, hdr + 38, 26);
    char *title_utf8 = mb_to_utf8(raw_title, (int)strlen(raw_title), 936, NULL);

    _fseeki64(fp, hdr_size, SEEK_SET);
    uint8_t sub32[32];
    if (fread(sub32, 1, 32, fp) != 32) {
        free(title_utf8);
        fclose(fp);
        return 1;
    }
    uint32_t idx_off = (uint32_t)hdr_size + rd_u16(sub32 + 1);

    _fseeki64(fp, idx_off, SEEK_SET);
    uint8_t dec96[96];
    if (fread(dec96, 1, 96, fp) != 96) {
        free(title_utf8);
        fclose(fp);
        return 1;
    }

    uint8_t keyB[8] = {0};
    for (int i = 0; i < 4; i++) {
        keyB[i] = dec96[8 * i] ^ dec96[8 * i + 1] ^ dec96[8 * i + 2] ^ dec96[8 * i + 3];
    }
    keyB[4] = dec96[33];
    keyB[5] = dec96[34];
    keyB[6] = dec96[35];
    for (int i = 0; i < 7; i++) keyB[7] ^= keyB[i];

    decyclopedical_decrypt(dec96, 96, keyA);

    uint32_t hfm_off = ((uint32_t)dec96[0] | ((uint32_t)dec96[1] << 8) | ((uint32_t)dec96[2] << 16)) + 64u;
    uint16_t h0 = rd_u16(dec96 + 3);
    uint16_t h1 = rd_u16(dec96 + 8);
    uint16_t h2 = rd_u16(dec96 + 13);
    size_t hfm_size = (size_t)h0 + (h1 != 0xFFFF ? h1 : 0) + (h2 != 0xFFFF ? h2 : 0);

    uint8_t *hfm_buf = (uint8_t *)malloc(hfm_size);
    _fseeki64(fp, hfm_off, SEEK_SET);
    if (fread(hfm_buf, 1, hfm_size, fp) != hfm_size) {
        free(hfm_buf);
        free(title_utf8);
        fclose(fp);
        return 1;
    }
    decyclopedical_decrypt(hfm_buf, hfm_size, keyB);

    BaikHuffTable ht1, ht2;
    if (baik_huff_init(&ht1, hfm_buf, h0) != 0 ||
        baik_huff_init(&ht2, hfm_buf + h0, h1 != 0xFFFF ? h1 : 0) != 0) {
        fprintf(stderr, "[ERR] Failed to initialize BaiKssl Huffman tables.\n");
        free(hfm_buf);
        free(title_utf8);
        fclose(fp);
        return 1;
    }

    uint32_t sec3c = rd_u32(dec96 + 0x3C) + 0x40u;
    uint32_t sec40 = rd_u32(dec96 + 0x40) + 0x40u;
    uint32_t sec44 = rd_u32(dec96 + 0x44) + 0x40u;
    uint32_t sec2d = rd_u32(dec96 + 0x2D) + 0x40u;

    /* 1. Extract help.nwf if present */
    _fseeki64(fp, sec2d, SEEK_SET);
    uint32_t nwf_len = 0;
    if (fread(&nwf_len, 4, 1, fp) == 1 && nwf_len > 16 && nwf_len < 64 * 1024 * 1024) {
        uint8_t *nwf = (uint8_t *)malloc(nwf_len);
        if (fread(nwf, 1, nwf_len, fp) == nwf_len && memcmp(nwf, "NEPLAYERV1.0", 12) == 0) {
            wchar_t nwf_path[MAX_PATH * 4];
            _snwprintf(nwf_path, sizeof(nwf_path) / sizeof(nwf_path[0]), L"%ls\\help.nwf", out_dir);
            write_entire_file_w(nwf_path, nwf, nwf_len);
        }
        free(nwf);
    }

    /* 2. Extract categories.txt */
    _fseeki64(fp, sec3c, SEEK_SET);
    uint32_t cnt3c = 0;
    fread(&cnt3c, 4, 1, fp);
    uint32_t *cat_pairs = (uint32_t *)malloc((size_t)cnt3c * 8);
    fread(cat_pairs, 8, cnt3c, fp);

    wchar_t cat_txt_path[MAX_PATH * 4];
    _snwprintf(cat_txt_path, sizeof(cat_txt_path) / sizeof(cat_txt_path[0]), L"%ls\\categories.txt", out_dir);
    FILE *f_cats = _wfopen(cat_txt_path, L"wb");
    if (f_cats) {
        char cat_buf[1024];
        for (uint32_t i = 0; i < cnt3c; i++) {
            _fseeki64(fp, (int64_t)sec3c + cat_pairs[i * 2], SEEK_SET);
            size_t r = fread(cat_buf, 1, sizeof(cat_buf) - 1, fp);
            cat_buf[r] = '\0';
            int slen = (int)strlen(cat_buf);
            char *u8 = mb_to_utf8(cat_buf, slen, 936, NULL);
            fprintf(f_cats, "%s\n", u8);
            free(u8);
        }
        fclose(f_cats);
    }
    free(cat_pairs);

    /* 3. Extract headwords.txt */
    _fseeki64(fp, sec40, SEEK_SET);
    uint32_t cnt40 = 0;
    fread(&cnt40, 4, 1, fp);
    uint32_t *hw_offs = (uint32_t *)malloc((size_t)cnt40 * 4);
    fread(hw_offs, 4, cnt40, fp);

    wchar_t hw_txt_path[MAX_PATH * 4];
    _snwprintf(hw_txt_path, sizeof(hw_txt_path) / sizeof(hw_txt_path[0]), L"%ls\\headwords.txt", out_dir);
    FILE *f_hw = _wfopen(hw_txt_path, L"wb");
    if (f_hw) {
        setvbuf(f_hw, NULL, _IOFBF, 1 << 20);
        char hw_buf[1024];
        for (uint32_t i = 0; i < cnt40; i++) {
            _fseeki64(fp, (int64_t)sec40 + hw_offs[i], SEEK_SET);
            size_t r = fread(hw_buf, 1, sizeof(hw_buf) - 1, fp);
            hw_buf[r] = '\0';
            int slen = (int)strlen(hw_buf);
            char *u8 = mb_to_utf8(hw_buf, slen, 936, NULL);
            fprintf(f_hw, "%s\n", u8);
            free(u8);
        }
        fclose(f_hw);
    }
    free(hw_offs);

    /* 4. Decode all articles in sec44 */
    _fseeki64(fp, sec44, SEEK_SET);
    uint32_t cnt44 = 0;
    fread(&cnt44, 4, 1, fp);
    uint32_t *art_offs = (uint32_t *)malloc((size_t)cnt44 * 4);
    fread(art_offs, 4, cnt44, fp);

    wchar_t jsonl_path[MAX_PATH * 4], tsv_path[MAX_PATH * 4], txt_path[MAX_PATH * 4], info_path[MAX_PATH * 4];
    _snwprintf(jsonl_path, sizeof(jsonl_path) / sizeof(jsonl_path[0]), L"%ls\\articles.jsonl", out_dir);
    _snwprintf(tsv_path, sizeof(tsv_path) / sizeof(tsv_path[0]), L"%ls\\index.tsv", out_dir);
    _snwprintf(txt_path, sizeof(txt_path) / sizeof(txt_path[0]), L"%ls\\articles.txt", out_dir);
    _snwprintf(info_path, sizeof(info_path) / sizeof(info_path[0]), L"%ls\\info.txt", out_dir);

    FILE *f_info = _wfopen(info_path, L"wb");
    if (f_info) {
        fprintf(f_info, "format=BaiKssl %s\ntitle=%s\ntimestamp=%s\ncategories=%u\nheadwords=%u\narticles=%u\n",
                ver, title_utf8, ts, cnt3c, cnt40, cnt44);
        fclose(f_info);
    }

    FILE *f_jsonl = _wfopen(jsonl_path, L"wb");
    FILE *f_tsv = _wfopen(tsv_path, L"wb");
    FILE *f_txt = _wfopen(txt_path, L"wb");
    if (!f_jsonl || !f_tsv || !f_txt) {
        if (f_jsonl) fclose(f_jsonl);
        if (f_tsv) fclose(f_tsv);
        if (f_txt) fclose(f_txt);
        free(art_offs);
        free(hfm_buf);
        free(title_utf8);
        fclose(fp);
        return 1;
    }
    setvbuf(f_jsonl, NULL, _IOFBF, 1 << 20);
    setvbuf(f_tsv, NULL, _IOFBF, 1 << 20);
    setvbuf(f_txt, NULL, _IOFBF, 1 << 20);
    fputs("id\ttitle\n", f_tsv);

    size_t comp_cap = 65536;
    uint8_t *comp_buf = (uint8_t *)malloc(comp_cap);
    size_t dec_cap = 65536;
    uint8_t *dec_buf = (uint8_t *)malloc(dec_cap);

    uint32_t bad = 0;
    for (uint32_t i = 0; i < cnt44; i++) {
        _fseeki64(fp, (int64_t)sec44 + art_offs[i], SEEK_SET);
        uint32_t plen = 0;
        if (fread(&plen, 4, 1, fp) != 1 || plen == 0 || plen > 16 * 1024 * 1024) {
            bad++;
            continue;
        }
        if (plen > comp_cap) {
            comp_cap = plen;
            comp_buf = (uint8_t *)realloc(comp_buf, comp_cap);
        }
        if (fread(comp_buf, 1, plen, fp) != plen) {
            bad++;
            continue;
        }
        size_t dec_len = 0;
        baik_huff_decode_article(&ht1, &ht2, comp_buf, plen, &dec_buf, &dec_cap, &dec_len);

        char *u8 = mb_to_utf8((const char *)dec_buf, (int)dec_len, 54936, NULL);
        for (char *p = u8; *p; p++) {
            if (*p == '\r') *p = '\n';
        }
        char *nl = strchr(u8, '\n');
        char *art_title = nl ? dup_range(u8, (size_t)(nl - u8)) : dup_range(u8, strlen(u8));
        trim_inplace(art_title);

        fprintf(f_jsonl, "{\"id\":%u,\"title\":", i);
        write_json_str(f_jsonl, art_title);
        fputs(",\"body\":", f_jsonl);
        write_json_str(f_jsonl, u8);
        fputs("}\n", f_jsonl);

        fprintf(f_tsv, "%u\t", i);
        write_tsv_field(f_tsv, art_title);
        fputc('\n', f_tsv);

        fprintf(f_txt, "=== [%u] %s ===\n%s\n\n", i, art_title, u8);

        free(art_title);
        free(u8);
    }

    fclose(f_jsonl);
    fclose(f_tsv);
    fclose(f_txt);
    free(comp_buf);
    free(dec_buf);
    free(art_offs);
    free(hfm_buf);
    free(title_utf8);
    fclose(fp);

    printf("BaiKssl %s decoded: %u categories, %u headwords, %u articles (bad=%u).\n",
           ver, cnt3c, cnt40, cnt44, bad);
    return bad ? 1 : 0;
}

static int process_one_ssl(const wchar_t *ssl_path, const wchar_t *out_dir_arg) {
    wchar_t out_dir[MAX_PATH * 4];
    if (out_dir_arg) {
        wcsncpy(out_dir, out_dir_arg, sizeof(out_dir) / sizeof(out_dir[0]) - 1);
        out_dir[sizeof(out_dir) / sizeof(out_dir[0]) - 1] = L'\0';
    } else {
        wchar_t exe_dir[MAX_PATH * 4];
        DWORD elen = GetModuleFileNameW(NULL, exe_dir, (DWORD)(sizeof(exe_dir) / sizeof(exe_dir[0]) - 1));
        exe_dir[elen] = L'\0';
        wchar_t *esl = wcsrchr(exe_dir, L'\\');
        wchar_t *efsl = wcsrchr(exe_dir, L'/');
        if (efsl && (!esl || efsl > esl)) esl = efsl;
        if (esl) *esl = L'\0';
        else wcscpy(exe_dir, L".");

        const wchar_t *base = ssl_path;
        const wchar_t *sl = wcsrchr(ssl_path, L'\\');
        const wchar_t *fsl = wcsrchr(ssl_path, L'/');
        if (fsl && (!sl || fsl > sl)) sl = fsl;
        if (sl) base = sl + 1;

        wchar_t stem[MAX_PATH * 2];
        wcsncpy(stem, base, sizeof(stem) / sizeof(stem[0]) - 1);
        stem[sizeof(stem) / sizeof(stem[0]) - 1] = L'\0';
        wchar_t *dot = wcsrchr(stem, L'.');
        if (dot) *dot = L'\0';

        _snwprintf(out_dir, sizeof(out_dir) / sizeof(out_dir[0]), L"%ls\\%ls_extracted", exe_dir, stem);
    }

    FILE *fp = _wfopen(ssl_path, L"rb");
    if (!fp) {
        fwprintf(stderr, L"[ERR] Cannot open SSL file: %ls\n", ssl_path);
        return 1;
    }
    uint8_t magic[8] = {0};
    fread(magic, 1, 8, fp);
    fclose(fp);

    if (memcmp(magic, "BaiKssl\0", 8) == 0) {
        if (unpack_baik_ssl(ssl_path, out_dir) != 0) {
            return 1;
        }
        wprintf(L"Output directory: %ls\n", out_dir);
        return 0;
    }

    wchar_t raw_dir[MAX_PATH * 4], decoded_dir[MAX_PATH * 4];
    _snwprintf(raw_dir, sizeof(raw_dir) / sizeof(raw_dir[0]), L"%ls\\raw", out_dir);
    _snwprintf(decoded_dir, sizeof(decoded_dir) / sizeof(decoded_dir[0]), L"%ls\\decoded", out_dir);

    int files = 0, crc_ok = 0;
    if (extract_raw_zip(ssl_path, raw_dir, &files, &crc_ok) != 0) {
        return 1;
    }
    printf("Raw ZIP extraction complete: %d files extracted, %d CRC32 verified.\n", files, crc_ok);

    if (decode_and_export(raw_dir, decoded_dir) != 0) {
        return 1;
    }
    wprintf(L"Output directory: %ls\n", out_dir);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    UINT old_cp = GetConsoleOutputCP();
    SetConsoleOutputCP(CP_UTF8);
    init_crc_tables();

    int rc = 0;
    if (argc >= 2) {
        const wchar_t *out_arg = (argc >= 3) ? argv[2] : NULL;
        rc = process_one_ssl(argv[1], out_arg);
        SetConsoleOutputCP(old_cp);
        return rc;
    }

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(L"*.ssl", &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Usage: noah_ssl_unpack.exe <input.ssl> [output_dir]\n");
        printf("Or drag and drop an .ssl file onto this program / launcher.\n");
        SetConsoleOutputCP(old_cp);
        return 1;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            wprintf(L"Processing: %ls\n", fd.cFileName);
            if (process_one_ssl(fd.cFileName, NULL) != 0) {
                rc = 1;
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    SetConsoleOutputCP(old_cp);
    return rc;
}
