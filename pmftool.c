/*
 * pmftool.c  —  Process Monitor Filter (*.PMF) file utility
 *               Windows-native version (replaces iconv with Windows API)
 *
 * Reverse-engineered from Procmon64.exe via IDA Pro.
 * Key functions analysed:
 *   sub_1400781C0  — ReadFile wrapper (load PMF)
 *   sub_14007A6C0  — WriteFile wrapper (save PMF)
 *   sub_140028BD0  — serialise filter list to binary blob
 *   sub_140028470  — deserialise binary blob to filter list
 *   sub_1400ACBD0  — write one UTF-16LE string field
 *   sub_1400ACA80  — read  one UTF-16LE string field
 *
 * ═══════════════════════════════════════════════════════════════════════
 * PMF binary layout (little-endian throughout):
 *
 *  File level
 *  ──────────
 *  [u32]  content_size     total byte count of everything that follows
 *
 *  Content blob  (content_size bytes)
 *  ────────────
 *  [u8]   version          always 0x01
 *  [u32]  count            number of filter entries
 *
 *  Per-entry  (repeated 'count' times)
 *  ─────────
 *  [u32]  column           (0x9C00 | column_low_byte)
 *  [u32]  relation         0–7  (see pmf_rel_t)
 *  [u8]   action           0=exclude  1=include
 *  [u32]  str_bytes        byte length of UTF-16LE value string
 *                          (includes null terminator; 0 means empty)
 *  [*]    UTF-16LE value   str_bytes bytes
 *  [u64]  reserved         8 zero bytes (runtime pointer in Procmon)
 *
 * ═══════════════════════════════════════════════════════════════════════
 * Text format (stdin / stdout):
 *
 *   PMF_COLUMN_xxx  PMF_RELATION_xxx  PMF_ACTION_xxx  <filter value>
 *
 * Usage:
 *   pmftool -r input.pmf  > output.txt    # dump PMF filters to text
 *   pmftool -w output.pmf < input.txt     # build  PMF from text
 *
 * Compile (MSVC x64) : cl /W3 /nologo pmftool.c
 * Compile (MinGW-w64): gcc -Wall -Wextra -o pmftool pmftool.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ── Column low-byte identifiers ────────────────────────────────────── */

/* The column DWORD stored in the file = (0x9C << 8) | column_low_byte  */
#define PMF_COL_HIGH    ((uint32_t)0x9Cu)
#define PMF_COL(x)      ((uint32_t)((PMF_COL_HIGH << 8) | (uint8_t)(x)))

typedef enum {
    COL_DATE_TIME          = 0x74,
    COL_PROCESS_NAME       = 0x75,
    COL_PID                = 0x76,
    COL_OPERATION          = 0x77,
    COL_RESULT             = 0x78,
    COL_DETAIL             = 0x79,
    COL_SEQUENCE           = 0x7A,
    COL_COMPANY            = 0x80,
    COL_DESCRIPTION        = 0x81,
    COL_COMMAND_LINE       = 0x82,
    COL_USER               = 0x83,
    COL_IMAGE_PATH         = 0x84,
    COL_SESSION            = 0x85,
    COL_PATH               = 0x87,
    COL_TID                = 0x88,
    COL_RELATIVE_TIME      = 0x8C,
    COL_DURATION           = 0x8D,
    COL_TIME_OF_DAY        = 0x8E,
    COL_VERSION            = 0x91,
    COL_EVENT_CLASS        = 0x92,
    COL_AUTHENTICATION_ID  = 0x93,
    COL_VIRTUALIZED        = 0x94,
    COL_INTEGRITY          = 0x95,
    COL_CATEGORY           = 0x96,
    COL_PARENT_PID         = 0x97,
    COL_ARCHITECTURE       = 0x98,
} pmf_col_t;

typedef enum {
    REL_IS           = 0,
    REL_IS_NOT       = 1,
    REL_LESS_THAN    = 2,
    REL_MORE_THAN    = 3,
    REL_BEGINS_WITH  = 4,
    REL_ENDS_WITH    = 5,
    REL_CONTAINS     = 6,
    REL_EXCLUDES     = 7,
} pmf_rel_t;

typedef enum {
    ACT_EXCLUDE = 0,
    ACT_INCLUDE = 1,
} pmf_act_t;

/* ── Name tables ────────────────────────────────────────────────────── */

static const struct { uint32_t id; const char *name; } COL_TABLE[] = {
    { COL_DATE_TIME,         "PMF_COLUMN_DATE_TIME"         },
    { COL_PROCESS_NAME,      "PMF_COLUMN_PROCESS_NAME"      },
    { COL_PID,               "PMF_COLUMN_PID"               },
    { COL_OPERATION,         "PMF_COLUMN_OPERATION"         },
    { COL_RESULT,            "PMF_COLUMN_RESULT"            },
    { COL_DETAIL,            "PMF_COLUMN_DETAIL"            },
    { COL_SEQUENCE,          "PMF_COLUMN_SEQUENCE"          },
    { COL_COMPANY,           "PMF_COLUMN_COMPANY"           },
    { COL_DESCRIPTION,       "PMF_COLUMN_DESCRIPTION"       },
    { COL_COMMAND_LINE,      "PMF_COLUMN_COMMAND_LINE"      },
    { COL_USER,              "PMF_COLUMN_USER"              },
    { COL_IMAGE_PATH,        "PMF_COLUMN_IMAGE_PATH"        },
    { COL_SESSION,           "PMF_COLUMN_SESSION"           },
    { COL_PATH,              "PMF_COLUMN_PATH"              },
    { COL_TID,               "PMF_COLUMN_TID"               },
    { COL_RELATIVE_TIME,     "PMF_COLUMN_RELATIVE_TIME"     },
    { COL_DURATION,          "PMF_COLUMN_DURATION"          },
    { COL_TIME_OF_DAY,       "PMF_COLUMN_TIME_OF_DAY"       },
    { COL_VERSION,           "PMF_COLUMN_VERSION"           },
    { COL_EVENT_CLASS,       "PMF_COLUMN_EVENT_CLASS"       },
    { COL_AUTHENTICATION_ID, "PMF_COLUMN_AUTHENTICATION_ID" },
    { COL_VIRTUALIZED,       "PMF_COLUMN_VIRTUALIZED"       },
    { COL_INTEGRITY,         "PMF_COLUMN_INTEGRITY"         },
    { COL_CATEGORY,          "PMF_COLUMN_CATEGORY"          },
    { COL_PARENT_PID,        "PMF_COLUMN_PARENT_PID"        },
    { COL_ARCHITECTURE,      "PMF_COLUMN_ARCHITECTURE"      },
    { 0, NULL }
};

static const struct { uint32_t id; const char *name; } REL_TABLE[] = {
    { REL_IS,          "PMF_RELATION_IS"          },
    { REL_IS_NOT,      "PMF_RELATION_IS_NOT"      },
    { REL_LESS_THAN,   "PMF_RELATION_LESS_THAN"   },
    { REL_MORE_THAN,   "PMF_RELATION_MORE_THAN"   },
    { REL_BEGINS_WITH, "PMF_RELATION_BEGINS_WITH" },
    { REL_ENDS_WITH,   "PMF_RELATION_ENDS_WITH"   },
    { REL_CONTAINS,    "PMF_RELATION_CONTAINS"    },
    { REL_EXCLUDES,    "PMF_RELATION_EXCLUDES"    },
    { 0xFFFFFFFFu, NULL }
};

static const struct { uint32_t id; const char *name; } ACT_TABLE[] = {
    { ACT_EXCLUDE, "PMF_ACTION_EXCLUDE" },
    { ACT_INCLUDE, "PMF_ACTION_INCLUDE" },
    { 0xFFFFFFFFu, NULL }
};

/* ── Name ↔ value helpers ───────────────────────────────────────────── */

static const char *col_name(uint32_t col_dword)
{
    uint32_t low = col_dword & 0xFFu;
    for (int i = 0; COL_TABLE[i].name; i++)
        if (COL_TABLE[i].id == low) return COL_TABLE[i].name;
    return "PMF_COLUMN_UNKNOWN";
}

static const char *rel_name(uint32_t r)
{
    for (int i = 0; REL_TABLE[i].name; i++)
        if (REL_TABLE[i].id == r) return REL_TABLE[i].name;
    return "PMF_RELATION_UNKNOWN";
}

static const char *act_name(uint32_t a)
{
    for (int i = 0; ACT_TABLE[i].name; i++)
        if (ACT_TABLE[i].id == a) return ACT_TABLE[i].name;
    return "PMF_ACTION_UNKNOWN";
}

static uint32_t col_from_name(const char *s)
{
    for (int i = 0; COL_TABLE[i].name; i++)
        if (strcmp(COL_TABLE[i].name, s) == 0)
            return PMF_COL(COL_TABLE[i].id);
    fprintf(stderr, "error: unknown column '%s'\n", s);
    exit(1);
}

static uint32_t rel_from_name(const char *s)
{
    for (int i = 0; REL_TABLE[i].name; i++)
        if (strcmp(REL_TABLE[i].name, s) == 0)
            return REL_TABLE[i].id;
    fprintf(stderr, "error: unknown relation '%s'\n", s);
    exit(1);
}

static uint32_t act_from_name(const char *s)
{
    for (int i = 0; ACT_TABLE[i].name; i++)
        if (strcmp(ACT_TABLE[i].name, s) == 0)
            return ACT_TABLE[i].id;
    fprintf(stderr, "error: unknown action '%s'\n", s);
    exit(1);
}

/* ── UTF-16LE ↔ UTF-8 via Windows API (replaces iconv) ─────────────── */

/*
 * Convert str_bytes of UTF-16LE (which includes a null terminator)
 * to a newly-allocated, null-terminated UTF-8 string.
 * Caller must free() the result.
 */
static char *utf16le_to_utf8(const uint8_t *src, uint32_t byte_len)
{
    if (byte_len < 2) {
        char *s = (char *)calloc(1, 1);
        return s;
    }
    /* Number of wide chars excluding the null terminator */
    int wchars = (int)(byte_len / 2) - 1;
    if (wchars <= 0) {
        return (char *)calloc(1, 1);
    }
    int need = WideCharToMultiByte(CP_UTF8, 0,
                                   (LPCWSTR)src, wchars,
                                   NULL, 0, NULL, NULL);
    char *out = (char *)malloc((size_t)need + 1);
    if (!out) return NULL;
    WideCharToMultiByte(CP_UTF8, 0,
                        (LPCWSTR)src, wchars,
                        out, need, NULL, NULL);
    out[need] = '\0';
    return out;
}

/*
 * Convert a null-terminated UTF-8 string to UTF-16LE (with null terminator).
 * *out_bytes receives the byte count including the null terminator.
 * Caller must free() the result. Returns NULL on failure.
 */
static void *utf8_to_utf16le(const char *src, uint32_t *out_bytes)
{
    /* -1: include the null terminator in the conversion */
    int wchars = MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
    *out_bytes = (uint32_t)((size_t)wchars * sizeof(WCHAR));
    WCHAR *out = (WCHAR *)malloc(*out_bytes);
    if (!out) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, src, -1, out, wchars);
    return out;
}

/* ── Growable byte buffer ────────────────────────────────────────────── */

typedef struct { uint8_t *data; size_t len, cap; } buf_t;

static void buf_free(buf_t *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static int buf_push(buf_t *b, const void *src, size_t n)
{
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->len + n) nc *= 2;
        void *p = realloc(b->data, nc);
        if (!p) return 0;
        b->data = (uint8_t *)p;
        b->cap  = nc;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 1;
}

static int buf_u8 (buf_t *b, uint8_t  v) { return buf_push(b, &v, 1); }
static int buf_u32(buf_t *b, uint32_t v) { return buf_push(b, &v, 4); }
static int buf_u64(buf_t *b, uint64_t v) { return buf_push(b, &v, 8); }

/* ── Read (dump) mode ────────────────────────────────────────────────── */

static int cmd_read(const char *path)
{
    FILE *f = fopen(path, "rb");   /* binary mode — essential on Windows */
    if (!f) {
        fprintf(stderr, "error: cannot open '%s': %s\n", path, strerror(errno));
        return 1;
    }

    /* 4-byte content size */
    uint32_t content_size = 0;
    if (fread(&content_size, 4, 1, f) != 1) {
        fprintf(stderr, "error: cannot read header\n");
        fclose(f); return 1;
    }
    if (content_size < 5 || content_size > 64 * 1024 * 1024) {
        fprintf(stderr, "error: implausible content_size=%u\n", content_size);
        fclose(f); return 1;
    }

    /* Read the entire content blob */
    uint8_t *blob = (uint8_t *)malloc(content_size);
    if (!blob) {
        fprintf(stderr, "error: out of memory\n");
        fclose(f); return 1;
    }
    if (fread(blob, 1, content_size, f) != content_size) {
        fprintf(stderr, "error: file truncated\n");
        free(blob); fclose(f); return 1;
    }
    fclose(f);

    /* Parse the blob */
    size_t pos = 0;

    uint8_t version = blob[pos++];                    /* version byte  */
    uint32_t count  = 0;
    memcpy(&count, blob + pos, 4); pos += 4;          /* entry count   */

    fprintf(stderr, "PMF  version=0x%02X  entries=%u\n", version, count);

    for (uint32_t i = 0; i < count; i++) {

        /* Minimum bytes for fixed fields: 4+4+1+4 = 13 */
        if (pos + 13 > content_size) {
            fprintf(stderr, "error: truncated at entry %u\n", i);
            break;
        }

        uint32_t column, relation, str_bytes;
        uint8_t  action;

        memcpy(&column,   blob + pos, 4); pos += 4;
        memcpy(&relation, blob + pos, 4); pos += 4;
        action = blob[pos++];
        memcpy(&str_bytes, blob + pos, 4); pos += 4;

        /* Read UTF-16LE value */
        char *value = NULL;
        if (str_bytes > 0) {
            if (pos + str_bytes > content_size) {
                fprintf(stderr, "error: string overrun at entry %u\n", i);
                break;
            }
            value = utf16le_to_utf8(blob + pos, str_bytes);
            pos  += str_bytes;
        } else {
            value = (char *)calloc(1, 1);
        }

        /* Skip 8-byte reserved field */
        if (pos + 8 <= content_size) pos += 8;

        printf("%s %s %s %s\n",
               col_name(column),
               rel_name(relation),
               act_name(action),
               value ? value : "");

        free(value);
    }

    free(blob);
    return 0;
}

/* ── Write (build) mode ──────────────────────────────────────────────── */

/* in_path: text rule file; out_path: PMF file to create */
static int cmd_write(const char *in_path, const char *out_path)
{
    FILE *fin = fopen(in_path, "r");
    if (!fin) {
        fprintf(stderr, "error: cannot open '%s': %s\n", in_path, strerror(errno));
        return 1;
    }

    buf_t blob = {0};

    /*
     * Blob header: [u8 version=0x01] [u32 count=placeholder]
     * count is patched in after all entries are written.
     */
    buf_u8 (&blob, 0x01u);
    buf_u32(&blob, 0u);

    char     colstr[128], relstr[128], actstr[128], valstr[1024];
    uint32_t count = 0;

    /*
     * Text format: COLUMN  RELATION  ACTION  value
     * The space before %1023[^\n] in the format string causes scanf to
     * skip any whitespace between ACTION and the value field.
     */
    while (fscanf(fin, "%127s %127s %127s %1023[^\n]\n",
                  colstr, relstr, actstr, valstr) == 4)
    {
        uint32_t column   = col_from_name(colstr);
        uint32_t relation = rel_from_name(relstr);
        uint32_t action   = act_from_name(actstr);

        uint32_t str_bytes = 0;
        void    *wval      = utf8_to_utf16le(valstr, &str_bytes);
        if (!wval) {
            fprintf(stderr, "error: out of memory encoding value\n");
            buf_free(&blob); return 1;
        }

        buf_u32(&blob, column);
        buf_u32(&blob, relation);
        buf_u8 (&blob, (uint8_t)action);
        buf_u32(&blob, str_bytes);
        buf_push(&blob, wval, str_bytes);
        buf_u64(&blob, (uint64_t)0);   /* 8-byte reserved field */

        free(wval);
        count++;
    }

    fclose(fin);

    /* Patch the count at byte offset 1 in the blob */
    if (blob.len >= 5)
        memcpy(blob.data + 1, &count, 4);

    /* Write: [u32 content_size] [blob] */
    FILE *f = fopen(out_path, "wb");   /* binary mode — essential on Windows */
    if (!f) {
        fprintf(stderr, "error: cannot create '%s': %s\n", out_path, strerror(errno));
        buf_free(&blob); return 1;
    }

    uint32_t content_size = (uint32_t)blob.len;
    int ok = (fwrite(&content_size, 4, 1, f) == 1) &&
             (fwrite(blob.data, 1, blob.len, f) == blob.len);

    fclose(f);
    buf_free(&blob);

    if (!ok) {
        fprintf(stderr, "error: write failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "wrote %u filter rule(s) -> '%s'\n", count, out_path);
    return 0;
}

/* ── Entry point ─────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "-r") == 0)
        return cmd_read(argv[2]);
    if (argc == 5 && strcmp(argv[1], "-w") == 0 && strcmp(argv[3], "-o") == 0)
        return cmd_write(argv[2], argv[4]);

    fprintf(stderr,
        "pmftool — Process Monitor PMF filter file utility\n"
        "          (compatible with current Procmon64.exe)\n"
        "\n"
        "Usage:\n"
        "  pmftool -r input.pmf          dump PMF filters to stdout\n"
        "  pmftool -w input.txt -o out.pmf   build PMF from text file\n"
        "\n"
        "Text format (one rule per line):\n"
        "  PMF_COLUMN_<col>  PMF_RELATION_<rel>  PMF_ACTION_<act>  <value>\n"
        "\n"
        "Columns  : PMF_COLUMN_PROCESS_NAME  PMF_COLUMN_PID  PMF_COLUMN_PATH\n"
        "           PMF_COLUMN_OPERATION  PMF_COLUMN_RESULT  PMF_COLUMN_DETAIL\n"
        "           PMF_COLUMN_IMAGE_PATH  PMF_COLUMN_COMMAND_LINE  ...\n"
        "Relations: PMF_RELATION_IS  PMF_RELATION_IS_NOT  PMF_RELATION_CONTAINS\n"
        "           PMF_RELATION_BEGINS_WITH  PMF_RELATION_ENDS_WITH\n"
        "           PMF_RELATION_LESS_THAN  PMF_RELATION_MORE_THAN\n"
        "           PMF_RELATION_EXCLUDES\n"
        "Actions  : PMF_ACTION_INCLUDE  PMF_ACTION_EXCLUDE\n"
        "\n"
        "Example input.txt:\n"
        "  PMF_COLUMN_PROCESS_NAME PMF_RELATION_IS PMF_ACTION_INCLUDE notepad.exe\n"
        "  PMF_COLUMN_PATH PMF_RELATION_CONTAINS PMF_ACTION_EXCLUDE \\Temp\\\n"
        "\n"
        "Compile (MSVC x64) : cl /W3 /nologo pmftool.c\n"
        "Compile (MinGW-w64): gcc -Wall -o pmftool pmftool.c\n");

    return 1;
}
