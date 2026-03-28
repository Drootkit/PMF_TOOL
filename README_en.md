# pmftool

A command-line utility for reading and writing Process Monitor Filter (`.PMF`) files.  
The binary format was recovered by reverse-engineering `Procmon64.exe` with IDA Pro.  
Encoding and decoding are implemented in standard C with the Win32 API — no third-party dependencies.

---

## PMF Binary Format

All fields are little-endian.

```
[u32]  content_size          total byte count of everything that follows

  [u8]   version             always 0x01
  [u32]  count               number of filter entries

  per entry (repeated 'count' times):
    [u32]  column            (0x9C << 8) | column_low_byte
    [u32]  relation          0–7, see pmf_rel_t
    [u8]   action            0=exclude  1=include
    [u32]  str_bytes         byte length of UTF-16LE value string
                             (includes null terminator; 0 = empty)
    [*]    UTF-16LE          str_bytes bytes of filter value
    [u64]  reserved          8 zero bytes
```

---

## Data Structures

### `pmf_col_t` — Column identifier enum

Stores the low-byte value for each filterable column.  
The `column` DWORD written to the file is produced by the macro:

```c
#define PMF_COL(x)  ((uint32_t)((0x9Cu << 8) | (uint8_t)(x)))
```

| Enum value | Low byte | Column |
|---|---|---|
| `COL_PROCESS_NAME` | `0x75` | Process Name |
| `COL_PID` | `0x76` | PID |
| `COL_PATH` | `0x87` | Path |
| `COL_OPERATION` | `0x77` | Operation |
| `COL_RESULT` | `0x78` | Result |
| `COL_DETAIL` | `0x79` | Detail |
| `COL_IMAGE_PATH` | `0x84` | Image Path |
| `COL_COMMAND_LINE` | `0x82` | Command Line |
| … | … | … |

### `pmf_rel_t` — Relation enum

```c
REL_IS=0  REL_IS_NOT=1  REL_LESS_THAN=2  REL_MORE_THAN=3
REL_BEGINS_WITH=4  REL_ENDS_WITH=5  REL_CONTAINS=6  REL_EXCLUDES=7
```

### `pmf_act_t` — Action enum

```c
ACT_EXCLUDE=0  ACT_INCLUDE=1
```

### Name tables (`COL_TABLE` / `REL_TABLE` / `ACT_TABLE`)

Three static arrays of `{ uint32_t id; const char *name; }` pairs, terminated by a sentinel entry.  
They provide bidirectional lookup between integer values and their text tokens:

- **integer → name**: used by read mode to produce human-readable output
- **name → integer**: used by write mode to parse the input text file

### `buf_t` — Growable byte buffer

Used in write mode to assemble the entire content blob in memory before writing to disk.  
This allows the `count` field at offset 1 to be back-patched once all entries have been appended.

```c
typedef struct { uint8_t *data; size_t len, cap; } buf_t;
```

Capacity doubles automatically via `realloc` whenever the buffer is full.

---

## Build

```bat
:: MSVC x64
cl /W3 /nologo pmftool.c

:: MinGW-w64
gcc -Wall -Wextra -o pmftool pmftool.c
```

---

## Usage

```powershell
# Dump PMF filters to stdout as text
.\pmftool.exe -r input.pmf

# Build a PMF file from a text file
.\pmftool.exe -w input.txt -o output.pmf
```

### Text format (one rule per line)

```
PMF_COLUMN_<col>  PMF_RELATION_<rel>  PMF_ACTION_<act>  <filter value>
```

Example:

```
PMF_COLUMN_PROCESS_NAME PMF_RELATION_IS PMF_ACTION_INCLUDE notepad.exe
PMF_COLUMN_PATH PMF_RELATION_CONTAINS PMF_ACTION_EXCLUDE \Temp\
PMF_COLUMN_OPERATION PMF_RELATION_BEGINS_WITH PMF_ACTION_EXCLUDE IRP_MJ
```
