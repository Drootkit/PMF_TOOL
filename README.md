# pmftool

Process Monitor Filter（`.PMF`）文件的命令行读写工具，通过逆向 `Procmon64.exe` 得到二进制格式，在 Windows 下用标准 C + Win32 API 实现编解码。

---

## PMF 二进制格式

全部字段小端序。

```
[u32]  content_size          后续全部字节数

  [u8]   version             固定 0x01
  [u32]  count               过滤条目总数

  per entry（重复 count 次）：
    [u32]  column            (0x9C << 8) | column_low_byte
    [u32]  relation          0–7，见 pmf_rel_t
    [u8]   action            0=exclude  1=include
    [u32]  str_bytes         UTF-16LE 字符串字节数（含 null；0=空串）
    [*]    UTF-16LE          str_bytes 字节的过滤值
    [u64]  reserved          8 字节全零
```

---

## 数据结构

### `pmf_col_t` — 列标识符枚举

存储过滤列的低字节值，文件中实际写入的 `column` DWORD 通过宏编码：

```c
#define PMF_COL(x)  ((uint32_t)((0x9Cu << 8) | (uint8_t)(x)))
```

| 枚举值 | 低字节 | 对应列 |
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

### `pmf_rel_t` — 关系枚举

```c
REL_IS=0  REL_IS_NOT=1  REL_LESS_THAN=2  REL_MORE_THAN=3
REL_BEGINS_WITH=4  REL_ENDS_WITH=5  REL_CONTAINS=6  REL_EXCLUDES=7
```

### `pmf_act_t` — 动作枚举

```c
ACT_EXCLUDE=0  ACT_INCLUDE=1
```

### 名称表（`COL_TABLE` / `REL_TABLE` / `ACT_TABLE`）

三组 `{ uint32_t id; const char *name; }` 静态数组，用于枚举值与文本标识符之间的双向查找（整数→名称用于读模式输出，名称→整数用于写模式解析）。

### `buf_t` — 可增长字节缓冲区

写模式下用于在内存中拼装完整 content blob，待全部条目写入后再回填 `count` 字段，最后一次性写入文件。

```c
typedef struct { uint8_t *data; size_t len, cap; } buf_t;
```

容量不足时自动 2 倍扩容（`realloc`）。

---

## 编译

```bat
:: MSVC x64
cl /W3 /nologo pmftool.c

:: MinGW-w64
gcc -Wall -Wextra -o pmftool pmftool.c
```

---

## 使用

```powershell
# 读取 PMF，输出文本到 stdout
.\pmftool.exe -r input.pmf

# 从文本文件生成 PMF
.\pmftool.exe -w input.txt -o output.pmf
```

### 文本格式（每行一条规则）

```
PMF_COLUMN_<col>  PMF_RELATION_<rel>  PMF_ACTION_<act>  <filter value>
```

示例：

```
PMF_COLUMN_PROCESS_NAME PMF_RELATION_IS PMF_ACTION_INCLUDE notepad.exe
PMF_COLUMN_PATH PMF_RELATION_CONTAINS PMF_ACTION_EXCLUDE \Temp\
PMF_COLUMN_OPERATION PMF_RELATION_BEGINS_WITH PMF_ACTION_EXCLUDE IRP_MJ
```
