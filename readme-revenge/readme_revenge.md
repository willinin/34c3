# 34c3 readme_revenge

首先看32c3的[readme](https://github.com/zookee1/32c3-ctf/tree/master/readme)。

32c3的利用大致是：
在开启canary的情况下，检查栈溢出的path如下：

```c
 __stack_chk_fail  -> __fortify_fail -> __libc_message
```
`__fortify_fail`源码：

```c
void
__attribute__ ((noreturn))
__fortify_fail (msg)
const char *msg; {
  /* The loop is added only to keep gcc happy. */
while (1)
__libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>")
libc_hidden_def (__fortify_fail)
```

`__libc_message`源码：

``` c
 void
__libc_message (int do_abort, const char *fmt, ...)
{
  va_list ap; 
  int fd = -1; 

  va_start (ap, fmt);

  /* Open a descriptor for /dev/tty unless the user explicitly
     requests errors on standard error.  */
  const char *on_2 = __libc_secure_getenv ("LIBC_FATAL_STDERR_");
  if (on_2 == NULL || *on_2 == '\0')
    fd = open_not_cancel_2 (_PATH_TTY, O_RDWR | O_NOCTTY | O_NDELAY);

  if (fd == -1) 
    fd = STDERR_FILENO;

  // then prints stuff and crashes
}

```

`argv`和`envp`及其指针都位于高地址，利用无限的栈溢出，就可以去溢出到栈中存储的 `argv` 和 `envp`环境变量。

推测`__libc_argv`是栈中`argv`中copy来的，这样就可以造成任意地址泄露。
如果远程利用需要 使得`engv`中

```c
LIBC_FATAL_STDERR_=1
```
readme_revenge中该条件满足，可以远程泄露。

但是该题没有栈溢出，无法直接调用 `__fortify_fail` 。因此需要一个能控制eip的指针，这里利用到了printf函数（printf源码应该好好看）。

vfprintf源码中有这么一段：

```c
 /* Use the slow path in case any printf handler is registered.  */
 if (__glibc_unlikely (__printf_function_table != NULL
                        || __printf_modifier_table != NULL
                        || __printf_va_arg_table != NULL))
    goto do_positional;	
``` 
意思大概是如果已经定义了printf的一些函数表，那么就用这些函数表里的函数去处理，那么可以让 `__printf_function_table != NULL`，使得跳转成立。

`do_positional` 调用了 ` printf_positional` 调用了 `__parse_one_specwc`：

```c
 /* Get the format specification.  */
  spec->info.spec = (wchar_t) *format++;
  spec->size = -1;
  if (__builtin_expect (__printf_function_table == NULL, 1)
      || spec->info.spec > UCHAR_MAX
      || __printf_arginfo_table[spec->info.spec] == NULL
      /* We don't try to get the types for all arguments if the format
         uses more than one.  The normal case is covered though.  If
         the call returns -1 we continue with the normal specifiers.  */
      || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])
                                   (&spec->info, 1, &spec->data_arg_type,
                                    &spec->size)) < 0)
```

```c
/* Array of functions indexed by format character.  */
libc_freeres_ptr (printf_arginfo_size_function **__printf_arginfo_table)
  attribute_hidden;
  printf_function **__printf_function_table attribute_hidden;
```
从源码中可以看见`__printf_arginfo_table`是处理格式化字符串的函数表(函数指针数组)，indexed by format character，这里是 ‘s’。

于是改写 `__printf_arginfo_table['s']` 和` __libc_argv` 和  `__printf_function_table` 即可。

当然，探索了一下源码，如果前面不使得`__printf_function_table != NULL`，那么就会跳转到`step0_jumps`函数表里去调用对应的函数。

```c
277	    static JUMP_TABLE_TYPE step0_jumps[30] =                                      \
278	    {                                                                              \
279	      REF (form_unknown),                                                      \
280	      REF (flag_space),                /* for ' ' */                                      \
281	      REF (flag_plus),                /* for '+' */                                      \
282	      REF (flag_minus),                /* for '-' */                                      \
283	      REF (flag_hash),                /* for '<hash>' */                              \
284	      REF (flag_zero),                /* for '0' */                                      \
285	      REF (flag_quote),                /* for '\'' */                                      \
286	      REF (width_asterics),        /* for '*' */                                      \
287	      REF (width),                /* for '1'...'9' */                              \
288	      REF (precision),                /* for '.' */                                      \
289	      REF (mod_half),                /* for 'h' */                                      \
290	      REF (mod_long),                /* for 'l' */                                      \
291	      REF (mod_longlong),        /* for 'L', 'q' */                              \
292	      REF (mod_size_t),                /* for 'z', 'Z' */                              \
293	      REF (form_percent),        /* for '%' */                                      \
294	      REF (form_integer),        /* for 'd', 'i' */                              \
295	      REF (form_unsigned),        /* for 'u' */                                      \
296	      REF (form_octal),                /* for 'o' */                                      \
297	      REF (form_hexa),                /* for 'X', 'x' */                              \
298	      REF (form_float),                /* for 'E', 'e', 'F', 'f', 'G', 'g' */              \
299	      REF (form_character),        /* for 'c' */                                      \
300	      REF (form_string),        /* for 's', 'S' */                              \
301	      REF (form_pointer),        /* for 'p' */                                      \
302	      REF (form_number),        /* for 'n' */                                      \
303	      REF (form_strerror),        /* for 'm' */                                      \
304	      REF (form_wcharacter),        /* for 'C' */                                      \
305	      REF (form_floathex),        /* for 'A', 'a' */                              \
306	      REF (mod_ptrdiff_t),      /* for 't' */                                      \
307	      REF (mod_intmax_t),       /* for 'j' */                                      \
308	      REF (flag_i18n),                /* for 'I' */                                      \
309	    };               
```
后面看源码可以看到是跳转到 

```c
#define REF(Name) &&do_##Name
# define REF(Name) &&do_##Name - &&JUMP_TABLE_BASE_LABEL
```
也就是 `do_form_string` 。
最终会跳转到 `process_string_arg`里的`LABEL(print_string)`去执行outstring 函数,outstring 调用PUT。

```c
#     define outstring(String, Len)                                                      \
169	  do                                                                              \
170	    {                                                                              \
171	      assert ((size_t) done <= (size_t) INT_MAX);                              \
172	      if ((size_t) PUT (s, (String), (Len)) != (size_t) (Len))                      \
173	        {                                                                      \
174	          done = -1;                                                              \
175	          goto all_done;                                                      \
176	        }                                                                      \
177	      if (__glibc_unlikely (INT_MAX - done < (Len)))                              \
178	      {                                                                              \
179	        done = -1;                                                              \
180	         __set_errno (EOVERFLOW);                                              \
181	        goto all_done;                                                              \
182	      }                                                                              \
183	      done += (Len);                                                              \
184	    }                                                                              \
185	  while (0)
```

然后：

```c
# define PUT(F, S, N)        _IO_sputn ((F), (S), (N))
```

### wp ref：[wp](https://github.com/r00ta/myWriteUps/tree/master/34C32017/pwn_readme_revenge)




 

