# Copyright 2021 Musa Ünal Licensed under the MIT License;
# Permission is hereby granted, free of charge, to any person obtaining a 
# copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
# DEALINGS IN THE SOFTWARE.

from fcntl import ioctl

from ctypes import *
from struct import *
from kvm import *
from mmap import *


# Path
KVM = "/dev/kvm"

# Constants
KVMIO = 0xAE
_KVM_FD = -1

# IO Macro
def IO(io, x):
    return((io << 8) | x)

# EXIT REASONS
KVM_EXIT_UNKNOWN            = 0x00
KVM_EXIT_EXCEPTION          = 0x01
KVM_EXIT_IO                 = 0x02
KVM_EXIT_HYPERCALL          = 0x03
KVM_EXIT_DEBUG              = 0x04
KVM_EXIT_HLT                = 0x05
KVM_EXIT_MMIO               = 0x06
KVM_EXIT_IRQ_WINDOW_OPEN    = 0x07
KVM_EXIT_SHUTDOWN           = 0x08
KVM_EXIT_FAIL_ENTRY         = 0x09
KVM_EXIT_INTR               = 0x0a
KVM_EXIT_SETTPR             = 0x0b
KVM_EXIT_TPRACCESS          = 0x0c
KVM_EXIT_S390SIEIC          = 0x0d
KVM_EXIT_S390RESET          = 0x0e
KVM_EXIT_DCR                = 0x0f     # deprecated
KVM_EXIT_NMI                = 0x10
KVM_EXIT_INTERNAL_ERROR     = 0x11

# Ioctls
KVM_GET_API_VERSION     = IO(KVMIO, 0x00)
KVM_CREATE_VM           = IO(KVMIO, 0x01)
KVM_CHECK_EXTENSION     = IO(KVMIO, 0x03)
KVM_GET_VCPU_MMAP_SIZE  = IO(KVMIO, 0x04)
KVM_CREATE_VCPU         = IO(KVMIO, 0x41)
KVM_RUN                 = IO(KVMIO, 0x80)
KVM_SET_SREGS           = IO(KVMIO, 0x81)

KVM_SET_USER_MEMORY_REGION = 0x4020AE46
KVM_SET_REGS               = 0x4090AE82
KVM_SET_SREGS              = 0x4138AE84
KVM_GET_MSRS               = 0xC008AE88
KVM_GET_REGS               = 0x8090AE81
KVM_GET_SREGS              = 0x8138AE83

# KVM structs
class kvm_userspace_memory_region(Structure):
    _fields_ = [('slot', c_uint32),
                ('flags', c_uint32),
                ('guest_phys_addr', c_uint64),
                ('memory_size', c_uint64),
                ('userspace_addr', c_uint64)]


class kvm_regs(Structure):
    _fields_ = [('rax', 'rbx', 'rcx', 'rdx', c_uint64),
                ('rsi', 'rdi', 'rsp', 'rbp', c_uint64),
                ('r8',  'r9',  'r10', 'r11', c_uint64),
                ('r12', 'r13', 'r14', 'r15', c_uint64),
                ('rip', 'rflags', c_uint64)]

class kvm_segment(Structure):
    _fields_ = [('base', c_uint64),
                ('limit', c_uint32),
                ('selector', c_uint16),
                ('type', c_uint8),
                ('present', 'dpl', 'db', 's', 'l', 'g', 'avl', c_uint8),
                ('unusable', c_uint8),
                ('padding', c_uint8)]

# KVM Functions
def open_kvm():
    global _KVM_FD
    _KVM_FD = open(KVM, "wb")

def close_kvm():
    _KVM_FD.close()

def get_kvm_version():
    res = ioctl(_KVM_FD, KVM_GET_API_VERSION, 0)
    return res

def create_vm():
    res = ioctl(_KVM_FD, KVM_CREATE_VM, 0)
    return res

# VCPU Functions
def create_vcpu(_vm_fd):
    res = ioctl(_vm_fd,KVM_CREATE_VCPU,0)
    return res

def kmv_set_user_memor_region(_vm_fd):
    mem_size = 0x40000000
    user_mem = mmap.mmap(-1, mem_size, prot=mmap.PROT_READ|mmap.PROT_WRITE)

    mem = kvm_userspace_memory_region()
    mem.slot = 0
    mem.flags = 0
    mem.guest_phys_addr = 0
    mem.memory_size = mem_size
    mem.userspace_addr = id(user_mem)

    res = ioctl(_vm_fd, KVM_SET_USER_MEMORY_REGION, id(mem))
    return res