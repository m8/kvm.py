from kvm import *

open_kvm()

vm_fd = create_vm()
if(vm_fd < 0):
    print("Error")
else:
    print("KVM Version {}".format(vm_fd))
