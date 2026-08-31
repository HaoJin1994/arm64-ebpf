savedcmd_bpf_memcpy_kfunc.mod := printf '%s\n'   bpf_memcpy_kfunc.o | awk '!x[$$0]++ { print("./"$$0) }' > bpf_memcpy_kfunc.mod
