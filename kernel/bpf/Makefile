obj-y := core.o
CFLAGS_core.o += $(call cc-disable-warning, override-init)

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o bpf_lru_list.o lpm_trie.o map_in_map.o
# A37: devmap (XDP) dan stackmap (STACK_TRACE) tidak dibangun.
# devmap butuh infrastruktur XDP yang tidak ada di 3.10; stackmap butuh
# get_perf_callchain() dan sysctl_perf_event_max_stack dari 4.6.
# Tidak satu pun program BPF Android 13 memakainya. Lihat BPF_FD_ARRAY_MAPS.
ifeq ($(CONFIG_NET),y)
obj-$(CONFIG_BPF_FD_ARRAY_MAPS) += devmap.o
endif
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_FD_ARRAY_MAPS) += stackmap.o
endif
obj-$(CONFIG_CGROUP_BPF) += cgroup.o
