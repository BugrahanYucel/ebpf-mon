// do not depends on types from the kernel headers
#include "c-types.h"

// uncomment if BPF_CORE_READ must be used
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>


#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_DEBUG 2


/*
IMPORTANT: it seems defining and using typedefs (for structs) in shim
makes it fail at linking, so don't do it.
Using anonymous structs seems to make the linking fail
*/

// this just a simple C macro to make easier shim definition
// the macro prefix the function name by "shim_" so that doing we can
// easily filter the shim functions to bindgen.
#define _SHIM_GETTER(ret, proto, accessed_member)                \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return __builtin_preserve_access_index(accessed_member); \
	}

#define _SHIM_GETTER_BPF_CORE_READ(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                \
	{                                                       \
		return BPF_CORE_READ(struc, memb);                  \
	}

#define _SHIM_GETTER_BPF_CORE_READ_BITFIELD(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                         \
	{                                                                \
		return BPF_CORE_READ_BITFIELD_PROBED(struc, memb);           \
	}

#define _SHIM_GETTER_BPF_CORE_READ_USER(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return BPF_CORE_READ_USER(struc, memb);                  \
	}

#define _SHIM_GETTER_BPF_CORE_READ_RECAST(ret, proto, old_struct, new_struct, memb) \
	__attribute__((always_inline)) ret proto                                        \
	{                                                                               \
		struct old_struct *old = (void *)new_struct;                                \
		return BPF_CORE_READ(old, memb);                                            \
	}

// macro used to define a function to check if a field exists
#define _FIELD_EXISTS_DEF(_struct, memb, memb_name)                                                       \
	__attribute__((always_inline)) _Bool shim_##_struct##_##memb_name##_##exists(struct _struct *_struct) \
	{                                                                                                     \
		return bpf_core_field_exists(_struct->memb);                                                      \
	}

#define SHIM_BITFIELD(struc, memb)                                                                                                  \
	_SHIM_GETTER_BPF_CORE_READ_BITFIELD(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define SHIM(struc, memb)                                                                                                              \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb)             \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define SHIM_WITH_NAME(struc, memb, memb_name)                                                                                              \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb_name(struct struc *struc), struc, memb)             \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb_name##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb_name)

#define SHIM_REF(struc, memb)                                                                                             \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb(struct struc *struc), &(struc->memb))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb)) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM(struc, memb)                                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM_WITH_NAME(struc, memb, memb_name)                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb_name)

#define SHIM_ENUM_VALUE(enum_type, enum_value)                                      \
	__attribute__((always_inline)) unsigned int shim_##enum_type##_##enum_value()   \
	{                                                                               \
		return bpf_core_enum_value(enum enum_type, enum_value);                     \
	}                                                                               \
	__attribute__((always_inline)) _Bool shim_##enum_type##_##enum_value##_exists() \
	{                                                                               \
		return bpf_core_enum_value_exists(enum enum_type, enum_value);              \
	}// do not depends on types from the kernel headers



// Defining shim for task_struct
// We just need to define the fields we need to access
#define COMM_LEN 16

enum cgroup_subsys_id {
	cpuset_cgrp_id = 0,
	cpu_cgrp_id = 1,
	cpuacct_cgrp_id = 2,
	io_cgrp_id = 3,
	memory_cgrp_id = 4,
	devices_cgrp_id = 5,
	freezer_cgrp_id = 6,
	net_cls_cgrp_id = 7,
	perf_event_cgrp_id = 8,
	net_prio_cgrp_id = 9,
	pids_cgrp_id = 10,
	rdma_cgrp_id = 11,
	misc_cgrp_id = 12,
	CGROUP_SUBSYS_COUNT = 13,
};

SHIM_ENUM_VALUE(cgroup_subsys_id, memory_cgrp_id)
SHIM_ENUM_VALUE(cgroup_subsys_id, perf_event_cgrp_id)
SHIM_ENUM_VALUE(cgroup_subsys_id, cpu_cgrp_id)
SHIM_ENUM_VALUE(cgroup_subsys_id, pids_cgrp_id)

struct kgid_t
{
	gid_t val;
} __attribute__((preserve_access_index));

struct kuid_t
{
	uid_t val;
} __attribute__((preserve_access_index));

SHIM(kuid_t, val)

#define _KERNEL_CAPABILITY_U32S 2


struct kernel_cap_t
{ 
	u64 val; 
} __attribute__((preserve_access_index));

SHIM(kernel_cap_t, val)

struct kernel_cap_t_older_v515
{
	u32 cap[_KERNEL_CAPABILITY_U32S];
} __attribute__((preserve_access_index));

ARRAY_SHIM(kernel_cap_t_older_v515, cap)

struct cred_cap_t_older_v515
{
	struct kernel_cap_t_older_v515 cap_effective;
} __attribute__((preserve_access_index));

SHIM_REF(cred_cap_t_older_v515, cap_effective)

struct cred
{
	struct kuid_t uid;
	struct kgid_t gid;
	struct kernel_cap_t cap_effective;
} __attribute__((preserve_access_index));

_SHIM_GETTER_BPF_CORE_READ(uid_t, shim_cred_uid(struct cred *pcred), pcred, uid.val);
_SHIM_GETTER_BPF_CORE_READ(gid_t, shim_cred_gid(struct cred *pcred), pcred, gid.val);
_SHIM_GETTER_BPF_CORE_READ(u64, shim_cred_cap_effective(struct cred *pcred), pcred, cap_effective.val);

struct qstr
{
	__u64 hash_len;
	const unsigned char *name;
}
__attribute__((preserve_access_index));

SHIM(qstr, name);
SHIM(qstr, hash_len);

struct vfsmount
{
	struct dentry *mnt_root;
} __attribute__((preserve_access_index));

SHIM(vfsmount, mnt_root);

struct mountpoint;

struct mount
{
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	struct mountpoint *mnt_mp;
} __attribute__((preserve_access_index));

SHIM(mount, mnt_parent);
SHIM(mount, mnt_mountpoint);
SHIM_REF(mount, mnt)
SHIM(mount, mnt_mp)

__attribute__((always_inline)) struct mount *shim_mount_from_vfsmount(struct vfsmount *vfs)
{
	struct mount *mount = 0;
	struct vfsmount *vfsmount = __builtin_preserve_access_index(&(mount->mnt));
	__u64 offset = (void *)vfsmount - (void *)mount;
	return ((void *)vfs - offset);
}

struct file_system_type
{
	const char *name;	
} __attribute__((preserve_access_index));

SHIM(file_system_type, name);

struct super_block
{
	struct dentry *s_root;
	struct file_system_type *s_type;
} __attribute__((preserve_access_index));

SHIM(super_block, s_root);
SHIM(super_block, s_type);

struct dentry
{
	unsigned int d_flags;
	struct dentry *d_parent;
	struct qstr d_name;
	struct super_block *d_sb;
	struct inode *d_inode;
} __attribute__((preserve_access_index));

SHIM(dentry, d_parent);
SHIM(dentry, d_flags);
SHIM_REF(dentry, d_name);
SHIM(dentry, d_sb);
SHIM(dentry, d_inode)

struct mountpoint
{
	struct dentry *m_dentry;
} __attribute__((preserve_access_index));

SHIM(mountpoint, m_dentry);

struct path
{
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

SHIM(path, mnt);
SHIM(path, dentry);

struct fs_struct
{
	struct path root;
	struct path pwd;
} __attribute__((preserve_access_index));

SHIM_REF(fs_struct, root);
SHIM_REF(fs_struct, pwd);

typedef __s64 time64_t;

struct timespec64
{
	time64_t tv_sec;
	long int tv_nsec;
};

typedef short unsigned int umode_t;
typedef long long int __kernel_loff_t;
typedef __kernel_loff_t loff_t;

struct inode
{
	umode_t i_mode;
	unsigned long i_ino;
	struct super_block *i_sb;
	loff_t i_size;
	// https://elixir.bootlin.com/linux/v6.11/source/include/linux/fs.h#L668
	time64_t i_atime_sec;
	time64_t i_mtime_sec;
	time64_t i_ctime_sec;
	u32 i_atime_nsec;
	u32 i_mtime_nsec;
	u32 i_ctime_nsec;
	// kernels < 6.11
	union {
		struct timespec64 i_atime;
		struct timespec64 __i_atime;
	};
	union {
		struct timespec64 i_mtime;
		struct timespec64 __i_mtime;
	};
	union {
		struct timespec64 i_ctime;
		struct timespec64 __i_ctime;
	};
} __attribute__((preserve_access_index));

SHIM(inode, i_ino);
SHIM(inode, i_mode);
SHIM(inode, i_sb);
SHIM(inode, i_size);
SHIM(inode, i_atime);
SHIM(inode, __i_atime);
SHIM(inode, i_atime_sec);
SHIM(inode, i_atime_nsec);
SHIM(inode, i_mtime);
SHIM(inode, __i_mtime);
SHIM(inode, i_mtime_sec);
SHIM(inode, i_mtime_nsec);
SHIM(inode, i_ctime);
SHIM(inode, __i_ctime);
SHIM(inode, i_ctime_sec);
SHIM(inode, i_ctime_nsec);


struct file
{
	struct inode *f_inode;
	struct path f_path;
	unsigned int f_flags;
	void *private_data;
} __attribute__((preserve_access_index));

SHIM_REF(file, f_path);
SHIM(file, f_inode);
SHIM(file, private_data);
SHIM(file, f_flags);

struct fd
{
	struct file *file;
	unsigned int flags;
} __attribute__((preserve_access_index));

SHIM(fd, file);
SHIM(fd, flags);

struct filename {
	const char	*name;	/* pointer to actual string */
	const char	*uptr;	/* original userland pointer */
};
SHIM(filename, name);
SHIM(filename, uptr);

struct mm_struct
{
	unsigned long arg_start;
	unsigned long arg_end;
	struct file *exe_file;
} __attribute__((preserve_access_index));

SHIM(mm_struct, arg_start);
SHIM(mm_struct, arg_end);
SHIM(mm_struct, exe_file);


struct ns_common
{
	unsigned int inum;
} __attribute__((preserve_access_index));

SHIM(ns_common, inum);

struct ipc_namespace{
	struct ns_common ns;
} __attribute__((preserve_access_index));

struct mnt_namespace
{
	struct ns_common ns;
	struct mount *root;
	unsigned int mounts; /* # of mounts in the namespace */
} __attribute__((preserve_access_index));

SHIM_REF(mnt_namespace, ns);
SHIM(mnt_namespace, root);
SHIM(mnt_namespace, mounts);

#define __NEW_UTS_LEN 64

struct new_utsname
{
	char sysname[__NEW_UTS_LEN + 1];
	char nodename[__NEW_UTS_LEN + 1];
	char release[__NEW_UTS_LEN + 1];
	char version[__NEW_UTS_LEN + 1];
	char machine[__NEW_UTS_LEN + 1];
	char domainname[__NEW_UTS_LEN + 1];
} __attribute__((preserve_access_index));

ARRAY_SHIM(new_utsname, sysname);
ARRAY_SHIM(new_utsname, nodename);
ARRAY_SHIM(new_utsname, release);
ARRAY_SHIM(new_utsname, version);
ARRAY_SHIM(new_utsname, machine);
ARRAY_SHIM(new_utsname, domainname);

struct uts_namespace
{
	struct new_utsname name;
	struct ns_common ns;
} __attribute__((preserve_access_index));

SHIM_REF(uts_namespace, ns);
SHIM_REF(uts_namespace, name);

struct upid {
	int nr;
	struct pid_namespace *ns;
} __attribute__((preserve_access_index));

SHIM(upid, nr);

struct pid {
	unsigned int level;
	struct upid numbers[];
} __attribute__((preserve_access_index));

SHIM(pid, level);

// Read the namespaced PID number at a given namespace level.
// Uses CO-RE to correctly access the flexible array pid->numbers[level].nr
// regardless of other fields in the real kernel struct pid.
__attribute__((always_inline))
int shim_pid_nr_at_level(struct pid *pid, unsigned int level) {
	return BPF_CORE_READ(pid, numbers[level].nr);
}

struct pid_namespace {
	unsigned int level;
} __attribute__((preserve_access_index));

SHIM(pid_namespace, level);

struct nsproxy
{
	struct mnt_namespace *mnt_ns;
	struct uts_namespace *uts_ns;
	struct pid_namespace *pid_ns_for_children;
} __attribute__((preserve_access_index));

SHIM(nsproxy, mnt_ns);
SHIM(nsproxy, uts_ns);
SHIM(nsproxy, pid_ns_for_children);


struct kernfs_node___older_v55 
{
    const char *name;
    union {
		struct {
			u32 ino;
			u32 generation;
		};
		u64 id;
	} id;
	struct kernfs_node___older_v55 *parent;
}__attribute__((preserve_access_index));

SHIM(kernfs_node___older_v55, id);
SHIM(kernfs_node___older_v55, parent);
SHIM(kernfs_node___older_v55, name);

struct rh_kabi_hidden_172{
	union {
		struct {
			u32 ino;
			u32 generation;
		};
		u64 id;
	} id;
}__attribute__((preserve_access_index));

SHIM(rh_kabi_hidden_172, id);

struct kernfs_node___rh8 
{
    const char *name;
    union {
        u64 id;
		struct rh_kabi_hidden_172 rh_id;
        union {
        };
    };
	struct kernfs_node___rh8 *parent;
}__attribute__((preserve_access_index));

SHIM(kernfs_node___rh8, id);
SHIM(kernfs_node___rh8, rh_id);
SHIM(kernfs_node___rh8, name);
SHIM(kernfs_node___rh8, parent);

struct kernfs_node
{
	struct kernfs_node *parent;
	const char *name;
	u64 id;
} __attribute__((preserve_access_index));

SHIM(kernfs_node, parent);
SHIM(kernfs_node, name);
SHIM(kernfs_node, id);

struct cgroup
{
	struct kernfs_node *kn; /* cgroup kernfs entry */
} __attribute__((preserve_access_index));

SHIM(cgroup, kn);

struct cgroup_subsys_state
{
	struct cgroup *cgroup;
} __attribute__((preserve_access_index));

SHIM(cgroup_subsys_state, cgroup);

// Task group related information
struct task_group
{
	struct cgroup_subsys_state css;
} __attribute__((preserve_access_index));

SHIM_REF(task_group, css);

struct fdtable
{
	unsigned int max_fds;
	struct file **fd; /* current fd array */
} __attribute__((preserve_access_index));

SHIM(fdtable, max_fds);
SHIM(fdtable, fd);

struct files_struct
{
	struct fdtable *fdt;
	struct file *fd_array[1];
} __attribute__((preserve_access_index));

ARRAY_SHIM(files_struct, fd_array);
SHIM(files_struct, fdt);

struct task_struct
{
	unsigned int flags;
	pid_t pid;
	__u64 start_time;
	// attempt to make compatible with older kernels
	union {
		__u64 start_boottime;
		__u64 real_start_time;
	};
	pid_t tgid;
	unsigned char comm[COMM_LEN];
	struct cred *cred; 
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	struct mm_struct *mm;
	struct files_struct *files;
	struct nsproxy *nsproxy;
	struct task_group *sched_task_group;
	struct fs_struct *fs;
	struct pid *thread_pid;
} __attribute__((preserve_access_index));

SHIM(task_struct, flags);
SHIM(task_struct, start_time);
SHIM(task_struct, start_boottime);
SHIM(task_struct, real_start_time);
ARRAY_SHIM(task_struct, comm);
SHIM(task_struct, pid);
SHIM(task_struct, tgid);
SHIM(task_struct, cred);
SHIM(task_struct, group_leader);
SHIM(task_struct, real_parent);
SHIM(task_struct, mm);
SHIM(task_struct, files);
SHIM(task_struct, nsproxy);
SHIM(task_struct, sched_task_group);
SHIM(task_struct, fs);
SHIM(task_struct, thread_pid);


struct linux_binprm
{
	struct mm_struct *mm;
	struct file *file;
	struct cred *cred;
} __attribute__((preserve_access_index));

SHIM(linux_binprm, mm);
SHIM(linux_binprm, file);
SHIM(linux_binprm, cred);


typedef short unsigned int __kernel_sa_family_t;
typedef __kernel_sa_family_t sa_family_t;

struct sockaddr
{
	sa_family_t sa_family;
} __attribute__((preserve_access_index));

SHIM(sockaddr, sa_family);

struct in_addr
{
	__be32 s_addr;
} __attribute((preserve_access_index));

struct sockaddr_in
{
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
} __attribute__((preserve_access_index));

SHIM(sockaddr_in, sin_family);
SHIM(sockaddr_in, sin_port);
SHIM_WITH_NAME(sockaddr_in, sin_addr.s_addr, s_addr);

struct sock_common
{
	unsigned short skc_family;
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
}__attribute__((preserve_access_index));

SHIM(sock_common, skc_family);
SHIM(sock_common, skc_daddr);
SHIM(sock_common, skc_rcv_saddr);
SHIM(sock_common, skc_dport);
SHIM(sock_common, skc_num);

struct sock
{
	struct sock_common __sk_common;
	struct kuid_t sk_uid;
	u16 sk_type;
}__attribute__((preserve_access_index));

SHIM_REF(sock, __sk_common);
SHIM(sock, sk_uid);
SHIM(sock, sk_type);

struct unix_sock
{
	struct sock *peer;
	struct path path;

}__attribute__((preserve_access_index));

SHIM(unix_sock, peer);
SHIM_REF(unix_sock, path);

struct socket
{
	struct file *file;
	struct sock *sk;
}__attribute__((preserve_access_index));

SHIM(socket, file);
SHIM(socket, sk);