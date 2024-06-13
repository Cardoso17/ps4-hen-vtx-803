/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __OFFSETS_H__
#define __OFFSETS_H__
#define ENABLE_DEBUG_MENU 1

#if (FIRMWARE == 800 || FIRMWARE == 801 || FIRMWARE == 803) // FW 8.00 / 8.01 / 8.03

#if ENABLE_DEBUG_MENU
#define enable_data_mount_patch 0x0031C503
#define enable_fpkg_patch 0x003D1A2F
#define fake_free_patch 0x00FC62B1
#define pkg_installer_patch 0x00A0C681
#define ext_hdd_patch 0x0060761D
#define debug_trophies_patch 0x0072D669

#define sceKernelIsGenuineCEX 0x00168D20
#define sceKernelIsGenuineCEX_1 0x0084D080
#define sceKernelIsGenuineCEX_2 0x0089C1E2
#define sceKernelIsGenuineCEX_3 0x00A236A0
#define dipsw_libSceDipsw 0x00168D4A
#define dipsw_libSceDipsw_1 0x00242978
#define dipsw_libSceDipsw_2 0x0084D0AA
#define dipsw_libSceDipsw_3 0x00A236CA
#define sys_debug_menu 0x0001D130
#define sys_debug_menu_1 0x0001D490
#endif

// libkernel_sys.srpx
#define _scePthreadAttrInit_offset 0x14100
#define _scePthreadAttrSetstacksize_offset 0x14120
#define _scePthreadCreate_offset 0x14540
#define _thr_initial_offset 0x8E8C0 // Needs to be checked

//kern
// kbase + offset (offsets are not in theflow format)
#define vm_map_protect_p 0x3ec68b
#define ptrace_p 0x174155
#define ptrace_p2 0x17462f
#define disable_aslr_p 0x2856f4
#define sceSblACMgrIsAllowedSystemLevelDebugging_p 0x14660
#define kemem_2 0x1b4c4
#define kemem_1 0x1b4bc
#define vm_map_lock_offset 0x3e7530
#define vm_map_insert_offset 0x3e8880
#define vm_map_unlock_offset 0x3e75a0
#define malloc_offset 0x46f7f0
#define free_offset 0x46f9b0
#define vm_map_lock_read_offset 0x3e7680
#define vm_map_unlock_read_offset 0x3e76d0
#define vm_map_lookup_entry_offset 0x3e7cc0
#define M_TEMP_offset 0x1a77e10
#define proc_rmem_offset 0x173770
#define vm_map_findspace_offset 0x3ea740
#define vm_map_delete_offset 0x3ea180
#define create_thread_offset 0x26fa50
#define all_proc_offset 0x1b244e0
#define sys_dynlib_dlsym_p 0x319337
#define sys_dynlib_dlsym_p2 0x951c0

/* kernel offsets */

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0

#define kdlsym_addr_printf 0xffffffff82630ae0

#define kdlsym_addr_sysent 0xffffffff832fc4d0

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff8245e407
#define kdlsym_addr_copyin_patch2 0xffffffff8245e413

#define kdlsym_addr_copyout_patch1 0xffffffff8245e312
#define kdlsym_addr_copyout_patch2 0xffffffff8245e31e

#define kdlsym_addr_copyinstr_patch1 0xffffffff8245e8b3
#define kdlsym_addr_copyinstr_patch2 0xffffffff8245e8bf
#define kdlsym_addr_copyinstr_patch3 0xffffffff8245e8f0

#elif FIRMWARE == 900 // FW 9.00

#if ENABLE_DEBUG_MENU
#define enable_data_mount_patch 0x0032079B
#define enable_fpkg_patch 0x003D7AFF
#define fake_free_patch 0x00FD3211
#define pkg_installer_patch 0x00A10A81
#define ext_hdd_patch 0x006180FD
#define debug_trophies_patch 0x00743299

#define sceKernelIsGenuineCEX 0x0016EAA4
#define sceKernelIsGenuineCEX_1 0x008621D4
#define sceKernelIsGenuineCEX_2 0x008AFBC2
#define sceKernelIsGenuineCEX_3 0x00A27BD4
#define dipsw_libSceDipsw 0x0016EAD2 
#define dipsw_libSceDipsw_1 0x00249F7B 
#define dipsw_libSceDipsw_2 0x00862202 
#define dipsw_libSceDipsw_3 0x00A27C02 
#define sys_debug_menu 0x0001D1C0
#define sys_debug_menu_1 0x0001D520
#endif

// libkernel_sys.srpx
#define _scePthreadAttrInit_offset 0x0014190
#define _scePthreadAttrSetstacksize_offset 0x00141B0
#define _scePthreadCreate_offset 0x00145D0
#define _thr_initial_offset 0x8E830

//kern
// kbase + offset (offsets are not in theflow format)
#define vm_map_protect_p 0x00080B8B
#define ptrace_p 0x41F4E5
#define ptrace_p2 0x41F9D1
#define disable_aslr_p 0x5F824
#define sceSblACMgrIsAllowedSystemLevelDebugging_p 0x0001D1C0
#define kemem_2 0x37BF44
#define kemem_1 0x37BF3C
#define vm_map_lock_offset 0x0007BA30
#define vm_map_insert_offset 0x0007CD80
#define vm_map_unlock_offset 0x0007BAA0
#define malloc_offset 0x00301B20
#define free_offset 0x00301CE0
#define vm_map_lock_read_offset 0x0007BB80
#define vm_map_unlock_read_offset 0x0007BBD0
#define vm_map_lookup_entry_offset 0x0007C1C0
#define M_TEMP_offset 0x015621E0 
#define proc_rmem_offset 0x0041EB00
#define vm_map_findspace_offset 0x0007EC40
#define vm_map_delete_offset 0x0007E680
#define create_thread_offset 0x001ED670
#define all_proc_offset 0x01B946E0
#define sys_dynlib_dlsym_p 0x0023B67F
#define sys_dynlib_dlsym_p2 0x00221B40

/* kernel offsets */

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0

#define kdlsym_addr_printf 0xffffffff822b7a30

#define kdlsym_addr_sysent 0xffffffff83300310

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff824716f7
#define kdlsym_addr_copyin_patch2 0xffffffff82471703

#define kdlsym_addr_copyout_patch1 0xffffffff82471602
#define kdlsym_addr_copyout_patch2 0xffffffff8247160e

#define kdlsym_addr_copyinstr_patch1 0xffffffff82471ba3
#define kdlsym_addr_copyinstr_patch2 0xffffffff82471baf
#define kdlsym_addr_copyinstr_patch3 0xffffffff82471be0

#elif FIRMWARE == 1100 // FW 11.00

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff824fcbd0

#define kdlsym_addr_sysent 0xffffffff83301760

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff824de037
#define kdlsym_addr_copyin_patch2 0xffffffff824de043

#define kdlsym_addr_copyout_patch1 0xffffffff824ddf42
#define kdlsym_addr_copyout_patch2 0xffffffff824ddf4e

#define kdlsym_addr_copyinstr_patch1 0xffffffff824de4e3
#define kdlsym_addr_copyinstr_patch2 0xffffffff824de4ef
#define kdlsym_addr_copyinstr_patch3 0xffffffff824de520

/*=================== POrt these =======================*/

#if ENABLE_DEBUG_MENU
// ShellCore offsets
#define enable_data_mount_patch 0x31F070// 1
#define enable_fpkg_patch 0x3D7C9F // 1
#define fake_free_patch 0x0FC8439 // 1
#define pkg_installer_patch 0xA06C10 // 1
#define ext_hdd_patch 0x60E17D // 1

#define sceKernelIsGenuineCEX 0x16B664 //
#define sceKernelIsGenuineCEX_1 0x086BD24 //
#define sceKernelIsGenuineCEX_2 0x08BC022 //
#define sceKernelIsGenuineCEX_3 0x0A1D6C4//
#define dipsw_libSceDipsw 0x016B692 // 
#define dipsw_libSceDipsw_1 0x249E0C //
#define dipsw_libSceDipsw_2 0x086BD52 //
#define dipsw_libSceDipsw_3 0xA1D6F2 // 
// debug menu libkernel_sys.prx
#define sys_debug_menu   0x1D100
#define sys_debug_menu_1 0x1D460
#endif

// libkernel_sys.srpx 
#define _scePthreadAttrInit_offset 0x14010 
#define _scePthreadAttrSetstacksize_offset 0x14030
#define _scePthreadCreate_offset 0x14450
#define _thr_initial_offset 0x8E830

//kern
#define vm_map_protect_p 0x0035C710
#define ptrace_p 0x00384285
#define ptrace_p2 0x00384771
#define disable_aslr_p 0x003B11A4
#define sceSblACMgrIsAllowedSystemLevelDebugging_p 0x003D0DE0
#define kemem_2 0x00245EE4
#define kemem_1 0x00245EDC

#define vm_map_lock_offset  0x00357760
#define vm_map_insert_offset 0x00358AB0
#define vm_map_unlock_offset  0x003577D0
#define malloc_offset 0x001A4220
#define free_offset 0x001A43E0
#define vm_map_lock_read_offset 0x003578B0
#define vm_map_unlock_read_offset 0x00357900
#define vm_map_lookup_entry_offset 0x00357EF0
#define M_TEMP_offset 0x015415B0
#define proc_rmem_offset  0x003838A0
#define vm_map_findspace_offset 0x0035A970
#define vm_map_delete_offset 0x0035A3B0
#define create_thread_offset 0x00295170
#define all_proc_offset 0x022D0A98

#else

#error "Invalid firmware"

#endif

#define kdlsym(sym) (kaslr_offset + kdlsym_addr_##sym)

#endif
