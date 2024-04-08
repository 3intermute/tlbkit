#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x3726c6aa, "module_layout" },
	{ 0x8335c0f7, "kmalloc_caches" },
	{ 0x5ac24451, "unregister_kprobe" },
	{ 0x85acb812, "register_kprobe" },
	{ 0x987c11c7, "__pv_phys_pfn_offset" },
	{ 0x706c5a65, "preempt_count_sub" },
	{ 0xc5850110, "printk" },
	{ 0x43b0c9c3, "preempt_schedule" },
	{ 0x86332725, "__stack_chk_fail" },
	{ 0xfe2e64c4, "kmem_cache_alloc_trace" },
	{ 0x9dc08a71, "pgprot_kernel" },
	{ 0xefd6cf06, "__aeabi_unwind_cpp_pr0" },
	{ 0x8f678b07, "__stack_chk_guard" },
	{ 0xf229424a, "preempt_count_add" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "80808CDBA7F97EB9F0CCFE8");
