/* Power-management notifications: this board never suspends through the Linux PM core, so registering is accepted and nothing is delivered. */
#ifndef LX_LINUX_SUSPEND_H
#define LX_LINUX_SUSPEND_H
#include <lx_ath.h>
#define PM_HIBERNATION_PREPARE 0x0001
#define PM_POST_HIBERNATION 0x0002
#define PM_SUSPEND_PREPARE 0x0003
#define PM_POST_SUSPEND 0x0004
#define PM_RESTORE_PREPARE 0x0005
#define PM_POST_RESTORE 0x0006
static inline int unregister_pm_notifier(struct notifier_block *nb) { (void)nb; return 0; }
#endif
