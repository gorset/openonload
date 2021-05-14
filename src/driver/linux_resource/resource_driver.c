/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains main driver entry points.
 *
 * Copyright 2005-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include "linux_resource_internal.h"
#include "kernel_compat.h"
#include <ci/driver/driverlink_api.h>
#include <ci/efrm/nic_table.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/nic.h>
#include <ci/efrm/buffer_table.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efrm/vf_resource.h>
#include <ci/efrm/driver_private.h>
#include <ci/efrm/pd.h>
#include <driver/linux_net/filter.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/syscall.h>
#include <ci/driver/internal.h>
#include <ci/efhw/falcon.h>
#include "compat_pat_wc.h"
#include "efrm_internal.h"

MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");

static struct efhw_ev_handler ev_handler = {
	.wakeup_fn = efrm_handle_wakeup_event,
	.timeout_fn = efrm_handle_timeout_event,
	.dmaq_flushed_fn = efrm_handle_dmaq_flushed_schedule,
};

const int max_hardware_init_repeats = 1;

/*--------------------------------------------------------------------
 *
 * Module load time variables
 *
 *--------------------------------------------------------------------*/

int pio = 1;
module_param(pio, int, S_IRUGO);
MODULE_PARM_DESC(pio,
                 "Set to 0 to prevent this driver from using PIO");
int efrm_is_pio_enabled(void)
  { return pio; }
EXPORT_SYMBOL(efrm_is_pio_enabled);

static int enable_accel_by_default = 1;
module_param(enable_accel_by_default, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(enable_accel_by_default,
                 "Allow Onload acceleration and use of ef_vi of all network "
				 "devices by default. Individual devices may be enabled or "
				 "disabled by writing to "
				 "/proc/driver/sfc_resource/<name>/enable. If this parameter "
				 "is set to zero then devices must be enabled in this way "
				 "to allow Onload acceleration or use of ef_vi.");

#ifdef HAS_COMPAT_PAT_WC
static int compat_pat_wc_inited = 0;
#endif

/*********************************************************************
 *
 * Export efrm_find_ksym()
 *
 *********************************************************************/

#ifdef ERFM_HAVE_NEW_KALLSYMS

struct efrm_ksym_name {
	const char *name;
	void *addr;
};
static int efrm_check_ksym(void *data, const char *name, struct module *mod,
			  unsigned long addr)
{
	struct efrm_ksym_name *t = data;
	if( strcmp(t->name, name) == 0 ) {
		t->addr = (void *)addr;
		return 1;
	}
	return 0;
}
void *efrm_find_ksym(const char *name)
{
	struct efrm_ksym_name t;

	t.name = name;
	t.addr = NULL;
	mutex_lock(&module_mutex);
	kallsyms_on_each_symbol(efrm_check_ksym, &t);
	mutex_unlock(&module_mutex);
	return t.addr;
}
EXPORT_SYMBOL(efrm_find_ksym);

#endif  /* ERFM_HAVE_NEW_KALLSYMS */

/*--------------------------------------------------------------------
 *
 * Linux specific NIC initialisation
 *
 *--------------------------------------------------------------------*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
# define IRQ_PT_REGS_ARG   , struct pt_regs *regs __attribute__ ((unused))
#else
# define IRQ_PT_REGS_ARG
#endif

#ifndef IRQF_SHARED
# define IRQF_SHARED SA_SHIRQ
#endif


/* Free buffer table entries allocated for a particular NIC.
 */
static int iomap_bar(struct linux_efhw_nic *lnic, size_t len)
{
	volatile char __iomem *ioaddr;

	ioaddr = efx_ioremap(lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr, len);
	if (ioaddr == 0)
		return -ENOMEM;

	lnic->efrm_nic.efhw_nic.bar_ioaddr = ioaddr;
	return 0;
}

static int linux_efhw_nic_map_ctr_ap(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	int rc;

	if (nic->ctr_ap_bytes == 0)
		return 0;

	rc = iomap_bar(lnic, nic->ctr_ap_bytes);

	/* Bug 5195: workaround for now. */
	if (rc != 0 && nic->ctr_ap_bytes > 16 * 1024 * 1024) {
		/* Try half the size for now. */
		nic->ctr_ap_bytes /= 2;
		EFRM_WARN("Bug 5195 WORKAROUND: retrying iomap of %d bytes",
			  nic->ctr_ap_bytes);
		rc = iomap_bar(lnic, nic->ctr_ap_bytes);
	}
	if (rc < 0) {
		EFRM_ERR("Failed (%d) to map bar (%d bytes)",
			 rc, nic->ctr_ap_bytes);
		return rc;
	}

	return rc;
}


/* Determines whether the control BAR for the device [dev] is where we expect
 * it to be for the NIC [nic]. This is a requirement for hotplug
 * revivification. */
static inline int
efrm_nic_bar_is_good(struct efhw_nic* nic, struct pci_dev* dev)
{
	return nic->ctr_ap_dma_addr == pci_resource_start(dev, nic->ctr_ap_bar);
}


static int
linux_efrm_nic_ctor(struct linux_efhw_nic *lnic, struct efx_dl_device *dl_device,
		    spinlock_t *reg_lock, unsigned nic_flags,
		    struct net_device *net_dev,
		    const struct vi_resource_dimensions *res_dim,
		    struct efhw_device_type *dev_type)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;
	int rc;
	unsigned map_min, map_max;
	unsigned vi_base = 0;
	unsigned vi_shift = 0;
	unsigned mem_bar = EFHW_MEM_BAR_UNDEFINED;
	unsigned vi_stride = 0;
#if EFX_DRIVERLINK_API_VERSION < 25
	unsigned vport_id = 0;
#endif
	struct pci_dev *dev = dl_device->pci_dev;

	/* Tie the lifetime of the kernel's state to that of our own. */
	pci_dev_get(dev);
	dev_hold(net_dev);

	if (dev_type->arch == EFHW_ARCH_EF10) {
		map_min = res_dim->vi_min;
		map_max = res_dim->vi_lim;
		vi_base = res_dim->vi_base;
		vi_shift = res_dim->vi_shift;
		if( res_dim->mem_bar != VI_RES_MEM_BAR_UNDEFINED )
			mem_bar = res_dim->mem_bar;
		vi_stride = res_dim->vi_stride;
#if EFX_DRIVERLINK_API_VERSION < 25
		vport_id = res_dim->vport_id;
#endif
	}
	else if (dev_type->arch == EFHW_ARCH_FALCON) {
		map_min = CI_MIN(res_dim->evq_int_min, res_dim->evq_timer_min);
		map_min = CI_MAX(map_min, res_dim->rxq_min);
		map_min = CI_MAX(map_min, res_dim->txq_min);
		
		map_max = CI_MAX(res_dim->evq_int_lim, res_dim->evq_timer_lim);
		map_max = CI_MIN(map_max, res_dim->rxq_lim);
		map_max = CI_MIN(map_max, res_dim->txq_lim);
	}
	else {
		rc = -EINVAL;
		goto fail;
	}

	efhw_nic_init(nic, nic_flags, NIC_OPT_DEFAULT, dev_type, map_min,
		      map_max, vi_base, vi_shift, mem_bar, vi_stride
#if EFX_DRIVERLINK_API_VERSION < 25
		      , vport_id
#endif
		      );
	lnic->efrm_nic.efhw_nic.pci_dev = dev;
	lnic->efrm_nic.efhw_nic.net_dev = net_dev;
	lnic->efrm_nic.efhw_nic.bus_number = dev->bus->number;
	lnic->efrm_nic.efhw_nic.domain = pci_domain_nr(dev->bus);
	lnic->efrm_nic.efhw_nic.ctr_ap_dma_addr =
		pci_resource_start(dev, nic->ctr_ap_bar);
	EFRM_ASSERT(efrm_nic_bar_is_good(nic, dev));

	spin_lock_init(&lnic->efrm_nic.efhw_nic.pci_dev_lock);
	init_rwsem(&lnic->dl_sem);

	rc = linux_efhw_nic_map_ctr_ap(lnic);
	if (rc < 0)
		goto fail;

	rc = efrm_nic_ctor(&lnic->efrm_nic, res_dim);
	if (rc < 0) {
		if (nic->bar_ioaddr) {
			iounmap(nic->bar_ioaddr);
			nic->bar_ioaddr = 0;
		}
		goto fail;
	}

	/* By default struct efhw_nic contains its own lock for protecting
	 * access to nic registers.  We override it with a pointer to the
	 * lock in the net driver.  This is needed when resource and net
	 * drivers share a single PCI function (falcon B series).
	 */
	if (dev_type->arch == EFHW_ARCH_FALCON)
		nic->reg_lock = reg_lock;

	if (enable_accel_by_default)
		lnic->efrm_nic.rnic_flags |= EFRM_NIC_FLAG_ADMIN_ENABLED;

	efrm_init_resource_filter(&dev->dev, net_dev->ifindex);

	return 0;

fail:
	pci_dev_put(dev);
	dev_put(net_dev);
	return rc;
}


/* This should be called instead of linux_efrm_nic_ctor() when reusing existing
 * NIC state (i.e. when a new NIC is compatible with one that had gone away).
 */
static void
linux_efrm_nic_reclaim(struct linux_efhw_nic *lnic,
                       struct efx_dl_device *dl_device,
		       struct net_device *net_dev,
		       const struct vi_resource_dimensions *res_dim,
                       struct efhw_device_type *dev_type)
{
	struct efhw_nic* nic = &lnic->efrm_nic.efhw_nic;
	struct pci_dev* old_pci_dev;
	struct pci_dev* dev = dl_device->pci_dev;
#ifndef NDEBUG
	struct net_device* old_net_dev;
#endif

	/* Replace the net & pci devs */
	pci_dev_get(dev);
	dev_hold(net_dev);
	spin_lock_bh(&nic->pci_dev_lock);
	old_pci_dev = nic->pci_dev;
	nic->pci_dev = dev;
#ifndef NDEBUG
	old_net_dev = nic->net_dev;
#endif
	nic->net_dev = net_dev;
	spin_unlock_bh(&nic->pci_dev_lock);

	/* Tidy up old state. */
	efrm_shutdown_resource_filter(&old_pci_dev->dev);

	/* Bring up new state. */
	nic->domain = pci_domain_nr(dev->bus);
	nic->bus_number = dev->bus->number;
	if (dev_type->arch == EFHW_ARCH_EF10) {
		nic->vi_base = res_dim->vi_base;
#if EFX_DRIVERLINK_API_VERSION < 25
		nic->vport_id = res_dim->vport_id;
#endif
	}
	efrm_init_resource_filter(&nic->pci_dev->dev, net_dev->ifindex);

	/* Drop reference to [old_pci_dev] now that the race window has been
	 * closed for someone else trying to take out a new reference. */
	pci_dev_put(old_pci_dev);
	EFRM_ASSERT(old_net_dev == NULL);
}

static void linux_efrm_nic_dtor(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;

	efrm_nic_dtor(&lnic->efrm_nic);
	efhw_nic_dtor(nic);

	if (nic->bar_ioaddr) {
		iounmap(nic->bar_ioaddr);
		nic->bar_ioaddr = 0;
	}
	efrm_shutdown_resource_filter(&nic->pci_dev->dev);
	pci_dev_put(nic->pci_dev);
	EFRM_ASSERT(nic->net_dev == NULL);
}

static void efrm_dev_show(struct pci_dev *dev, int revision,
			  struct efhw_device_type *dev_type, int ifindex,
			  const struct vi_resource_dimensions *res_dim)
{
	const char *dev_name = pci_name(dev) ? pci_name(dev) : "?";
	EFRM_NOTICE("%s pci_dev=%04x:%04x(%d) type=%d:%c%d ifindex=%d",
		    dev_name, (unsigned) dev->vendor, (unsigned) dev->device,
		    revision, dev_type->arch, dev_type->variant,
		    dev_type->revision, ifindex);
	if( dev_type->arch == EFHW_ARCH_FALCON )
		EFRM_NOTICE("%s evq_timer=%d-%d buf_tbl=%d-%d rxq=%d-%d "
			    "txq=%d-%d rx_chans=%d", dev_name,
			    res_dim->evq_timer_min, res_dim->evq_timer_lim,
			    res_dim->bt_min, res_dim->bt_lim, res_dim->rxq_min,
			    res_dim->rxq_lim, res_dim->txq_min, res_dim->txq_lim,
			    res_dim->rss_channel_count);
}


/* Determines whether a known NIC is equivalent to one that would be
 * instantiated according to a [pci_dev] and an [efhw_device_type]. The
 * intended use-case is to check whether a new NIC can step into the shoes of
 * one that went away. */
static inline int
efrm_nic_matches_device(struct efhw_nic* nic, const struct pci_dev* dev,
			const struct efhw_device_type* dev_type)
{
	struct pci_dev* nic_dev = efhw_nic_get_pci_dev(nic);
	int result = nic->domain           == pci_domain_nr(dev->bus) &&
		     nic->bus_number	   == dev->bus->number	 &&
		     nic_dev->devfn	   == dev->devfn	 &&
		     nic_dev->device	   == dev->device	 &&
		     nic->devtype.arch	   == dev_type->arch	 &&
		     nic->devtype.revision == dev_type->revision &&
		     nic->devtype.variant  == dev_type->variant;
	pci_dev_put(nic_dev);
	return result;
}


/* A count of how many NICs this driver knows about. */
static int n_nics_probed;


/****************************************************************************
 *
 * procfs 'enable' file stuff
 *
 ****************************************************************************/


static ssize_t efrm_nic_enable_write(struct file *file,
                                     const char __user *ubuf,
                                     size_t count, loff_t *ppos)
{
	struct linux_efhw_nic* lnic = PDE_DATA(file_inode(file));
	struct efrm_nic* nic = &lnic->efrm_nic;
	int enable;

	/* kstrtobool would be preferable, but it's 4.6+ only (and RHEL7) */
	int rc = kstrtoint_from_user(ubuf, count, 10, &enable);
	if (rc) {
		EFRM_ERR("%s: Invalid data in dev/enable write, rc=%d.",
		         __func__, rc);
		return rc;
	}

	spin_lock_bh(&nic->lock);
	if (enable)
		nic->rnic_flags |= EFRM_NIC_FLAG_ADMIN_ENABLED;
	else
		nic->rnic_flags &=~ EFRM_NIC_FLAG_ADMIN_ENABLED;
	spin_unlock_bh(&nic->lock);

	return count;
}


static int efrm_nic_enable_read_proc(struct seq_file *seq, void *s)
{
	struct linux_efhw_nic* lnic = seq->private;
	struct efrm_nic* nic = &lnic->efrm_nic;
	int enable;

	spin_lock_bh(&nic->lock);
	enable = (nic->rnic_flags & EFRM_NIC_FLAG_ADMIN_ENABLED) != 0;
	spin_unlock_bh(&nic->lock);
	seq_printf(seq, "%d\n", enable);
	return 0;
}


static int efrm_nic_enable_open_proc(struct inode *inode, struct file *file)
{
	return single_open(file, efrm_nic_enable_read_proc, PDE_DATA(inode));
}


static const struct proc_ops efrm_nic_enable_fops_proc = {
	PROC_OPS_SET_OWNER
	.proc_open	= efrm_nic_enable_open_proc,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write     = efrm_nic_enable_write,
	.proc_release	= single_release,
};


static void efrm_nic_proc_intf_added(const char* intf_name,
                                     struct linux_efhw_nic* nic)
{
	EFRM_ASSERT(nic->proc_dir == NULL);
	EFRM_ASSERT(nic->enable_file == NULL);
	nic->proc_dir = efrm_proc_intf_dir_get(intf_name);
	if (nic->proc_dir) {
		nic->enable_file = efrm_proc_create_file("enable", 0644,
		                                         nic->proc_dir,
		                                         &efrm_nic_enable_fops_proc,
												 nic);
	}
	/* efrm_proc_* already logged warnings on error, no need to log more
	 * here */
}


static void efrm_nic_proc_intf_removed(struct linux_efhw_nic* nic)
{
	if (nic->enable_file) {
		EFRM_ASSERT(nic->proc_dir != NULL);
		efrm_proc_remove_file(nic->enable_file);
		nic->enable_file = NULL;
	}
	if (nic->proc_dir) {
		efrm_proc_intf_dir_put(nic->proc_dir);
		nic->proc_dir = NULL;
	}
}



/****************************************************************************
 *
 * efrm_nic_add: add the NIC to the resource driver
 *
 * NOTE: the flow of control through this routine is quite subtle
 * because of the number of operations that can fail. We therefore
 * take the apporaching of keeping the return code (rc) variable
 * accurate, and only do operations while it is non-negative. Tear down
 * is done at the end if rc is negative, depending on what has been set up
 * by that point.
 *
 * So basically just make sure that any code you add checks rc>=0 before
 * doing any work and you'll be fine.
 *
 ****************************************************************************/
int
efrm_nic_add(struct efx_dl_device *dl_device, unsigned flags, 
	     struct net_device *net_dev,
	     struct linux_efhw_nic **lnic_out, spinlock_t *reg_lock,
	     const struct vi_resource_dimensions *res_dim,
	     unsigned timer_quantum_ns, unsigned rx_prefix_len,
	     unsigned rx_usr_buf_size)
{
	struct efhw_device_type dev_type;
	struct linux_efhw_nic *lnic = NULL;
	struct efrm_nic *efrm_nic = NULL;
	struct efhw_nic *nic = NULL;
	struct pci_dev *dev = dl_device->pci_dev;
	int count = 0, rc = 0, resources_init = 0;
	int constructed = 0;
	int registered_nic = 0;
	u8 class_revision;
	int nic_index;
	int nics_probed_delta = 0;
	struct efhw_nic* old_nic;

	rc = pci_read_config_byte(dev, PCI_CLASS_REVISION, &class_revision);
	if (rc != 0) {
		EFRM_ERR("%s: pci_read_config_byte failed (%d)",
			 __func__, rc);
		return rc;
	}
	if (!efhw_device_type_init(&dev_type, dev->vendor, dev->device,
				   class_revision)) {
		EFRM_ERR("%s: efhw_device_type_init failed %04x:%04x(%d)",
			 __func__, (unsigned) dev->vendor,
			 (unsigned) dev->device, (int) class_revision);
		return -ENODEV;
	}

	efrm_dev_show(dev, class_revision, &dev_type, net_dev->ifindex, res_dim);

	if (n_nics_probed == 0) {
		rc = efrm_resources_init();
		if (rc != 0)
			goto failed;
		resources_init = 1;
	}

	spin_lock_bh(&efrm_nic_tablep->lock);
	EFRM_FOR_EACH_NIC(nic_index, old_nic) {
		/* We would like to break out of this loop after rediscovering
		 * a NIC, but the EFRM_FOR_EACH_NIC construct doesn't allow
		 * this, so instead we check explicitly that we haven't set
		 * [lnic] yet. */
		if (lnic == NULL && old_nic != NULL &&
		    efrm_nic_matches_device(old_nic, dev, &dev_type)) {
			EFRM_ASSERT(old_nic->resetting);
			if (efrm_nic_bar_is_good(old_nic, dev)) {
				EFRM_NOTICE("%s: Rediscovered nic_index %d",
					    __func__, nic_index);
				lnic = linux_efhw_nic(old_nic);
			}
			else {
				EFRM_WARN("%s: New device matches nic_index %d "
					  "but has different BAR. Existing "
					  "Onload stacks will not use the new "
					  "device.",
					  __func__, nic_index);
			}
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);
	/* We can drop the lock now as [lnic] will not go away until the module
	 * unloads. */

	if (lnic != NULL) {
		linux_efrm_nic_reclaim(lnic, dl_device, net_dev, res_dim,
				       &dev_type);
		/* We have now taken ownership of the state and should pull it
		 * down on failure. */
		constructed = registered_nic = 1;
	}
	else {
		/* Allocate memory for the new adapter-structure. */
		lnic = kmalloc(sizeof(*lnic), GFP_KERNEL);
		if (lnic == NULL) {
			EFRM_ERR("%s: ERROR: failed to allocate memory",
				 __func__);
			rc = -ENOMEM;
			goto failed;
		}
		memset(lnic, 0, sizeof(*lnic));

		lnic->ev_handlers = &ev_handler;

		/* OS specific hardware mappings */
		rc = linux_efrm_nic_ctor(lnic, dl_device, reg_lock, flags,
					 net_dev, res_dim, &dev_type);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: linux_efrm_nic_ctor failed (%d)",
				 __func__, rc);
			goto failed;
		}
		constructed = 1;

		/* Tell the driver about the NIC - this needs to be done before
		   the resources managers get created below. Note we haven't
		   initialised the hardware yet, and I don't like doing this
		   before the perhaps unreliable hardware initialisation.
		   However, there's quite a lot of code to review if we wanted
		   to hardware init before bringing up the resource managers.
		   */
		rc = efrm_driver_register_nic(&lnic->efrm_nic);
		if (rc < 0) {
			EFRM_ERR("%s: ERROR: efrm_driver_register_nic failed "
				 "(%d)", __func__, rc);
			goto failed;
		}
		registered_nic = 1;

		++nics_probed_delta;

		efrm_nic_proc_intf_added(net_dev->name, lnic);
	}

	lnic->dl_device = dl_device;
	efrm_nic = &lnic->efrm_nic;
	nic = &efrm_nic->efhw_nic;
	efrm_driverlink_resume(efrm_nic);

	if( timer_quantum_ns )
		nic->timer_quantum_ns = timer_quantum_ns;

	/* Falcon only */
	nic->rx_prefix_len = rx_prefix_len;
	nic->rx_usr_buf_size = rx_usr_buf_size;

	/* There is a race here: we need to clear [nic->resetting] so that
	 * efhw_nic_init_hardware() can do MCDI, but that means that any
	 * existing clients can also attempt MCDI, potentially before
	 * efhw_nic_init_hardware() completes. NIC resets already suffer from
	 * an equivalent race. TODO: Fix this, perhaps by introducing an
	 * intermediate degree of resetting-ness during which we can do MCDI
	 * but no-one else can. */
	ci_wmb();
	nic->resetting = 0;

	/****************************************************/
	/* hardware bringup                                 */
	/****************************************************/
	/* Detecting hardware can be a slightly unreliable process;
	   we want to make sure that we maximise our chances, so we
	   loop a few times until all is good. */
	for (count = 0; count < max_hardware_init_repeats; count++) {
		rc = efhw_nic_init_hardware(nic, &ev_handler, net_dev->dev_addr,
					    res_dim->non_irq_evq, 
					    res_dim->bt_min, res_dim->bt_lim);
		if (rc >= 0)
			break;

		/* pain */
		EFRM_TRACE("%s hardware init failed (%d, attempt %d of %d)",
			   pci_name(dev) ? pci_name(dev) : "?",
			   rc, count + 1, max_hardware_init_repeats);
	}
	if (rc < 0) {
		/* Again, PCI VFs may be available. */
		EFRM_ERR("%s: ERROR: hardware init failed rc=%d",
			 pci_name(dev) ? pci_name(dev) : "?", rc);
	}

        efrm_resource_manager_add_total(EFRM_RESOURCE_VI,
                                        efrm_nic->max_vis);
        efrm_resource_manager_add_total(EFRM_RESOURCE_PD,
                                        efrm_nic->max_vis);

	/* Tell NIC to spread wakeup events. */
	if (nic->devtype.arch == EFHW_ARCH_FALCON) {
		int n_int = 1;
		while ((n_int << 1) <= res_dim->rss_channel_count)
			n_int <<= 1;
		efrm_nic->falcon_wakeup_mask = n_int - 1;
		if (efrm_nic->falcon_wakeup_mask > 0)
			falcon_nic_wakeup_mask_set(
				nic, efrm_nic->falcon_wakeup_mask);
	}
	efrm_nic->rss_channel_count = res_dim->rss_channel_count;

	EFRM_NOTICE("%s index=%d ifindex=%d",
		    pci_name(dev) ? pci_name(dev) : "?",
		    nic->index, net_dev->ifindex);

        efrm_nic->dmaq_state.unplugging = 0;

	*lnic_out = lnic;
	n_nics_probed += nics_probed_delta;
	efrm_nic_enable_post_reset(nic);
	efrm_nic_post_reset(nic);

	return 0;

failed:
	if (registered_nic)
		efrm_driver_unregister_nic(efrm_nic);
	if (constructed)
		linux_efrm_nic_dtor(lnic);
	kfree(lnic); /* safe in any case */
	if (resources_init)
		efrm_resources_fini();
	return rc;
}


void
efrm_nic_rename(struct efhw_nic* nic, struct net_device *net_dev)
{
	struct linux_efhw_nic* lnic = linux_efhw_nic(nic);
	EFRM_ASSERT(nic != NULL);
	EFRM_ASSERT(net_dev != NULL);
	efrm_nic_proc_intf_removed(lnic);
	efrm_nic_proc_intf_added(net_dev->name, lnic);
}


int
efrm_nic_unplug(struct efhw_nic* nic, struct efx_dl_device *dl_device)
{
	struct net_device* net_dev;

	/* We keep the pci device to reclaim it after hot-plug, but release
	 * the net device. */
	spin_lock_bh(&nic->pci_dev_lock);
	net_dev = nic->net_dev;
	nic->net_dev = NULL;
	spin_unlock_bh(&nic->pci_dev_lock);

	EFRM_ASSERT(net_dev != NULL);
	dev_put(net_dev);

	return 0;
}


/****************************************************************************
 *
 * efrm_nic_shutdown: Shut down our access to the NIC hw
 *
 ****************************************************************************/
static void efrm_nic_shutdown(struct linux_efhw_nic *lnic)
{
	struct efhw_nic *nic = &lnic->efrm_nic.efhw_nic;

	EFRM_TRACE("%s:", __func__);
	EFRM_ASSERT(nic);

	efrm_vi_wait_nic_complete_flushes(nic);
	linux_efrm_nic_dtor(lnic);

        efrm_resource_manager_del_total(EFRM_RESOURCE_VI,
                                        lnic->efrm_nic.max_vis);
        efrm_resource_manager_del_total(EFRM_RESOURCE_PD,
                                        lnic->efrm_nic.max_vis);

	EFRM_TRACE("%s: done", __func__);
}
/****************************************************************************
 *
 * efrm_nic_del: Remove the nic from the resource driver structures
 *
 ****************************************************************************/
static void efrm_nic_del(struct linux_efhw_nic *lnic)
{
	EFRM_TRACE("%s:", __func__);

	efrm_driver_unregister_nic(&lnic->efrm_nic);
	efrm_nic_proc_intf_removed(lnic);

	/* Close down hardware and free resources. */
	if (--n_nics_probed == 0)
		efrm_resources_fini();

	kfree(lnic);

	EFRM_TRACE("%s: done", __func__);
}


/****************************************************************************
 *
 * efrm_nic_del_all: Shut down our access to any hw or driverlink
 *
 ****************************************************************************/
static void efrm_nic_shutdown_all(void)
{
	int i;
	struct efhw_nic* nic;

	EFRM_FOR_EACH_NIC(i, nic)
		efrm_nic_shutdown(linux_efhw_nic(nic));
}
/****************************************************************************
 *
 * efrm_nic_del_all: Delete all remaining efrm_nics. Call this before
 * efrm_driver_stop().
 *
 ****************************************************************************/
static void efrm_nic_del_all(void)
{
	int i;
	struct efhw_nic* nic;

	EFRM_FOR_EACH_NIC(i, nic)
		efrm_nic_del(linux_efhw_nic(nic));
}


/****************************************************************************
 *
 * init_module: register as a PCI driver.
 *
 ****************************************************************************/
static int init_sfc_resource(void)
{
	int rc = 0;

	EFRM_TRACE("%s: RESOURCE driver starting", __func__);

	rc = efrm_syscall_ctor();
	if( rc != 0 ) {
		EFRM_ERR("%s: ERROR: failed to find syscall table", __func__);
		return rc;
	}

	efrm_driver_ctor();
	efrm_filter_init();

        /* efrm_driverlink_register() attempts to create files in
         * /proc, so it is important that /proc is initialised
         * first. */

	if (efrm_install_proc_entries() != 0) {
		/* Do not fail, but print a warning */
		EFRM_WARN("%s: WARNING: failed to install /proc entries",
			  __func__);
	}
	efrm_filter_install_proc_entries();

	/* Register the driver so that our 'probe' function is called for
	 * each EtherFabric device in the system.
	 */
	rc = efrm_driverlink_register();
	if (rc == -ENODEV)
		EFRM_ERR("%s: no devices found", __func__);
	if (rc < 0)
		goto failed_driverlink;

#ifdef HAS_COMPAT_PAT_WC
	compat_pat_wc_inited = 0;
	if (pio)
		if (compat_pat_wc_init() == 0)
			compat_pat_wc_inited = 1;
#endif

	return 0;

failed_driverlink:
	efrm_filter_remove_proc_entries();
	efrm_uninstall_proc_entries();
	efrm_driver_stop();
	efrm_filter_shutdown();
	efrm_driver_dtor();
	return rc;
}

/****************************************************************************
 *
 * cleanup_module: module-removal entry-point
 *
 ****************************************************************************/
static void cleanup_sfc_resource(void)
{
#ifdef HAS_COMPAT_PAT_WC
	if (compat_pat_wc_inited) {
		compat_pat_wc_inited = 0;
		compat_pat_wc_shutdown();
	}
#endif

	/* Unregister from driverlink first, free
	 * the per-NIC structures next. */
	efrm_driverlink_unregister();
	efrm_nic_shutdown_all();
	efrm_nic_del_all();

	efrm_filter_shutdown();
	efrm_filter_remove_proc_entries();
	efrm_uninstall_proc_entries();

	efrm_driver_stop();

	/* Clean up char-driver specific initialisation.
	   - driver dtor can use both work queue and buffer table entries */
	efrm_driver_dtor();

	EFRM_TRACE("%s: unloaded", __func__);
}

module_init(init_sfc_resource);
module_exit(cleanup_sfc_resource);
