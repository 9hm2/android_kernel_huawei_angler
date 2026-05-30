/*
 * Broadcom Dongle Host Driver (DHD), Linux monitor network interface
 *
 * Copyright (C) 1999-2014, Broadcom Corporation
 * 
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 * 
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 * 
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 * $Id: wl_linux_mon.c 467328 2014-04-03 01:23:40Z $
 */

#include <osl.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/ieee80211.h>
#include <linux/rtnetlink.h>
#include <net/ieee80211_radiotap.h>
#ifdef CONFIG_BCMDHD_MONITOR_MODE
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <net/cfg80211.h>	/* full struct wireless_dev for ieee80211_ptr setup */
#endif /* CONFIG_BCMDHD_MONITOR_MODE */

#include <wlioctl.h>
#include <bcmutils.h>
#include <dhd_dbg.h>
#include <dngl_stats.h>
#include <dhd.h>

typedef enum monitor_states
{
	MONITOR_STATE_DEINIT = 0x0,
	MONITOR_STATE_INIT = 0x1,
	MONITOR_STATE_INTERFACE_ADDED = 0x2,
	MONITOR_STATE_INTERFACE_DELETED = 0x4
} monitor_states_t;
int dhd_add_monitor(char *name, struct net_device **new_ndev, void *wdev);
extern int dhd_start_xmit(struct sk_buff *skb, struct net_device *net);
int dhd_del_monitor(struct net_device *ndev);
int dhd_monitor_init(void *dhd_pub);
int dhd_monitor_uninit(void);

/**
 * Local declarations and defintions (not exposed)
 */
#ifndef DHD_MAX_IFS
#define DHD_MAX_IFS 16
#endif
#define MON_PRINT(format, ...) printk("DHD-MON: %s " format, __func__, ##__VA_ARGS__)
#define MON_TRACE MON_PRINT

typedef struct monitor_interface {
	int radiotap_enabled;
	struct net_device* real_ndev;	/* The real interface that the monitor is on */
	struct net_device* mon_ndev;
} monitor_interface;

typedef struct dhd_linux_monitor {
	void *dhd_pub;
	monitor_states_t monitor_state;
	monitor_interface mon_if[DHD_MAX_IFS];
	struct mutex lock;		/* lock to protect mon_if */
#ifdef CONFIG_BCMDHD_MONITOR_MODE
	struct workqueue_struct *inject_wq;	/* serializes frame injection */
	atomic_t inject_pending;	/* frames queued but not yet sent to fw */
#endif /* CONFIG_BCMDHD_MONITOR_MODE */
} dhd_linux_monitor_t;

#ifdef CONFIG_BCMDHD_MONITOR_MODE
/* Upper bound on injection frames queued to the (single-threaded) workqueue
 * but not yet handed to the dongle. Each NEX_INJECT_FRAME ioctl sleeps waiting
 * on the firmware, so an unbounded queue lets a flood (aireplay-ng/wifite) pile
 * up faster than the dongle drains it, eventually timing out (-110) and
 * crashing the chip. Drop frames past this watermark instead.
 */
#define DHD_MON_INJECT_MAX_PENDING	16
#endif /* CONFIG_BCMDHD_MONITOR_MODE */

static dhd_linux_monitor_t g_monitor;

#ifdef CONFIG_BCMDHD_MONITOR_MODE
/* nexmon NEX_INJECT_FRAME ioctl payload: a length-prefixed list of frames.
 * type == 0 -> firmware adds a dummy radiotap header (frame has none);
 * type == 1 -> frame already begins with a radiotap header (our case).
 */
struct dhd_inject_hdr {
	uint16 len;	/* bytes of 'data' for this entry, plus 4 (see fw) */
	uint8  pad;
	uint8  type;
	uint8  data[0];
};

/* Deferred injection work: ndo_start_xmit runs in atomic (softirq) context but
 * dhd_wl_ioctl_cmd sleeps waiting on the dongle, so the actual ioctl must run
 * from process context on a workqueue.
 */
struct dhd_inject_work {
	struct work_struct work;
	struct sk_buff *skb;
};

/* dhd_wl_ioctl_cmd() is declared in dhd.h (already included). */

static void dhd_mon_inject_work(struct work_struct *ws)
{
	struct dhd_inject_work *iw = container_of(ws, struct dhd_inject_work, work);
	struct sk_buff *skb = iw->skb;
	dhd_pub_t *dhdp = (dhd_pub_t *)g_monitor.dhd_pub;
	struct dhd_inject_hdr *frm;
	int buflen, ret;
	char *buf;

	if (!dhdp || !dhdp->monitor_type)
		goto out;

	/* Build the NEX_INJECT_FRAME buffer: one header followed by the frame,
	 * which already carries its radiotap header (type 1). The firmware copies
	 * (frm->len - 4) bytes, so frm->len = framelen + 4. The firmware loop then
	 * advances by frm->len and reads the next entry's length; append a
	 * zero-length terminator (kzalloc-cleared) so it stops without reading
	 * past our buffer.
	 */
	buflen = sizeof(*frm) + skb->len + sizeof(*frm);
	buf = kzalloc(buflen, GFP_KERNEL);
	if (!buf)
		goto out;

	frm = (struct dhd_inject_hdr *)buf;
	frm->len = (uint16)(skb->len + 4);
	frm->pad = 0;
	frm->type = 1;	/* radiotap header present */
	memcpy(frm->data, skb->data, skb->len);

	ret = dhd_wl_ioctl_cmd(dhdp, DHD_NEX_INJECT_FRAME, buf, buflen, TRUE, 0);
	if (ret < 0)
		MON_PRINT("NEX_INJECT_FRAME ioctl failed: %d\n", ret);

	kfree(buf);
out:
	atomic_dec(&g_monitor.inject_pending);
	dev_kfree_skb_any(skb);
	kfree(iw);
}
#endif /* CONFIG_BCMDHD_MONITOR_MODE */

static struct net_device* lookup_real_netdev(char *name);
static monitor_interface* ndev_to_monif(struct net_device *ndev);
static int dhd_mon_if_open(struct net_device *ndev);
static int dhd_mon_if_stop(struct net_device *ndev);
static int dhd_mon_if_subif_start_xmit(struct sk_buff *skb, struct net_device *ndev);
static void dhd_mon_if_set_multicast_list(struct net_device *ndev);
static int dhd_mon_if_change_mac(struct net_device *ndev, void *addr);

static const struct net_device_ops dhd_mon_if_ops = {
	.ndo_open		= dhd_mon_if_open,
	.ndo_stop		= dhd_mon_if_stop,
	.ndo_start_xmit		= dhd_mon_if_subif_start_xmit,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0))
	.ndo_set_rx_mode = dhd_mon_if_set_multicast_list,
#else
	.ndo_set_multicast_list = dhd_mon_if_set_multicast_list,
#endif
	.ndo_set_mac_address 	= dhd_mon_if_change_mac,
};

/**
 * Local static function defintions
 */

/* Look up dhd's net device table to find a match (e.g. interface "eth0" is a match for "mon.eth0"
 * "p2p-eth0-0" is a match for "mon.p2p-eth0-0")
 */
static struct net_device* lookup_real_netdev(char *name)
{
	struct net_device *ndev_found = NULL;

	int i;
	int len = 0;
	int last_name_len = 0;
	struct net_device *ndev;

	/* We need to find interface "p2p-p2p-0" corresponding to monitor interface "mon-p2p-0",
	 * Once mon iface name reaches IFNAMSIZ, it is reset to p2p0-0 and corresponding mon
	 * iface would be mon-p2p0-0.
	 */
	for (i = 0; i < DHD_MAX_IFS; i++) {
		ndev = dhd_idx2net(g_monitor.dhd_pub, i);

		/* Skip "p2p" and look for "-p2p0-x" in monitor interface name. If it
		 * it matches, then this netdev is the corresponding real_netdev.
		 */
		if (ndev && strstr(ndev->name, "p2p-p2p0")) {
			len = strlen("p2p");
		} else {
		/* if p2p- is not present, then the IFNAMSIZ have reached and name
		 * would have got reset. In this casse,look for p2p0-x in mon-p2p0-x
		 */
			len = 0;
		}
		if (ndev && strstr(name, (ndev->name + len))) {
			if (strlen(ndev->name) > last_name_len) {
				ndev_found = ndev;
				last_name_len = strlen(ndev->name);
			}
		}
	}

	return ndev_found;
}

static monitor_interface* ndev_to_monif(struct net_device *ndev)
{
	int i;

	for (i = 0; i < DHD_MAX_IFS; i++) {
		if (g_monitor.mon_if[i].mon_ndev == ndev)
			return &g_monitor.mon_if[i];
	}

	return NULL;
}

static int dhd_mon_if_open(struct net_device *ndev)
{
	int ret = 0;

	MON_PRINT("enter\n");
	return ret;
}

static int dhd_mon_if_stop(struct net_device *ndev)
{
	int ret = 0;

	MON_PRINT("enter\n");
	return ret;
}

static int dhd_mon_if_subif_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	int rtap_len;
	struct ieee80211_radiotap_header *rtap_hdr;
	monitor_interface *mon_if;
#ifdef CONFIG_BCMDHD_MONITOR_MODE
	struct dhd_inject_work *iw;
#endif

	MON_PRINT("enter\n");

	mon_if = ndev_to_monif(ndev);
	if (mon_if == NULL || mon_if->real_ndev == NULL) {
		MON_PRINT(" cannot find matched net dev, skip the packet\n");
		goto fail;
	}

	/* Frames written to the monitor interface are radiotap-prefixed raw
	 * 802.11 frames (aireplay-ng, etc.). Validate the radiotap header before
	 * handing the frame to the firmware.
	 */
	if (unlikely(skb->len < sizeof(struct ieee80211_radiotap_header)))
		goto fail;

	rtap_hdr = (struct ieee80211_radiotap_header *)skb->data;
	if (unlikely(rtap_hdr->it_version))
		goto fail;

	rtap_len = ieee80211_get_radiotap_len(skb->data);
	/* Need the radiotap header plus at least a minimal 802.11 header. */
	if (unlikely(skb->len < rtap_len + 10))
		goto fail;

	MON_PRINT("inject %d bytes (radiotap %d) via %s\n",
		skb->len, rtap_len, mon_if->real_ndev->name);

#ifdef CONFIG_BCMDHD_MONITOR_MODE
	/* Inject through the nexmon NEX_INJECT_FRAME ioctl, which expects the
	 * full radiotap + 802.11 frame and handles every frame type (management,
	 * control, data). Because the ioctl sleeps and we are in the atomic
	 * xmit path, defer it to a workqueue. The skb (incl. radiotap header) is
	 * handed off verbatim and freed by the work item.
	 */
	if (!g_monitor.inject_wq)
		goto fail;

	/* Apply backpressure: if the dongle has not drained previously queued
	 * frames, drop this one rather than letting the queue grow without bound
	 * (which floods the firmware and triggers a -110 timeout / chip crash).
	 */
	if (atomic_inc_return(&g_monitor.inject_pending) >
			DHD_MON_INJECT_MAX_PENDING) {
		atomic_dec(&g_monitor.inject_pending);
		goto fail;
	}

	iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
	if (!iw) {
		atomic_dec(&g_monitor.inject_pending);
		goto fail;
	}

	iw->skb = skb;
	INIT_WORK(&iw->work, dhd_mon_inject_work);
	queue_work(g_monitor.inject_wq, &iw->work);

	return 0;
#else
	goto fail;
#endif /* CONFIG_BCMDHD_MONITOR_MODE */

fail:
	dev_kfree_skb_any(skb);
	return 0;
}

static void dhd_mon_if_set_multicast_list(struct net_device *ndev)
{
	monitor_interface* mon_if;

	mon_if = ndev_to_monif(ndev);
	if (mon_if == NULL || mon_if->real_ndev == NULL) {
		MON_PRINT(" cannot find matched net dev, skip the packet\n");
	} else {
		MON_PRINT("enter, if name: %s, matched if name %s\n",
		ndev->name, mon_if->real_ndev->name);
	}
}

static int dhd_mon_if_change_mac(struct net_device *ndev, void *addr)
{
	int ret = 0;
	monitor_interface* mon_if;

	mon_if = ndev_to_monif(ndev);
	if (mon_if == NULL || mon_if->real_ndev == NULL) {
		MON_PRINT(" cannot find matched net dev, skip the packet\n");
	} else {
		MON_PRINT("enter, if name: %s, matched if name %s\n",
		ndev->name, mon_if->real_ndev->name);
	}
	return ret;
}

/**
 * Global function definitions (declared in dhd_linux_mon.h)
 */

int dhd_add_monitor(char *name, struct net_device **new_ndev, void *wdev)
{
	int i;
	int idx = -1;
	int ret = 0;
	struct net_device* ndev = NULL;
	dhd_linux_monitor_t **dhd_mon;

	mutex_lock(&g_monitor.lock);

	MON_TRACE("enter, if name: %s\n", name);
	if (!name || !new_ndev) {
		MON_PRINT("invalid parameters\n");
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Find a vacancy
	 */
	for (i = 0; i < DHD_MAX_IFS; i++)
		if (g_monitor.mon_if[i].mon_ndev == NULL) {
			idx = i;
			break;
		}
	if (idx == -1) {
		MON_PRINT("exceeds maximum interfaces\n");
		ret = -EFAULT;
		goto out;
	}

	ndev = alloc_etherdev(sizeof(dhd_linux_monitor_t*));
	if (!ndev) {
		MON_PRINT("failed to allocate memory\n");
		ret = -ENOMEM;
		goto out;
	}

	ndev->type = ARPHRD_IEEE80211_RADIOTAP;
	strncpy(ndev->name, name, IFNAMSIZ);
	ndev->name[IFNAMSIZ - 1] = 0;
	ndev->netdev_ops = &dhd_mon_if_ops;
#ifdef CONFIG_BCMDHD_MONITOR_MODE
	/* Attach the wireless_dev the cfg80211 core needs. With P2P_DEV_IF builds
	 * add_virtual_intf returns ndev->ieee80211_ptr, and the nl80211 core
	 * dereferences it during NETDEV_REGISTER; a NULL here panics the kernel.
	 * Both the wdev link and the parent (wiphy) device must be set before
	 * register_netdevice(), because the NETDEV_REGISTER notifier creates a
	 * "phy80211" sysfs link to the parent.
	 */
	if (wdev) {
		ndev->ieee80211_ptr = (struct wireless_dev *)wdev;
		((struct wireless_dev *)wdev)->netdev = ndev;
		SET_NETDEV_DEV(ndev, wiphy_dev(((struct wireless_dev *)wdev)->wiphy));
	}
	/* Free via the core's unregister todo, not a manual free_netdev() after
	 * unregister_netdevice(): under rtnl the unregister is only scheduled, so
	 * an immediate free_netdev() hits BUG_ON(reg_state != UNREGISTERED).
	 */
	ndev->destructor = free_netdev;
#endif /* CONFIG_BCMDHD_MONITOR_MODE */

	ret = register_netdevice(ndev);
	if (ret) {
		MON_PRINT(" register_netdevice failed (%d)\n", ret);
		goto out;
	}

	*new_ndev = ndev;
	g_monitor.mon_if[idx].radiotap_enabled = TRUE;
	g_monitor.mon_if[idx].mon_ndev = ndev;
	g_monitor.mon_if[idx].real_ndev = lookup_real_netdev(name);
	if (g_monitor.mon_if[idx].real_ndev == NULL) {
		/* Monitor names such as "mon0" do not embed the parent interface
		 * name, so the heuristic lookup fails. Fall back to the primary
		 * interface (index 0) so the monitor still shadows a real device
		 * instead of leaving a NULL real_ndev (which the TX/RX paths
		 * dereference).
		 */
		g_monitor.mon_if[idx].real_ndev = dhd_idx2net(g_monitor.dhd_pub, 0);
		MON_PRINT("no name match for %s, defaulting to primary netdev\n", name);
	}
	dhd_mon = (dhd_linux_monitor_t **)netdev_priv(ndev);
	*dhd_mon = &g_monitor;
	g_monitor.monitor_state = MONITOR_STATE_INTERFACE_ADDED;
	MON_PRINT("net device returned: 0x%p\n", ndev);
	if (g_monitor.mon_if[idx].real_ndev)
		MON_PRINT("monitor %s shadows real net device %s\n",
			name, g_monitor.mon_if[idx].real_ndev->name);

out:
	if (ret && ndev)
		free_netdev(ndev);

	mutex_unlock(&g_monitor.lock);
	return ret;

}

#ifdef CONFIG_BCMDHD_MONITOR_MODE
/* Return the registered monitor net_device that shadows real_ndev, so the RX
 * path can deliver radiotap-tagged 802.11 frames to it. NULL if there is no
 * monitor interface for that real device.
 *
 * This is called from the RX datapath, which may run in softirq/interrupt
 * context, so it must not sleep: the g_monitor mutex is intentionally NOT
 * taken here. The mon_if[] table is only mutated from add/delete paths that
 * run under RTNL, and we only read word-sized pointers, so a lockless scan is
 * safe for the purpose of locating the current monitor device.
 */
struct net_device *dhd_mon_lookup_dev(struct net_device *real_ndev)
{
	int i;

	if (!real_ndev)
		return NULL;

	for (i = 0; i < DHD_MAX_IFS; i++) {
		if (g_monitor.mon_if[i].mon_ndev &&
			g_monitor.mon_if[i].real_ndev == real_ndev) {
			return g_monitor.mon_if[i].mon_ndev;
		}
	}

	return NULL;
}
#endif /* CONFIG_BCMDHD_MONITOR_MODE */

int dhd_del_monitor(struct net_device *ndev)
{
	int i;
	if (!ndev)
		return -EINVAL;
	mutex_lock(&g_monitor.lock);
	for (i = 0; i < DHD_MAX_IFS; i++) {
		if (g_monitor.mon_if[i].mon_ndev == ndev ||
			g_monitor.mon_if[i].real_ndev == ndev) {

			g_monitor.mon_if[i].real_ndev = NULL;
			unregister_netdevice(g_monitor.mon_if[i].mon_ndev);
#ifndef CONFIG_BCMDHD_MONITOR_MODE
			free_netdev(g_monitor.mon_if[i].mon_ndev);
#endif /* !CONFIG_BCMDHD_MONITOR_MODE */
			g_monitor.mon_if[i].mon_ndev = NULL;
			g_monitor.monitor_state = MONITOR_STATE_INTERFACE_DELETED;
			break;
		}
	}

	if (g_monitor.monitor_state != MONITOR_STATE_INTERFACE_DELETED)
		MON_PRINT("IF not found in monitor array, is this a monitor IF? 0x%p\n", ndev);
	mutex_unlock(&g_monitor.lock);

	return 0;
}

int dhd_monitor_init(void *dhd_pub)
{
	if (g_monitor.monitor_state == MONITOR_STATE_DEINIT) {
		g_monitor.dhd_pub = dhd_pub;
		mutex_init(&g_monitor.lock);
#ifdef CONFIG_BCMDHD_MONITOR_MODE
		/* Single-threaded so injected frames preserve submission order. */
		g_monitor.inject_wq = create_singlethread_workqueue("dhd_mon_inject");
		if (!g_monitor.inject_wq)
			MON_PRINT("failed to create injection workqueue\n");
		atomic_set(&g_monitor.inject_pending, 0);
#endif /* CONFIG_BCMDHD_MONITOR_MODE */
		g_monitor.monitor_state = MONITOR_STATE_INIT;
	}
	return 0;
}

int dhd_monitor_uninit(void)
{
	int i;
	struct net_device *ndev;
	mutex_lock(&g_monitor.lock);
#ifdef CONFIG_BCMDHD_MONITOR_MODE
	/* Clear cached firmware monitor state so a fresh bring-up does not start
	 * diverting RX frames before monitor mode is actually re-enabled.
	 */
	if (g_monitor.dhd_pub)
		((dhd_pub_t *)g_monitor.dhd_pub)->monitor_type = 0;
	/* Drain and tear down the injection workqueue. The work items do not take
	 * g_monitor.lock, so flushing under the mutex cannot deadlock.
	 */
	if (g_monitor.inject_wq) {
		destroy_workqueue(g_monitor.inject_wq);
		g_monitor.inject_wq = NULL;
	}
#endif /* CONFIG_BCMDHD_MONITOR_MODE */
	if (g_monitor.monitor_state != MONITOR_STATE_DEINIT) {
		for (i = 0; i < DHD_MAX_IFS; i++) {
			ndev = g_monitor.mon_if[i].mon_ndev;
			if (ndev) {
				unregister_netdevice(ndev);
#ifndef CONFIG_BCMDHD_MONITOR_MODE
				free_netdev(ndev);
#endif /* !CONFIG_BCMDHD_MONITOR_MODE */
				g_monitor.mon_if[i].real_ndev = NULL;
				g_monitor.mon_if[i].mon_ndev = NULL;
			}
		}
		g_monitor.monitor_state = MONITOR_STATE_DEINIT;
	}
	mutex_unlock(&g_monitor.lock);
	return 0;
}
