/*
 * Kernel version: linux-v5.0
 * Original file: kernels/linux-v5.0/drivers/ps3/ps3-vuart.c
 * Checker: linuxkernel-use-after-free
 */

				"%s:%d cleared buf_%lu, %llxh bytes\n",
				__func__, __LINE__, lb->dbg_number,
				bytes_written);
			goto port_full;
		}

		dev_dbg(&dev->core, "%s:%d free buf_%lu\n", __func__, __LINE__,
			lb->dbg_number);

		list_del(&lb->link);
/* LINUXGUARD ISSUE: Line 771, Column 3
 * Message: Potential use-after-free vulnerability: Memory freed but possibly accessed later.
 */
		kfree(lb);
	}

	ps3_vuart_disable_interrupt_tx(dev);
port_full:
	spin_unlock_irqrestore(&priv->tx_list.lock, flags);
	dev_dbg(&dev->core, "%s:%d wrote %lxh bytes total\n",
		__func__, __LINE__, bytes_total);
	return result;
}

