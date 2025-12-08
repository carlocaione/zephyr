/*
 * Copyright (c) 2025 Carlo Caione <carlo.caione@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>

#include <smtc_modem_hal.h>
#include <smtc_modem_hal_ext.h>

static const struct device *prv_transceiver_dev;

void smtc_modem_hal_init(const struct device *transceiver)
{
	__ASSERT(transceiver, "transceiver must be provided");
	__ASSERT(DEVICE_API_IS(lora, transceiver), "transceiver must be a LoRa device");

	prv_transceiver_dev = transceiver;
}

void smtc_modem_hal_irq_config_radio_irq(void (*callback)(void *context), void *context)
{

}
