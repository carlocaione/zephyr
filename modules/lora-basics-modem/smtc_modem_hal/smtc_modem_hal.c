/*
 * Copyright (c) 2025 Carlo Caione <carlo.caione@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/gpio.h>

#include <lbm_common.h>
#include <smtc_modem_hal.h>
#include <smtc_modem_hal_ext.h>

typedef void (*dio_callback_t)(void *context);

struct cb_data_t {
	struct gpio_callback cb;
	dio_callback_t dio_cb;
	void *context;
};

static const struct device *prv_transceiver_dev;

void smtc_modem_hal_init(const struct device *transceiver)
{
	__ASSERT(transceiver, "transceiver must be provided");
	__ASSERT(DEVICE_API_IS(lora, transceiver), "transceiver must be a LoRa device");

	prv_transceiver_dev = transceiver;
}

static void hal_irq_callback(const struct device *port, struct gpio_callback *cb, uint32_t pins)
{
	struct cb_data_t *data = CONTAINER_OF(cb, struct cb_data_t, cb);

	if (data->dio_cb != NULL) {
		data->dio_cb(data->context);
	}
}

void smtc_modem_hal_irq_config_radio_irq(dio_callback_t dio_cb, void *context)
{
	static struct cb_data_t cb_data;

	cb_data.dio_cb = dio_cb;
	cb_data.context = context;

	gpio_init_callback(&cb_data.cb, hal_irq_callback, 0);
	lbm_driver_add_dio1_gpio_callback(prv_transceiver_dev, &cb_data.cb);

}

void smtc_modem_hal_start_radio_tcxo(void)
{
	/*
	 * We only support TCXO's that are wired to the transceiver. In such cases,
	 * this function must be empty. See 5.25 of the porting guide.
	 */
}

void smtc_modem_hal_set_ant_switch(bool is_tx_on)
{
	/*
	 * From the porting guide:
	 * If no antenna switch is used then implement an empty command.
	 */
}

void smtc_modem_hal_stop_radio_tcxo(void)
{
	/*
	 * We only support TCXO's that are wired to the transceiver. In such cases,
	 * this function must be empty. See 5.26 of the porting guide.
	 */
}

