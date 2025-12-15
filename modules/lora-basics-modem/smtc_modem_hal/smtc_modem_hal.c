/*
 * Copyright (c) 2025 Carlo Caione <carlo.caione@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lbm_common.h>
#include <smtc_modem_hal.h>
#include <smtc_modem_hal_ext.h>

LOG_MODULE_REGISTER(smtc_modem_hal, CONFIG_LORA_LOG_LEVEL);

#define HAL_WORKQ_STACK_SIZE 1024
#define HAL_WORKQ_PRIORITY (-1)

typedef void (*callback_t)(void *context);

struct cb_data_t {
	struct gpio_callback cb;
	struct k_work work;
	callback_t dio_cb;
	void *context;
};

struct timer_data_t {
	struct k_timer timer;
	callback_t timer_cb;
	void *context;
};

static struct cb_data_t prv_cb_data;
static struct timer_data_t prv_timer_data;

static const struct device *prv_transceiver_dev;

static K_THREAD_STACK_DEFINE(hal_workq_stack, HAL_WORKQ_STACK_SIZE);
static struct k_work_q hal_workq;

static void hal_irq_work_handler(struct k_work *work)
{
	struct cb_data_t *data = CONTAINER_OF(work, struct cb_data_t, work);

	if (data->dio_cb != NULL) {
		data->dio_cb(data->context);
	}
}

static void hal_irq_callback(const struct device *port, struct gpio_callback *cb, uint32_t pins)
{
	struct cb_data_t *data = CONTAINER_OF(cb, struct cb_data_t, cb);

	k_work_submit_to_queue(&hal_workq, &data->work);
}

static void hal_timer_callback(struct k_timer *timer)
{
	struct timer_data_t *data = CONTAINER_OF(timer, struct timer_data_t, timer);

	if (data->timer_cb != NULL) {
		data->timer_cb(data->context);
	}
}

void smtc_modem_hal_init(const struct device *transceiver)
{
	__ASSERT(transceiver, "transceiver must be provided");
	__ASSERT(DEVICE_API_IS(lora, transceiver), "transceiver must be a LoRa device");

	prv_transceiver_dev = transceiver;

	k_work_queue_start(&hal_workq, hal_workq_stack,
			   K_THREAD_STACK_SIZEOF(hal_workq_stack),
			   HAL_WORKQ_PRIORITY, NULL);
	k_thread_name_set(&hal_workq.thread, "lbm_hal_workq");

	k_work_init(&prv_cb_data.work, hal_irq_work_handler);
	k_timer_init(&prv_timer_data.timer, hal_timer_callback, NULL);
}

void smtc_modem_hal_irq_config_radio_irq(callback_t dio_cb, void *context)
{
	int ret;

	__ASSERT(dio_cb, "DIO1 callback must be provided");

	if (prv_cb_data.dio_cb != NULL) {
		ret = lbm_driver_remove_dio1_gpio_callback(prv_transceiver_dev, &prv_cb_data.cb);
		if (ret < 0) {
			LOG_ERR("Failed to remove DIO1 GPIO callback: %d", ret);
		}
	}

	prv_cb_data.dio_cb = dio_cb;
	prv_cb_data.context = context;

	gpio_init_callback(&prv_cb_data.cb, hal_irq_callback, 0);

	ret = lbm_driver_add_dio1_gpio_callback(prv_transceiver_dev, &prv_cb_data.cb);
	if (ret < 0) {
		LOG_ERR("Failed to add DIO1 GPIO callback: %d", ret);
	}
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

uint32_t smtc_modem_hal_get_time_in_s(void)
{
	return k_uptime_seconds();
}

uint32_t smtc_modem_hal_get_time_in_ms(void)
{
	return k_uptime_get_32();
}

uint32_t smtc_modem_hal_get_radio_tcxo_startup_delay_ms(void)
{
	return 0;
}

void smtc_modem_hal_start_timer(const uint32_t milliseconds, callback_t callback, void *context)
{
	prv_timer_data.timer_cb = callback;
	prv_timer_data.context = context;

	k_timer_start(&prv_timer_data.timer, K_MSEC(milliseconds), K_NO_WAIT);
}

void smtc_modem_hal_stop_timer(void)
{
	k_timer_stop(&prv_timer_data.timer);
}

