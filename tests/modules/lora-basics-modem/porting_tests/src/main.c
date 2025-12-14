/*
 * Copyright (c) 2025 Carlo Caione <ccaione@baylibre.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <smtc_modem_hal_ext.h>
#include <smtc_modem_hal.h>
#include <ralf_sx126x.h>
#include <sx126x.h>

#define NB_LOOP_TEST_SPI 2
#define SYNC_WORD_NO_RADIO 0x21
#define FREQ_NO_RADIO 868300000

#define DEFAULT_RADIO_NODE DT_ALIAS(lora0)
BUILD_ASSERT(DT_NODE_HAS_STATUS_OKAY(DEFAULT_RADIO_NODE),
	     "No default LoRa radio specified in DT");

struct lbm_porting_fixture {
	ralf_t modem_radio;
	const struct device *transceiver;
	volatile bool radio_irq_raised;
	ralf_params_lora_t rx_lora_param;
};

/* Radio IRQ callback (runs in thread context via HAL work queue) */
static void radio_rx_irq_callback(void *context)
{
	struct lbm_porting_fixture *fixture = (struct lbm_porting_fixture *)context;

	fixture->radio_irq_raised = true;

	/* Clear IRQ status */
	ral_clear_irq_status(&fixture->modem_radio.ral, RAL_IRQ_ALL);

	/* Shut down the TCXO */
	smtc_modem_hal_stop_radio_tcxo();
}

/**
 * @brief Reset and initialize radio
 *
 * Test processing:
 * - Reset radio
 * - Initialize radio
 * - Set radio in sleep mode
 *
 * @param fixture Test fixture containing modem radio
 * @return ral_status_t Status of the operation
 */
static ral_status_t reset_init_radio(struct lbm_porting_fixture *fixture)
{
	ral_status_t status;

	/* Reset radio */
	status = ral_reset(&fixture->modem_radio.ral);
	if (status != RAL_STATUS_OK) {
		return status;
	}

	/* Initialize radio */
	status = ral_init(&fixture->modem_radio.ral);
	if (status != RAL_STATUS_OK) {
		return status;
	}

	/* Set radio in sleep mode */
	status = ral_set_sleep(&fixture->modem_radio.ral, true);
	smtc_modem_hal_set_ant_switch(false);
	if (status != RAL_STATUS_OK) {
		return status;
	}

	return RAL_STATUS_OK;
}

static void *lbm_porting_setup(void)
{
	static struct lbm_porting_fixture fixture = {
		.modem_radio = RALF_SX126X_INSTANTIATE(NULL),
		.transceiver = DEVICE_DT_GET(DEFAULT_RADIO_NODE),
		.radio_irq_raised = false,

		/* LoRa configurations TO NOT receive or transmit */
		.rx_lora_param = {
			.rf_freq_in_hz = FREQ_NO_RADIO,
			.sync_word = SYNC_WORD_NO_RADIO,
			.symb_nb_timeout = 0,
			.mod_params = {
				.sf = RAL_LORA_SF12,
				.bw = RAL_LORA_BW_125_KHZ,
				.cr = RAL_LORA_CR_4_5,
				.ldro = 0,
			},
			.pkt_params = {
				.preamble_len_in_symb = 8,
				.header_type = RAL_LORA_PKT_EXPLICIT,
				.pld_len_in_bytes = 255,
				.crc_is_on = false,
				.invert_iq_is_on = true,
			},
		},
	};

	fixture.modem_radio.ral.context = fixture.transceiver;

	smtc_modem_hal_init(fixture.transceiver);

	return &fixture;
}

ZTEST_SUITE(lbm_porting, NULL, lbm_porting_setup, NULL, NULL, NULL);

/**
 * @brief Test SPI communication with radio
 *
 * Test processing:
 * - Reset radio
 * - Read radio status through SPI
 * - Check if data is coherent and chip mode is valid
 */
ZTEST_F(lbm_porting, test_spi)
{
	ral_status_t ral_status;
	uint32_t counter_nok = 0;

	/* Reset radio */
	ral_status = ral_reset(&fixture->modem_radio.ral);
	zassert_equal(ral_status, RAL_STATUS_OK, "SPI test failed: ral_reset returned 0x%x", ral_status);

	/* Read chip status multiple times to verify SPI communication */
	for (int i = 0; i < NB_LOOP_TEST_SPI; i++) {
		sx126x_chip_status_t chip_status;
		sx126x_status_t status;

		/* Get chip status via SPI */
		status = sx126x_get_status(fixture->transceiver, &chip_status);

		if (status == SX126X_STATUS_OK) {
			/* Check chip mode is valid (not UNUSED) */
			if (chip_status.chip_mode == SX126X_CHIP_MODE_UNUSED) {
				TC_PRINT("Wrong SX126X chip mode, get SX126X_CHIP_MODE_UNUSED\n");
				counter_nok++;
			}
		} else {
			TC_PRINT("Failed to get SX126X status\n");
			counter_nok++;
		}
	}

	zassert_equal(counter_nok, 0, "SPI test failed: %u / %u tests failed",
		      counter_nok, NB_LOOP_TEST_SPI);
}

/**
 * @brief Test radio interrupt functionality
 *
 * Test processing:
 * - Reset and initialize radio
 * - Configure radio IRQ callback
 * - Configure radio with bad parameters to receive a RX timeout IRQ
 * - Configure radio in reception mode with a timeout
 * - Wait for timeout to expire
 * - Check if RX timeout IRQ was raised
 */
ZTEST_F(lbm_porting, test_radio_irq)
{
	ral_status_t status;
	uint32_t rx_timeout_in_ms = 500;

	/* Reset IRQ flag */
	fixture->radio_irq_raised = false;

	/* Reset, init radio and put it in sleep mode */
	status = reset_init_radio(fixture);
	zassert_equal(status, RAL_STATUS_OK, "Could not reset/init radio: 0x%x", status);

	/* Setup radio and IRQ */
	smtc_modem_hal_irq_config_radio_irq(radio_rx_irq_callback, fixture);
	smtc_modem_hal_start_radio_tcxo();
	smtc_modem_hal_set_ant_switch(false);

	/* Setup LoRa parameters */
	status = ralf_setup_lora(&fixture->modem_radio, &fixture->rx_lora_param);
	zassert_equal(status, RAL_STATUS_OK, "ralf_setup_lora failed: 0x%x", status);

	/* Configure IRQ parameters */
	status = ral_set_dio_irq_params(&fixture->modem_radio.ral,
					RAL_IRQ_RX_DONE | RAL_IRQ_RX_TIMEOUT |
					RAL_IRQ_RX_HDR_ERROR | RAL_IRQ_RX_CRC_ERROR);
	zassert_equal(status, RAL_STATUS_OK, "ral_set_dio_irq_params failed: 0x%x", status);

	/* Set radio in RX mode */
	status = ral_set_rx(&fixture->modem_radio.ral, rx_timeout_in_ms);
	zassert_equal(status, RAL_STATUS_OK, "ral_set_rx failed: 0x%x", status);

	/* Wait for 2 * timeout */
	k_busy_wait((rx_timeout_in_ms * 2) * 1000);

	/* Check if IRQ was raised */
	zassert_true(fixture->radio_irq_raised,
		     "Timeout, radio irq not received");
}
