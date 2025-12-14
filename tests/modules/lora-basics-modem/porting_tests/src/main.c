/*
 * Copyright (c) 2025 Carlo Caione <ccaione@baylibre.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

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
#define MARGIN_GET_TIME_IN_MS 1
#define MARGIN_TIMER_IRQ_IN_MS 2

/**
 * @brief Return test enumeration
 */
enum return_code_test {
	RC_PORTING_TEST_OK = 0x00,
	RC_PORTING_TEST_NOK = 0x01,
	RC_PORTING_TEST_RELAUNCH = 0x02,
};

#define DEFAULT_RADIO_NODE DT_ALIAS(lora0)
BUILD_ASSERT(DT_NODE_HAS_STATUS_OKAY(DEFAULT_RADIO_NODE),
	     "No default LoRa radio specified in DT");

struct lbm_porting_fixture {
	ralf_t modem_radio;
	const struct device *transceiver;
	volatile bool radio_irq_raised;
	volatile bool irq_rx_timeout_raised;
	volatile bool timer_irq_raised;
	volatile uint32_t irq_time_ms;
	volatile uint32_t irq_time_s;
	ralf_params_lora_t rx_lora_param;
};

/* Radio IRQ callback (runs in thread context via HAL work queue) */
static void radio_rx_irq_callback(void *context)
{
	struct lbm_porting_fixture *fixture = (struct lbm_porting_fixture *)context;
	ral_irq_t radio_irq = 0;

	fixture->radio_irq_raised = true;

	/* Record time in thread context */
	fixture->irq_time_ms = smtc_modem_hal_get_time_in_ms();

	/* Get IRQ status to check for RX timeout */
	ral_get_irq_status(&fixture->modem_radio.ral, &radio_irq);

	if ((radio_irq & RAL_IRQ_RX_TIMEOUT) == RAL_IRQ_RX_TIMEOUT) {
		fixture->irq_rx_timeout_raised = true;
	}

	/* Clear IRQ status */
	ral_clear_irq_status(&fixture->modem_radio.ral, RAL_IRQ_ALL);

	/* Shut down the TCXO */
	smtc_modem_hal_stop_radio_tcxo();
}

/* Radio IRQ callback for time in seconds test (runs in thread context via HAL work queue) */
static void radio_rx_irq_callback_get_time_in_s(void *context)
{
	struct lbm_porting_fixture *fixture = (struct lbm_porting_fixture *)context;
	ral_irq_t radio_irq = 0;

	fixture->radio_irq_raised = true;

	/* Record time in seconds in thread context */
	fixture->irq_time_s = smtc_modem_hal_get_time_in_s();

	/* Get IRQ status to check for RX timeout */
	ral_get_irq_status(&fixture->modem_radio.ral, &radio_irq);

	if ((radio_irq & RAL_IRQ_RX_TIMEOUT) == RAL_IRQ_RX_TIMEOUT) {
		fixture->irq_rx_timeout_raised = true;
	}

	/* Clear IRQ status */
	ral_clear_irq_status(&fixture->modem_radio.ral, RAL_IRQ_ALL);

	/* Shut down the TCXO */
	smtc_modem_hal_stop_radio_tcxo();
}

/* Timer IRQ callback */
static void timer_irq_callback(void *context)
{
	struct lbm_porting_fixture *fixture = (struct lbm_porting_fixture *)context;

	fixture->irq_time_ms = smtc_modem_hal_get_time_in_ms();
	fixture->timer_irq_raised = true;
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

/**
 * @brief Test get time in seconds
 *
 * Test processing:
 * - Reset, init and configure radio
 * - Configure radio in reception mode with a timeout
 * - Get start time
 * - Wait for radio IRQ (get stop time in IRQ callback)
 * - Check if time is coherent with the configured timeout
 *
 * @return enum return_code_test RC_PORTING_TEST_OK, RC_PORTING_TEST_NOK, or RC_PORTING_TEST_RELAUNCH
 */
static enum return_code_test test_get_time_in_s(struct lbm_porting_fixture *fixture)
{
	ral_status_t status;
	uint32_t rx_timeout_in_ms = 5000;
	uint32_t start_time_s;
	uint32_t elapsed_time;

	TC_PRINT("Get time in seconds\n");

	/* Reset flags */
	fixture->radio_irq_raised = false;
	fixture->irq_rx_timeout_raised = false;
	fixture->rx_lora_param.symb_nb_timeout = 0;

	/* Reset, init radio and put it in sleep mode */
	status = reset_init_radio(fixture);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("Could not reset/init radio: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Setup radio and IRQ - use callback that records time in seconds */
	smtc_modem_hal_irq_config_radio_irq(radio_rx_irq_callback_get_time_in_s, fixture);
	smtc_modem_hal_start_radio_tcxo();
	smtc_modem_hal_set_ant_switch(false);

	/* Setup LoRa parameters */
	status = ralf_setup_lora(&fixture->modem_radio, &fixture->rx_lora_param);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("ralf_setup_lora failed: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Configure IRQ parameters */
	status = ral_set_dio_irq_params(&fixture->modem_radio.ral,
					RAL_IRQ_RX_DONE | RAL_IRQ_RX_TIMEOUT |
					RAL_IRQ_RX_HDR_ERROR | RAL_IRQ_RX_CRC_ERROR);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("ral_set_dio_irq_params failed: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Set radio in RX mode */
	status = ral_set_rx(&fixture->modem_radio.ral, rx_timeout_in_ms);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("ral_set_rx failed: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Get start time */
	start_time_s = smtc_modem_hal_get_time_in_s();

	/* Wait for radio IRQ */
	while (fixture->radio_irq_raised == false) {
		k_sleep(K_MSEC(10));
	}

	/* Relaunch test if IRQ was not RX timeout */
	if (fixture->irq_rx_timeout_raised == false) {
		TC_PRINT("Radio IRQ received but not RX timeout -> relaunch test\n");
		return RC_PORTING_TEST_RELAUNCH;
	}

	/* Check elapsed time */
	elapsed_time = fixture->irq_time_s - start_time_s;
	if (elapsed_time != rx_timeout_in_ms / 1000) {
		TC_PRINT("Time is not coherent: expected %us / got %us\n",
			 rx_timeout_in_ms / 1000, elapsed_time);
		return RC_PORTING_TEST_NOK;
	}

	TC_PRINT("Time expected %us / got %us (no margin)\n",
		 rx_timeout_in_ms / 1000, elapsed_time);

	return RC_PORTING_TEST_OK;
}

/**
 * @brief Test get time in milliseconds
 *
 * Test processing:
 * - Reset, init and configure radio with a timeout symbol number
 * - Get start time
 * - Configure radio in reception mode
 * - Wait for radio IRQ (get stop time in IRQ callback)
 * - Check if time is coherent with the configured timeout symbol number
 *
 * @return enum return_code_test RC_PORTING_TEST_OK, RC_PORTING_TEST_NOK, or RC_PORTING_TEST_RELAUNCH
 */
static enum return_code_test test_get_time_in_ms(struct lbm_porting_fixture *fixture)
{
	ral_status_t status;
	uint32_t start_time_ms;
	uint32_t elapsed_time;
	uint32_t symb_time_ms;
	uint8_t wait_start_ms = 5;

	TC_PRINT("Get time in milliseconds\n");

	/* Reset flags */
	fixture->radio_irq_raised = false;
	fixture->irq_rx_timeout_raised = false;

	/*
	 * Configure symbol timeout.
	 * To avoid misalignment between symb timeout and real timeout,
	 * use a number of symbols smaller than 63.
	 */
	fixture->rx_lora_param.symb_nb_timeout = 62;
	fixture->rx_lora_param.mod_params.sf = RAL_LORA_SF12;
	fixture->rx_lora_param.mod_params.bw = RAL_LORA_BW_125_KHZ;

	/* Calculate expected symbol time: 2^SF / BW * symb_nb_timeout */
	symb_time_ms = (uint32_t)(fixture->rx_lora_param.symb_nb_timeout *
				  ((1 << 12) / 125.0));

	/* Reset, init radio and put it in sleep mode */
	status = reset_init_radio(fixture);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("Could not reset/init radio: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Setup radio and IRQ */
	smtc_modem_hal_irq_config_radio_irq(radio_rx_irq_callback, fixture);
	smtc_modem_hal_start_radio_tcxo();
	smtc_modem_hal_set_ant_switch(false);

	/* Setup LoRa parameters */
	status = ralf_setup_lora(&fixture->modem_radio, &fixture->rx_lora_param);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("ralf_setup_lora failed: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Configure IRQ parameters */
	status = ral_set_dio_irq_params(&fixture->modem_radio.ral,
					RAL_IRQ_RX_DONE | RAL_IRQ_RX_TIMEOUT |
					RAL_IRQ_RX_HDR_ERROR | RAL_IRQ_RX_CRC_ERROR);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("ral_set_dio_irq_params failed: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Wait to align start time */
	start_time_ms = smtc_modem_hal_get_time_in_ms() + wait_start_ms;
	while (smtc_modem_hal_get_time_in_ms() < start_time_ms) {
		/* Busy wait */
	}

	/* Set radio in RX mode with symbol timeout (timeout_in_ms = 0) */
	status = ral_set_rx(&fixture->modem_radio.ral, 0);
	if (status != RAL_STATUS_OK) {
		TC_PRINT("ral_set_rx failed: 0x%x\n", status);
		return RC_PORTING_TEST_NOK;
	}

	/* Wait for radio IRQ */
	while (fixture->radio_irq_raised == false) {
		k_sleep(K_MSEC(1));
	}

	/* Relaunch test if IRQ was not RX timeout */
	if (fixture->irq_rx_timeout_raised == false) {
		TC_PRINT("Radio IRQ received but not RX timeout -> relaunch test\n");
		return RC_PORTING_TEST_RELAUNCH;
	}

	/* Calculate elapsed time, compensating for TCXO startup delay */
	elapsed_time = fixture->irq_time_ms - start_time_ms -
		       smtc_modem_hal_get_radio_tcxo_startup_delay_ms();

	/* Check elapsed time within margin */
	if (abs((int)(elapsed_time - symb_time_ms)) > MARGIN_GET_TIME_IN_MS) {
		TC_PRINT("Time is not coherent: expected %ums / got %ums (margin +/-%ums)\n",
			 symb_time_ms, elapsed_time, MARGIN_GET_TIME_IN_MS);
		return RC_PORTING_TEST_NOK;
	}

	TC_PRINT("Time expected %ums / got %ums (margin +/-%ums)\n",
		 symb_time_ms, elapsed_time, MARGIN_GET_TIME_IN_MS);

	return RC_PORTING_TEST_OK;
}

/**
 * @brief Test time (Get time in s and in ms)
 *
 * Test processing:
 * - Run test_get_time_in_s (with retry on relaunch)
 * - Run test_get_time_in_ms (with retry on relaunch)
 */
ZTEST_F(lbm_porting, test_get_time)
{
	enum return_code_test ret;

	/* Test get time in seconds */
	do {
		ret = test_get_time_in_s(fixture);
		zassert_not_equal(ret, RC_PORTING_TEST_NOK, "test_get_time_in_s failed");
	} while (ret == RC_PORTING_TEST_RELAUNCH);

	/* Test get time in milliseconds */
	do {
		ret = test_get_time_in_ms(fixture);
		zassert_not_equal(ret, RC_PORTING_TEST_NOK, "test_get_time_in_ms failed");
	} while (ret == RC_PORTING_TEST_RELAUNCH);
}

/**
 * @brief Test timer IRQ
 *
 * Test processing:
 * - Get start time
 * - Configure and start timer
 * - Wait timer irq (get stop time in irq callback)
 * - Check the time elapsed between timer start and timer IRQ reception
 */
ZTEST_F(lbm_porting, test_timer_irq)
{
	uint32_t timer_ms = 3000;
	uint8_t wait_start_ms = 5;
	uint16_t timeout_ms = 2000;
	uint32_t start_time_ms;
	uint32_t elapsed_time;

	fixture->timer_irq_raised = false;

	smtc_modem_hal_stop_timer();

	/* Wait to align start time */
	start_time_ms = smtc_modem_hal_get_time_in_ms() + wait_start_ms;
	while (smtc_modem_hal_get_time_in_ms() < start_time_ms) {
		k_sleep(K_MSEC(1));
	}

	smtc_modem_hal_start_timer(timer_ms, timer_irq_callback, fixture);

	/* Wait for timer IRQ with timeout */
	while ((fixture->timer_irq_raised == false) &&
	       ((smtc_modem_hal_get_time_in_ms() - start_time_ms) < (timer_ms + timeout_ms))) {
		k_sleep(K_MSEC(1));
	}

	zassert_true(fixture->timer_irq_raised, "Timeout: timer irq not received");

	elapsed_time = fixture->irq_time_ms - start_time_ms;

	zassert_true((elapsed_time >= timer_ms) &&
		     (elapsed_time <= timer_ms + MARGIN_TIMER_IRQ_IN_MS),
		     "Timer irq delay is not coherent: expected %ums / got %ums (margin +%ums)",
		     timer_ms, elapsed_time, MARGIN_TIMER_IRQ_IN_MS);

	TC_PRINT("Timer irq configured with %ums / got %ums (margin +%ums)\n",
		 timer_ms, elapsed_time, MARGIN_TIMER_IRQ_IN_MS);
}

/**
 * @brief Test stop timer
 *
 * Test processing:
 * - Configure and start timer
 * - Wait half of timer duration
 * - Stop timer
 * - Wait past the end of timer
 * - Check if timer IRQ is not received
 */
ZTEST_F(lbm_porting, test_stop_timer)
{
	uint32_t timer_ms = 1000;
	uint32_t time;

	fixture->timer_irq_raised = false;

	smtc_modem_hal_start_timer(timer_ms, timer_irq_callback, fixture);

	/* Wait half of timer */
	time = smtc_modem_hal_get_time_in_ms();
	while ((smtc_modem_hal_get_time_in_ms() - time) < (timer_ms / 2)) {
		k_sleep(K_MSEC(1));
	}

	smtc_modem_hal_stop_timer();

	/* Wait past the end of timer */
	time = smtc_modem_hal_get_time_in_ms();
	while ((smtc_modem_hal_get_time_in_ms() - time) < (timer_ms + 500)) {
		k_sleep(K_MSEC(1));
	}

	zassert_false(fixture->timer_irq_raised,
		      "Timer irq raised while timer is stopped");
}
