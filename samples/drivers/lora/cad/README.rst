.. zephyr:code-sample:: lora-cad
   :name: LoRa Channel Activity Detection
   :relevant-api: lora_interface

   Detect LoRa channel activity and use Listen Before Talk.

Overview
********

This sample demonstrates Channel Activity Detection (CAD) on the LoRa API:

* ``lora_cad()`` (blocking) and ``lora_cad_async()`` (callback-based) to probe
  the channel for LoRa activity.
* ``LORA_CAD_MODE_LBT`` to perform "listen before talk" automatically inside
  ``lora_send()``.

By default the sample starts in **scanner** mode. Hold **button 0** during
boot to select **sender** mode.

The scanner demonstrates ``lora_cad_async()`` once, then runs ``lora_cad()``
continuously. When CAD detects activity, it tries to receive and validate a
packet. Each window of 20 probes reports CAD-positive probes separately from
valid packets received, receive timeouts/errors, and invalid packets. A
CAD-positive probe is not a measure of how long the channel was busy: a long
packet preamble can trigger CAD only once, and CAD alone does not confirm that
a full packet was received. The sender enables ``LORA_CAD_MODE_LBT`` and
transmits repeatedly with a long preamble to give the scanner time to detect
activity and receive the frame.

Note that CAD detects LoRa modulation (chirps), not arbitrary RF energy, so
the channel must be loaded with real LoRa transmissions; a continuous wave
would not reliably trip CAD.

Building and Running
********************

Build and flash on a board with a ``lora0`` alias, for example
``nucleo_wl55jc`` or ``nrf52840dk/nrf52840`` with the SX1261 shield:

.. zephyr-app-commands::
   :zephyr-app: samples/drivers/lora/cad
   :host-os: unix
   :board: nucleo_wl55jc
   :goals: build flash
   :compact:

Sample Output (scanner)
=======================

.. code-block:: console

   [00:00:00.070,000] <inf> lora_cad: Scanner mode: probing channel with CAD
   [00:00:00.070,000] <inf> lora_cad: Asynchronous CAD probe
   [00:00:00.116,000] <inf> lora_cad: Async CAD result: channel clear
   [00:00:00.116,000] <inf> lora_cad: Continuous CAD scan
   [00:00:00.900,000] <inf> lora_cad: Received packet 0 (RSSI -45 dBm, SNR 9 dB)
   [00:00:01.800,000] <inf> lora_cad: CAD activity on 1/20 probes; received 1 packets, 0 RX timeouts, 0 RX errors, 0 invalid packets
   [00:00:02.700,000] <inf> lora_cad: CAD activity on 1/20 probes; received 1 packets, 0 RX timeouts, 0 RX errors, 0 invalid packets
   [00:00:03.600,000] <inf> lora_cad: CAD activity on 0/20 probes; received 0 packets, 0 RX timeouts, 0 RX errors, 0 invalid packets

Sample Output (sender)
======================

.. code-block:: console

   [00:00:00.250,000] <inf> lora_cad: Sender mode: Listen Before Talk enabled
   [00:00:00.290,000] <inf> lora_cad: Sent packet 0
   [00:00:01.120,000] <inf> lora_cad: Sent packet 1
   [00:00:01.950,000] <inf> lora_cad: Sent packet 2
