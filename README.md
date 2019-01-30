# GprsInit

A bit of a prepared Chatscript alternative written with Python,
that I use to connect a Raspberry Pi -> Rs232 -> Gprs Module (Telit) -> PPPoE -> internet.

It can be used together with an XML file containing APNs of Providers to "automagically" find the "best" APN,
however a manual APN can be added too.

If no PIN is required, fine.
If a PIN is required, it will try it once.
If PUK is required it will stop immediately.

a few commands (ATH && AT&K0) are specific to my situation regarding the telit and the raspberry only using rxd,txd,gnd and echo
