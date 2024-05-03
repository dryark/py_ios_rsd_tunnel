# iosRsdTunnel
Tool for making iOS 17+ RSD tunnels

The code here is a pared down version of pymobiledevice3 that has been revamped greatly to simplify
it and reduce dependencies.

New code files that are not derived from any old code have been added with AGPL licensing.
This effectively makes the overall project AGPL.
All files that are derivatives of GPL code remain GPL as necessary.

The zeroconf fetching of devices has been rewritten to use an external module, cf_mdns.
It can be found at https://github.com/dryark/py_cf_mdns

The utun interactivity has been rewritten to use "external utuns".
An example of one way to do this is in external_utun.py

The code has been changed to suspend / resume remoted using an external c program via shell-out.
