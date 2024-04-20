# iosRsdTunnel
Tool for making iOS 17+ RSD tunnels

The code here is a pared down version of pymobiledevice3 that has been revamped greatly to simplify it and reduce dependencies.

This code is not functional as-is.

The zeroconf fetching of devices has been rewritten to use an external module.
A dummy example of what would be needed is in mdns.py

The utun interactivity has been rewritten to use "external utuns".
A dummy example of what would be needed is in external_utun.py

The code has been changed to suspend / resume remoted using an external tool.

This code is here mainly to comply with GPL requirements, but you are welcome to implement the missing bits and contribute them if you want to make it work again.
