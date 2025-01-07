# HydraCap Tool

HydraCap helps you to capture and export traffic on Aruba CXOS based switches.

## Features

- Create PCAPs from multiple CXOS based devices and interfaces in parallel (mirror session to CPU)
	- export via SFTP / SCP
- Create ERSPANs from multiple CXOS based devices and interfaces in parallel

All options are configured withtin the .env file.<br />

![](https://github.com/Max1211/Images/blob/main/hydracap.png)


### Example .env file:
```
# Device Configuration
IP_ADDRESSES=<sw01_ip>, <sw02_ip>
USERNAME=<user>
PASSWORD=<password>
API_VERSION=v10.15 #Fallback: 10.13.
```
