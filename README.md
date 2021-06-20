# panw-nutanix-doctor

panw-nutanix-doctor.py is a tool that allows Palo Alto Network Panorama to Dynamically Quarantine Infected Guests On Nutanix environment.

The workflow that panw-nutanix-doctor will take to Dynamically Quarantine Infected Guests is:
1. Source machine initiate malicious traffic.
2. Palo Alto Networks NGFW detect the malicious activity.
3. Palo Alto Networks NGFW share logs with Panorama.
4. Panorama initiate API call via [HTTP profile](https://docs.paloaltonetworks.com/pan-os/9-0/pan-os-admin/monitoring/forward-logs-to-an-https-destination.html#) to the panw-nutanix-doctor middleware. The API call from Panorama will include the IP address of the infected workload.
5. Using the IP address, The panw-nutanix-doctor resolves all the relevant information from Nutanix PRISM (I.e. workload uuid and spec), and attach quarantine category and value (For example quarantine:Strict)
6. The infected workload will be isolated.

Workflow Diagram:
![Workflow](https://raw.githubusercontent.com/mohanadelamin/panw-nutanix-doctor/master/images/workflow.png)

## Prerequisites

1. Python3
2. The following python modules (see requirements.txt)
	- requests
	- flask
	- flask_restful


## Installation

```
$ git clone https://github.com/mohanadelamin/panw-nutanix-doctor.git
$ cd panw-nutanix-doctor
$ pip3 install -r requirements.txt
```
    
## Configuration

### panw-nutanix-doctor machine configuration

1. In home directry create new folder on the home directory
	```
    $ mkdir ~/panw-nutanix-doctor
	```

2. Create new file named .doctor.config
	```
	$ vim .doctor.conf
	```

3. Add the following to the .doctor.config file
	```
	[doctor_config]
	USER=
	PASS=
	PRISM=
	CERT_PATH=
	KEY_PATH=
	PORT=
	DEBUG=
	```

4. Fill the config file above with the required information:
- **Mandatory fields** 
	- USER: PRISM username
	- PASS: PRISM password
	- PRISM= PRISM IP address
- **Optional fields**
	- CERT_PATH: add the certificate file path if the connection from panorama need to be over SSL.
	- KEY_PATH: add the key file path if the connection from panorama need to be over SSL.
	- PORT: add the port in which panw-nutanix-doctor will listen. (Default is 80 or 443 if SSL is required)
	- LENGTH: number of vms to be pulled by the API. Default is 100
	- DEBUG: allowed values are "yes" or "no".

### Palo Alto Networks Panorama configuration

### Step 1: Configure HTTP profile on panorama to send API Calls to panw-nutanix-doctor
1. Select **Panorama** > **Server Profiles** > **HTTP** and **Add** a new HTTP Server Profile.
2. Enter a descriptive **Name**
3. Select **Add** to provide the details of panw-nutanix-doctor Manager.
4. Enter a **Name** for panw-nutanix-doctor.
5. Enter the **IP Address** of the panw-nutanix-doctor.
6. Select the **Protocol** (HTTP or HTTPS). The default Port is 80 or 443 respectively.
7. Select **POST** under the HTTP Method column.

Example:fusion
![Example1](https://raw.githubusercontent.com/mohanadelamin/panw-nutanix-doctor/master/images/example1.png)

8. Select **Payload Format** and select the log type **Threat.**
9. Add a descriptive **Name**
10. In the **URI** section add "/api/nutanix
11. In the **Payload** section enter ** {"ip": "$src", "category": "Quarantine", "value": "Default"} **
12. Click **Ok**

Example:
![Example2](https://raw.githubusercontent.com/mohanadelamin/panw-nutanix-doctor/master/images/example2.png)

### Step 2: Define the match criteria for when Panorama will trigger the API call to panw-nutanix-doctor, and attach the HTTP profile.

1. Select **Panorama** > **Collector Groups** > **Collector Log Forwarding** for Threat or Traffic logs.
2. On the **Threat** section click **Add**
3. Add a descriptive **Name**
4. Click **Add** on the **HTTP** section
5. Select the HTTP profile.
6. Click **Ok**

Example:
![Example3](https://raw.githubusercontent.com/mohanadelamin/panw-nutanix-doctor/master/images/example3.png)


## Running

1. Login to the panw-nutanix-doctor machine
2. Run the script
```
$ python3 panw-nutanix-doctor.py
```


## Disclaimer

panw-nutanix-doctor is for illustrative purposes only. This software is supplied "AS IS" without any warranties and support.