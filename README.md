LLDP Webhook Agent for AOS-CX
This NAE (Network Analytics Engine) script for AOS-CX switches monitors interface up events and sends webhook notifications containing LLDP neighbor information. This helps automate network discovery and documentation.
Features

Monitors interface link state changes
Extracts LLDP neighbor information when interfaces come up
Sends webhook notifications with switch and neighbor details
Configurable interface monitoring and wait times
Test webhook functionality

Installation

Download the LLDP-Webhook-NAE.py script
From the AOS-CX Web UI, navigate to Diagnostics > Network Analytics > Agents
Click + Add and upload the script file
Configure the parameters as described below
Click Save to deploy the agent

Parameters
webhook_url (Required)

Description: URL to send the webhook notification to
Type: string
Default: https://webhook.site/your-webhook-id
Instructions: Replace with your actual webhook endpoint URL. This could be a custom application, webhook.site test endpoint, integration platform URL, etc.

interfaces (Optional)

Description: Specifies which interfaces to monitor
Type: string
Default: all
Format: Comma-separated list with optional ranges, e.g., 1/1/1-1/1/10,1/1/12,1/1/15-20
Instructions: Use all to monitor all interfaces, or specify a list to monitor only particular interfaces

lldp_wait_time (Optional)

Description: Time in seconds to wait for LLDP discovery after an interface comes up
Type: integer
Default: 15
Range: 5-60 seconds
Instructions: Adjust this parameter if LLDP information isn't being detected. Longer wait times ensure LLDP has time to be discovered but will delay webhook notifications.
