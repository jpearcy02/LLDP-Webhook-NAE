# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.


Manifest = {
    'Name': 'LLDP_Webhook_Simple',
    'Description': 'This agent sends webhook notifications when interfaces change state with LLDP neighbor information.',
    'Version': '1.0',
    'Author': 'Modified from HPE Aruba Networking Original',
    'Tags': ['service'],
    'AOSCXVersionMin': '10.11'
}

ParameterDefinitions = {
    'interfaces': {
        'Name': 'Monitored Interfaces',
        'Description': 'Indicates the specific interfaces to monitor - If not present in the list, a port won\'t be monitored - format : 1/1/1-1/1/10,1/1/12',
        'Type': 'string',
        'Default': 'all'
    },
    'webhook_url': {
        'Name': 'Webhook URL',
        'Description': 'URL to send the webhook notification to',
        'Type': 'string',
        'Default': 'https://webhook.site/your-webhook-id'
    },
    'lldp_wait_time': {
        'Name': 'LLDP Discovery Wait Time',
        'Description': 'Time in seconds to wait for LLDP discovery after interface comes up (5-60)',
        'Type': 'integer',
        'Default': 15
    }
}

URI_PREFIX_GET = "/rest/v10.08/"
URI_PREFIX_MONITOR = "/rest/v1/"


class Agent(NAE):

    def __init__(self):
        try:
            # We are monitoring the interface state.
            # When the interface goes up, the alert is triggered.
            uri1 = URI_PREFIX_MONITOR + 'system/interfaces/*?attributes=link_state'
            self.m1 = Monitor(uri1, 'Interface Link State on Switch')
            
            # Rule for interface UP events
            self.r1 = Rule('Interface Up Webhook Notification')
            self.r1.condition('transition {} from "down" to "up"', [self.m1])
            self.r1.action(self.handle_interface_up)
            
            # Log rule creation
            ActionSyslog("LLDP_Webhook: Agent initialized and monitoring interface state changes")
        except Exception as e:
            ActionSyslog(f"LLDP_Webhook: ERROR in initialization: {str(e)}")

    def on_agent_start(self, event):
        """
        Desc: This function executes when agent is created and initializes globals
        Args: event - event which triggered the action of executing this function
        Retn: None
        """
        try:
            self.logger.info("Agent starting...")
            ActionSyslog("LLDP_Webhook: Agent starting")
            
            # Initialize hostname with default value in case get_switch_hostname fails
            self.hostname = "Unknown"
            
            # Initialize globals
            self.init_global()
            
            # Test if webhook URL is configured and log it
            webhook_url = str(self.params.get('webhook_url', ''))
            if webhook_url and webhook_url != 'https://webhook.site/your-webhook-id':
                self.logger.info("Configured webhook URL")
                ActionSyslog("LLDP_Webhook: Configured with webhook URL")
            else:
                self.logger.warning("Webhook URL not configured or using default value!")
                ActionSyslog("LLDP_Webhook: WARNING - Webhook URL not properly configured")
                
            # Send a test webhook
            self.send_test_webhook()
        except Exception as e:
            self.logger.error(f"Error during agent start: {str(e)}")
            ActionSyslog(f"LLDP_Webhook: Error during agent start: {str(e)}")

    def init_global(self):
        """
        Desc: Initialize global variables
        Args: None
        Retn: None
        """
        # Create the list of monitored interfaces
        if str(self.params['interfaces']) == "all":
            self.monitor_all_interfaces = True
            self.ports_list = set()
        else:
            self.monitor_all_interfaces = False
            self.create_interfaces_list()
        
        # Get the switch hostname for webhook payload
        self.get_switch_hostname()

    def get_switch_hostname(self):
        """
        Desc: Get the switch hostname for inclusion in webhook payload
        Args: None
        Retn: None
        """
        url = "{}{}system".format(HTTP_ADDRESS, URI_PREFIX_GET)
        try:
            system_info = self.get_rest_request_json(url)
            if system_info and 'hostname' in system_info:
                self.hostname = system_info['hostname']
            else:
                self.hostname = "Unknown"
                self.logger.info("Hostname not found in system info, using 'Unknown'")
        except Exception as e:
            self.hostname = "Unknown"
            self.logger.error(f"Failed to get switch hostname: {str(e)}")
            ActionSyslog(f"LLDP_Webhook: Failed to get switch hostname: {str(e)}")

    def create_interfaces_list(self):
        """
        Desc: Create the full list with every single allowed interface
        Args: None
        Retn: None
        """
        self.ports_list = set(str(self.params['interfaces']).split(','))

        # Process ranges like 1/1/1-1/1/10
        ports_to_remove = set()
        ports_to_add = set()
        
        for port in self.ports_list:
            if "-" in port:
                try:
                    ports_to_remove.add(port)
                    tmp_list = port.split('-')
                    
                    # Simple case: expand ports only for third segment (1/1/1-10)
                    if len(tmp_list) == 2 and "/" in tmp_list[0]:
                        base_parts = tmp_list[0].split('/')
                        
                        # If second part is just a number (1/1/1-10)
                        if tmp_list[1].isdigit():
                            start_num = int(base_parts[-1])
                            end_num = int(tmp_list[1])
                            prefix = '/'.join(base_parts[:-1]) + '/'
                            
                            # Add all ports in the range
                            for i in range(start_num, end_num + 1):
                                ports_to_add.add(f"{prefix}{i}")
                except Exception as e:
                    self.logger.error(f"Error parsing port range {port}: {str(e)}")
        
        # Remove ranges and add expanded ports
        self.ports_list = self.ports_list - ports_to_remove
        self.ports_list.update(ports_to_add)

    def handle_interface_up(self, event):
        """
        Desc: This function gathers LLDP info and sends a webhook notification
        Args: event - event which triggered the action of executing this function
        Retn: None
        """
        try:
            # Log rule trigger
            self.logger.info("Rule triggered: Interface Up Webhook Notification")
            ActionSyslog("LLDP_Webhook: Rule triggered for interface state change")

            # Extract the interface name from the event
            label = event['labels']
            self.logger.info(f'Event labels: {label}')
            
            # Parse the interface from the label
            try:
                parts = label.split(',')[0].split('=')
                if len(parts) >= 2:
                    interface_id = parts[1]
                    self.logger.info(f"Detected interface: {interface_id}")
                    ActionSyslog(f"LLDP_Webhook: Detected interface change on {interface_id}")
                else:
                    self.logger.error(f"Failed to parse interface from label: {label}")
                    return
            except Exception as e:
                self.logger.error(f"Failed to parse interface from event label: {str(e)}")
                ActionSyslog("LLDP_Webhook: Failed to parse interface from event")
                return
            
            # Make sure hostname is initialized
            if not hasattr(self, 'hostname'):
                self.hostname = "Unknown"
                self.logger.warning("Hostname not initialized, using 'Unknown'")
            
            # Check if this interface should be monitored
            if hasattr(self, 'monitor_all_interfaces'):
                if not self.monitor_all_interfaces and interface_id not in self.ports_list:
                    self.logger.info(f"Interface {interface_id} not in monitored list, ignoring")
                    return
            
            # Get LLDP wait time from parameters (with validation)
            try:
                lldp_wait_time = int(self.params.get('lldp_wait_time', 15))
                if lldp_wait_time < 5:
                    lldp_wait_time = 5  # Minimum wait time
                elif lldp_wait_time > 60:
                    lldp_wait_time = 60  # Maximum wait time
            except:
                lldp_wait_time = 15  # Default if parameter is invalid
            
            # LLDP discovery takes time - wait for it before proceeding
            self.logger.info(f"Waiting {lldp_wait_time} seconds for LLDP discovery on interface {interface_id}")
            ActionSyslog(f"LLDP_Webhook: Waiting {lldp_wait_time} seconds for LLDP discovery")
            
            import time
            time.sleep(lldp_wait_time)  # Use configurable wait time
            
            # Get LLDP information for this interface
            lldp_data = self.get_lldp_info(interface_id)
            
            # Log LLDP neighbors count
            if lldp_data:
                neighbor_count = len(lldp_data)
                self.logger.info(f"Found {neighbor_count} LLDP neighbors for {interface_id}")
                ActionSyslog(f"LLDP_Webhook: Found {neighbor_count} LLDP neighbors for {interface_id}")
            else:
                self.logger.info(f"No LLDP neighbors for {interface_id}")
                ActionSyslog(f"LLDP_Webhook: No LLDP neighbors for {interface_id}")
            
            # Prepare and send webhook notification
            self.send_webhook(interface_id, lldp_data)
        
        except Exception as e:
            self.logger.error(f"Exception in webhook notification handler: {str(e)}")
            ActionSyslog(f"LLDP_Webhook: Exception in notification handler: {str(e)}")

    def get_lldp_info(self, port):
        """
        Desc: Gathers the LLDP information related to the specified interface
        Args: port - name of the port
        Retn: LLDP information dictionary
        """
        try:
            port_name = str(port).replace("/", "%2F")
            url_lldp = "{}{}system/interfaces/{}/lldp_neighbors?depth=2".format(
                HTTP_ADDRESS, URI_PREFIX_GET, port_name)
            
            self.logger.info(f"Getting LLDP neighbors from: {url_lldp}")
            lldp_data = self.get_rest_request_json(url_lldp)
            
            # Log the raw LLDP data for debugging
            self.logger.info(f"Raw LLDP data: {lldp_data}")
            
            if lldp_data and len(lldp_data) > 0:
                self.logger.info(f"Found {len(lldp_data)} LLDP neighbors for {port}")
                
                # Attempt a second retrieval to ensure complete data
                # (no need for additional delay since we already waited in the main handler)
                lldp_data = self.get_rest_request_json(url_lldp)
                self.logger.info("Retrieved LLDP data second time")
                
                return lldp_data
            else:
                self.logger.info(f"No LLDP neighbors found for {port}")
                return {}
        except Exception as e:
            self.logger.error(f"Error getting LLDP info: {str(e)}")
            return {}

    def send_webhook(self, port, lldp_data):
        """
        Desc: Send webhook notification with port and LLDP info
        Args: 
            port - the port that triggered the event
            lldp_data - LLDP information for the port
        Retn: None
        """
        try:
            import json
            
            # Log that we're attempting to send a notification
            self.logger.info(f"Preparing webhook notification for port {port}")
            
            # Get webhook URL
            webhook_url = str(self.params.get('webhook_url', ''))
            if not webhook_url or webhook_url == 'https://webhook.site/your-webhook-id':
                self.logger.error("Invalid webhook URL configured")
                ActionSyslog("LLDP_Webhook: Invalid webhook URL")
                return
            
            # Make sure hostname is initialized
            if not hasattr(self, 'hostname'):
                self.hostname = "Unknown"
                self.logger.warning("Hostname not initialized, using 'Unknown'")
            
            # Prepare payload
            payload = {
                "event_type": "interface_up",
                "switch_hostname": self.hostname,
                "interface": port,
                "timestamp": self.get_current_time(),
                "lldp_neighbors": []
            }
            
            # Add LLDP information if available
            lldp_neighbor_count = 0
            if lldp_data and isinstance(lldp_data, dict) and len(lldp_data) > 0:
                self.logger.info(f"Processing {len(lldp_data)} LLDP neighbors")
                
                for key, neighbor in lldp_data.items():
                    self.logger.info(f"Processing LLDP neighbor with key: {key}")
                    
                    if isinstance(neighbor, dict) and 'neighbor_info' in neighbor:
                        neighbor_info = neighbor['neighbor_info']
                        self.logger.info(f"Neighbor info found: {neighbor_info}")
                        
                        # Extract remote device info
                        remote_device = neighbor_info.get('chassis_name', '')
                        if not remote_device and 'mgmt_ip_list' in neighbor_info:
                            remote_device = neighbor_info.get('mgmt_ip_list', '')
                        
                        # Extract remote port info
                        remote_port = neighbor_info.get('port_description', '')
                        
                        # Add to payload
                        neighbor_data = {
                            "remote_device": remote_device,
                            "remote_port": remote_port,
                            "chassis_id": neighbor_info.get('chassis_id', ''),
                            "capabilities": neighbor_info.get('capabilities', ''),
                            "mgmt_ip": neighbor_info.get('mgmt_ip_list', '')
                        }
                        
                        self.logger.info(f"Adding neighbor data: {neighbor_data}")
                        payload["lldp_neighbors"].append(neighbor_data)
                        lldp_neighbor_count += 1
            
            self.logger.info(f"Added {lldp_neighbor_count} LLDP neighbors to payload")
            
            # Set headers
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Convert payload to JSON
            json_str = json.dumps(payload)
            
            # Send webhook
            self.logger.info(f"Sending webhook to {webhook_url}")
            response = self.post_rest_request(
                webhook_url,
                headers=headers,
                data=json_str,
                verify=False  # Skip SSL verification
            )
            
            # Check response
            status_code = getattr(response, 'status_code', None)
            
            if status_code and status_code >= 200 and status_code < 300:
                self.logger.info(f"Webhook notification sent successfully for port {port}")
                ActionSyslog(f"LLDP_Webhook: Notification sent for port {port}")
            else:
                self.logger.error(f"Failed to send webhook notification: HTTP {status_code}")
                ActionSyslog(f"LLDP_Webhook: Failed to send notification for port {port}: HTTP {status_code}")
        except Exception as e:
            self.logger.error(f"Exception when sending webhook: {str(e)}")
            ActionSyslog(f"LLDP_Webhook: Exception when sending notification for port {port}: {str(e)}")

    def send_test_webhook(self):
        """
        Sends a test webhook to verify connectivity
        """
        try:
            import json
            import datetime
            
            # Make sure hostname is initialized
            if not hasattr(self, 'hostname'):
                self.hostname = "Unknown"
                self.logger.warning("Hostname not initialized, using 'Unknown'")
            
            # Get webhook URL
            webhook_url = str(self.params.get('webhook_url', ''))
            if not webhook_url or webhook_url == 'https://webhook.site/your-webhook-id':
                self.logger.error("Invalid webhook URL configured")
                ActionSyslog("LLDP_Webhook: Invalid webhook URL for test")
                return
                
            # Prepare payload
            payload = {
                "event_type": "test",
                "switch_hostname": self.hostname,
                "message": "This is a test webhook from LLDP_Webhook agent",
                "timestamp": datetime.datetime.now().isoformat()
            }
            
            # Set headers
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Convert to JSON and send
            json_str = json.dumps(payload)
            self.logger.info(f"Sending test webhook to {webhook_url}")
            
            response = self.post_rest_request(
                webhook_url,
                headers=headers,
                data=json_str,
                verify=False
            )
            
            # Check response
            status_code = getattr(response, 'status_code', None)
            if status_code and 200 <= status_code < 300:
                msg = f"Test webhook sent successfully! Response code: {status_code}"
                self.logger.info(msg)
                ActionSyslog(f"LLDP_Webhook: {msg}")
            else:
                msg = f"Test webhook failed! Response code: {status_code}"
                self.logger.error(msg)
                ActionSyslog(f"LLDP_Webhook: {msg}")
        except Exception as e:
            self.logger.error(f"Error sending test webhook: {str(e)}")
            ActionSyslog(f"LLDP_Webhook: Error sending test webhook: {str(e)}")

    def get_current_time(self):
        """
        Desc: Get current timestamp in ISO format
        Args: None
        Retn: Timestamp string
        """
        import datetime
        return datetime.datetime.now().isoformat()

    def on_agent_re_enable(self, event):
        """
        Desc: This function starts when the agent has been re-enabled
        Args: event - event which triggered the action of executing this function
        Retn: None
        """
        try:
            self.logger.info("Agent re-enabled")
            ActionSyslog("LLDP_Webhook: Agent re-enabled")
            
            # Initialize hostname with default value
            self.hostname = "Unknown"
            
            # Initialize globals
            self.init_global()
            
            # Send a test webhook
            self.send_test_webhook()
        except Exception as e:
            self.logger.error(f"Error during agent re-enable: {str(e)}")
            ActionSyslog(f"LLDP_Webhook: Error during agent re-enable: {str(e)}")