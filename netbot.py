import argparse
import boto3
from operator import itemgetter
import yaml
import logging
from scapy.all import srp, Ether, ARP
from prettytable import PrettyTable 
from datetime import datetime



# Process command line opitons
parser = argparse.ArgumentParser()
parser.add_argument("-a", "--aws_profile", dest="aws_profile", default="default",help="aws credentials profile")
parser.add_argument("-n", "--subnet", dest="subnet", default="10.10.1.0/24", help="net range to scan")
parser.add_argument("-b", "--bucket", dest="s3bucket", default="netbot-store", help="s3 bucket for device")
parser.add_argument("-p", "--net_profile", dest="net_profile", default="pi-redtail", help="netbot profile name")
parser.add_argument("-c", "--config_file", dest="config_file", default="config.yaml", help="config file for devices")
parser.add_argument("-l", "--debug", action="store_true", default=False, help="Enable debug logging")
parser.add_argument("-t", "--timeout", type=int, dest="timeout", default=1, help="Enable debug logging")
parser.add_argument("-f", "--local-config",  dest="local_config_file", help="Local Config file")

options = parser.parse_args()

#setup logging
loglevel= logging.DEBUG if options.debug else  logging.INFO
logging.basicConfig(handlers=[logging.FileHandler("netbot.log"),logging.StreamHandler() ], level=loglevel, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def send_mail(msgFrom,msgTo,subject,txtMessage,htmlMessage):
    session = boto3.Session(profile_name=options.aws_profile)
    sesClient = session.client('ses',region_name='us-east-1')
    logger.debug(f"Sending email from {msgFrom} to {msgTo}")
    logger.debug(f"Subject: {subject}")
    logger.debug(f"Text Message: {txtMessage}")
    logger.debug(f"HTML Message: {htmlMessage}")

    #send email with scan report
    response = sesClient.send_email(
                    Destination={'ToAddresses': [ msgTo],},
                    Message={
                        'Body': {
                            'Html': {
                                    'Charset': 'UTF-8',
                                    'Data': htmlMessage,
                                },
                            'Text': {
                                'Charset': 'UTF-8',
                                'Data': txtMessage,
                            },
                        },
                        'Subject': {
                            'Charset': 'UTF-8',
                            'Data': subject,
                        },
                        },
                        Source=msgFrom,
                    )
    logger.debug(f"Email sent: {response}")


#function to read config file from s3
def read_configfile_from_s3():
    session = boto3.Session(profile_name=options.aws_profile)
    s3 = session.client('s3')

    try:
        response = s3.get_object(Bucket=options.s3bucket, Key=f"{options.net_profile}/{options.config_file}")
    except Exception as e:
        logger.error(f"Error reading config file: {e}")
        return None
    #check if response is successful
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        logger.error(f"Error reading config file: {response['ResponseMetadata']['HTTPStatusCode']}")
        return None
    
    config = response['Body'].read().decode('utf-8')
    device_config = yaml.load(config, Loader=yaml.FullLoader)
    return device_config

def scan_network(subnet,options):
    logger.info(f"Scanning network {subnet}")
    """Scans the network for devices."""


    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = subnet), 
		     timeout = options.timeout,
			 retry = 1, 
		     inter = 0.1,
             verbose=False)
  
    clients_list = []
    for snd,rcv in ans: 
        client_dict = {"ip": rcv.sprintf(r'%ARP.psrc%'), "mac": rcv.sprintf(r'%Ether.src%')}
        clients_list.append(client_dict)
    
    return sorted(clients_list, key=itemgetter('ip'))

def process_devices(device_list,devices_mapping):
    offlineTable = PrettyTable(["Mac", "Brand", "Type", "Name"])
    offlineTable.align["Name"] = "l"
    offlineTable.align["Brand"] = "l"
    offlineTable.align["Type"] = "l"
    offlineTable.title = "Offline Devices"

    onlineTable = PrettyTable(["Mac", "IP", "Name", "Brand", "Type"])
    onlineTable.align["Name"] = "l"
    onlineTable.align["Brand"] = "l"
    onlineTable.align["Type"] = "l"
    onlineTable.title = "Online Devices"

    unknownTable = PrettyTable(["Mac", "IP"])
    unknownTable.align["IP"] = "l"
    unknownTable.title = "Unknown Devices"

    statusTable = PrettyTable(["Status", "Count"])
    statusTable.align["Status"] = "l"
    statusTable.title = "Device Counts"

    unkown_list = []
    logger.debug("Online Devices")
    for client in device_list:
        if client["mac"] in devices_mapping:
            logger.debug(f"{client['mac']}\t\t{client['ip']}\t\t{devices_mapping[client['mac']]['name']}")
            onlineTable.add_row([client['mac'],client['ip'],devices_mapping[client['mac']]['name'],devices_mapping[client['mac']]['brand'],devices_mapping[client['mac']]['type']])
        else:
            unkown_list.append(client)
            unknownTable.add_row([client["mac"],client["ip"]])
            
    if len(unkown_list) == 0:
        logger.debug("No unknown devices found")
    else:
        logger.debug("Uknown devices found")
        for client in unkown_list:
            logger.debug(client["mac"] +"\t\t" + client["ip"])

    logger.debug("Offline Devices")
    offline_devices =[]
    for device_mac in devices_mapping.keys():
        device_online = False
        for client in device_list:
            if client["mac"] == device_mac :
                logger.debug(f"\tDevice Online {client['mac']}\t\t{client['ip']}\t\t{devices_mapping[client['mac']]['name']}")
                device_online = True
                break
        if not device_online:
            offlineTable.add_row([device_mac,devices_mapping[device_mac]['brand'],devices_mapping[device_mac]['type'],devices_mapping[device_mac]['name']])
            offline_devices.append(device_mac)
            logger.debug(f"Device offline {device_mac}\t\t{devices_mapping[device_mac]['name']}")


    statusTable.add_row(["Online Devices", len(device_list)])
    statusTable.add_row(["Unknown Devices", len(unkown_list)])
    statusTable.add_row(["Offline Devices", len(offline_devices)])
    statusTable.add_row(["Trusted Devices", len(devices_mapping)])
    reportTables = [statusTable,unknownTable,onlineTable,offlineTable]
    return len(unkown_list), reportTables 



start_time = datetime.now()

logger.debug(f"Program Options {options}")
# read config file 
if options.local_config_file:
    with open(options.local_config_file) as f:
        run_config = yaml.load(f, Loader=yaml.FullLoader)
else: # read from s3
        run_config=read_configfile_from_s3()

devices_list = scan_network(options.subnet,options)
logger.debug(f"Total number of devices on the network: {len(devices_list)}")
unkownCount,reportTables = process_devices(devices_list,run_config['devices'])

logger.info(f"Report: \n{reportTables[0]}\n{reportTables[1]}\n{reportTables[2]}\n{reportTables[3]}")
if unkownCount > 0:
    logger.info("Unknown devices found. Sending email")
    html_report = "<html><head></head><body>"
    for table in reportTables:
        html_report += table.get_html_string() + "<br>"
    html_report += "</body></html>"

    txt_report = f"Report: \n{reportTables[0]}\n{reportTables[1]}\n{reportTables[2]}\n{reportTables[3]}"

    send_mail(run_config['config']['emailFrom'],run_config['config']['emailTo'],f"{options.net_profile}:NetBot {unkownCount} Unkwown Devices Found",txt_report,html_report)

stop_time = datetime.now()
total_time = stop_time - start_time 
logger.info(f"Scan Complete. Duration {total_time}")