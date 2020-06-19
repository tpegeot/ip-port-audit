#!/usr/bin/env python

""" Compare known ports for certain ip addresses to current open ports """

import argparse
import re
import sys
import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ipaddress import IPv4Network, ip_address
from jinja2 import Environment
import nmap
import yaml

# Config file
DEFAULT_CONFIG_FILE_PATH = 'config.yaml'
# Port regex
VALID_PORT_REGEX = r"^((tcp|udp)\/[0-9]{1,5})$"
# Port range regeix
VALID_PORT_RANGE_REGEX = r'^((tcp|udp)\/[0-9]{1,5}\-[0-9]{1,5})$'
# IP regex
VALID_IP_REGEX = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" \
                 + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
# IP network regex
# Only /8, /16 and /24 are supported at the moment
VALID_NETWORK_REGEX = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" \
                      + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\/(8|16|24)$"
# IP range regex
VALID_IP_RANGE_REGEX = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" \
                       + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\-" \
                       + "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}" \
                       + "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"


def init_log():
    """
    Init log mechanism
    :return:
    :rtype:
    """
    __formatter = logging.Formatter('%(asctime)s — %(name)s — %(levelname)s — %(message)s')
    logging.VERBOSE = 15
    logging.addLevelName(logging.VERBOSE, 'VERBOSE')
    __logger = logging.getLogger('ip_port_audit')
    __logger.setLevel('INFO')
    __console_handler = logging.StreamHandler(sys.stdout)
    __console_handler.setFormatter(__formatter)
    __logger.addHandler(__console_handler)
    __logger.propagate = False
    return __logger


def load_config_from_yaml(config_path, parent_logger):
    """
    Open and load yaml file content into object
    :param config_path:
    :type config_path:
    :type parent_logger: logger
    :param: parent log mechanism
    :return config_from_file: Python object containing data from yaml file
    """
    # First find out right path to config file
    if config_path and os.path.exists(config_path):
        config_file = config_path
    elif os.path.exists(DEFAULT_CONFIG_FILE_PATH):
        config_file = DEFAULT_CONFIG_FILE_PATH
    else:
        parent_logger.error('Cannot find config file')
        sys.exit(os.EX_NOINPUT)
    # Then try to load yaml file
    try:
        yaml_file = open(config_file)
    except OSError as err:
        parent_logger.error("OS error: {0}".format(err))
        sys.exit(os.EX_NOINPUT)
    else:
        config_from_file = yaml.load(yaml_file, Loader=yaml.FullLoader)
        yaml_file.close()
    return config_from_file


def check_port_regex(port_, port_regex_, port_range_regex_, parent_logger):
    """
    Check if port syntax is valid
    :param parent_logger: parent log mechanism
    :type parent_logger: logger
    :param port_range_regex_:
    :type port_range_regex_:
    :param port_: port extract from config file
    :param port_regex_: regex
    :return:
    """
    is_port_syntax_valid = True

    if port_regex_.match(port_):
        # Extract port number
        extracted_port_number = port_.split('/')[1]
        # Check if port is in right port range
        if int(extracted_port_number) in range(1, 65535):
            parent_logger.debug('Port ' + extracted_port_number + ' is in range 1-65535')
        else:
            parent_logger.debug('Port ' + extracted_port_number + ' is NOT in range 1-65535')
            is_port_syntax_valid = False
    elif port_range_regex_.match(port_):
        # Extract port number
        extracted_port_number_start = (port_.split('/')[1]).split('-')[0]
        extracted_port_number_end = (port_.split('/')[1]).split('-')[1]

        # Check if port is in right port range
        if int(extracted_port_number_start) in range(1, 65535) \
                and int(extracted_port_number_end) in range(1, 65535):
            parent_logger.debug('Port range ' + extracted_port_number_start +
                                ' - ' + extracted_port_number_end + ' is in range 1-65535')
        else:
            parent_logger.debug('Port range ' + extracted_port_number_start +
                                ' - ' + extracted_port_number_end + ' is NOT in range 1-65535')
            is_port_syntax_valid = False
    else:
        is_port_syntax_valid = False

    return is_port_syntax_valid


def check_port_syntax(address_ports, parent_logger):
    """
    Check port syntex
    :param address_ports:
    :type address_ports:
    :param parent_logger: parent log mechanism
    :type parent_logger: logger
    :return:
    :rtype:
    """
    is_port_syntax_valid = True
    port_regex = re.compile(VALID_PORT_REGEX)
    port_range_regex = re.compile(VALID_PORT_RANGE_REGEX)

    # Check if at least one port is defined
    if "ports" in address_ports:
        parent_logger.debug('Ports is present for : ' + address_ports["ip"])

        # Iterate through ports
        for port in address_ports["ports"]:

            # Check if ip matches port regex
            if check_port_regex(port, port_regex, port_range_regex, parent_logger):
                parent_logger.debug('Port syntax is ok : '
                                    + address_ports["ip"] + '/' + port)
            else:
                parent_logger.verbose('Port syntax is incorrect : '
                                      + address_ports["ip"] + '/' + port)
                is_port_syntax_valid = False

    return is_port_syntax_valid


def check_address_syntax(addresses, parent_logger):
    """
    Return if config file syntax is valid or not
    Mandatory items : ip and ports
    Optional items : name
    :param parent_logger: parent log mechanism
    :type parent_logger: logger
    :param addresses: data loaded from config file
    :return:
    """
    is_syntax_valid = True
    ip_regex = re.compile(VALID_IP_REGEX)
    network_ip_regex = re.compile(VALID_NETWORK_REGEX)
    range_ip_regex = re.compile((VALID_IP_RANGE_REGEX))

    if addresses:
        # Iterate through ip addresses
        for address in addresses:

            # If ip exists
            if "ip" in address:

                # Check if ip matches ip regex
                if ip_regex.match(address["ip"])\
                        or network_ip_regex.match(address["ip"])\
                        or range_ip_regex.match(address["ip"]):
                    if not check_port_syntax(address, parent_logger):
                        is_syntax_valid = False
                else:
                    parent_logger.warning(address["ip"] + ' syntax is incorrect')
                    is_syntax_valid = False
            else:
                is_syntax_valid = False

    return is_syntax_valid


def expand_port_list(ports):
    """
    Expand port range to port array
    :param ports:
    :type ports:
    :return:
    :rtype:
    """
    expanded_port_list = []
    port_range_regex = re.compile(VALID_PORT_RANGE_REGEX)
    for port_ in ports:
        if port_range_regex.match(port_):
            # Extract port number
            protocol = port_.split('/')[0]
            port_range = port_.split('/')[1]
            extracted_port_number_start = int(port_range.split('-')[0])
            extracted_port_number_end = int(port_range.split('-')[1])
            for port_number in range(extracted_port_number_start, extracted_port_number_end+1):
                expanded_port_list.append(protocol + '/' + str(port_number))
        else:
            expanded_port_list.append(port_)
    return expanded_port_list


def expand_ip_list(addresses):
    """
    Function to expand IP list / IP subnet to single IP addresses
    :param addresses:
    :type addresses:
    """
    # Regex
    network_ip_regex = re.compile(VALID_NETWORK_REGEX)
    range_ip_regex = re.compile(VALID_IP_RANGE_REGEX)
    ip_regex = re.compile(VALID_IP_REGEX)
    for address in addresses:
        # If ip address is really an ip address
        if "ip" in address and ip_regex.match(address["ip"]):
            if "ports" in address:
                # Expand port list to single ports
                # 21-23 => 21, 22, 23
                address["ports"] = expand_port_list(address["ports"])
        # If ip address is actually an ip network
        # Then expand it in single IP address
        if "ip" in address and network_ip_regex.match(address["ip"]):
            # Browse through the ip network using IPv4Network
            for ipv4_address in IPv4Network(address["ip"]):
                expanded_ip_address = {"ip": str(ipv4_address)}
                if "name" in address:
                    expanded_ip_address["name"] = address["name"]
                # Expand port list to single ports
                # 21-23 => 21, 22, 23
                if "ports" in address:
                    expanded_ip_address["ports"] = expand_port_list(address["ports"])
                addresses.append(expanded_ip_address)
            addresses.remove(address)
        # If ip address is actually a ip range
        # Then expand it in single IP address
        if "ip" in address and range_ip_regex.match(address["ip"]):
            # Use ip_address to convert start of ip range to int
            extracted_ip_start = int(ip_address(address["ip"].split('-')[0]))
            # Use ip_address to convert end of ip range to int
            extracted_ip_end = int(ip_address(address["ip"].split('-')[1])+1)
            # Having int allows us to use range :
            # For inclusive range, we added +1 above
            for ip_from_range in range(extracted_ip_start, extracted_ip_end):
                expanded_ip_address = {"ip": str(ip_address(ip_from_range))}
                if "name" in address:
                    expanded_ip_address["name"] = address["name"]
                if "ports" in address:
                    # Expand port list to single ports
                    # 21-23 => 21, 22, 23
                    expanded_ip_address["ports"] = expand_port_list(address["ports"])
                addresses.append(expanded_ip_address)
            addresses.remove(address)


def scan_and_compare(addresses, parent_logger):
    """
    Return any difference from baseline
    :param parent_logger: parent log mechanism
    :type parent_logger: logger
    :param addresses: data loaded from config file
    :return:
    """
    open_ports_delta = {}
    closed_ports_delta = {}
    # if "addresses" in data_from_yaml:
    #    addresses = data_from_yaml.get("addresses")
    if addresses:
        try:
            nmap_instance = nmap.PortScanner()
        except nmap.PortScannerError:
            print('Nmap not found or Nmap version < 5.00', sys.exc_info()[0])
            return None

        # Iterate through ip addresses
        for address in addresses:

            # Syntax has already been checked
            if "ip" in address and "ports" in address:

                # Run nmap scan
                try:
                    nmap_instance.scan(address["ip"], arguments='-F')
                except nmap.PortScannerError:
                    return None

                # Array to store results
                scanned_ports = []

                if address["ip"] in nmap_instance.all_hosts():
                    # Nmap sorts results by protocol
                    # Iterate through protocols
                    for protocol in nmap_instance[address["ip"]].all_protocols():
                        # For each protocol, iterate through ports
                        for port in nmap_instance[address["ip"]][protocol]:
                            # Store results
                            scanned_ports.append(protocol + '/' + str(port))

                    # Check if more open ports than defined in baseline
                    missing_ports_from_baseline = [x for x in scanned_ports
                                                   if x not in address["ports"]]
                    # Check if Ports defined in baseline are not open any more
                    missing_ports_from_scan = [x for x in address["ports"]
                                               if x not in scanned_ports]

                    # If delta exists, store results by ip
                    if missing_ports_from_baseline:
                        open_ports_delta[address["ip"]] = missing_ports_from_baseline

                    if missing_ports_from_scan:
                        closed_ports_delta[address["ip"]] = missing_ports_from_scan
                else:
                    parent_logger.warning('Could not run nmap on this ip address : '
                                          + address["ip"])

    return open_ports_delta, closed_ports_delta


def display_results(results, parent_logger):
    """
    Display verbose results
    :param parent_logger: parent log mechanism
    :type parent_logger: logger
    :param results: results from scan
    :return: True
    """
    for host in results:
        parent_logger.warning(host + ' : ' + str(results[host]))
    return True


def send_email(open_ports, closed_ports):
    """
    Send email to notify admins about compliance issues
    :param closed_ports:
    :type closed_ports:
    :param open_ports:
    :type open_ports:
    """
    smtp_port = 25  #
    smtp_server = 'localhost' # Use your own SMTP server
    sender_email = 'server@example.com' # Set sender
    receiver_email = "netadmins@example.com" # Set receiver

    # Generate email title
    if open_ports:
        email_title_level = 'ERROR'
        email_title = 'Found more open ports than defined'
    else:
        email_title_level = 'WARNING'
        email_title = 'Found ports defined in baseline not open any more'

    # Email headers
    message = MIMEMultipart("alternative")
    message['Subject'] = email_title_level + ' : compliance issues : ' + email_title
    message['From'] = sender_email
    message['To'] = receiver_email

    # Jinga email template
    template = """
    <html>
    <body>

    {% if html_open_ports is defined %}
    Error : we found more open ports than defined in the baseline! 
    <p>
    {% for result in html_open_ports %} 
    {{ result }} : {{ html_open_ports[result] }} <br>
    {% endfor %}
    </p>
    {% else %}
    We didn't found any open port which weren't defined in baseline
    {% endif %}

    {% if html_closed_ports is defined %}
    Warning : we found ports defined which are not open anymore! 
    <p>
    {% for result in html_closed_ports %} 
    {{ result }} : {{ html_closed_ports[result] }} <br>
    {% endfor %}
    </p>
    {% endif %}
    
    </body>
    </html>
    """

    # Generate email body from Jinga html template
    generate_email_body = Environment().from_string(template).render(html_open_ports=open_ports,
                                                                     html_closed_ports=closed_ports)
    email_body = MIMEText(generate_email_body, 'html')
    message.attach(email_body)

    # Send email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )


def parse_args():
    """
    Parse script arguments
    :return: parsed arguments
    :rtype:
    """
    parser = argparse.ArgumentParser()
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument('-v', '--verbose', action="store_true")
    log_group.add_argument('-d', '--debug', action="store_true")
    parser.add_argument('-b', '--batch', action="store_true")
    parser.add_argument('-c', '--config', help='path to config file')
    args = parser.parse_args()
    return args


def main():
    """
    Main function
    """
    # Init log
    logs = init_log()

    # Argument management
    args = parse_args()

    if args.verbose:
        logs.setLevel('VERBOSE')

    if args.debug:
        logs.setLevel('DEBUG')

    if args.batch:
        interactive = False
    else:
        interactive = True

    # Open config file and load data into variable
    data = load_config_from_yaml(args.config, logs)

    # Check if config file syntax is ok
    if check_address_syntax(data["addresses"], logs):
        logs.log(logging.VERBOSE, 'File syntax is ok')
    else:
        # if not, exit
        logs.error('File syntax is incorrect')
        sys.exit(os.EX_DATAERR)

    expand_ip_list(data["addresses"])

    # Run scans and get results
    scan_results_open_ports, scan_results_closed_ports = scan_and_compare(data["addresses"], logs)

    #  If we found more open ports than defined in baseline
    #  Then, take actions
    if scan_results_open_ports:
        logs.warning('Found more open ports than defined in baseline')
        display_results(scan_results_open_ports, logs)

    #  If we found  ports defined in baseline which are not open any more
    #  Then, take actions
    if scan_results_closed_ports:
        logs.warning('Ports defined in baseline are not open any more')
        display_results(scan_results_closed_ports, logs)

    # Final actions
    # If any compliance issue
    if scan_results_open_ports or scan_results_closed_ports:
        # If not interactive, send an email
        if not interactive:
            send_email(scan_results_open_ports, scan_results_closed_ports)

        # Exit script
        sys.exit(1)
    else:
        logs.info('Compliant to baseline')


if __name__ == "__main__":
    main()
