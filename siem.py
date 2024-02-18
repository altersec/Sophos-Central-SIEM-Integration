#!/usr/bin/env python3

# Copyright 2019-2021 Sophos Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and limitations under the
# License.
#
import sys
import json
import logging
import logging.handlers
import datetime
import logging_config #Make sure to have here, before import state!
import os
import re
import state
from optparse import OptionParser
import name_mapping
import config
import api_client
import vercheck
import configparser
import asyncio
from graph import Graph
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

VERSION = "2.1.0"
QUIET = False
MISSING_VALUE = "NA"
DEFAULT_ENDPOINT = "event"

SEVERITY_MAP = {"none": 0, "low": 1, "medium": 5, "high": 8, "very_high": 10}

CEF_CONFIG = {
    "cef.version": "0",
    "cef.device_vendor": "sophos",
    "cef.device_product": "sophos central",
    "cef.device_version": 1.0,
}

# CEF format from https://www.protect724.hpe.com/docs/DOC-1072
CEF_FORMAT = (
    "CEF:%(version)s|%(device_vendor)s|%(device_product)s|"
    "%(device_version)s|%(device_event_class_id)s|%(name)s|%(severity)s|"
)


CEF_MAPPING = {
    # This is used for mapping CEF header prefix and extension to json returned by server
    # CEF header prefix to json mapping
    # Format
    # CEF_header_prefix: JSON_key
    "device_event_class_id": "type",
    "name": "name",
    "severity": "severity",
    # json to CEF extension mapping
    # Format
    # JSON_key: CEF_extension
    "source": "suser",
    "when": "end",
    "user_id": "duid",
    "created_at": "rt",
    "full_file_path": "filePath",
    "location": "dhost",
}

schema = {
    'datastream': str, #	String		This has the value Alert or Event to distinguish between events and alerts.
    'group': str, #	String	Enum	Event group. One of: AD_SYNC, APP_REPUTATION, APPLICATION_CONTROL, BLOCKLISTED, CONNECTIVITY, 'CREDENTIAL_MANAGER,CSWITCH, DATA_LOSS_PREVENTION, DENC, DOWNLOAD_REPUTATION, ENDPOINT_FIREWALL, FORENSIC_SNAPSHOT, 'GENERAL, ISOLATION, MALWARE, MDR, MOBILES, PERIPHERALS, POLICY, PROTECTION, PUA, RUNTIME_DETECTIONS, SECURITY, 'SYSTEM_HEALTH, UAV, UNCATEGORIZED, UPDATING, UTM, VIRT, WEB, WIRELESS, XGEMAIL, ZTNA_AUTHENTICATION, ZTNA_GATEWAY, 'ZTNA_RESOURCE.
    'type': str, #	String		Event type.
    'severity': str, #	String	Enum	Allowed values: NONE, LOW, MEDIUM, HIGH, CRITICAL.
    'source': str, #	String		For endpoint events: "n/a" (for Windows Server), or user name (such as "John Smith"), or the login 'associated with the user "John-PC\Administrator".
    'source_info': str, #	Object	Source Info object (see below)	
    'location': str, #	String		For most events, this is the computer/server/firewall host name where the event occurred.
    'dhost': str, #	String		Destination host.
    'suser': str, #	String		Name of user signed in at the time of the event.

    'name': str, #	String		Event description.
    'data': str, #	Object	Alert Data object (see below)	Alert data.
    'info': str, #	Object	Alert Info object (see below)	Alert info.
    'description': str, #	String		Alert description.

    'when': str, #	String	Date-time	When the event was reported.
    'created_at': str, #	String	Date-time	When the event record was created.
    'end': str, #	String	Timestamp	When an event is created. This matches what you see in Sophos Central UI. Its value is the same as when in the JSON object, and its CEF equivalent is reported_at.

    'id': str, #	String	UUID	Event ID.
    # 'customer_id': str, #	String	UUID	Customer ID.
    # 'user_id': str, #	String		Identifies the user related to the event.
    # 'threat': str, #	String		Threat correlation ID.
    # 'endpoint_type': str, #	String	Enum	Endpoint type. One of: mobile, computer, server, security_vm, sensor, utm, access_point, wireless_network, mailbox, slec, xgfirewall, ztna_gateway, nta_appliance. Present only if endpoint_id is also present.
    # # 'endpoint_id': str, #	String	UUID	Endpoint ID associated with the event.
    # 'whitelist_properties': str, #	List of objects	Endpoint Whitelist object (see below)	
    # 'core_remedy_items': str, #	Object	Core Remedy Items object (see below)	This is set only for Endpoint Core Detection events (see below).
    # 'origin': str, #	String 	Enum	This is set only for Endpoint Core Detection events (see below). The possible values are: ML_MALWARE_DETECTION, VDL_MALWARE_DETECTION, ML_PUA_DETECTION, VDL_PUA_DETECTION, HMPA_DETECTION, MTD_DETECTION, HBT_DETECTION, SCAN_NOW, SCHEDULED_SCAN, REP_MALWARE_DETECTION, REP_PUA_DETECTION, BLOCKLISTED_BY_ADMIN, AMSI_DETECTION, IPS_DETECTION, BEHAVIORAL_DETECTION, DRIVER_BLOCKLIST.
    # 'appSha256': str, #	String	SHA256	SHA 256 hash of the application associated with the threat, if available. This is set only for Endpoint Core Detection events (see below).
    # 'appCerts': str, #	List of objects	Endpoint Core Event Certificate object (see below)	
    # 'ips_threat_data': str, #	Object	IPS Threat Data object (see below)	IPS Threat data associated with the threat, if available. This is set only for Endpoint IPS Detection events.
    # 'amsi_threat_data': str, #	Object	AMSI Threat Data object (see below)	
}

# Initialize the SIEM_LOGGER
SIEM_LOGGER = logging.getLogger("SIEM")
SIEM_LOGGER.setLevel(logging.INFO)
SIEM_LOGGER.propagate = False
logging.basicConfig(format="%(message)s")


def is_valid_fqdn(fqdn):
    fqdn = fqdn.strip()
    fqdn = fqdn[:-1] if fqdn.endswith(".") else fqdn  # chomp trailing period
    return fqdn and len(fqdn) < 256 and all(part and len(part) < 64 and re.match(r"^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$", part) for part in fqdn.split("."))

def convert_to_valid_fqdn(value):
    return ".".join([re.sub("[^-a-z0-9]+", "-", x.strip()).strip("-") for x in value.lower().split(".") if x.strip()])

def write_json_format(results, config):
    """Write JSON format data.
    Arguments:
        results {list}: data
    """
    for i in results:
        i = remove_null_values(i)
        update_cef_keys(i, config)
        name_mapping.update_fields(log, i)
        SIEM_LOGGER.info(json.dumps(i, ensure_ascii=False).strip())


def write_keyvalue_format(results, config):
    """Write key value format data.
    Arguments:
        results {dict}: results
    """
    for i in results:
        i = remove_null_values(i)
        update_cef_keys(i, config)
        name_mapping.update_fields(log, i)
        date = i[u"rt"]
        # TODO:  Spaces/quotes/semicolons are not escaped here, does it matter?
        events = list('%s="%s";' % (k, v) for k, v in i.items())
        SIEM_LOGGER.info(
            " ".join(
                [
                    date,
                ]
                + events
            ).strip()
        )


def write_cef_format(results, config):
    """Write CEF format data.
    Arguments:
        results {list}: data
    """
    for i in results:
        i = remove_null_values(i)
        name_mapping.update_fields(log, i)
        SIEM_LOGGER.info(format_cef(flatten_json(i), config).strip())


# Flattening JSON objects in Python
# https://medium.com/@amirziai/flattening-json-objects-in-python-f5343c794b10#.37u7axqta
def flatten_json(y):
    out = {}

    def flatten(x, name=""):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + "_")
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def log(s):
    """Write the log.
    Arguments:
        log_message {string} -- log content
    """
    if not QUIET:
        sys.stderr.write("%s\n" % s)


def format_prefix(data):
    """ pipe and backslash in header must be escaped. escape group with backslash
    Arguments:
        data {string}: data
    Returns:
        string -- backslash escape string
    """
    # pipe and backslash in header must be escaped
    # escape group with backslash
    return re.compile(r"([|\\])").sub(r"\\\1", data)


def format_extension(data):
    """ equal sign and backslash in extension value must be escaped. escape group with backslash.
    Arguments:
        data : data
    Returns:
        string/list -- backslash escape string or return same value
    """
    if type(data) is str:
        return re.compile(r"([=\\])").sub(r"\\\1", data)
    else:
        return data


def map_severity(severity):
    if severity in SEVERITY_MAP:
        return SEVERITY_MAP[severity]
    else:
        msg = 'The "%s" severity can not be mapped, defaulting to 0' % severity
        log(msg)
        return SEVERITY_MAP["none"]


def extract_prefix_fields(data):
    """ extract prefix fields and remove those from data dictionary
    Arguments:
        data {dict}: data
    Returns:
        fields {dict} -- fields object
    """
    name_field = CEF_MAPPING["name"]
    device_event_class_id_field = CEF_MAPPING["device_event_class_id"]
    severity_field = CEF_MAPPING["severity"]

    name = data.get(name_field, MISSING_VALUE)
    name = format_prefix(name)
    data.pop(name_field, None)

    device_event_class_id = data.get(device_event_class_id_field, MISSING_VALUE)
    device_event_class_id = format_prefix(device_event_class_id)
    data.pop(device_event_class_id_field, None)

    severity = data.get(severity_field, MISSING_VALUE)
    severity = map_severity(severity)
    data.pop(severity_field, None)

    fields = {
        "name": name,
        "device_event_class_id": device_event_class_id,
        "severity": severity,
        "version": CEF_CONFIG["cef.version"],
        "device_vendor": CEF_CONFIG["cef.device_vendor"],
        "device_version": CEF_CONFIG["cef.device_version"],
        "device_product": CEF_CONFIG["cef.device_product"],
    }
    return fields


def update_cef_keys(data, config):
    """ Replace if there is a mapped CEF key
    Arguments:
        data {dict}: data
    """
    # Replace if there is a mapped CEF key
    for key, value in list(data.items()):
        new_key = CEF_MAPPING.get(key, key)
        if new_key == key:
            continue
        if config.convert_dhost_field_to_valid_fqdn.lower() == "true" and new_key == "dhost" and not is_valid_fqdn(value):
            value = convert_to_valid_fqdn(value)
        data[new_key] = value
        del data[key]


def format_cef(data, config):
    """ Message CEF formatted
    Arguments:
        data {dict}: data
    Returns:
        data {str}: message
    """
    fields = extract_prefix_fields(data)
    msg = CEF_FORMAT % fields

    update_cef_keys(data, config)
    for index, (key, value) in enumerate(data.items()):
        value = format_extension(value)
        if index > 0:
            msg += " %s=%s" % (key, value)
        else:
            msg += "%s=%s" % (key, value)
    return msg


def remove_null_values(data):
    """ Removed null value
    Arguments:
        data {dict}: data
    Returns:
        data {dict}: update data
    """
    return {k: v for k, v in data.items() if v is not None}


def parse_args_options():
    """ Parsed the command line arguments
    Returns:
        options {dict}: options data
    """
    global QUIET
    if "SOPHOS_SIEM_HOME" in os.environ:
        app_path = os.environ["SOPHOS_SIEM_HOME"]
    else:
        # Setup path
        app_path = os.path.join(os.getcwd())

    config_file = os.path.join(app_path, "config.ini")

    parser = OptionParser(
        description="Download event and/or alert data and output to various formats. "
        "config.ini is a configuration file that exists by default in the siem-scripts "
        "folder."
        "Script keeps tab of its state, it will always pick-up from where it left-off "
        "based on a state file stored in state folder. Set SOPHOS_SIEM_HOME environment "
        "variable to point to the folder where config.ini, mapping files, state "
        "and log folders will be located. state and log folders are created when the "
        "script is run for the first time. "
    )
    parser.add_option(
        "-s",
        "--since",
        default=False,
        action="store",
        help="Return results since specified Unix "
        "Timestamp, max last 24 hours, defaults to "
        "last 12 hours if there is no state file",
    )
    parser.add_option(
        "-c",
        "--config",
        default=config_file,
        action="store",
        help="Specify a configuration file, " "defaults to config.ini",
    )
    parser.add_option(
        "-l",
        "--light",
        default=True,
        action="store_true",
        help="Ignore noisy events - web control, "
        "device control, update failure, "
        "application allowed, (non)compliant",
    )
    parser.add_option(
        "-d", "--debug", default=False, action="store_true", help="Print debug logs"
    )
    parser.add_option(
        "-v", "--version", default=False, action="store_true", help="Print version"
    )
    parser.add_option(
        "-q",
        "--quiet",
        default=False,
        action="store_true",
        help="Suppress status messages",
    )

    options, args = parser.parse_args()

    if options.config is None:
        parser.error("Need a config file specified")

    if options.version:
        log(VERSION)
        sys.exit(0)
    if options.quiet:
        QUIET = True

    return options


def load_config(config_path):
    """ Get config file data
    Arguments:
        config_path {str}: config file path
    Returns:
        cfg {dice}: config.ini data
    """
    cfg = config.Config(config_path)
    cfg.format = cfg.format.lower()
    cfg.endpoint = cfg.endpoint.lower()
    validate_format(cfg.format)
    validate_endpoint(cfg.endpoint)
    return cfg

def validate_format(format):
    if format not in ("json", "keyvalue", "cef"):
        raise Exception("Invalid format in config.ini, format can be json, cef or keyvalue")

def validate_endpoint(endpoint):
    endpoint_map = api_client.ENDPOINT_MAP
    if endpoint not in endpoint_map:
        raise Exception("Invalid endpoint in config.ini, endpoint can be event, alert or all")

def get_alerts_or_events(endpoint, options, config, state):
    """ Get alerts/events data
    Arguments:
        endpoint {str}: endpoint name
        options {dict}: options
        config {dict}: config file details
        state {dict}: state file details
    """
    api_client_obj = api_client.ApiClient(endpoint, options, config, state)
    results = api_client_obj.get_alerts_or_events()
    
    if config.format == "json":
        write_json_format(results, config)
    elif config.format == "keyvalue":
        write_keyvalue_format(results, config)
    elif config.format == "cef":
        write_cef_format(results, config)
    else:
        write_json_format(results, config)

def run(options, config_data, state):
    """ Call the fetch alerts/events method
    Arguments:
        options {dict}: options
        config_data {dict}: config file details
        state {dict}: state file details
    """
    endpoint_map = api_client.ENDPOINT_MAP
    if config_data.endpoint in endpoint_map:
        tuple_endpoint = endpoint_map[config_data.endpoint]
    else:
        tuple_endpoint = endpoint_map[DEFAULT_ENDPOINT]

    for endpoint in tuple_endpoint:
        get_alerts_or_events(
            endpoint, options, config_data, state
        )

async def send_mail(graph: Graph, subject, body, recipient, sender):
    await graph.send_mail(subject,body,recipient,sender)

async def main():
    options = parse_args_options()

    logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).astimezone().isoformat(sep="T",timespec="milliseconds"))
  


    config_data = load_config(options.config)
    logging.info("Logging Level is set as: "+config_data.logging_level)
    logger = logging.getLogger()
    logger.setLevel(config_data.logging_level)
    if (logger.level <= logging.DEBUG):
        logger.handlers[0].setFormatter(logging.Formatter(logging_config.DEBUG_FORMAT))
       
    state_data = state.State(options, config_data.state_file_path)
    run(options, config_data, state_data)

    config_ini = configparser.ConfigParser()
    config_ini.read('config.ini')
    azure_settings = config_ini['azure']
    sender = config_ini['email']['senderEmail']
    recipient = config_ini['email']['recipientEmail']

    log_file_path = 'log/'+config_data.filename
    log_old_file_path = 'log/'+config_data.filename+'.old'

    with open(log_file_path, 'a+', encoding='utf-8') as file:
        lines = file.readlines()
        file.seek(0)
        file.truncate()
    data = [json.loads(line) for line in lines]

    with open(log_old_file_path, 'a+', encoding='utf-8') as file:
        lines = file.readlines()
        last_500_lines = lines[-500:]
        file.seek(0)
        file.truncate()
        file.writelines(last_500_lines)
        for item in data:
            file.write(json.dumps(item, ensure_ascii=False) + '\n')

    graph: Graph = Graph(azure_settings)

    for line in data:
        subject = '[MDR Alert] '+ str(line.get('type'))
        message = []
        for key in schema.keys():
            if line.get(key) != None:
                message.append(f'{key}: {line.get(key)}')
        body='\n'.join(message)
    
        try:
            await send_mail(graph, subject, body, recipient, sender)
        except ODataError as odata_error:
            print('Error:')
            if odata_error.error:
                print(odata_error.error.code, odata_error.error.message)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
    