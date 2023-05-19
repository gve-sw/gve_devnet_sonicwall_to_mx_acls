#!/usr/bin/env python3
"""
Copyright (c) 2023 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Trevor Maco <tmaco@cisco.com>"
__copyright__ = "Copyright (c) 2023 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import copy
import csv
import getopt
import ipaddress
import itertools
import json
import os
import re
import sys

import meraki
from ciscoconfparse import CiscoConfParse
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.prompt import Confirm

from config import *

# Rich Console Instance
console = Console()

# Meraki Dashboard instance
dashboard = meraki.DashboardAPI(MERAKI_API_KEY, suppress_logging=True)

# Maintain list of Policy Objects and Policy Object Groups (initialized with existing groups)
objects = {}
fqdn_objects = {}
range_objects = {}
object_groups = {}
range_object_groups = {}
fqdn_object_groups = {}
group_of_groups = {}

# Service objects
service_objects = {}
service_object_groups = {}
service_group_of_groups = {}

# Map corresponding to default behavior between zones
default_zone_map = {}

# Global Flags
MAPPING_FLAG = False

# Subnet / wildcard mask to CIDR prefix length lookup table
SUBNET_MASKS = {
    "128.0.0.0": "1",
    "127.255.255.255": "1",
    "192.0.0.0": "2",
    "63.255.255.255": "2",
    "224.0.0.0": "3",
    "31.255.255.255": "3",
    "240.0.0.0": "4",
    "15.255.255.255": "4",
    "248.0.0.0": "5",
    "7.255.255.255": "5",
    "252.0.0.0": "6",
    "3.255.255.255": "6",
    "254.0.0.0": "7",
    "1.255.255.255": "7",
    "255.0.0.0": "8",
    "0.255.255.255": "8",
    "255.128.0.0": "9",
    "0.127.255.255": "9",
    "255.192.0.0": "10",
    "0.63.255.255": "10",
    "255.224.0.0": "11",
    "0.31.255.255": "11",
    "255.240.0.0": "12",
    "0.15.255.255": "12",
    "255.248.0.0": "13",
    "0.7.255.255": "13",
    "255.252.0.0": "14",
    "0.3.255.255": "14",
    "255.254.0.0": "15",
    "0.1.255.255": "15",
    "255.255.0.0": "16",
    "0.0.255.255": "16",
    "255.255.128.0": "17",
    "0.0.0.127.255": "17",
    "255.255.192.0": "18",
    "0.0.63.255": "18",
    "255.255.224.0": "19",
    "0.0.31.255": "19",
    "255.255.240.0": "20",
    "0.0.15.255": "20",
    "255.255.248.0": "21",
    "0.0.7.255": "21",
    "255.255.252.0": "22",
    "0.0.3.255": "22",
    "255.255.254.0": "23",
    "0.0.1.255": "23",
    "255.255.255.0": "24",
    "0.0.0.255": "24",
    "255.255.255.128": "25",
    "0.0.0.127": "25",
    "255.255.255.192": "26",
    "0.0.0.63": "26",
    "255.255.255.224": "27",
    "0.0.0.31": "27",
    "255.255.255.240": "28",
    "0.0.0.15": "28",
    "255.255.255.248": "29",
    "0.0.0.7": "29",
    "255.255.255.252": "30",
    "0.0.0.3": "30",
    "255.255.255.254": "31",
    "0.0.0.1": "31",
    "255.255.255.255": "32",
    "0.0.0.0": "32",
}

# Note: this regex matches ipv4 rules only and extracts out pieces if they are present
ACL_RULE_REGEX = r'access-rule ipv4 from (\w+) to (\w+)(?: action (\w+))?(?: source address (name "[^"]+"|name [\w|\-|\.]+|group "[^"]+"|group [\w|\-|\.]+))?(?: service (name "[^"]+"|name [\w|\-|\.]+|group "[^"]+"|group [\w|\-|\.]+))?(?: destination address (name "[^"]+"|name [\w|\-|\.]+|group "[^"]+"|group [\w|\-|\.]+))?'


def build_mx_object(print_console, object_type, element, broken_fp):
    """
    Process individual object from show run config file, individual processing determined based on object type.
    :param broken_fp: file to write broken objects to
    :param print_console: print status messages to console
    :param object_type: type of object we are processing
    :param element: object we are processing
    :return:
    """
    global objects, fqdn_objects, range_objects, object_groups, fqdn_object_groups, service_objects, service_object_groups, group_of_groups, \
        service_group_of_groups

    mx_object = {}

    # Build Policy Object
    if object_type == 'object':
        name = element.text.replace('address-object ipv4 ', '')
        name = name.replace('"', '').replace('.', '_').replace(':', '_')

        if name not in objects and name + '__range__' not in range_objects:
            mx_object['name'] = name
            mx_object['category'] = 'network'

            # Process sub-lines of element
            lines = element.children

            # Case of no children elements, ignore
            if len(lines) == 0:
                return None

            for line in lines:
                content = line.text.split()

                if content[0] == 'host':
                    mx_object['type'] = 'cidr'
                    mx_object['cidr'] = content[1] + '/32'
                elif content[0] == 'network':
                    mx_object['type'] = 'cidr'
                    mx_object['cidr'] = content[1] + '/' + SUBNET_MASKS[content[2]]
                elif content[0] == 'range':
                    mx_object['type'] = 'cidr'

                    # Set start and end IP
                    startip = ipaddress.IPv4Address(content[1])
                    endip = ipaddress.IPv4Address(content[2])

                    mx_object['range'] = [str(ipaddr) for ipaddr in ipaddress.summarize_address_range(startip, endip)]
                elif content[0] == 'zone':
                    mx_object['zone'] = content[1]

            if 'type' not in mx_object:
                reason = "No valid host or network line"

                print_console.print(f'[red]{reason}... skipping.[/]')
                broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')
                return None

        else:
            print_console.print(f'[red]Object already exists! ... skipping.[/]')
            return None

    # Build Policy FQDN Object
    elif object_type == 'fqdn':
        name = element.text.replace('address-object fqdn ', '')
        name = name.replace('"', '').replace('.', '_').replace(':', '_').replace('*', '_')

        if name not in fqdn_objects:

            mx_object['name'] = name
            mx_object['category'] = 'network'

            # Process sub-lines of element
            lines = element.children

            # Case of no children elements, ignore
            if len(lines) == 0:
                return None

            for line in lines:
                content = line.text.split()

                if content[0] == 'domain':
                    mx_object['type'] = 'fqdn'
                    mx_object['fqdn'] = content[1]

            if 'type' not in mx_object:
                reason = "No domain line"

                print_console.print(f'[red]{reason}... skipping.[/]')
                broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')
                return None

        else:
            print_console.print(f'[red]Object already exists! ... skipping.[/]')
            return None

    # Build Policy Object Group (ipv4)
    elif object_type == 'group':
        name = element.text.replace('address-group ipv4 ', '')
        name = name.replace('"', '').replace('.', '_').replace(':', '_')

        # Ignore objects that already exist
        if name not in object_groups:
            mx_object['name'] = name
            mx_object['category'] = 'NetworkObjectGroup'
            mx_object['objectIds'] = []
            mx_object['rangeIds'] = []
            mx_object['group_of_groups'] = []

            # Process sub-lines of element
            lines = element.children

            # Case of no children elements, ignore
            if len(lines) == 0:
                return None

            for line in lines:
                content = line.text.strip()

                # Add object id to object group
                if content.startswith('address-object ipv4'):
                    content = content.replace('address-object ipv4', '').strip()

                    # Sanitize
                    content = content.replace('"', '').replace('.', '_').replace(':', '_')

                    # Invalid object that was unsupported before, won't be in group (write to broken file)
                    if content not in objects and content + '__range__' not in range_objects:
                        reason = f'Invalid object "{content}" in group "{element.text}"'

                        print_console.print(f'[red]{reason}... skipping.[/]')
                        broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')

                        continue

                    if content in objects:
                        object_id = objects[content]
                        mx_object['objectIds'].append(object_id)
                    elif content + '__range__' in range_objects:
                        range_id = range_objects[content + '__range__']
                        mx_object['rangeIds'].append(range_id)
                    else:
                        group_id = object_groups[content]
                        mx_object['group_of_groups'].append(group_id)

                # Nested group object case
                elif content.startswith('address-group ipv4'):
                    content = content.replace('address-group ipv4', '').strip()

                    # Sanitize
                    content = content.replace('"', '').replace('.', '_').replace(':', '_')

                    # Nested group not found
                    if content not in object_groups:
                        reason = f'Invalid object "{content}" in group "{element.text}"'

                        print_console.print(f'[red]{reason}... skipping.[/]')
                        broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')

                        continue

                    group_id = object_groups[content]
                    mx_object['group_of_groups'].append(group_id)
        else:
            print_console.print(f'[red]Object Group already exists! ... skipping.[/]')
            return None

    # Build Policy Object Group (ipv6)
    elif object_type == 'group-ipv6':
        name = element.text.replace('address-group ipv6 ', '')
        name = name.replace('"', '')

        # Ignore objects that already exist
        if name not in object_groups and name not in fqdn_object_groups:
            mx_object['name'] = name
            mx_object['category'] = 'NetworkObjectGroup'
            mx_object['objectIds'] = []
            mx_object['objectCidrs'] = []
            mx_object['objectFQDNs'] = []
            mx_object['group_of_groups'] = []

            # Process sub-lines of element
            lines = element.children

            # Case of no children elements, ignore
            if len(lines) == 0:
                return None

            for line in lines:
                content = line.text.strip()

                # fqdn object case
                if content.startswith('address-object fqdn'):
                    content = content.replace('address-object fqdn', '').strip()

                    # Sanitize
                    content = content.replace('"', '').replace('.', '_').replace(':', '_').replace('*', '_')

                    # Invalid object that was unsupported before, won't be in group
                    if content not in fqdn_objects:
                        reason = f'Invalid object "{content}" in group "{element.text}"'

                        print_console.print(f'[red]{reason}... skipping.[/]')
                        broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')

                        continue

                    object_id = fqdn_objects[content]
                    mx_object['objectFQDNs'].append(object_id)

                # Add object id to object group
                elif content.startswith('address-object ipv4'):
                    content = content.replace('address-object ipv4', '').strip()

                    # Sanitize
                    content = content.replace('"', '').replace('.', '_').replace(':', '_')

                    # Invalid object that was unsupported before, won't be in group
                    if content not in objects:
                        reason = f'Invalid object "{content}" in group "{element.text}"'

                        print_console.print(f'[red]{reason}... skipping.[/]')
                        broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')

                        continue

                    object_id = objects[content]
                    mx_object['objectIds'].append(object_id)

        else:
            print_console.print(f'[red]Object Group already exists! ... skipping.[/]')
            return None

    # Build service object (custom data structure, not natively supported in Meraki)
    elif object_type == 'service':
        element = element.text.replace('service-object ', '')

        # Check if element name is in quotes
        if element[0] == '"':
            element = element.split('"')

            mx_object['name'] = element[1]
            element = element[2].strip().split()

            if element[0] == 'TCP' or element[0] == 'UDP':
                mx_object['protocol'] = element[0]
                # if port is the same, then a single port case, else a range case
                if element[1] == element[2]:
                    mx_object['port'] = element[1]
                else:
                    mx_object['port'] = element[1] + '-' + element[2]
            elif element[0] == 'ICMP' or element[0] == 'ICMPV6':
                # ICMP Support
                mx_object['protocol'] = element[0]
            else:
                reason = f'Invalid Service Object (service not supported, missing ports, etc.)'

                print_console.print(f'[red]{reason}... skipping.[/]')
                broken_fp.write('service object ' + mx_object['name'] + '\n\t' + f'- Reason: {reason}\n')
                return None

        else:
            element = element.split()

            mx_object['name'] = element[0]

            if element[1] == 'TCP' or element[1] == 'UDP':
                mx_object['protocol'] = element[1]
                # if port is the same, then a single port case, else a range case
                if element[2] == element[3]:
                    mx_object['port'] = element[2]
                else:
                    mx_object['port'] = element[2] + '-' + element[3]
            elif element[1] == 'ICMP' or element[1] == 'ICMPV6':
                # ICMP Support
                mx_object['protocol'] = element[1]
            else:
                print_console.print(
                    '[red]Invalid Service Object (service not supported, missing ports, etc.)... skipping.[/]')
                return None

    # Build service group (custom data structure, not natively supported in Meraki)
    elif object_type == 'service-group':
        name = element.text.replace('service-group ', '').replace('"', '')

        mx_object['name'] = name
        mx_object['service_objects'] = []
        mx_object['group_of_groups'] = []

        # Ignore objects that already exist
        if name not in service_object_groups:
            # Process sub-lines of element
            lines = element.children

            # Case of no children elements, ignore
            if len(lines) == 0:
                return None

            for line in lines:
                content = line.text.strip()

                # Process Service object
                if content.startswith('service-object'):
                    content = content.replace('service-object', '').strip()

                    # Sanitize
                    content = content.replace('"', '')

                    # Invalid object that was unsupported before, won't be in group
                    if content not in service_objects:
                        reason = f'Invalid service object "{content}" in group "{element.text}"'

                        print_console.print(f'[red]{reason}... skipping.[/]')
                        broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')
                        continue

                    mx_object['service_objects'].append([service_objects[content][0], service_objects[content][1]])

                # Nested group object case
                elif content.startswith('service-group'):
                    content = content.replace('service-group', '').strip()

                    # Sanitize
                    content = content.replace('"', '')

                    # Nested group not found
                    if content not in service_object_groups:
                        reason = f'Invalid service object "{content}" in group "{element.text}"'

                        print_console.print(f'[red]{reason}... skipping.[/]')
                        broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')

                        continue

                    services = service_object_groups[content]
                    mx_object['group_of_groups'] += services

            if len(mx_object['service_objects']) == 0:
                reason = f'No valid service object line... skipping.'

                print_console.print(f'[red]{reason}... skipping.[/]')
                broken_fp.write(element.text + '\n\t' + f'- Reason: {reason}\n')
                return None
        else:
            print_console.print(f'[red]Service Group already exists... skipping.[/]')
            return None

    return mx_object


def duplicate_splitter(object_list, object_type):
    """
    Splits nested objects, rules, etc. Splits on keyword 'exit', clones and dynamically builds new objects from nested objects.
    :param object_list: current object list (needed to duplicate list for processing
    :param object_type: object type, changes name processing for new object
    :return:
    """
    new_entries = []

    # If there are nested sub-objects, separate contents -> prepare to build new object
    duplicates = object_list.copy()
    for element in duplicates:
        size = len(element.children)

        # Find 'Exit' indexes
        idx_list = [idx + 1 for idx, val in enumerate(element.children) if 'exit' in val.text]

        # Weird case of exit not present
        if len(idx_list) == 0:
            continue

        # Separate list by exits
        res = [element.children[i: j] for i, j in
               zip([0] + idx_list, idx_list + ([size] if idx_list[-1] != size else []))]

        if len(res) > 1:
            clone = copy.deepcopy(element)
            if object_type == 'ipv4':
                clone.text = f"address-object ipv4 {res[1][0].text.strip().replace('name ', '')}"
            elif object_type == 'ipv4-group':
                clone.text = f"address-group ipv4 {res[1][0].text.strip().replace('name ', '')}"
            elif object_type == 'ipv6-group':
                clone.text = f"address-group ipv6 {res[1][0].text.strip().replace('name ', '')}"
            elif object_type == 'ipv6':
                clone.text = f"address-object ipv6 {res[1][0].text.strip().replace('name ', '')}"
            elif object_type == 'fqdn':
                clone.text = f"address-object fqdn {res[1][0].text.strip().replace('name ', '')}"
            elif object_type == 'rule':
                clone.text = f"{element.text} (Sub Rule)"

            clone.children = res[1]

            # Add clone to list
            new_entries.append(clone)

            console.print(f'Broke apart new sub element {clone.text}')

            # remove back half children
            element.children = res[0]

    return new_entries


def create_objects(org_id, parse):
    """
    Build out objects and constructs from ASA Show Run and ACL for the MX. Objects include network objects, network object groups, port groups, protocol groups, and nat table.
    :param org_id: meraki org id
    :param parse: CiscoConfParse object representing parsed form of show run file
    :return:
    """
    global objects, fqdn_objects, range_objects, object_groups, fqdn_object_groups, service_objects, service_object_groups, group_of_groups

    # Grab existing list of policy objects, create new dictionary mapping name to id
    policy_objects = dashboard.organizations.getOrganizationPolicyObjects(organizationId=org_id)

    for obj in policy_objects:
        # Network Case
        if obj['type'] == 'cidr':
            objects[obj['name']] = obj['id']
        # FQDN Case
        elif obj['type'] == 'fqdn':
            fqdn_objects[obj['name']] = obj['id']

    # Grab existing list of policy object groups, create new dictionary mapping name to id
    policy_object_groups = dashboard.organizations.getOrganizationPolicyObjectsGroups(organizationId=org_id)

    for obj in policy_object_groups:
        # range case
        if '__range__' in obj['name']:
            range_objects[obj['name']] = obj['id']
            continue

        res = all(ele in list(objects.values()) for ele in obj['objectIds'])

        if res:
            # Object group is normal ipv4 object group
            object_groups[obj['name']] = obj['id']
        else:
            # check failed, therefore object ids are in fqdn list and this is a fqdn group
            fqdn_object_groups[obj['name']] = obj['id']

    # Open invalid objects file
    broken_fp = open('unprocessed_objects.txt', 'w')

    # Parse network objects (ipv4)
    solo_objects = parse.find_objects(r'^address-object ipv4')

    # If there are nested sub-objects, separate contents -> prepare to build new object
    new_entries = duplicate_splitter(solo_objects, 'ipv4')
    solo_objects += new_entries

    solo_object_count = len(solo_objects)

    console.print("[blue]Creating IPv4 Network Objects[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=solo_object_count, transient=True)
        counter = 1

        for element in solo_objects:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(element.text.replace('address-object ipv4 ', ''),
                                                                   str(counter), solo_object_count))
            # Construct post body
            mx_object = build_mx_object(progress.console, 'object', element, broken_fp)

            # Error building object (likely not supported) if this skips
            if mx_object:
                # Range case
                if 'range' in mx_object:
                    object_ids = []
                    for idx, ip in enumerate(mx_object['range']):
                        # Create MX Object (cidr) -  no need to add to local dictionary!y
                        new_object = dashboard.organizations.createOrganizationPolicyObject(organizationId=org_id,
                                                                                            name=mx_object[
                                                                                                     'name'] + '__range__' + str(
                                                                                                idx),
                                                                                            category=mx_object[
                                                                                                'category'],
                                                                                            type=mx_object["type"],
                                                                                            cidr=ip)
                        object_ids.append(new_object['id'])

                    # Create new object network group (no empty groups!)
                    if len(object_ids) > 0:
                        new_group = dashboard.organizations.createOrganizationPolicyObjectsGroup(organizationId=org_id,
                                                                                                 name=mx_object[
                                                                                                          'name'] + '__range__',
                                                                                                 objectIds=object_ids)
                        # Add new object to list
                        range_objects[new_group['name']] = new_group['id']
                    else:
                        progress.console.print(f"[red]Ignoring Empty Object[/]")

                else:
                    # Create MX Object (cidr)
                    new_object = dashboard.organizations.createOrganizationPolicyObject(organizationId=org_id,
                                                                                        name=mx_object['name'],
                                                                                        category=mx_object['category'],
                                                                                        type=mx_object["type"],
                                                                                        cidr=mx_object["cidr"])
                    # Add new object to list
                    objects[new_object['name']] = new_object['id']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse fqdn objects
    solo_fqdn_objects = parse.find_objects(r'^address-object fqdn')

    # If there are nested sub-objects, separate contents -> prepare to build new object
    new_entries = duplicate_splitter(solo_fqdn_objects, 'fqdn')
    solo_fqdn_objects += new_entries

    solo_fqdn_objects_count = len(solo_fqdn_objects)

    console.print("[blue]Creating FQDN Objects[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=solo_fqdn_objects_count, transient=True)
        counter = 1

        for element in solo_fqdn_objects:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(
                    element.text.replace('address-object fqdn ', ''),
                    str(counter), solo_fqdn_objects_count))

            # Construct post body
            mx_object = build_mx_object(progress.console, 'fqdn', element, broken_fp)

            # Error building object (likely not supported) if this skips
            if mx_object:
                if mx_object["type"] == 'fqdn':
                    # Create MX Object (fqdn)
                    new_object = dashboard.organizations.createOrganizationPolicyObject(organizationId=org_id,
                                                                                        name=mx_object['name'],
                                                                                        category=mx_object['category'],
                                                                                        type=mx_object["type"],
                                                                                        fqdn=mx_object["fqdn"])

                # Add new object to list
                fqdn_objects[new_object['name']] = new_object['id']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse group network objects (ipv4)

    # Only grab non nested address groups first (due to SonicWall allowing definition of address groups after usage)
    group_objects = parse.find_objects_wo_child(r'^address-group ipv4', r'address-group ipv4')

    new_entries = duplicate_splitter(group_objects, 'ipv4-group')
    group_objects += new_entries

    group_objects_count = len(group_objects)

    console.print("[blue]Creating IPv4 Network Object Groups[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=group_objects_count, transient=True)
        counter = 1

        for element in group_objects:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(
                    element.text.replace('address-group ipv4 ', ''),
                    str(counter), group_objects_count))

            # Construct post body
            mx_object = build_mx_object(progress.console, 'group', element, broken_fp)

            # Error building object (likely not supported) if this skips
            if mx_object:
                if 'rangeIds' in mx_object and len(mx_object['rangeIds']) > 0:
                    # If range ips present, nested group with range objects
                    range_object_groups[mx_object['name'] + '__range__'] = [mx_object['objectIds'],
                                                                            mx_object['rangeIds']]
                else:
                    # Create new object network group (no empty groups!)
                    if len(mx_object['objectIds']) > 0:
                        new_group = dashboard.organizations.createOrganizationPolicyObjectsGroup(organizationId=org_id,
                                                                                                 name=mx_object['name'],
                                                                                                 objectIds=mx_object[
                                                                                                     'objectIds'])

                        # Add new object to list
                        object_groups[new_group['name']] = new_group['id']
                    else:
                        reason = f'"{mx_object["name"]}" contains no valid entries'

                        progress.console.print(f'[red]{reason}[/]')
                        broken_fp.write('address-group ipv4 ' + mx_object["name"] + '\n\t' + f'- Reason: {reason}\n')

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse group network objects (FQDN groups)
    # Only grab non nested address groups first (due to SonicWall allowing definition of address groups after usage)
    group_objects = parse.find_objects_wo_child(r'^address-group ipv6', r'address-group ipv6')

    new_entries = duplicate_splitter(group_objects, 'ipv6-group')
    group_objects += new_entries

    group_objects_count = len(group_objects)

    console.print("[blue]Creating FQDN Network Object Groups[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=group_objects_count, transient=True)
        counter = 1

        for element in group_objects:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(
                    element.text.replace('address-group ipv6 ', ''),
                    str(counter), group_objects_count))

            # Construct post body
            mx_object = build_mx_object(progress.console, 'group-ipv6', element, broken_fp)

            # Error building object (likely not supported) if this skips
            if mx_object:
                # FQDN's present, meaning this ipv6 group is really an ipv4 group with fqdn (and possible ipv4 objects)
                if len(mx_object['objectFQDNs']) > 0:
                    # Meraki Mixed Objects Not Supported, splitting group!
                    if len(mx_object['objectIds']) > 0:
                        # Create FQDN split group
                        if mx_object['name'] + '__fqdn__split' not in fqdn_object_groups:
                            new_group_fqdn = dashboard.organizations.createOrganizationPolicyObjectsGroup(
                                organizationId=org_id,
                                name=mx_object['name'] + '__fqdn__split',
                                objectIds=mx_object['objectFQDNs'])

                            # Add new object to list
                            fqdn_object_groups[new_group_fqdn['name']] = new_group_fqdn['id']

                        # Create IPv4 split group
                        if mx_object['name'] + '__ipv4__split' not in object_groups:
                            new_group_ipv4 = dashboard.organizations.createOrganizationPolicyObjectsGroup(
                                organizationId=org_id,
                                name=mx_object['name'] + '__ipv4__split',
                                objectIds=mx_object['objectIds'])

                            # Add new object to list
                            object_groups[new_group_ipv4['name']] = new_group_ipv4['id']

                    else:
                        # Create new object network group (no empty groups!)
                        if len(mx_object['objectIds'] + mx_object['objectFQDNs']) > 0:
                            new_group = dashboard.organizations.createOrganizationPolicyObjectsGroup(
                                organizationId=org_id,
                                name=mx_object['name'],
                                objectIds=mx_object[
                                              'objectIds'] +
                                          mx_object[
                                              'objectFQDNs'])

                            # Add new object to list
                            fqdn_object_groups[new_group['name']] = new_group['id']
                        else:
                            reason = f'"{mx_object["name"]}" contains no valid entries'

                            progress.console.print(f'[red]{reason}[/]')
                            broken_fp.write(
                                'address-group ipv6 ' + mx_object["name"] + '\n\t' + f'- Reason: {reason}\n')

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse group network nested objects - Only grab remaining nested address groups (and mixed groups)
    group_objects = parse.find_objects_w_child(r'^address-group ipv4', r'address-group ipv4')
    group_objects_count = len(group_objects)

    console.print("[blue]Creating IPv4 Network Object Groups (Nested)[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=group_objects_count, transient=True)
        counter = 1

        for element in group_objects:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(
                    element.text.replace('address-group ipv4 ', ''),
                    str(counter), group_objects_count))

            # Construct post body
            mx_object = build_mx_object(progress.console, 'group', element, broken_fp)

            # Error building object (likely not supported) if this skips
            if mx_object:
                # nested group case
                if len(mx_object['group_of_groups']) > 0 and mx_object['name'] not in group_of_groups:
                    group_of_groups[mx_object['name']] = [mx_object['objectIds'], mx_object['group_of_groups']]

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse service-objects
    service_object = parse.find_objects(r'^service-object')
    service_groups_count = len(service_object)

    console.print("[blue]Creating Service Objects[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=service_groups_count, transient=True)
        counter = 1

        for element in service_object:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(
                    element.text.replace('service-object ', ''),
                    str(counter), service_groups_count))

            service_element = build_mx_object(progress.console, 'service', element, broken_fp)

            if service_element:
                # Build service object dictionary
                service_objects[service_element['name']] = [service_element['protocol'], service_element[
                    'port'] if 'port' in service_element else 'N/A']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse non nested service-groups first (due to SonicWall allowing definition of address groups after usage)
    service_groups = parse.find_objects_wo_child(r'^service-group', r'service-group')
    service_groups_count = len(service_groups)

    console.print("[blue]Creating Service Groups[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=service_groups_count, transient=True)
        counter = 1

        for element in service_groups:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(
                    element.text.replace('service-group ', ''),
                    str(counter), service_groups_count))

            service_element = build_mx_object(progress.console, 'service-group', element, broken_fp)

            if service_element:
                # Build service object group dictionary
                service_object_groups[service_element['name']] = service_element['service_objects']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Parse nested service-group objects - Only grab remaining nested groups (and mixed groups)
    service_groups = parse.find_objects_w_child(r'^service-group', r'service-group')
    service_groups_count = len(service_groups)

    console.print("[blue]Creating Service Groups (Nested)[/]")
    with Progress() as progress:
        overall_progress = progress.add_task("Overall Progress", total=service_groups_count, transient=True)
        counter = 1

        for element in service_groups:
            progress.console.print(
                "Processing object: [blue]{}[/] ({} of {})".format(
                    element.text.replace('service-group ', ''),
                    str(counter), service_groups_count))

            service_element = build_mx_object(progress.console, 'service-group', element, broken_fp)

            # Error building object (likely not supported) if this skips
            if service_element:
                # nested group case
                if len(service_element['group_of_groups']) > 0 and service_element[
                    'name'] not in service_group_of_groups:
                    service_group_of_groups[service_element['name']] = service_element['service_objects'] + \
                                                                       service_element['group_of_groups']

            counter += 1
            progress.update(overall_progress, advance=1)

    # Close file
    broken_fp.close()

    return


def combine_like_services(service_objs):
    """
    Combine like protocol elements into comma separated list (not including ranges)
    :param service_objs: list of service objects
    :return:
    """
    # Combine like protocol elements into comma separated lists (ranges are kept separate)
    result = []
    tcp_list = []
    udp_list = []
    icmp_list = []

    for service in service_objs:
        # Maintain range objects
        if '-' in service[1]:
            result.append(service)
        # Break down individual objects to build comma separated list
        else:
            if service[0] == 'TCP':
                # Handle nested service objects, service objects
                if service[1] not in tcp_list:
                    tcp_list.append(service[1])
                else:
                    continue
            elif service[0] == 'UDP':
                # Handle nested service objects, service objects
                if service[1] not in udp_list:
                    udp_list.append(service[1])
                else:
                    continue
            elif service[0] == 'ICMP' or service[0] == 'ICMPV6':
                icmp_list = [service[0], 'N/A']

    # Combine joined lists back into results
    if len(tcp_list) > 0:
        tcp_list = ','.join(tcp_list)
        result.append(['TCP', tcp_list])

    if len(udp_list) > 0:
        udp_list = ','.join(udp_list)
        result.append(['UDP', udp_list])

    if len(icmp_list) > 0:
        result.append(icmp_list)

    return result


def regex_match(line, acl):
    """
    Attempt to extract information from line using regex. Done before child processing due to possibly SonicWall discrepencies.
    :param line: current line
    :param acl: current rule's acl
    :return:
    """
    # attempt to match access rule line to regex, group all present components
    match = re.match(ACL_RULE_REGEX, line)

    if match:
        # Zones
        src_zone = match.group(1)
        dst_zone = match.group(2)

        action = match.group(3)
        source_address = match.group(4)
        service = match.group(5)
        destination_address = match.group(6)

        if src_zone:
            acl['src_zone'] = src_zone

        if dst_zone:
            acl['dst_zone'] = dst_zone

        if action:
            acl['action'] = action

        if source_address:
            result = source_parser(source_address, acl)

            if result != 'Success':
                return result

        if destination_address:
            result = destination_parser(destination_address, acl)

            if result != 'Success':
                return result

        if service:
            result = service_parser(service, acl)

            if result != 'Success':
                return result

    return 'Success'


def source_parser(src_address, acl):
    """
    Parse source objects, extract and build relevant objects
    :param src_address: line containing source
    :param acl: current rule's acl dictionary
    :return:
    """
    # Any Case
    if 'any' in src_address:
        acl['src'] = 'any'

    # Source Object Case
    elif 'name' in src_address:
        src_obj = src_address.replace('name', '').strip()

        # Sanitize
        src_obj = src_obj.replace('"', '').replace('.', '_').replace(':', '_').replace('*', '_')

        # If object found, use ID as source
        if src_obj in objects:
            obj_id = objects[src_obj]
            acl["src"] = f"OBJ[{obj_id}]"
        elif src_obj + '__range__' in range_objects:
            obj_id = range_objects[src_obj + '__range__']
            acl["src"] = f"GRP[{obj_id}]"
        elif src_obj in fqdn_objects:
            return 'FQDN Source Address not supported in Meraki'
        else:
            return "No valid Source Object exists"

    # Source Group
    elif 'group' in src_address:
        src_obj_group = src_address.replace('group', '').strip()

        # Sanitize
        src_obj_group = src_obj_group.replace('"', '').replace('.', '_').replace(':', '_').replace('*', '_')

        # If object found (ipv4 groups), use ID as source
        if src_obj_group in object_groups:
            obj_id = object_groups[src_obj_group]
            acl["src"] = f"GRP[{obj_id}]"
        # Range case
        elif src_obj_group + '__range__' in range_object_groups:
            obj_list = range_object_groups[src_obj_group + '__range__']
            acl["src"] = [f"OBJ[{obj}]" for obj in obj_list[0]] + [f"GRP[{obj}]" for obj in obj_list[1]]
        # Mixed case
        elif src_obj_group + '__fqdn__split' in fqdn_object_groups:
            obj_list = [fqdn_object_groups[src_obj_group + '__fqdn__split']] + [
                object_groups[src_obj_group + '__ipv4__split']]
            acl["src"] = [f"GRP[{obj}]" for obj in obj_list]
        # Groups of Groups Case
        elif src_obj_group in group_of_groups:
            obj_list = group_of_groups[src_obj_group]
            acl["src"] = [f"OBJ[{obj}]" for obj in obj_list[0]] + [f"GRP[{obj}]" for obj in obj_list[1]]
        elif src_obj_group in fqdn_object_groups:
            return 'FQDN Source Address Group not supported in Meraki'
        else:
            return "No valid Source Object Group exists (group contains no valid objects)"

    return 'Success'


def destination_parser(dst_address, acl):
    """
    Parse destination objects, extract and build relevant objects
    :param dst_address: line containing destination
    :param acl: current rule's acl dictionary
    :return:
    """
    # Any Case
    if 'any' in dst_address:
        acl['dst'] = 'any'

    # Destination Object Case
    elif 'name' in dst_address:
        dst_obj = dst_address.replace('name', '').strip()

        # Sanitize
        dst_obj = dst_obj.replace('"', '').replace('.', '_').replace(':', '_').replace('*', '_')

        # If object found, use ID as destination
        if dst_obj in objects:
            obj_id = objects[dst_obj]
            acl["dst"] = f"OBJ[{obj_id}]"
        elif dst_obj in fqdn_objects:
            obj_id = fqdn_objects[dst_obj]
            acl["dst"] = f"OBJ[{obj_id}]"
        elif dst_obj + '__range__' in range_objects:
            obj_id = range_objects[dst_obj + '__range__']
            acl["dst"] = f"GRP[{obj_id}]"
        else:
            return "No valid Destination Object exists"

    # Destination Group
    elif 'group' in dst_address:
        dst_obj_group = dst_address.replace('group', '').strip()

        # Sanitize
        dst_obj_group = dst_obj_group.replace('"', '').replace('.', '_').replace(':', '_').replace('*', '_')

        # If object found, use ID as source
        if dst_obj_group in object_groups:
            obj_id = object_groups[dst_obj_group]
            acl["dst"] = f"GRP[{obj_id}]"
        # FQDN object case
        elif dst_obj_group in fqdn_object_groups:
            obj_id = fqdn_object_groups[dst_obj_group]
            acl["dst"] = f"GRP[{obj_id}]"
        # Range case
        elif dst_obj_group + '__range__' in range_objects:
            obj_list = dst_obj_group[dst_obj_group + '__range__']
            acl["dst"] = [f"OBJ[{obj}]" for obj in obj_list[0]] + [f"GRP[{obj}]" for obj in obj_list[1]]
        # Mixed case
        elif dst_obj_group + '__fqdn__split' in fqdn_object_groups:
            obj_list = [fqdn_object_groups[dst_obj_group + '__fqdn__split']] + [
                object_groups[dst_obj_group + '__ipv4__split']]
            acl["dst"] = [f"GRP[{obj}]" for obj in obj_list]
        # Groups of Groups Case
        elif dst_obj_group in group_of_groups:
            obj_list = group_of_groups[dst_obj_group]
            acl["dst"] = [f"OBJ[{obj}]" for obj in obj_list[0]] + [f"GRP[{obj}]" for obj in obj_list[1]]
        else:
            return "No valid Destination Object Group exists (group contains no valid objects)"

    return 'Success'


def service_parser(service, acl):
    """
    Parse service objects, extract and build relevant objects
    :param service: line containing service
    :param acl: current rule's acl dictionary
    :return:
    """
    acl['services'] = []

    # Any Case
    if 'any' in service:
        acl['services'].append(['any', 'any'])

    # Service Object Case
    if 'name' in service:
        service_obj = service.replace('name', '').strip()

        # Sanitize
        service_obj = service_obj.replace('"', '')

        # If object found, use ID as destination
        if service_obj in service_objects:
            acl['services'].append(service_objects[service_obj])
        else:
            return "No valid Service Object found in local list (unsupported protocol, no port numbers, etc.)"

    # Service Group Case
    elif 'group' in service:
        service_obj_group = service.replace('group', '').strip()

        # Sanitize
        service_obj_group = service_obj_group.replace('"', '')

        # Service Object Group Case
        if service_obj_group in service_object_groups:
            service_objs = service_object_groups[service_obj_group]

            result = combine_like_services(service_objs)

            acl['services'] += result
        # Groups of Groups Case
        elif service_obj_group in service_group_of_groups:
            service_groups = service_group_of_groups[service_obj_group]

            result = combine_like_services(service_groups)

            acl['services'] += result
        else:
            return "No valid Service Object Group found in local list (no valid service objects present)"

    return 'Success'


def parse_line(line):
    """
    Parse each ASA ACL line. Match lines to regex pattern, process individual pieces utilizing object constructs created previously.
    :param line: ACL line
    :return: Meraki compatible rule pieces in the form of a dictionary
    """
    acl = {}

    # Regex match line, attempt to extract as much data as possible
    result = regex_match(line.text, acl)

    # Result != None means theres an error message -> pass it up
    if result != 'Success':
        return result

    # Get children
    children = line.children

    # Case of no children elements, ignore
    if len(children) == 0:
        return 'No valid line entries in rule, skipping...'

    # Iterate through children, extract out fields for rule
    for child in children:
        content = child.text.strip()

        # Skip Inactive Lines!
        if content.startswith('no enable'):
            return 'Inactive rules not allowed in Meraki'

        # Zones
        if 'src_zone' not in acl and content.startswith('from'):
            acl['src_zone'] = content.replace('from', '').strip()

        if 'dst_zone' not in acl and content.startswith('to'):
            acl['dst_zone'] = content.replace('to', '').strip()

        # Action
        if 'action' not in acl and content.startswith('action'):
            acl['action'] = content.replace('action', '').strip()

        # Comment
        if content.startswith('comment'):
            acl['comment'] = content.replace('comment', '').strip().replace('"', '')

        # Source Address
        if 'src' not in acl and content.startswith('source address'):
            src_address = content.replace('source address', '').strip()

            result = source_parser(src_address, acl)

            if result != 'Success':
                return result

        # Source Port
        if content.startswith('source port'):
            src_port = content.replace('source port', '').strip()

            # Any case
            if src_port == 'any':
                acl['src_port'] = 'any'

        # Destination Address
        if 'dst' not in acl and content.startswith('destination address'):
            dst_address = content.replace('destination address', '').strip()

            result = destination_parser(dst_address, acl)

            if result != 'Success':
                return result

        # Service
        if 'services' not in acl and content.startswith('service'):
            service = content.replace('service', '').strip()

            result = service_parser(service, acl)

            if result != 'Success':
                return result

    # Make sure all components are present
    if all(k in acl for k in ("action", "src", "dst", "services", "src_zone", "dst_zone")):
        if acl['src'] == 'any' and acl['dst'] == 'any' and acl['services'][0][0] == 'any' and acl['services'][0][
            1] == 'any':

            # Add inter-zone behavior to default map
            if acl['src_zone'] in default_zone_map and acl['dst_zone'] in default_zone_map:
                if acl['action'] == 'allow':
                    default_zone_map[acl['src_zone']][acl['dst_zone']] = 'allow'
                else:
                    default_zone_map[acl['src_zone']][acl['dst_zone']] = 'deny'

            return "Any Any Any Any Rule placed in mapping file. Skipping"

        return acl
    else:
        return "Invalid line"


def parse_rules(parse):
    """
    Parse show access-list file rules, process each individual line, extract pieces for MX rules.
    :param parse: ConfParse Object, used to parse access rules
    :return: newly created acls
    """
    # List that holds on to ACL Rules
    acl_list = []

    with open('unprocessed_rules.txt', 'w') as broken_fp:

        # Parse ipv4 rules
        ipv4_rules = parse.find_objects(r'^access-rule ipv4')

        new_entries = duplicate_splitter(ipv4_rules, 'rule')
        ipv4_rules += new_entries

        ipv4_rules_count = len(ipv4_rules)

        with Progress() as progress:
            overall_progress = progress.add_task("Overall Progress", total=ipv4_rules_count, transient=True)
            counter = 1

            for rule in ipv4_rules:
                # Parse each line, returning dictionary with SonicWall ACL Entry mapped to key fields for MX L3 Rule
                acl_line = parse_line(rule)

                # Don't add any any rules to broken file
                if acl_line != 'Any Any Any Any Rule placed in mapping file. Skipping':

                    # If returned type is not a dict, then something failed during line processing
                    if not type(acl_line) is dict:
                        # Write un-processable rules to file
                        broken_fp.write(rule.text + f' -> {acl_line} \n')

                        progress.console.print(
                            "Error Processing line: [red]{}[/] ({} of {}) -> {}".format(rule.text.strip(), str(counter),
                                                                                        ipv4_rules_count, acl_line))

                    # Add to acl rule set
                    else:
                        acl_list.append(acl_line)
                        progress.console.print(
                            "Processing line: [green]{}[/] ({} of {})".format(rule.text.strip(), str(counter),
                                                                              ipv4_rules_count))

                counter += 1
                progress.update(overall_progress, advance=1)

    return acl_list


def create_mx_rules(org_id, network_id, acl_list):
    """
    Create L3 rules on Meraki MX, using pieces obtaining from object constructs and parsing ACL lines.
    :param org_id: meraki org id
    :param network_id: meraki network id
    :param acl_list: list of MX L3 acl objects (containing pieces of MX rules)
    :return: response of API call
    """
    # If the network was found, add the firewall rules to it
    if org_id is not None and network_id is not None:
        # Convert the Cisco SonicWall ACL list into Meraki MX firewall rules
        firewall_rules = []
        for acl in acl_list:
            # Build every possible combo of src, dst, and services (cartesian product of lists to create
            # larger list of tuples representing all possible combinations)
            combos = [[], [], []]

            # Handle Special Object Cases for Src
            if isinstance(acl['src'], list):
                combos[0] += acl['src']
            else:
                combos[0].append(acl['src'])

            # Handle Special Object Cases for Dst
            if isinstance(acl['dst'], list):
                combos[1] += acl['dst']
            else:
                combos[1].append(acl['dst'])

            # Handle Services
            combos[2] += acl['services']

            results = list(itertools.product(*combos))

            for result in results:
                # set protocol (handle icmp cases)
                if result[2][0] == 'ICMP':
                    protocol = 'icmp'
                elif result[2][0] == 'ICMPV6':
                    protocol = 'icmp6'
                else:
                    protocol = result[2][0]

                firewall_rule = {
                    'comment': acl['comment'] if 'comment' in acl else '',
                    'policy': acl['action'],
                    'protocol': protocol,
                    'srcPort': acl['src_port'] if 'src_port' in acl else 'any',
                    'srcCidr': result[0],
                    'destCidr': result[1],
                    'destPort': result[2][1] if result[2][1] != 'N/A' else 'any'
                }

                # Keep zone's for mapping
                if MAPPING_FLAG:
                    firewall_rule['src_zone'] = acl['src_zone']
                    firewall_rule['dst_zone'] = acl['dst_zone']

                firewall_rules.append(firewall_rule)

        console.print(
            f"Adding [green]{len(firewall_rules)}[/] Rules to [blue]{NETWORK_NAME}[/]. Please wait, this may take a few minutes...")

        # if mapping flag is set, perform intelligent mapping of rules to MX
        if MAPPING_FLAG:
            rule_mapping(org_id, network_id, firewall_rules)
        else:
            # Update the firewall rules in the Meraki MX network (L3 Outbound Only)
            dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, rules=firewall_rules)

    return


def rule_mapping(org_id, network_id, firewall_rules):
    """
    Map MX rules to different rule sets based on zone tags (if enabled)
    :param org_id: org ID
    :param network_id: network ID
    :param firewall_rules: newly parsed firewall ruleset
    :return:
    """
    site2site_rules = []
    outbound_rules = []
    inbound_rules = []

    for rule in firewall_rules:
        src_zone = rule['src_zone']
        dst_zone = rule['dst_zone']

        # Remove zones from firewall rule
        del rule['src_zone']
        del rule['dst_zone']

        # Inbound rule
        if src_zone in INBOUND:
            inbound_rules.append(rule)
        # Site 2 Site VPN rule
        elif src_zone in SITE2SITE or dst_zone in SITE2SITE:
            site2site_rules.append(rule)
        # Outbound rule
        else:
            outbound_rules.append(rule)

    # Create Rule sets
    dashboard.appliance.updateOrganizationApplianceVpnVpnFirewallRules(org_id, rules=site2site_rules)
    console.print(f'[green]Site to Site Rule List Written[/]')

    dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, rules=outbound_rules)
    console.print('[green]Outbound List Written[/]')

    dashboard.appliance.updateNetworkApplianceFirewallInboundFirewallRules(network_id, rules=inbound_rules)
    console.print('[green]Inbound List Written[/]')


def default_map_to_csv(csv_file):
    """
    Creates inter-zone default behavior map
    :param csv_file: csv output file
    :return:
    """
    # Create CSV table showing default traffic rules between zones
    with open(csv_file, 'w', newline='') as csvfile:
        # headers
        headers = ['Source Zone \ Destination Zone'] + list(default_zone_map.keys())

        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()

        # Write traffic rules between zones onto table
        for zone in default_zone_map:
            default_zone_map[zone]['Source Zone \ Destination Zone'] = zone
            writer.writerow(default_zone_map[zone])

    console.print(f'[green]Successfully wrote to CSV File[/]: {csv_file}')


def create_vlans(vlan_file_name, network_id):
    """
    Create vlans on target MX network if provided.
    :param vlan_file_name: vlan file name that contains vlans
    :param network_id: meraki network id
    :return:
    """
    with open(vlan_file_name, 'r') as fp:

        # load vlans
        vlans = json.load(fp)

        # Get list of currently defined vlans
        existing_vlans = dashboard.appliance.getNetworkApplianceVlans(networkId=network_id)
        existing_vlans = [d['name'] for d in existing_vlans]

        # Get Count of Rules
        vlan_count = len(vlans)

        with Progress() as progress:
            overall_progress = progress.add_task("Overall Progress", total=vlan_count, transient=True)
            counter = 1

            for vlan in vlans:
                progress.console.print(
                    "Processing vlan: [blue]'{}'[/] ({} of {})".format(vlan['id'], str(counter), vlan_count))

                # If vlan doesn't exist create it
                if vlan['name'] not in existing_vlans:
                    dashboard.appliance.createNetworkApplianceVlan(networkId=network_id, id=vlan['id'],
                                                                   name=vlan['name'], subnet=vlan['subnet'],
                                                                   applianceIp=vlan['applianceIp'],
                                                                   groupPolicyId=vlan['groupPolicyId'])

                counter += 1
                progress.update(overall_progress, advance=1)


def create_static_rules(static_file_name, network_id):
    """
    Create static routes on MX Network if file provided.
    :param static_file_name: static file name that contains static routes
    :param network_id: meraki network id
    :return:
    """
    with open(static_file_name, 'r') as fp:

        # load vlans
        routes = json.load(fp)

        # Get list of currently defined vlans
        existing_routes = dashboard.appliance.getNetworkApplianceStaticRoutes(networkId=network_id)
        existing_routes = [d['name'] for d in existing_routes]

        # Get Count of Rules
        route_count = len(routes)

        with Progress() as progress:
            overall_progress = progress.add_task("Overall Progress", total=route_count, transient=True)
            counter = 1

            for route in routes:
                progress.console.print(
                    "Processing route: [yellow]'{}'[/] ({} of {})".format(route['name'], str(counter), route_count))

                # If vlan doesn't exist create it
                if route['name'] not in existing_routes:
                    dashboard.appliance.createNetworkApplianceStaticRoute(networkId=network_id, name=route['name'],
                                                                          subnet=route['subnet'],
                                                                          gatewayIp=route['gatewayIp'])

                counter += 1
                progress.update(overall_progress, advance=1)


def create_vlan_rules(network_id):
    """
    Create vlan's from vlans.json file
    :param network_id: meraki mx network ID
    :return:
    """
    # Get existing rules
    rules = dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(network_id)

    default_rules = []
    for src_zone in default_zone_map:

        if ZONES[src_zone] == '':
            continue

        # Define rule (only deny's, allows are implicit)
        firewall_rule = {
            'comment': "Any Any Inter-zone rule",
            'protocol': 'any',
            'policy': 'deny',
            'srcPort': 'any',
            'srcCidr': f'VLAN({ZONES[src_zone]}).*',
            'destCidr': [],
            'destPort': 'any'
        }

        for dst_zone in default_zone_map[src_zone]:
            # If destination not defined as local VLANs or implicit allow, skip
            if ZONES[dst_zone] == '' or default_zone_map[src_zone][dst_zone] == 'allow':
                continue

            firewall_rule['destCidr'].append(f'VLAN({ZONES[dst_zone]}).*')

        if len(firewall_rule['destCidr']) > 0:
            # Combine destination vlan's into comma separated list
            firewall_rule['destCidr'] = ','.join(firewall_rule['destCidr'])

            default_rules.append(firewall_rule)

    # Update the firewall rules in the Meraki MX network (L3 Outbound Only)
    dashboard.appliance.updateNetworkApplianceFirewallL3FirewallRules(network_id, rules=rules['rules'] + default_rules)

    console.print(f'[green]Successfully created {len(default_rules)} VLAN rules![/]')


def print_help():
    """
    Print's help line if incorrect input provided to script.
    :return:
    """
    console.print('This script imports SonicWall ACLs into the target MX network\n')
    console.print(
        'To run the script, enter: python3 sonicwall_to_mx.py -r [yellow]<SonicWall Show Run file>[/] -v [yellow]<Meraki vlan file>[/] (optional) -s [yellow]<Meraki static routes file>[/] (optional)')


def main():
    global MAPPING_FLAG

    console.print(Panel.fit("SonicWall ACL Config to MX Config"))

    # Get Inputs args
    show_run_file = ''
    vlan_file_name = ''
    static_file_name = ''

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'r:v:s:')
    except getopt.GetoptError:
        print_help()
        sys.exit(-2)

    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()
        elif opt == '-r':
            show_run_file = arg
        elif opt == '-v':
            vlan_file_name = arg
        elif opt == '-s':
            static_file_name = arg

    if len(sys.argv) <= 1:
        print_help()
        sys.exit(-1)

    # Check current directory for show run file
    if not os.path.exists(show_run_file):
        console.print('[red]Error:[/] show run file not found!')
        sys.exit(-1)

    # Check current directory for vlan file
    if vlan_file_name != '':
        if not os.path.exists(vlan_file_name):
            console.print('[red]Error:[/] vlan file not found!')
            sys.exit(-1)
    else:
        answer = Confirm.ask(
            "No vlan file detected. Please ensure necessary source vlans/static routes are created on the target "
            "MX, otherwise the script will fail. Continue?", default=True)
        if not answer:
            sys.exit(1)

    # Check current directory for static route file
    if static_file_name != '':
        if not os.path.exists(static_file_name):
            console.print('[red]Error:[/] static file not found!')
            sys.exit(-1)
    else:
        answer = Confirm.ask(
            "No static file detected. Please ensure necessary source vlans/static routes are created on the target "
            "MX, otherwise the script will fail. Continue?", default=True)
        if not answer:
            sys.exit(1)

    # Get Meraki Org Id
    orgs = dashboard.organizations.getOrganizations()

    org_id = None
    for org in orgs:
        if org['name'] == ORG_NAME:
            org_id = org['id']
            break

    # Get the list of Meraki MX networks
    networks = dashboard.organizations.getOrganizationNetworks(org_id)

    # Find the network ID of the network you want to add the firewall rules to
    network_id = None
    for network in networks:
        if network['name'] == NETWORK_NAME:
            network_id = network['id']
            break

    # Determine if 'mapping translation' should be done
    answer = Confirm.ask("Should the code perform mapping of firewall rules to rulesets? (see README for explanation)",
                         default=False)
    if answer:
        MAPPING_FLAG = True

    # Create default rule map (2D list object)
    for zone in ZONES.keys():
        default_zone_map[zone] = {}

    # Parse config, create various object dictionaries
    console.print(Panel.fit("Creating Network Objects, Network Group Objects, Protocol Objects, Port Groups, etc.",
                            title="Step 1"))
    parse = CiscoConfParse(show_run_file, syntax='asa')
    create_objects(org_id, parse)

    # Create VLAN's necessary for ACL Rules
    console.print(Panel.fit("Creating VLAN's", title="Step 2"))
    if vlan_file_name != '':
        create_vlans(vlan_file_name, network_id)

    # Create Static Rules (necessary) for ACL Rules
    console.print(Panel.fit("Creating Static Rules", title="Step 2.5"))
    if static_file_name != '':
        create_static_rules(static_file_name, network_id)

    # Iterate through ACL, parse rules
    console.print(Panel.fit("Parsing ASA ACL Rules", title="Step 3"))

    # Parse normal outbound rules and nat outbound rules
    acl_list = parse_rules(parse)

    # Creating MX Rules
    console.print(Panel.fit("Creating MX Rules", title="Step 4"))

    # Create outbound rules
    create_mx_rules(org_id, network_id, acl_list)
    console.print(f'[green]Success![/] ACL Rules Converted.')

    # Write default zone map to csv, add VLAN rules to end of outbound list
    console.print(Panel.fit("Creating Default Zone Behavior Rules", title="Step 5"))

    # Determine if 'mapping translation' should be done
    answer = Confirm.ask("Should the code create default VLAN zone rules? (see README for explanation)",
                         default=False)
    if answer:
        create_vlan_rules(network_id)

    # At a minimum, write default zone map to csv for reference
    csv_file = 'zone_default_traffic_map.csv'
    default_map_to_csv(csv_file)

    return


if __name__ == "__main__":
    main()
