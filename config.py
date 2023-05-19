MERAKI_API_KEY = ""
ORG_NAME = ""
NETWORK_NAME = ""

# Define Zone to VLAN ID mapping, used when creating default VLAN rules
# If zone is not a local VLAN, leave blank (important for default rule table)
ZONES = {
    "Zone Name": "Vlan Number",
}

# Define special zone keywords which map rule to ruleset (for intelligent mapping)
INBOUND = ['WAN']
SITE2SITE = ['VPN', 'SSLVPN']
