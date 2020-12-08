import requests, json, time
import meraki
import os
import re
import ast
import base64
import logging
import azure.functions as func
from math import radians, cos, sin, asin, sqrt

# Author: Mitchell Gulledge

# class that contains all Meraki necessary config
class MerakiConfig:
    meraki_api_key = os.environ['meraki_api_key'].lower()
    meraki_org_name = os.environ['meraki_org_name']
    tag_prefix = os.environ['tag_prefix']
    org_id = None
    sdk_auth = meraki.DashboardAPI(meraki_api_key)

    # writing function to obtain org ID via linking ORG name
    result_org_id = sdk_auth.organizations.getOrganizations()
    for x in result_org_id:
        if x['name'] == meraki_org_name:
            org_id = x['id']

    # creating original list of Meraki VPNs to later append to
    meraki_vpn_list = []

    # obtaining original list of Meraki third party VPNs
    original_vpn = sdk_auth.appliance.getOrganizationApplianceVpnThirdPartyVPNPeers(
    org_id) 

    meraki_vpn_list = original_vpn['peers']

    # Meraki call to obtain Network information
    tags_network = sdk_auth.organizations.getOrganizationNetworks(org_id)

    # filtering None types from the list using filter
    res_tags_network = list(filter(None, tags_network)) 

# class that contains all Umbrella necessary config
class UmbrellaConfig:
    # this is obtained from the api keys tab and specifically the umbrella management keys
    umbrella_key = os.environ['umbrella_key']
    umbrella_secret = os.environ['umbrella_secret']
    umbrella_org_id = os.environ['umbrella_org_id']

    # Command -  echo -n 'secret:key' | base64 in terminal
    base64_value = umbrella_key + ':' + umbrella_secret
    message_bytes = base64_value.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    # url for network tunnels in umbrella dashboard
    tunnel_url = "https://management.api.umbrella.com/v1/organizations/"+umbrella_org_id+"/tunnels"

    # url for listing umbrella DCs
    dc_url = 'https://management.api.umbrella.com/v1/service/tunnel/datacenters'

    # delete umbrella tunnel url 
    delUrl = 'https://management.api.umbrella.com/v1/organizations/'+ \
        umbrella_org_id+'/tunnels/'

    # creating header to authenticate API requests to Umbrella
    headers = {'Authorization': 'Basic ' + base64_message}

# function to parse list of tags for an individual network
def strip_meraki_network_tags(meraki_network_tag):
    # below parses the for the specific network tag on the network that correlates with SIG-
    meraki_tag_strip_part1 = re.findall(r'[S]+[I]+[G]+[-].*', str(meraki_network_tag))
    meraki_tag_strip_part2 = re.findall(r'^([\S]+)', str(meraki_tag_strip_part1[0]))
    new_string = str(meraki_tag_strip_part2[0])
    new_string = new_string[0:-2]
    logging.info(f"Parsed tag for matched network is : {new_string}")
    return new_string

# defining function that creates dictionary of IPsec config from Umbrella config
def get_meraki_ipsec_config(name, public_ip, secret, network_tags, local_id) -> dict:
    ipsec_config = {
        "name": name,
        "publicIp": public_ip,
        "privateSubnets": ["0.0.0.0/0"],
        "secret": secret,
        "ikeVersion": "2",
        "ipsecPolicies": {
            "ikeCipherAlgo": ["aes256"],
            "ikeAuthAlgo": ["sha256"],
            "ikeDiffieHellmanGroup": ["group14"],
            "ikeLifetime": 28800,
            "childCipherAlgo": ["aes256"],
            "childAuthAlgo": ["sha256"],
            "childPfsGroup": ["group14"],
            "childLifetime": 3600
        },
        "networkTags": [ network_tags ],
        "myUserFqdn": local_id
    }

    return ipsec_config

# this function performs the haversine formula to calculate distance between two endpoints
# the variables being fed in are the long/lat of the Umbrella DC and MX site IP
def haversine(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians 
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    # haversine formula 
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    r = 6371 # Radius of earth in kilometers. Use 3956 for miles
    return c * r

# this function is intended to replace define_vpn_peer_ip function
def get_dc_ip(network_id):
    # variables for the longitude/latitude for both sites
    lon1 = ''
    lat1 = ''
    lon2 = ''
    lat2 = ''
    site_continent = ''

    # creating variable to that contains branch IP of MX
    mx_branch_ip = ''

    # obtaining branch MXs public IP w/ org wide network devices call
    logging.info("Obtaining list of Meraki device statuses")
    list_of_device_statuses = MerakiConfig.sdk_auth.organizations.getOrganizationDevicesStatuses(
        MerakiConfig.org_id)

    if str(network_id) in str(list_of_device_statuses):
        logging.info("Successfully obtained list of Device statuses")
    else:
        logging.info("Unable to obtain list of Meraki Network Device statuses")

    for device in list_of_device_statuses:
        # conditional statement to match based on network id variable
        if network_id == device['networkId']:
            # setting public ip for branch to later calculate long/lat
            mx_branch_ip = device['publicIp']
            logging.info("public IP of Branch is: " + str(mx_branch_ip))
            # calculating long/lat of mx branch ip address
            geo_url = "https://ipinfo.io/" + mx_branch_ip 
            geo_response2 = requests.get(geo_url).json()
            logging.info(geo_response2)
            
            logging.info(f"Longitude/Lat for Branch is : {geo_response2['loc']}")

            x = geo_response2['loc']
            long_lat_tuple = tuple(x.split(','))

            lon1 = long_lat_tuple[0]
            lat1 = long_lat_tuple[1]

            logging.info("branch longitude is " + str(lon1))
            logging.info("branch latitude is " + str(lat1))

            # obtaining country name to later map to a continent
            branch_country = geo_response2['country']

            # creating continent variable so we can later iterate through smaller list of umbrella DCs
            continent_name = pc.country_alpha2_to_continent_code(branch_country)
            logging.info("The branch site has been mapped to continent " + continent_name)

            # mapping continent code to continent name
            if continent_name == 'NA':
                site_continent = 'North America'
            elif continent_name == 'SA':
                site_continent = 'South America'
            elif continent_name == 'AS':
                site_continent = 'Asia'
            elif continent_name == 'OC':
                site_continent = 'Australia'
            elif continent_name == 'AF':
                site_continent = 'Africa'

    # variable for umbrella public IP
    primary_vpn_tunnel_ip = '' 

    # distance variable that will be used to select closest DC
    distance_to_dc = 999999

    # request to obtain list of DCs
    get_dc_req = requests.get(UmbrellaConfig.dc_url, headers=UmbrellaConfig.headers)
    logging.info("Obtaining a list of all Umbrella Datacenters: " + str(get_dc_req.content))

    # creating list to hold all regional DCs 
    list_of_regional_dcs = []

    # iterating through list of DCs to match based on continent name
    for dc in get_dc_req.json()['continents']:
        if str(site_continent) in str(dc['name']):

            # appending DC to list of DCs in the same continent
            list_of_regional_dcs.append(dc)

    logging.info("List of regional DCs: " + str(list_of_regional_dcs))

    # if response is successful begin building variables to feed into haversine formula
    if get_dc_req.status_code == 200:
        for datacenters in list_of_regional_dcs:
            logging.info("matched site to corressponding continent for DC selection")
        
            for umb_datacenter in datacenters['cities']:
                if not umb_datacenter['range'].split('/')[0][-1] == '8':
                    continue
                logging.info(umb_datacenter)
                # umbrella dc latitude
                lat2 = umb_datacenter['latitude']
                logging.info("Latitude of potential Umbrella DC: " + str(lat2))

                # umbrella dc latitude
                lon2 = umb_datacenter['longitude']
                logging.info("Longitude of potential Umbrella DC: " + str(lon2))

                # executing Haversine Formula
                haversince_result = haversine(float(lon1), float(lat1),
                                              float(lon2), float(lat2))
                print("Haversine result for branch to potential Umbrella DC: " + str(haversince_result))

                # setting haversine result to the absolute value
                haversince_result = abs(haversince_result)

                # when iterating through list if haversince_result is less than distance_to_dc
                # rewrite the distance_to_dc variable to the haversince_result
                if haversince_result < distance_to_dc:
                    distance_to_dc = haversince_result
                    logging.info("Haversine Result (distance to DC) is: " + str(distance_to_dc))
                    primary_vpn_tunnel_ip = umb_datacenter['range']
                    primary_vpn_tunnel_ip = str(primary_vpn_tunnel_ip)[0:-3]
                    logging.info("IP address for DC described above: " + str(primary_vpn_tunnel_ip))

        return primary_vpn_tunnel_ip


def delete_umbrella_tunnel(vpn_tunnel_name):
    
    # fetching list of umbrella tunnel config
    get_req = requests.get(UmbrellaConfig.tunnel_url, headers=UmbrellaConfig.headers)
    umbrella_tunnel_info = get_req.json()
    
    # logging list of network tunnels before deleting
    logging.info(f"current list of umbrella tunnels before deleting : {umbrella_tunnel_info}")

    for tunnel in umbrella_tunnel_info:
        # matching against tunnel name as conditional statement
        if vpn_tunnel_name == tunnel["name"]:

            # parsing umbrella tunnel config for id
            umb_tunnel_id = tunnel["id"]

            # crafting tunnel specific url to delete ipsec config in umbrella dashboard
            del_tunnel_url = str(UmbrellaConfig.delUrl) + str(umb_tunnel_id)
            
            # deleting Umbrella tunnel
            delReq = requests.delete(del_tunnel_url, headers=UmbrellaConfig.headers)

            if delReq.reason == 200:
                # logging the successful deletion of the umbrella tunnel
                logging.info(f"successfully deleted network tunnel  : {umb_tunnel_id}")
                
                # if tunnel deleted successfully, swapping tunnel already made variable back to false
                tunnel_already_made = False
                logging.info(f"tunnel_already_made variable current value : {umb_tunnel_id}")

# function to update Meraki VPN config
def update_meraki_vpn(vpn_list):
    updatemvpn = MerakiConfig.sdk_auth.appliance.updateOrganizationApplianceVpnThirdPartyVPNPeers(
    MerakiConfig.org_id, vpn_list
    )

# function to validate that MX is on version 15 or greater
def validate_mx_firmware(branch_node):
    # call to get device info
    devices = MerakiConfig.sdk_auth.networks.getNetworkDevices(branch_node)
    # validating firmware to ensure device is on 15
    firmwareversion = devices[0]['firmware'] 
    logging.info(f"MX firmware version : {firmwareversion}")
    # validation to say True False if MX appliance is on 15 firmware
    firmwarecompliance = str(firmwareversion).startswith("wired-15") 
    if firmwarecompliance == True:
        logging.info("firmware is compliant")
    else:
        logging.info("firmware is not compliant breaking loop")
        firmwarecompliance = False

    return firmwarecompliance

# this function creates an umbrella IPsec tunnel and return FQDN and Secret
def create_umbrella_tunnel(tunnel_name):
    # Post to create tunnel in SIG dashboard
    tunnel_response = requests.post(UmbrellaConfig.tunnel_url, headers=UmbrellaConfig.headers, \
         data=tunnel_name)
    umbrella_tunnel_info = tunnel_response.json()
    # parsing tunnel info for tunnel psk and id
    # Access tunnel ID
    tunnelId = umbrella_tunnel_info["id"]
    logging.info(f"new umbrella tunnel ID : {tunnelId}")
    # Access PSK id:key
    client = umbrella_tunnel_info["client"]

    # parsing the local id/fqdn for the meraki vpn config here
    tunnelPSKFqdn = client["authentication"]["parameters"]["id"] 
    # parsing the pre shared key for the meraki vpn config here
    tunnelPSKSecret = client["authentication"]["parameters"]["secret"] 
    
    return tunnelPSKFqdn, tunnelPSKSecret

# creating a main function for Azure Function
def main(MerakiTimer: func.TimerRequest) -> None:
    
    # before executing loop setting the variable for tunnel already made being false
    tunnel_already_made = False

    # loop that iterates through the variable tagsnetwork and matches networks with SIG- in the tag
    for meraki_networks in MerakiConfig.res_tags_network:
        logging.info(f"Current list of Meraki networks with a tag : {MerakiConfig.res_tags_network}")
        if "SIG-" in str(meraki_networks['tags']): 
            logging.info("tag detected in Meraki network")
            
            # obtaining network ID in order to obtain device information
            network_info = meraki_networks['id'] 
            logging.info(f"Network ID for MX is : {network_info}")
            
            # network name used to label Meraki VPN and Umbrella ipsec config
            netname = meraki_networks['name'] 
            logging.info(f"Network name is : {netname}")
            
            # obtaining all tags for network as this will be placed in VPN config
            nettag = meraki_networks['tags']  

            # calling function to validate branch firmware version
            firmware_validate = validate_mx_firmware(network_info)

            if firmware_validate == False:
                logging.info(f"Firmware validation failed for network : {netname}")
                # if the firmware validation returns as false the script will break from the loop
                break 

            # executing function to obtain the vpn peer ip for the meraki branch device
            meraki_branch_peer_ip = get_dc_ip(network_info)
            logging.info(f"Meraki VPN config public IP is : {meraki_branch_peer_ip}")

            # creating umbrella ipsec config to be the data in the post, netname variable is tunnel name
            umbrella_tunnel_name = {"name": netname, 'deviceType': 'Meraki MX'}
            umbrella_tunnel_data = json.dumps(umbrella_tunnel_name)
            logging.info(f"Umbrella tunnel config with branch info : {umbrella_tunnel_data}")

            # fetching list of umbrella tunnel config
            get_req = requests.get(UmbrellaConfig.tunnel_url, headers=UmbrellaConfig.headers)
            logging.info(f"List of current Network tunnels in Umbrella : {get_req}")

            # converting get_req (list of umbrella vpn tunnels) from json response to dictionary
            umbrella_tunnel_dict = get_req.json()

            # creating placeholder variable for detecting whether the tunnel is created or not in umbrella
            tunnel_already_made = False

            # placeholder variable for detecting whether the tunnel is created in umbrella and meraki
            in_umb_and_meraki_config = False 

            # now we can iterate through the loop and see if netname is contained within the get_req variable
            for tunnel_name in umbrella_tunnel_dict:
                if netname == str(tunnel_name['name']):
                    tunnel_already_made = True
                    logging.info("tunnel detected in Umbrella config")
                else:
                    logging.info("tunnel not detected in Umbrella config")

            # logging state of whether tunnel is detected or now
            logging.info(f"tunnel is created : {tunnel_already_made}")
                    
            # if tunnel is built in umbrella already but not Meraki we need to detect and update config
            if tunnel_already_made == True:
                # iterating through original list of vpn tunnels from Meraki to match on name
                for meraki_tunnel_name in MerakiConfig.meraki_vpn_list:
                    if netname == meraki_tunnel_name['name']:
                        logging.info("tunnel config in umbrella matches Meraki for " + netname)
                        # changing variable for being detected in umbrella and meraki config
                        in_umb_and_meraki_config = True
                    else:
                        logging.info(f"tunnel not built in Meraki config for : {netname}")
 
            # logging state of whether tunnel is detected or now
            logging.info(f"tunnel is preconfigured in Meraki and Umbrella : {in_umb_and_meraki_config}")

            # if tunnel is built in umbrella already but not Meraki we need to detect and update config
            if in_umb_and_meraki_config == False:

                # calling function to strip tag for network in umbrella config
                meraki_net_tag = strip_meraki_network_tags(nettag)

                # calling function to determine public vpn peer ip for Meraki config
                vpn_peer_ip = get_dc_ip(network_info)

                # deleting umbrella tunnel config and set tunnel_already_made variable to False
                delete_umb_tun = delete_umbrella_tunnel(netname)
                logging.info(delete_umb_tun)

            if tunnel_already_made == False:

                # calling function to create umbrella tunnel and return psk and fqdn
                umbrella_tunnel_information = create_umbrella_tunnel(umbrella_tunnel_data)

                # calling function to parse tags for SIG specific tag
                meraki_net_tag = strip_meraki_network_tags(nettag)

                # Build meraki config for IPsec configuration (using get_meraki_ipsec_config function)
                primary_vpn_tunnel_template = get_meraki_ipsec_config(netname,  \
                meraki_branch_peer_ip, umbrella_tunnel_information[1], meraki_net_tag, umbrella_tunnel_information[0])

                # creating variable to detect whether or not umbrella tunnel exists in Meraki config
                is_meraki_tunnel_updated = False

                for vpn_peer_name in MerakiConfig.meraki_vpn_list:
                    # iterating through list of existing meraki vpn peers validating if tunnel is created
                    if vpn_peer_name == str(MerakiConfig.meraki_vpn_list):
                        logging.info("peer detected in the config already updating PSK")
                        is_meraki_tunnel_updated = True
                        # updating psk for meraki vpn tunnel to umbrella
                        logging.info("updating psk for existing tunnel in Meraki to match Umbrella")
                        vpn_peer_name['secret'] = tunnelPSKSecret

                if is_meraki_tunnel_updated == False:
                    logging.info(f"updating tunnel with new Umbrella PSK + Local ID")
                    # appending newly created tunnel config to original VPN list
                    MerakiConfig.meraki_vpn_list.append(primary_vpn_tunnel_template)                    
                    local_id =  umbrella_tunnel_information[0]
                    secret = umbrella_tunnel_information[1]
                    # logging new vpn dictionary to append to rest of VPN peers
                    logging.info(f"New MX VPN site config : {primary_vpn_tunnel_template}")

    # final function performing update to Meraki VPN config
    logging.info(f"New Meraki Org VPN config : {MerakiConfig.meraki_vpn_list}")
    update_meraki_vpn(MerakiConfig.meraki_vpn_list)
