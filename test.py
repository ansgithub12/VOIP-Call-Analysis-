import pyshark
from collections import defaultdict
import requests

packets = pyshark.FileCapture('Forensic_challenge_4.pcap', display_filter='sip')

def packet_number(file_contents):
    count = sum(1 for _ in file_contents)
    return count

def unique_call_id(file_contents):
    calls = {}
    # methods = []
    for packet in file_contents:
        if hasattr(packet, 'sip'):
            callid = packet.sip.get_field_value('Call-ID')
            if not callid:
                continue
            
            sender = packet.sip.get_field_value('From')
            receiver = packet.sip.get_field_value('To')
            contact = packet.sip.get_field_value('Contact') # actual device ip
            method = packet.sip.get_field_value('Method')
            status_code = packet.sip.get_field_value('Status-Code') # checking 200 OK methods - call acceptance time
            timestamp = packet.sniff_time
            # below stuff used to check for IP spoofing
            via = packet.sip.get_field_value('Via')
            sender_ip = packet.ip.src if hasattr(packet, 'ip') else 'Unknown'
            
            if callid not in calls:
                calls[callid] = {
                    'Call ID': callid,
                    'Sender': sender,
                    'Receiver': receiver,
                    'Device IP': contact,
                    'Methods': [],
                    'Sender Actual IP': sender_ip,
                    'Via': via,
                    'Start Time': None,
                    '200 OK Time': None, # this is call acceptance time
                    'End Time': None,
                    'Duration': None         
                }
            
            if method:
                calls[callid]['Methods'].append(method)
            
            if (method == 'INVITE'):
                calls[callid]['Start Time'] = timestamp
            if (status_code == '200'):
                calls[callid]['200 OK Time'] = timestamp
            if (method == 'BYE'):
                calls[callid]['End Time'] = timestamp
            
            '''
            if callid:
                calls[callid] = (sender, receiver, contact, methods, duration)
            '''
            
    for callid, data in calls.items():
        start = data['Start Time']
        # ok_time = data['200 OK Time']
        end = data['End Time']
        if start and end:
            data['Duration'] = (end - start).total_seconds()
            
            # calls.add(callid)
    return calls

def sdp_info(file_contents): # this is for rtp payload analysis; essentially for media infornation like port nos and call type
    if hasattr(file_contents, 'sip') and 'application/sdp' in file_contents.sip.get('Content-Type', ''):
        sdp_payload = file_contents.sip.get('msg_body', '')
        
        media_info = {
            "IP": None,
            "RTP Ports": [],
            "Codecs": [],
            "Media Types": []
        }

        for line in sdp_payload.splitlines():
            if line.startswith("c=IN IP4"):
                media_info["IP"] = line.split()[-1]
            elif line.startswith("m="):
                parts = line.split()
                media_type, port = parts[1], parts[2]
                media_info["Media Types"].append(parts[0][2:])
                media_info["RTP Ports"].append(port)
            elif line.startswith("a=rtpmap:"):
                codec_info = line.split(" ")[1]
                media_info["Codecs"].append(codec_info)

        return media_info
    

analysis_for_each_packet = unique_call_id(packets)


for packet in packets: #sdp details
    print(packet)
    
'''sdp_details = sdp_info(packet)
    if sdp_details:
        print(sdp_details)'''
 
def more_details(ip): # this includes geolocation, ISP, timezone, browser, provided for the ip entered by user
    url = f"https://ipinfo.io/{ip}/json"
    response = requests.get(url)
    data = response.json()
    
    location = data.get("loc", "Unknown")  # Latitude, Longitude
    city = data.get("city", "Unknown")
    region = data.get("region", "Unknown")
    country = data.get("country", "Unknown")
    isp = data.get("org", "Unknown")  # ISP and org
    
    return {
        "IP": ip,
        "Location": location,
        "City": city,
        "Region": region,
        "Country": country,
        "ISP": isp
    }


'''
for call_id, (sender, receiver, contact, methods, start, end, duration) in analysis_for_each_packet.items():
    print(f"Call-ID: {call_id}\n  Sender: {sender}\n  Receiver: {receiver}\n Device IP: {contact}\n Methods: {methods}\n Start Time: {start}\n End Time: {end}\n Duration: {duration}\n")
'''


for call_id, details in analysis_for_each_packet.items(): # general details
    print(f"Call-ID: {call_id}")
    print(f"  Sender: {details['Sender']}")
    print(f"  Receiver: {details['Receiver']}")
    print(f"  Device IP: {details['Device IP']}")
    print(f"  Methods: {details['Methods']}")
    print(f"  Sender IP: {details['Sender Actual IP']}")
    print(f"  Via: {details['Via']}")
    print(f"  Start Time: {details['Start Time']}")
    print(f"  200 OK Time: {details['200 OK Time']}")
    print(f"  End Time: {details['End Time']}")
    print(f"  Duration: {details['Duration']} seconds\n")
    print("-" * 40)


packets.close()



# print all methods used in call 
# print initial timestamp?
# seperate fucntion for timing of each method?
# can save results to a csv file for better analysis, will also be better to retrieve if 
# user wants to analyse one call in particular
