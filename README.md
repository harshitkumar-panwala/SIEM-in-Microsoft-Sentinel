# SIEM Implementation in Microsoft Sentinel

This project is a demonstration of implementing a Security Information and Event Management (SIEM) system in Microsoft Sentinel, previously known as Azure Sentinel.

## Documentation

[SIEM Project Documentation](https://github.com/harshitkumar-panwala/SIEM-in-Microsoft-Sentinel/blob/main/SIEM%20Project%20Documentation.pdf) is a detailed document that will give you all the answers that you would need. Apologies for some of the blurry screenshots.

## PowerShell Script

[Log_Exporter.ps1](https://github.com/harshitkumar-panwala/SIEM-in-Microsoft-Sentinel/blob/main/Log_Exporter.ps1) is the PowerShell script that will use the API key to find the geolocation of the IP addresses that were used for the Brute Force attack. **DO NOT FORGET TO CHANGE THE API KEY WITH YOUR API KEY.**

## Logs

[failed_rdp.log](https://github.com/harshitkumar-panwala/SIEM-in-Microsoft-Sentinel/blob/main/failed_rdp.log) is the actual log file that I transferred from the honeypot VM to my machine later. It has all logs of the attacks.

## Dataflow Diagram

Dataflow Diagram.drawio can be added and viewed [here](https://app.diagrams.net/). It is the dataflow diagram that I created for the documentation.


-----------------------------------------------------------------------------------------------------------------------------------------------------------------


QUERY FOR LOG ANALYTICS WORKSPACE
FAILED_RDP_WITH_GEO_CL
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude


-----------------------------------------------------------------------------------------------------------------------------------------------------------------


QUERY FOR MICROSOFT SENTINEL 
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country
