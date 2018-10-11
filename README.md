# 365_audit
This script will parse Office 365 audit logs for foreign IPs and alert you if IPs from foreign countries have accessed the account.

## Requirements
* [Office 365 auditing enabled](https://blogs.technet.microsoft.com/exovoice/2017/03/14/how-to-see-the-ip-addresses-from-where-your-office-365-users-are-accessing-owa/)
* [ipaddress](https://docs.python.org/3/library/ipaddress.html) python module installed
* [ipstack](https://ipstack.com) API key
* Only tested on Python v2.7

## Setup
After grabbing the script, fill in the following variables:

* **self.key**: ipstack.com API key
* **self.org\_ip**: your organizations WAN IP address (https://ifconfig.co)
* **self.country**: the country that all logins should be coming from
* **known\_ips\_file**: the path to where you want to track IPs checked by ipstack

## Parsing Logs
* Log into your Office 365 admin account
* Go to **Security & Compliance**
* Click **Search & investigation** -> **Audit log search**
* Set your start and end date
* Fill in the user you want to audit
* Click **Search**
* Click **Export results**
* Click **Download all results**
* Run `python 365_audit.py -l /path/to/AuditLog.csv`
* Review the output