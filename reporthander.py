import json
import sys
import random
import requests
if __name__ == '__main__':
    url = "https://hooks.slack.com/services/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"
    reporturl =sys.argv[1]
    message = (reporturl)
    scannedjscount = sys.argv[2]
    findingscount = sys.argv[3]
    title = (f"{findingscount} findings in {scannedjscount} newly scanned js files. :bell:")
    slack_data = {
        "username": "NotificationBot",
        "icon_emoji": ":satellite:",
        "channel" : "C02MXN0JYHE",
        "attachments": [
            {
                "color": "#9733EE",
                "fields": [
                    {
                        "title": title,
                        "value": message,
                        "short": "false",
                    }
                ]
            }
        ]
    }
    byte_length = str(sys.getsizeof(slack_data))
    headers = {'Content-Type': "application/json", 'Content-Length': byte_length}
    response = requests.post(url, data=json.dumps(slack_data), headers=headers)
    if response.status_code != 200:
        raise Exception(response.status_code, response.text)
