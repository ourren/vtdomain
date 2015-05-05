#!/usr/bin/env python
# encoding: utf-8
# author: ourren
# website: http://ourren.github.io/

import sys
import simplejson
import json
import urllib
import urllib2

uv = "https://www.virustotal.com/vtapi/v2/url/report"
apikey = "ea636c21f9e2131b9fcea6eda7046a5456a2a66858f7af5fbd7a90c33561f010"


def check(url):
    '''
    plugin: *.json
    target: ip, url
    target_type: target type
    '''
    parameters = {"resource": url, "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(uv, data)
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
    print 'positives:', response_dict.get("positives")

def main():
    reload(sys)
    sys.setdefaultencoding("utf-8")
    print '[*] App: vtdomain check'
    print '[*] Version: V1.0(20150503)'
    print 'python vtdomain.py http://www.google.com'
    if len(sys.argv) == 2:
        check(sys.argv[1])
    else:
        exit()

if __name__ == '__main__':
    main()
