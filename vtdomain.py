#!/usr/bin/env python
# encoding: utf-8
# author: ourren
# website: http://ourren.github.io/

import sys
import simplejson
import urllib
import urllib2
import sqlite3
import time

uv = "https://www.virustotal.com/vtapi/v2/url/report"
apikey = "add you own api"

db_eml = 'm_domain.db'
db = sqlite3.connect(db_eml)
db.text_factory = str

vtdic = {'AutoShun':'AutoShun', 'Quttera':'Quttera ', 'ADMINUSLabs':'ADMINUSLabs', 'AegisLab WebGuard':'AegisLab', 'AlienVault':'AlienVault', 'Antiy-AVL':'Antiy', 'Avira':'Avira', 'Baidu-International':'Baidu', 'BitDefender':'BitDefender', 'Blueliv':'Blueliv', 'C-SIRT':'CSIRT', 'CLEAN MX':'CLEAN', 'CRDF':'CRDF', 'Comodo Site Inspector':'Comodo', 'CyberCrime':'CyberCrime', 'Dr.Web':'DrWeb', 'ESET':'ESET', 'Emsisoft':'Emsisoft', 'Fortinet':'Fortinet', 'FraudSense':'FraudSense', 'G-Data':'GData', 'Google Safebrowsing':'Google', 'K7AntiVirus':'K7AntiVirus', 'Kaspersky':'Kaspersky', 'Malc0de Database':'Malc0de', 'Malekal':'Malekal', 'Malware Domain Blocklist':'Malware', 'MalwareDomainList':'MalwareDomainList', 'MalwarePatrol':'MalwarePatrol', 'Malwarebytes hpHosts':'Malwarebytes', 'Malwared':'Malwared', 'Netcraft':'Netcraft', 'OpenPhish':'OpenPhish', 'Opera':'Opera', 'PalevoTracker':'PalevoTracker', 'ParetoLogic':'ParetoLogic', 'PhishLabs':'PhishLabs', 'Phishtank':'Phishtank', 'Rising':'Rising', 'SCUMWARE.org':'SCUMWARE', 'SecureBrain':'SecureBrain', 'Sophos':'Sophos', 'Spam404':'Spam404', 'SpyEyeTracker':'SpyEyeTracker', 'StopBadware':'StopBadware', 'Sucuri SiteCheck':'Sucuri ', 'Tencent':'Tencent', 'ThreatHive':'ThreatHive', 'Trustwave':'Trustwave', 'URLQuery':'URLQuery', 'VX Vault':'VXVault', 'Web Security Guard':'WebSecurityGuard', 'Websense ThreatSeeker':'Websense ', 'Webutation':'Webutation', 'Wepawet':'Wepawet', 'Yandex Safebrowsing':'Yandex ', 'ZCloudsec':'ZCloudsec', 'ZDB Zeus':'ZDB', 'ZeroCERT':'ZeroCERT', 'Zerofox':'Zerofox', 'ZeusTracker':'ZeusTracker', 'malwares.com URL checker':'malwares ', 'zvelo':'zvelo'}

def table_mdomain():
    # init domain table
    c = db.cursor()
    # init the malware table
    c.execute("""create table if not exists domain( id integer primary key autoincrement, domain text, positive text, AutoShun text, Quttera text, ADMINUSLabs text, AegisLab text, AlienVault text, Antiy text, Avira text, Baidu text, BitDefender text, Blueliv text, CSIRT text, CLEAN text, CRDF text, Comodo text, CyberCrime text, DrWeb text, ESET text, Emsisoft text, Fortinet text, FraudSense text, GData text, Google text, K7AntiVirus text, Kaspersky text, Malc0de text, Malekal text, Malware text, MalwareDomainList text, MalwarePatrol text, Malwarebytes text, Malwared text, Netcraft text, OpenPhish text, Opera text, PalevoTracker text, ParetoLogic text, PhishLabs text, Phishtank text, Rising text, SCUMWARE text, SecureBrain text, Sophos text, Spam404 text, SpyEyeTracker text, StopBadware text, Sucuri text, Tencent text, ThreatHive text, Trustwave text, URLQuery text, VXVault text, WebSecurityGuard text, Websense text, Webutation text, Wepawet text, Yandex text, ZCloudsec text, ZDB text, ZeroCERT text, Zerofox text, ZeusTracker text, malwares text, zvelo text) """)
    db.commit()

def check(url):
    # remove http://
    if url.startswith("http://") or url.startswith("https://"):
        url = url.replace("http://", "").replace("https://", "")
    # check if exist
    c = db.cursor()
    c.execute("select count(*) from domain where domain ='" + url + "'")
    row = c.fetchone()
    if row[0] == 0:
        parameters = {"resource": url, "apikey": apikey}
        data = urllib.urlencode(parameters)
        try:
            req = urllib2.Request(uv, data)
            response = urllib2.urlopen(req)
            json = response.read()
            response_dict = simplejson.loads(json)
            positives = response_dict.get("positives")
            print url, positives
            c.execute("""insert into domain(domain, positive) values(?,?)""", (url, positives))
            db.commit()
            id = c.lastrowid
            scans = response_dict["scans"]
            for (k, v) in vtdic.items():
                usql = "UPDATE domain set " + v + " = '" + scans[k]["result"] + "' where id="+ str(id)
                c.execute(usql)
            db.commit()
            return True
        except:
            return True
    else:
        print 'already checked..'
        return False


def main():
    print '[*] App: vtdomain check'
    print '[*] Version: V1.1(20150514)'
    table_mdomain()
    for line in open("domain").readlines():
        line = line.strip()
        if check(line):
            time.sleep(15)

if __name__ == '__main__':
    main()
