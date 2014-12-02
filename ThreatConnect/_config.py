import re

#
# verify SSL certs?
#
verify_ssl_certs = True

"""standard TC API values"""

#
# adversaries base uri
#
api_uri_adversaries = '/v2/groups/adversaries'

#
# emails base uri
#
api_uri_emails = '/v2/groups/emails'

#
# groups base uri
#
api_uri_groups = '/v2/groups'

#
# incidents base uri
#
api_uri_incidents = '/v2/groups/incidents'

#
# indicators base uri
#
api_uri_indicators = '/v2/indicators'

#
# owners base uri
#
api_uri_owners = '/v2/owners'

#
# signatures base uri
#
api_uri_signatures = '/v2/groups/signatures'

#
# tags base uri
#
api_uri_tags = '/v2/tags'

#
# threats base uri
#
api_uri_threats = '/v2/groups/threats'

#
# default failure status
#
failure_status = 'Failure'

#
# error message for bad indicator
#
bad_indicator = 'bad indicator'

#
# error message for bad indicator type
#
bad_indicator_type = 'invalid indicator type'

#
# error message for bad group type
#
bad_group_type = 'invalid group type'

#
# error message for invalid request uri
#
bad_request_uri = 'invalid request uri'

#
# error message for invalid max results
#
bad_max_results = 'max results must be an integer'

#
# error message for bad rating
#
bad_rating = 'rating must be string in ["1.0", "2.0", "3.0", "4.0", "5.0"]'

#
# error message for bad confidence
#
bad_confidence = 'confidence must be integer between 1-100'

#
# address indicator (ipv4/ipv6 regex)
#
ipv4_pat = r'\.'.join([r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])'] * 4)
ipv4_re = re.compile(ipv4_pat + '$')
ipv6_re = re.compile('(?:%(hex4)s:){6}%(ls32)s$'
                     '|::(?:%(hex4)s:){5}%(ls32)s$'
                     '|(?:%(hex4)s)?::(?:%(hex4)s:){4}%(ls32)s$'
                     '|(?:(?:%(hex4)s:){0,1}%(hex4)s)?::(?:%(hex4)s:){3}%(ls32)s$'
                     '|(?:(?:%(hex4)s:){0,2}%(hex4)s)?::(?:%(hex4)s:){2}%(ls32)s$'
                     '|(?:(?:%(hex4)s:){0,3}%(hex4)s)?::%(hex4)s:%(ls32)s$'
                     '|(?:(?:%(hex4)s:){0,4}%(hex4)s)?::%(ls32)s$'
                     '|(?:(?:%(hex4)s:){0,5}%(hex4)s)?::%(hex4)s$'
                     '|(?:(?:%(hex4)s:){0,6}%(hex4)s)?::$'
                     % {
    'ls32': r'(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|%s)' % ipv4_pat,
    'hex4': r'[0-9a-f]{1,4}'
}, re.IGNORECASE)

#
# emailAddress indicator
#
email_pat = r'[^@]+@[^@]+\.[^@]+$'
email_re = re.compile(email_pat)

#
# md5/sha256 indicator
#
md5_pat = r'^([a-fA-F\d]{32})$'
md5_re = re.compile(md5_pat)
sha1_pat = r'^([a-fA-F\d]{40})$'
sha1_re = re.compile(sha1_pat)
sha256_pat = r'^([a-fA-F\d]{64})$'
sha256_re = re.compile(sha256_pat)

#
# host indicator
#
host_pat = r'\b(([a-zA-Z0-9\-_]+)\.)+(?!exe|php|dll|doc|docx|txt|rtf|odt|xls|xlsx|ppt|pptx|bin|pcap|ioc|pdf|mdb|asp|html|xml|jpg|gif|png|lnk|log|vbs|lco|bat|shell|quit|pdb|vbp|bdoda|bsspx|save|cpl|wav|tmp|close|py|ico|ini|sleep|run|dat|scr|jar|jxr|apt|w32|css|js|xpi|class|apk|rar|zip|hlp|tmp|cpp|crl|cfg|cer|plg|tmp)([a-zA-Z]{2,5})\b'
host_re = re.compile(host_pat)

#
# url indicator (this regex needs some work)
#
# url_pat = r'^https?:\/\/([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
url_pat = r'^https?:\/\/'
url_re = re.compile(url_pat)

#
# dictionary of indicator type
#
indicator_types = {
    'addresses': {
        'regex': [
            ipv4_re,
            ipv6_re],
        'keys': [
            'ip']},
    'emailAddresses': {
        'regex': [
            email_re],
        'keys': [
            'address']},
    'files': {
        'regex': [
            md5_re,
            sha1_re,
            sha256_re],
        'keys': [
            'md5',
            'sha1',
            'sha256']},
    'hosts': {
        'regex': [
            host_re],
        'keys': [
            'hostName']},
    'urls': {
        'regex': [
            url_re],
        'keys': [
            'text']}}

data_structure_defs = {
            'addresses': [
                'confidence', 'dateAdded', 'id', 'ip', 'lastModified',
                'owner', 'rating', 'webLink'],
            'emailAddresses': [
                'address', 'confidence', 'dateAdded', 'description', 'id',
                'lastModified', 'owner', 'rating', 'source', 'webLink'],
            'files': [
                'confidence', 'dateAdded', 'fileOccurence', 'id',
                'lastModified', 'md5', 'owner', 'rating', 'sha1', 'sha256',
                'webLink'],
            'hosts': [
                'confidence', 'dateAdded', 'description', 'dnsActive',
                'hostName', 'id', 'lastModified', 'owner', 'rating',
                'source', 'webLink', 'whoisActive'],
            'urls': [
                'confidence', 'dateAdded', 'description', 'id',
                'lastModified', 'owner', 'rating', 'text', 'webLink'],
             'adversaries' : ['dateAdded', 'id', 'name', 'owner', 'webLink'],
             'emails' : ['dateAdded', 'id', 'name', 'ownerName', 'score', 'webLink'],
             'incidents' : ['dateAdded', 'eventDate', 'id', 'name', 'ownerName', 'webLink'],
             'signatures' : ['dateAdded', 'fileName', 'fileType', 'id', 'name', 'owner', 'webLink'],
             'threats' : ['dateAdded', 'id', 'name', 'ownerName', 'webLink'],
             'securityLabels' : ['name', 'description', 'dateAdded'],
             'tags' : ['name', 'webLink']
             }

#
# dictionary of resource type
#
resource_types = {
    'adversaries': {
        'request_uri': api_uri_adversaries},
    'attributes': {
        'request_uri': api_uri_groups},
    'emails': {
        'request_uri': api_uri_emails},
    'groups': {
        'request_uri': api_uri_groups},
    'incidents': {
        'request_uri': api_uri_incidents},
    'indicators': {
        'request_uri': api_uri_indicators},
    'owners': {
        'request_uri': api_uri_owners},
    'signatures': {
        'request_uri': api_uri_signatures},
    'signatures_download': {
        'request_uri': api_uri_signatures},
    'tags': {
        'request_uri': api_uri_tags},
    'threats': {
        'request_uri': api_uri_threats}}
