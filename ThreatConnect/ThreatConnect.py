import base64
import csv
import hashlib
import hmac
import io
import json
import pprint
import re
import requests
import sys
import time
import urllib
import datetime

# import config items
from _config import *

"""
Notes:

https://google-styleguide.googlecode.com/svn/trunk/pyguide.html

Some function name do not adhere to standard naming conventions.  This was
done intentionally to match the ThreatConnect API naming convention.

* implement dnsResolutions
* adding error messages/required fields to configs
* certain field validation
"""


class ThreatConnect(object):
    """Group of methods to work with ThreatConnect API"""

    def __init__(self, api_aid, api_sec, api_org, api_url, api_max_results=200):
        """Initialize class objects"""

        # credentials
        self._api_aid = api_aid
        self._api_sec = api_sec


        # user defined values
        self._api_max_results = api_max_results
        self._api_org = api_org

        # config items
        self._api_url = api_url
        self.indicator_types = indicator_types
        self._resource_types = resource_types
        self._data_structures = data_structure_defs
        self._verify_ssl = verify_ssl_certs

        if not self._verify_ssl:
            requests.packages.urllib3.disable_warnings()

        #todo - add to config
        #todo - victims?
        self.group_types = ["adversaries", "emails", "incidents", "signatures", "threats", "documents"]  
        
        # error messaging
        self._failure_status = failure_status
        self._bad_indicator = bad_indicator
        self._bad_indicator_type = bad_indicator_type
        self._bad_group_type = bad_group_type         #todo make in conf
        self._bad_request_uri = bad_request_uri
        self._bad_max_results = bad_max_results
        self._bad_rating = bad_rating
        self._bad_confidence = bad_confidence

        # initialize request session handle
        self._rh = requests.Session()

        # initialize filter
        self._data_filter = []

    def _api_request(self, request_uri, method="GET", body=None):
        """Make TC API call.

        Args:
            request_uri: (string) The URI containing the API request data.

        Returns:
            A dict containing the response from the API request.

        """

        # Decide whether or not to suppress all activity logs
        # todo - make this a configuration option (or function arg?)
        SUPPRESS = True
        if SUPPRESS:
            if '?' in request_uri:
                request_uri += "&createActivityLog=false"
            else:
                request_uri += "?createActivityLog=false"


        api_headers = self._generate_headers(method, request_uri)
        full_path = '%s%s' % (self._api_url, request_uri)
        if body or body is not None:
            body_json = json.dumps(body)
        else:
            body_json = None
        
        # Change this if you're using a self-signed/unsigned cert (priv cloud/on prem)
        VERIFY=self._verify_ssl
        if method == 'GET':
            api_response = self._rh.get(full_path, headers=api_headers, verify=VERIFY)
        elif method == 'POST':
            api_headers['Content-Type'] = 'application/json'
            api_response = self._rh.post(full_path, data=body_json, headers=api_headers, verify=VERIFY)
        elif method == 'PUT':
            api_headers['Content-Type'] = 'application/json'
            api_response = self._rh.put(full_path, data=body_json, headers=api_headers, verify=VERIFY)
        elif method == 'DELETE':
            api_response = self._rh.delete(full_path, headers=api_headers, verify=VERIFY)

        if "/signatures/" in request_uri and "/download" in request_uri and api_response.status_code == 200:
            return  {'status' : 'Success', 'data' : {'signatureDownload' : api_response.text}}
        elif "/signatures/" in request_uri and "/download" in request_uri and api_response.status_code != 200:
            return  {'status' : 'Failure', 'message' : 'Error code %d' % api_response.status_code}
            
        try:
            api_response.encoding = 'utf-8'
            api_response_json = json.dumps(api_response.json())
            api_response_dict = json.loads(api_response_json)
        except:
            api_response_dict = {'status' : 'Failure', 'message' : 'Error code %d' % api_response.status_code}

        return api_response_dict

    def _api_response(self, tr, request_uri, method="GET", body=None):
        """Handle API response dict for basic request.

        Args:
            tr: (object) ThreatResponse Object to use to store response
                and result data.
            request_uri: (string) The URI containing the API request data.

        Returns:
            The ThreatResponse Object with response and result data.

        """

        # request uri
        tr.add_max_results(self._api_max_results)

        # request uri
        tr.add_request_uri(request_uri)

        # api call
        api_response = self._api_request(request_uri, method, body)

        # complete api response
        tr.add_api_response(api_response)

        # status
        tr.add_request_status(api_response['status'])

        # successful api request
        if api_response['status'] == 'Success' and 'data' in api_response:
            tr.add_response_data(api_response['data'])

        elif api_response['status'] == 'Failure':
            tr.add_error_message(api_response['message'])

        return tr

    def _api_response_owners(self, tr, request_uri, owners, method="GET", body=None):
        """Handle API response dict for request with multiple owners.

        Args:
            tr: (object) ThreatResponse Object to use to store response
                and result data.
            request_uri: (string) The URI containing the API request data.
            owners: (list) List of owners to request threat data.

        Returns:
            The ThreatResponse Object with response and result data.

        """

        if owners == None or not owners:
            owners = [self._api_org]

        # request uri
        tr.add_max_results(self._api_max_results)


        # iterate through each owner/community
        for owner in owners:

            # uri data
            owner = "owner=%s" %  urllib.quote(owner, safe='~')

            # update request_uri with owner
            owner_request_uri = request_uri
            owner_request_uri += "?%s" % owner

            # request uri
            tr.add_request_uri(owner_request_uri)

            # api call
            api_response = self._api_request(owner_request_uri, method, body)

            # status
            tr.add_request_status(api_response['status'])

            # api response
            tr.add_api_response(api_response)

            # successful api request
            if api_response['status'] == 'Success' and 'data' in api_response:
                tr.add_response_data(api_response['data'])

                # result_count
                tr.add_result_count(len(api_response['data']))

            elif api_response['status'] == 'Failure':
                tr.add_error_message(api_response['message'])

        return tr

    def _api_response_pagination(self, tr, request_uri, owners=None, method="GET", body=None):
        """Handle API response dict for request with multiple owners and
           requiring pagination.

        Args:
            tr: (object) ThreatResponse Object to use to store response
                and result data.
            request_uri: (string) The URI containing the API request data.
            owners: (list) List of owners to request threat data.

        Returns:
            The ThreatResponse Object with response and result data.

        """

        if owners == None or not owners:
            owners = [self._api_org]

        # request uri
        tr.add_max_results(self._api_max_results)

        # iterate through each owner/community
        for owner in owners:

            # start position
            start_position = 0

            # counts
            owner_count = 0
            limit_count = int(self._api_max_results)
            remaining_count = (limit_count + 1)

            # uri data
            owner = "owner=%s" % urllib.quote(owner, safe='~')

            # update api_uri with owner
            owner_request_uri = request_uri
            owner_request_uri += "?%s" % owner

            # iterate through all results
            while remaining_count > 0:

                # response limit
                if remaining_count < limit_count:
                    limit_count = remaining_count

                # request limit
                limits = "resultLimit=%s" % limit_count

                # result start
                start = "resultStart=%s" % start_position

                # increment start position
                start_position = (start_position + limit_count)

                # build api uri
                limit_request_uri = owner_request_uri
                limit_request_uri += "&%s" % start
                limit_request_uri += "&%s" % limits

                # request uri
                tr.add_request_uri(limit_request_uri)

                # api response
                api_response = self._api_request(limit_request_uri, method, body)

                # status
                tr.add_request_status(api_response['status'])

                # api response
                tr.add_api_response(api_response)

                # successful api request
                if api_response['status'] == 'Failure':
                    tr.add_error_message(api_response['message'])

                    # move on to next owner
                    break

                elif api_response['status'] == 'Success':
                    tr.add_response_data(api_response['data'])

                    # response counts
                    if owner_count == 0:
                        owner_count = api_response['data']['resultCount']
                        remaining_count = owner_count

                        # result_count
                        tr.add_result_count(owner_count)

                    # remaining results
                    remaining_count = (remaining_count - limit_count)

                else:
                    tr.add_error_message('API Response was not expected.')

        return tr

    def _create_indicator(self, indicator_type, body=None, owners=None):
        # indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr
       
        # validate indicator for non-files
        if indicator_type != 'files':
            indicator = body[self.indicator_types[indicator_type]['keys'][0]]
            if not self._validate_indicator(indicator):
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)   
                tr.add_error_message(self._bad_indicator)
                return tr

        # validate files
        if indicator_type == 'files':
            valid = True
            valid_keys = self.indicator_types['files']['keys']

            # must contain a key from valid file hash types (md5/sha1/sha256)
            if not any(k in valid_keys for k in body):
                valid = False

            # each value must pass regex validation
            # todo - i think this considers any hash valid as long as it matches one of the 3 regexes
            for k in valid_keys:
                if k in body:
                    if not self._validate_indicator(body[k]):
                        valid = False

            if not valid:
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator)
                return tr

        # create appropriate response object
        tr = ThreatResponse(self._data_structures[indicator_type])

        # request uri
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type

        return self._api_response_owners(tr, request_uri, owners, method="POST", body=body)


    def _create_group(self, group_type, body=None, owners=None):
        # validate group type
        if group_type not in self.group_types:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)
            return tr

        # required fields when creating groups
        # todo - make this conf-accessible?
        required_fields = {
            'adversaries': ['name'],
            'incidents' : ['name', 'eventDate'],
            'threats' : ['name'],
            'emails' : ['name', 'subject', 'header', 'body'],
            'signatures' : ['name', 'fileName', 'fileType', 'fileText']
        }
        
        # all required fields as defined above must be in body
        if not all(k in body for k in required_fields[group_type]):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)      #todo - appropriate error
            return tr


        tr = ThreatResponse(self._data_structures[group_type])

        request_uri = self._resource_types[group_type]['request_uri']
        
        return self._api_response_owners(tr, request_uri, owners, method="POST", body=body)
        
    def _delete_group(self, group_type, group_id, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        # create appropriate response object
        tr = ThreatResponse([])

        # request uri
        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % group_id

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")
    
    def _delete_indicator(self, indicator_type, indicator, owners=None):
        # indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator for non-files
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        # encode url
        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        # create appropriate response object
        tr = ThreatResponse(['status'])

        # request uri
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")
    
    def _validate_rating(self, rating):
        if rating in ["1.0", "2.0", "3.0", "4.0", "5.0", 0, 1, 2, 3, 4, 5]:
            return True

        #todo - make this a bit more robust, 0?
        return False

    def _validate_confidence(self, confidence):
        if not isinstance(confidence, int):
            return False

        #todo - 0?
        return confidence in range(1,101)
    
    def _generate_headers(self, request_method, api_uri):
        """Generate HTTP headers for API request.

        Args:
            request_method: (string) POST or GET HTTP method.
            api_uri: (string) base URI for the API request.

        Returns:
            The HTTP header data for the request.

        """

        timestamp = int(time.time())
        signature = "%s:%s:%d" % (api_uri, request_method, timestamp)
        hmac_signature = hmac.new(self._api_sec, signature, digestmod=hashlib.sha256).digest()
        authorization = 'TC %s:%s' % (self._api_aid, base64.b64encode(hmac_signature))

        return {'Timestamp': timestamp, 'Authorization': authorization}

    def _get_resource(self, tr, resource_type, owners=None):
        """Get resource from ThreatConnect API

        # methods utilizing this method
        * get_groups
          /v1/groups
        * get_owners
          /v1/owners

        * get_adversaries
          /v1/groups/adversaries
        * get_emails
          /v1/groups/emails
        * get_incidents
          /v1/groups/incidents
        * get_signatures
          /v1/groups/signatures
        * get_threats
          /v1/groups/threats

        Args:
            tr: (object) ThreatResponse Object to use to store response
                and result data.
            resource_type: (string) The resource type used in this request.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.

        """

        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        # request uri
        request_uri = self._resource_types[resource_type]['request_uri']

        # get response data
        if resource_type == "owners":
            return self._api_response(tr, request_uri)
        else:
            return self._api_response_pagination(tr, request_uri, owners)

    def _get_resource_by_id(self, tr, resource_type, resource_id):
        """Get resource by ID from ThreatConnect API

        * get_adversary_by_id
          /v1/groups/adversaries/<ID>
        * get_email_by_id
          /v1/groups/emails/<ID>
        * get_incident_by_id
          /v1/groups/emails/<ID>
        * get_incident_by_id
          /v1/groups/incidents/<ID>
        * get_signature_by_id
          /v1/groups/signatures/<ID>
        * get_signature_download_by_id
          /v1/groups/signatures/<ID>/download
        * get_threat_by_id
          /v1/groups/threats/<ID>

        Args:
            tr: (object) ThreatResponse Object to use to store response
                and result data.
            resource_type: (string) The type of resource requested.
            resource_id: (string) ThreatConnect internal ID of resource.

        Returns:
            Threat Response object.

        """

        # build request uri
        request_uri = self._resource_types[resource_type]['request_uri']
        request_uri += "/%s" % resource_id

        # special case for signature download
        if resource_type == "signatures_download":
            request_uri += "/download"

        # get results
        return self._api_response(tr, request_uri)
        
    def _update_indicator(self, indicator_type, indicator, body, owners=None):
        # indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator for non-files
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        # create appropriate response object
        tr = ThreatResponse(self._data_structures[indicator_type])

        # url-encode url indicators
        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        # request uri
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator

        return self._api_response_owners(tr, request_uri, owners, method="PUT", body=body)

    def _update_group(self, group_type, group_id, body, owners=None):
       # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse(self._data_structures[group_type])

        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % group_id

        return self._api_response_owners(tr, request_uri, owners, method="PUT", body=body)

    
        
    
        
    
    def _get_resource_by_indicator(self, tr, resource_type, indicator, indicator_type, owners=None):
        """Get resource by indicator from ThreatConnect API

        * get_groups_by_indicator
          /v1/indicators/<indicator type>/<value>/groups
        * get_owners_by_indicator
          /v1/indicators/<indicator type>/<value>/owners
        * get_tags_by_indicator
          /v1/indicators/<indicator type>/<value>/tags

        * get_adversaries_by_indicator
          /v1/indicators/<indicator type>/<value>/groups/adversaries
        * get_emails_by_indicator
          /v1/indicators/<indicator type>/<value>/groups/emails
        * get_incidents_by_indicator
          /v1/indicators/<indicator type>/<value>/groups/incidents
        * get_signatures_by_indicator
          /v1/indicators/<indicator type>/<value>/groups/signatures
        * get_threats_by_indicator
          /v1/indicators/<indicator type>/<value>/groups/threats

        Args:
            tr: (object) ThreatResponse Object to use to store response
                and result data.
            resource_type: (string) The type of resource requested.
            indicator: (string) The indicator to match to the  resource requested.
            indicator_type: (string) The type of indicator provided.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.

        """

        # validate indicator
        if not self._validate_indicator(indicator):
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        # indicator type
        if indicator_type is None:
            indicator_type = self.get_indicator_type(indicator)
        elif not self._validate_indicator_type(indicator_type):
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        # url
        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        # build request uri
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator


        # special case for uri's with "groups"
        if resource_type in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            request_uri += "/groups"

        request_uri += "/%s" % resource_type


        # special case for owners
        if resource_type == "owners":
            return self._api_response(tr, request_uri)
        # special case for securityLabels
        if resource_type == "securityLabels":  
            return self._api_response_owners(tr, request_uri, owners)
        else:
            return self._api_response_pagination(tr, request_uri, owners)

    def _get_resource_by_tag(self, tr, resource_type, tag_name, owners=None):
        """Get resource by tag from ThreatConnect API.

        * get_groups_by_tag
          /v1/indicators/<indicator type>/<value>/groups
        * get_adversaries_by_tag
          /v1/indicators/<indicator type>/<value>/groups/adversaries
        * get_emails_by_tag
          /v1/indicators/<indicator type>/<value>/groups/emails
        * get_incidents_by_tag
          /v1/indicators/<indicator type>/<value>/groups/incidents
        * get_signatures_by_tag
          /v1/indicators/<indicator type>/<value>/groups/signatures
        * get_threats_by_tag
          /v1/indicators/<indicator type>/<value>/groups/threats

        Args:
            tr: (object) ThreatResponse Object to use to store response
                and result data.
            resource_type: (string) The type of resource requested.
            tag_name: (string) The name of the Tag in ThreatConnect.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """

        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        # build request uri
        request_uri = self._resource_types['tags']['request_uri']
        request_uri += "/%s" % tag_name.replace(" ", "%20")
        if resource_type is not "groups":
            request_uri += "/groups"
        request_uri += "/%s" % resource_type

        return self._api_response_pagination(tr, request_uri, owners)

    def _validate_indicator(self, indicator):
        """Validate the indicator.

        Args:
            indicator: (string) The user provided indicator.

        Returns:
            A Boolean representing the validity of the indicator.
        """

        for indicator_type in self.indicator_types:
            for indicator_re in self.indicator_types[indicator_type]['regex']:
                if indicator_re.match(indicator):
                    return True

        return False

    def _validate_indicator_type(self, indicator_type):
        """Validates the indicator type.

        Args:
            indicator_type: (string) The indicator type.

        Returns:
            A Boolean representing the validity of the indicator type.
        """
        if indicator_type in self.indicator_types.keys():
            return True
        else:
            return False

    def _validate_integer(self, integer_value):
        """Validates integer.

        Args:
            integer_value: (string) The integer to be validated.

        Returns:
            A Boolean representing the validity of the indicator type.
        """
        if isinstance(integer_value, (int, long)):
            return True
        else:
            return False

    def add_filter(self, field, expression, value=None, missing_allowed=False):
        """Add filter to threat data

        Args:
            field: (string) The field to filter on.
            expression: (string) The comparission expression.
            value: (string) The value to match.

        """

        valid_filter_expressions = [
            '==', '>', '>=', '<', '<=']

        if expression in valid_filter_expressions:
            self._data_filter.append({
                'name': field,
                'expression': expression,
                'value': value,
                'missing_allowed': missing_allowed})
        else:
            print "Invalid Filter Expression"
            sys.exit(1)

    def reset_filter(self):
        """Reset filter to threat data"""

        self._data_filter = []
        
    def add_securityLabel_to_attribute(self, main_branch, main_val, attribute_id, securityLabel, owners=None):
        # validate attribute id
        if not isinstance(int(attribute_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Attribute ID must be an integer")   #todo make thsi configurable
            return tr

        # indicators
        if main_branch in self.indicator_types:
            indicator_type = main_branch
            indicator = main_val

            # indicator type
            if indicator_type is None:
                indicator_type = self.get_indicator_type(indicator)
            elif not self._validate_indicator_type(indicator_type):
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator_type)
                return tr

            # indicator val
            if not self._validate_indicator(indicator):
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator)
                return tr

            if indicator_type == 'urls':
                indicator = urllib.quote(indicator, safe='~')

            request_uri = self._resource_types['indicators']['request_uri']
            request_uri += "/%s" % indicator_type
            request_uri += "/%s" % indicator
            request_uri += "/attributes/%d" % int(attribute_id)
            request_uri += "/securityLabels"
            request_uri += "/%s" % urllib.quote(securityLabel, safe='~')

        # groups
        elif main_branch in self.group_types:
            group_type = main_branch
            group_id = main_val
            # validate group type
            if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
                return tr

            # validate group id
            if not isinstance(int(group_id), int):
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
                return tr

            request_uri = self._resource_types[group_type]['request_uri']
            request_uri += "/%d" % int(group_id)
            request_uri += "/attributes/%d" % int(attribute_id)
            request_uri += "/securityLabels"
            request_uri += "/%s" % urllib.quote(securityLabel, safe='~')

        else:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Invalid main branch")   #todo make thsi configurable
            return tr

        tr = ThreatResponse(self._data_structures['securityLabels'])
        

        return self._api_response_owners(tr, request_uri, owners, method="POST")
        
    def add_securityLabel_to_group(self, group_type, group_id, securityLabel, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])

        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % int(group_id)
        request_uri += "/securityLabels/%s" % urllib.quote(securityLabel, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="POST")

    def add_securityLabel_to_indicator(self, indicator_type, indicator, securityLabel, owners=None):
        # validate indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    #todo - why did this break?
            tr.add_error_message(self._bad_indicator)
            return tr

        tr = ThreatResponse([])

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')


        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/securityLabels/%s" % urllib.quote(securityLabel, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="POST")
        
    def add_tag_to_group(self, group_type, group_id, tag, owners=None):
        if len(tag) > 35:
            tag = tag[:35]

        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse(['status'])

        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % int(group_id)
        request_uri += "/tags/%s" % urllib.quote(tag, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="POST")
        
    def add_tag_to_indicator(self, indicator_type, indicator, tag, owners=None):
        if len(tag) > 85:
            tag = tag[:35]

        # validate indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    #todo - why did this break?
            tr.add_error_message(self._bad_indicator)
            return tr

        tr = ThreatResponse(['status'])

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')


        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/tags/%s" % urllib.quote(tag, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="POST")
        
    def associate_group_to_indicator(self, group_type, group_id, indicator_type, indicator, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    #todo - why did this break?
            tr.add_error_message(self._bad_indicator)
            return tr

        # encode url
        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        tr = ThreatResponse(['status'])

        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%s" % group_id
        request_uri += "/indicators/%s/%s" % (indicator_type, indicator)

        return self._api_response_owners(tr, request_uri, owners, method="POST")

    def associate_group_to_group(self, from_group_type, from_group_id, to_group_type, to_group_id, owners=None):
        # validate group type
        if from_group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group type
        if to_group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])

        request_uri = self._resource_types[from_group_type]['request_uri']
        request_uri += "/%d" % int(from_group_id)
        request_uri += "/groups/%s" % to_group_type
        request_uri += "/%d" % int(to_group_id)

        return self._api_response_owners(tr, request_uri, owners, method="POST")
    
    def associate_indicator_to_group(self, indicator_type, indicator, group_type, group_id, owners=None):
        return self.associate_group_to_indicator(group_type, group_id, indicator_type, indicator, owners)
        
    def create_address(self, ip, rating=None, confidence=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)       
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr

        body = {}
        key = self.indicator_types['addresses']['keys'][0]
        body[key] = ip
        
        if confidence is not None:
            body['confidence'] = confidence

        if rating is not None:
            body['rating'] = rating

        return self._create_indicator("addresses", body, owners)

    def create_emailAddress(self, email, rating=None, confidence=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)      
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence) 
            return tr

        body = {} 
        key = self.indicator_types['emailAddresses']['keys'][0]
        body[key] = email
             
        if confidence is not None:
            body['confidence'] = confidence

        if rating is not None:
            body['rating'] = rating

        return self._create_indicator("emailAddresses", body, owners)
        
    def create_file(self, hashes, rating=None, confidence=None, size=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)
            return tr
            
        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr
            
        if size is not None and not isinstance(size, int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("The file size variable must be an integer.")   #todo configurable
            return tr

        body = {}
        for h in hashes:
            body[h] = hashes[h]
            
        if confidence is not None:
            body['confidence'] = confidence

        if rating is not None:
            body['rating'] = rating
            
        if size is not None:
            body['size'] = size
            
            

        return self._create_indicator("files", body, owners)
        
    def create_fileOccurrence(self, hash, fileName=None, path=None, date=None, owners=None):
        # validate indicator
        if not self._validate_indicator(hash):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    
            tr.add_error_message(self._bad_indicator)
            return tr
        
        #todo validate date
        
        body = {}
        if fileName is not None:
            body['fileName'] = fileName
        if path is not None:
            body['path'] = path
        if date is not None:
            body['date'] = date
            
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/files"
        request_uri += "/%s" % hash
        request_uri += "/fileOccurrences"
        
        tr = ThreatResponse(['id', 'fileName', 'path', 'date'])
        
        return self._api_response_owners(tr, request_uri, owners=owners, method="POST", body=body)

    def create_host(self, host, rating=None, confidence=None, dnsActive=None, whoisActive=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating) 
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr

        body = {}
        key = self.indicator_types['hosts']['keys'][0]
        body[key] = host

        if confidence is not None:
            body['confidence'] = confidence

        if rating is not None:
            body['rating'] = rating
            
        if dnsActive is not None:
            body['dnsActive'] = dnsActive
            
        if whoisActive is not None:
            body['whoisActive'] = whoisActive

        return self._create_indicator("hosts", body, owners)

    def create_url(self, url, rating=None, confidence=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr

        body = {}
        key = self.indicator_types['urls']['keys'][0]
        body[key] = url

        if confidence is not None:
            body['confidence'] = confidence

        if rating is not None:
            body['rating'] = rating

        return self._create_indicator("urls", body, owners)

    def create_adversary(self, name, createIfExists=True, owners=None):
        if not name or name is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr
        
        # required fields when creating groups
        # todo - make this conf-accessible?
        required_fields = {
            'adversaries': ['name'],
            'incidents' : ['name', 'eventDate'],
            'threats' : ['name'],
            'emails' : ['name', 'subject', 'header', 'body'],
            'signatures' : ['name', 'fileName', 'fileType', 'fileText']
        }

        # user might not want to create duplicate threats if they exist
        if not createIfExists:
            self.add_filter('name', '==', name)
            results = self.get_adversaries(owners=owners)
            self.reset_filter()
            if results.single_result() is not None:
                return results


        body = {'name' : name}

        return self._create_group("adversaries", body=body, owners=owners)

    def create_email(self, name, fromField, subject, header, emailBody, toField=None, createIfExists=True, owners=None):
        if not name or name is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        if not fromField or fromField is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        if not subject or subject is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        if not header or header is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        if not emailBody or emailBody is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr 

        # user might not want to create duplicate threats if they exist
        if not createIfExists:
            self.add_filter('name', '==', name)
            results = self.get_emails(owners=owners)
            self.reset_filter()
            if results.single_result() is not None:
                return results


        body = {'name':name, 'from':fromField, 'subject':subject, 'header':header, 'body':emailBody}
        if toField is not None:
            body['to'] = toField

        return self._create_group('emails', body=body, owners=owners)

    def create_incident(self, name, date, createIfExists=True, owners=None):
        if not name or name is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr
        
        #todo - validate date?

        # required fields when creating groups
        # todo - make this conf-accessible?
        required_fields = {
            'adversaries': ['name'],
            'incidents' : ['name', 'eventDate'],
            'threats' : ['name'],
            'emails' : ['name', 'subject', 'header', 'body'],
            'signatures' : ['name', 'fileName', 'fileType', 'fileText']
        }

        # user might not want to create duplicate threats if they exist
        if not createIfExists:
            self.add_filter('name', '==', name)
            results = self.get_incidents(owners=owners)
            self.reset_filter()
            if results.single_result() is not None:
                return results


        body = {'name' : name, 'eventDate' : date}

        return self._create_group("incidents", body=body, owners=owners)

    def create_signature(self, name, fileName, fileType, fileText, createIfExists=True, owners=None):
        if not name or name is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr        

        if not fileName or fileName is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        if not fileText or fileText is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        if not fileType or fileType not in ['Snort', 'Suricata', 'YARA', 'ClamAV', 'OpenIOC', 'CybOX', 'Bro']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        # user might not want to create duplicate signature if they exist
        if not createIfExists:
            self.add_filter('name', '==', name)
            results = self.get_signatures(owners=owners)
            self.reset_filter()
            if results.single_result() is not None:
                return results
    
        body = {'name':name, 'fileName':fileName, 'fileType':fileType, 'fileText':fileText}
        
        return self._create_group("signatures", body=body, owners=owners)

    def create_threat(self, name, createIfExists=True, owners=None):
        if not name or name is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo appropriate error
            return tr

        # user might not want to create duplicate threats if they exist
        if not createIfExists:
            self.add_filter('name', '==', name)
            results = self.get_threats(owners=owners)
            self.reset_filter()
            if results.single_result() is not None:
                return results

        # required fields when creating groups
        # todo - make this conf-accessible?
        required_fields = {
            'adversaries': ['name'],
            'incidents' : ['name', 'eventDate'],
            'threats' : ['name'],
            'emails' : ['name', 'subject', 'header', 'body'],
            'signatures' : ['name', 'fileName', 'fileType', 'fileText']
        }

        body = {'name' : name}

        return self._create_group("threats", body=body, owners=owners)
        
    def create_victim(self, name, org=None, suborg=None, workLocation=None, nationality=None, createIfExists=True, owners=None):
        if not name or name is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Name is required")   #todo appropriate error
            return tr
            
        # user might not want to create duplicate victims if they exist
        if not createIfExists:
            self.add_filter('name', '==', name)
            results = self.get_victims(owners=owners)
            self.reset_filter()
            if results.single_result() is not None:
                return results
                
        body = {'name' : name}
        if org is not None:
            body['org'] = org
        if suborg is not None:
            body['suborg'] = suborg
        if workLocation is not None:
            body['workLocation'] = workLocation
        if nationality is not None:
            body['nationality'] = nationality
        
        tr = ThreatResponse(self._data_structures['victims'])

        request_uri = self._resource_types['victims']['request_uri']
        
        return self._api_response_owners(tr, request_uri, owners, method="POST", body=body)
        
    def create_victimEmailAddress(self, victim_id, emailAddress, addressType=None, createIfExists=False, owners=None):
        if not createIfExists:
            self.add_filter('address', '==', emailAddress)
            results = self.get_victimEmailAddresses(victim_id)
            self.reset_filter()
            if results.single_result() is not None:
                return results
                
        body = {'address' : emailAddress}
        if addressType is not None:
            body['addressType'] = addressType

        data_structure = ['id', 'type', 'webLink', 'address', 'addressType']
        tr = ThreatResponse(data_structure)
        
        request_uri = self._resource_types['victims']['request_uri']
        request_uri += "/%s" % str(victim_id)
        request_uri += "/victimAssets"
        request_uri += "/emailAddresses"
            
        return self._api_response_owners(tr, request_uri, owners, method="POST", body=body)

    def create_indicator_attribute(self, indicator_type, indicator, attribute_type, attribute_value, createIfExists=True, displayed=False, owners=None):
        # indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator for non-files
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        #todo - validate "displayed" field?
        
        # If createIfExists flag is set to False, check and update existing attribute of this type
        # TODO - needs some love to check for multiple instances of attributes; currently just updates first instance
        if not createIfExists:
            att_results = self.get_indicator_attributes(indicator_type, indicator, owners=owners)
            if att_results.status() != "Success":
                return att_results
            
            atts = json.loads(att_results.data().json())
            for att in atts:
                if att['type'].lower() == attribute_type.lower():
                    return self.update_indicator_attribute(indicator_type, indicator, att['id'], attribute_value, displayed=displayed, owners=owners)
            
                

        body = {'type' : attribute_type, 'value' : attribute_value, 'displayed' : displayed}
        data_structure = ['dateAdded', 'id', 'type', 'value', 'lastModified', 'displayed']
        tr = ThreatResponse(data_structure)

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')
        
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/attributes"

        return self._api_response_owners(tr, request_uri, owners=owners, body=body, method="POST")        
    
    def create_group_attribute(self, group_type, group_id, attribute_type, attribute_value, createIfExists=True, displayed=None, owners=None):
       # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr
            
        # If createIfExists flag is set to False, check and update existing attribute of this type
        # TODO - needs some love to check for multiple instances of attributes; currently just updates first instance
        if not createIfExists:
            att_results = self.get_group_attributes(group_type, group_id)
            if att_results.status() != "Success":
                return att_results
            
            atts = json.loads(att_results.data().json())
            for att in atts:
                if att['type'].lower() == attribute_type.lower():
                    return self.update_group_attribute(group_type, group_id, att['id'], attribute_value, displayed=displayed, owners=owners)

        body = {'type' : attribute_type, 'value' : attribute_value}

        if displayed is not None and displayed in ['true', 'false', True, False]:
            body['displayed'] = displayed

        data_structure = ['dateAdded', 'id', 'type', 'value', 'lastModified', 'displayed']
        tr = ThreatResponse(data_structure)

        # create request uri
        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%s" % group_id
        request_uri += "/attributes"

        return self._api_response_owners(tr, request_uri, owners=owners, body=body, method="POST")
        
    def delete_fileOccurrence(self, hash, id, owners=None):
        # validate indicator
        if not self._validate_indicator(hash):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    
            tr.add_error_message(self._bad_indicator)
            return tr
        
        # validate fileOccurrence id
        if not id or not isinstance(id, int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    
            tr.add_error_message("Bad fileOccurrence ID, must be an integer")
            return tr
            
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/files" 
        request_uri += "/%s" % hash
        request_uri += "/fileOccurrences"
        request_uri += "/%d" % int(id)
        
        tr = ThreatResponse([])
        
        return self._api_response_owners(tr, request_uri, owners, method="DELETE")

    def delete_indicator_attribute(self, indicator_type, indicator, attribute_id, owners=None):
        # indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        # validate attribute id
        if not isinstance(int(attribute_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Attribute ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/attributes/%d" % attribute_id

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")


    def delete_group_attribute(self, group_type, group_id, attribute_id, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        # validate attribute id
        if not isinstance(int(attribute_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Attribute ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])

        # create request uri
        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%s" % group_id
        request_uri += "/attributes/%d" % attribute_id

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")
        
    def delete_securityLabel_from_attribute(self, main_branch, main_val, attribute_id, securityLabel, owners=None):
        # validate attribute id
        if not isinstance(int(attribute_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Attribute ID must be an integer")   #todo make thsi configurable
            return tr

        # indicators
        if main_branch in self.indicator_types:
            indicator_type = main_branch
            indicator = main_val

            # indicator type
            if indicator_type is None:
                indicator_type = self.get_indicator_type(indicator)
            elif not self._validate_indicator_type(indicator_type):
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator_type)
                return tr

            # indicator val
            if not self._validate_indicator(indicator):
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator)
                return tr

            if indicator_type == 'urls':
                indicator = urllib.quote(indicator, safe='~')

            request_uri = self._resource_types['indicators']['request_uri']
            request_uri += "/%s" % indicator_type
            request_uri += "/%s" % indicator
            request_uri += "/attributes/%d" % int(attribute_id)
            request_uri += "/securityLabels"
            request_uri += "/%s" % urllib.quote(securityLabel, safe='~')

        # groups
        elif main_branch in self.group_types:
            group_type = main_branch
            group_id = main_val
            # validate group type
            if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
                return tr

            # validate group id
            if not isinstance(int(group_id), int):
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
                return tr

            request_uri = self._resource_types[group_type]['request_uri']
            request_uri += "/%d" % int(group_id)
            request_uri += "/attributes/%d" % int(attribute_id)
            request_uri += "/securityLabels"
            request_uri += "/%s" % urllib.quote(securityLabel, safe='~')

        else:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Invalid main branch")   #todo make thsi configurable
            return tr

        tr = ThreatResponse(self._data_structures['securityLabels'])
        return self._api_response_owners(tr, request_uri, owners, method="DELETE")
        
    def delete_securityLabel_from_group(self, group_type, group_id, securityLabel, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])

        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % int(group_id)
        request_uri += "/securityLabels/%s" % urllib.quote(securityLabel, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")

    def delete_securityLabel_from_indicator(self, indicator_type, indicator, securityLabel, owners=None):
        # validate indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    #todo - why did this break?
            tr.add_error_message(self._bad_indicator)
            return tr

        tr = ThreatResponse([])

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')


        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/securityLabels/%s" % urllib.quote(securityLabel, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")

    def delete_tag_from_group(self, group_type, group_id, tag, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])

        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % int(group_id)
        request_uri += "/tags/%s" % urllib.quote(tag, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")
    
    def delete_tag_from_indicator(self, indicator_type, indicator, tag, owners=None):
        # validate indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    #todo - why did this break?
            tr.add_error_message(self._bad_indicator)
            return tr

        tr = ThreatResponse([])

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')


        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/tags/%s" % urllib.quote(tag, safe='~')

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")
        
    def dissociate_group_from_group(self, from_group_type, from_group_id, to_group_type, to_group_id, owners=None):
        # validate group type
        if from_group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group type
        if to_group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])

        request_uri = self._resource_types[from_group_type]['request_uri']
        request_uri += "/%d" % int(from_group_id)
        request_uri += "/groups/%s" % to_group_type
        request_uri += "/%d" % int(to_group_id)

        return self._api_response_owners(tr, request_uri, owners, method="DELETE") 
    
    def dissociate_group_from_indicator(self, group_type, group_id, indicator_type, indicator, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    #todo - why did this break?
            tr.add_error_message(self._bad_indicator)
            return tr

        # encode url
        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        tr = ThreatResponse([])

        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%s" % group_id
        request_uri += "/indicators/%s/%s" % (indicator_type, indicator)

        return self._api_response_owners(tr, request_uri, owners, method="DELETE")

    def dissociate_indicator_from_group(self, indicator_type, indicator, group_type, group_id, owners=None):
        return self.dissociate_group_from_indicator(self, group_type, group_id, indicator_type, indicator_id, owners)
        
        
    def get_adversary_by_id(self, resource_id):
        """Get adversary by id.

        /v1/groups/adversaries/<ID>

        Args:
            resource_id: (string) The adversary id.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'owner', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "adversaries"
        return self._get_resource_by_id(tr, resource_type, resource_id)

    def get_adversaries(self, owners=None):
        """Get all adversaries.

        /v1/groups/adversaries?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "adversaries"
        return self._get_resource(tr, resource_type, owners)

    def get_adversaries_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all adversaries by indicator.

        /v1/indicators/<indicator type>/<indicator>/group/adversaries?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "adversaries"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)

    def get_adversaries_by_tag(self, tag_name, owners=None):
        """Get all adversaries by tag.

        /v1/tags/<tag name>/groups/adversaries?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "adversaries"
        return self._get_resource_by_tag(tr, resource_type, tag_name, owners)

    def get_email_by_id(self, resource_id):
        """Get email by id.

        /v1/groups/emails/<ID>

        Args:
            resource_id: (string) The adversary id.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'body', 'dateAdded', 'from', 'header', 'id', 'name', 'owner',
            'score', 'subject', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "emails"
        return self._get_resource_by_id(tr, resource_type, resource_id)

    def get_emails(self, owners=None):
        """Get all email threats.

        /v1/groups/emails?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'id', 'name', 'ownerName', 'score', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "emails"
        return self._get_resource(tr, resource_type, owners)

    def get_emails_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all emails by indicator.

        /v1/indicators/<indicator type>/<indicator>/group/emails?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'id', 'name', 'ownerName', 'score', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "emails"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)

    def get_emails_by_tag(self, tag_name, owners=None):
        """Get all emails by tag.

        /v1/tags/<tag name>/groups/emails?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'id', 'name', 'ownerName', 'score', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "emails"
        return self._get_resource_by_tag(tr, resource_type, tag_name, owners)
        
    def get_fileOccurrences(self, hash, owners=None):
        # validate indicator 
        if not self._validate_indicator(hash):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr
            
        data_structure = ['fileName', 'path', 'id', 'date']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/files"
        request_uri += "/%s" % hash
        request_uri += "/fileOccurrences"
        
        return self._api_response_owners(tr, request_uri, owners=owners)

    def get_indicator_attributes(self, indicator_type, indicator, owners=None):
        # indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator 
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        data_structure = ['dateAdded', 'id', 'type', 'value', 'lastModified', 'displayed']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "attributes"

        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/attributes"

        return self._api_response_owners(tr, request_uri, owners=owners)

    

    

    

    

    def get_group_attributes(self, group_type, group_id):
        """Get all group attributes.

        /v1/groups/<group_type>/<group id>/attributes?owner=<owner>

        Args:
            group_type: (string) The predefined group type.
            group_id: (string) The ThreatConnect group ID.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'type', 'value']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "attributes"

        # create request uri
        request_uri = self._resource_types[resource_type]['request_uri']
        request_uri += "/%s" % group_type
        request_uri += "/%s" % group_id
        request_uri += "/attributes"

        return self._api_response_owners(tr, request_uri, owners=None)

    def get_groups(self, owners=None):
        """Get all group threats.

        /v1/groups?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'id', 'name', 'ownerName', 'type', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "groups"
        return self._get_resource(tr, resource_type, owners)
        
    def get_groups_by_group(self, group_id, group_type, owners=None):
        """Get all the groups associated with a provided group:
        
        /v2/groups/<group type>/<group id>/groups
        
        Args:
            group_id: (string) the string ID of the group
            group_type: (string) the type of the group (incidents, threats, etc.)
        
        """
        
        
        data_structure = ['dateAdded', 'id', 'name', 'ownerName', 'type', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        
        request_uri = self._resource_types['groups']['request_uri']
        request_uri += "/%s" % group_type
        request_uri += "/%s" % group_id
        request_uri += "/groups"

        return self._api_response_pagination(tr, request_uri, owners)

    def get_groups_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all emails by indicator.

        /v1/indicators/<indicator type>/<indicator>/groups?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'id', 'name', 'ownerName', 'type', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "groups"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)

    def get_groups_by_tag(self, tag_name, owners=None):
        """Get all groups by tag.

        /v1/tags/<tag name>/groups?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'id', 'name', 'ownerName', 'type', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "groups"
        return self._get_resource_by_tag(tr, resource_type, tag_name, owners)

    def get_incident_by_id(self, resource_id):
        """Get incident by id.

        /v1/groups/incident/<ID>

        Args:
            resource_id: (string) The adversary id.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'eventDate', 'id', 'name', 'owner', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "incidents"
        return self._get_resource_by_id(tr, resource_type, resource_id)

    def get_incidents(self, owners=None):
        """Get all incidents.

        /v1/groups/incidents?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'eventDate', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "incidents"
        return self._get_resource(tr, resource_type, owners)

    def get_incidents_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all incidents by indicator.

        /v1/indicators/<indicator type>/<indicator>/group/incidents?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'eventDate', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "incidents"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)

    def get_incidents_by_tag(self, tag_name, owners=None):
        """Get all incidents by tag.

        /v1/tags/<tag name>/groups/incidents?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'eventDate', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "incidents"
        return self._get_resource_by_tag(tr, resource_type, tag_name, owners)

    def get_indicator(self, indicator, indicator_type=None, owners=None):
        """Get indicator from ThreatConnect API.

        /v1/indicators/<indicator type>/<indicator>?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        # indicator type
        if indicator_type is None:
            indicator_type = self.get_indicator_type(indicator)
        elif not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # url
        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        data_structures = {
            'addresses': [
                'confidence', 'dateAdded', 'id', 'ip', 'lastModified',
                'owner', 'rating', 'webLink'],
            'emailAddresses': [
                'address', 'confidence', 'dateAdded', 'description', 'id',
                'lastModified', 'owner', 'rating', 'source', 'webLink'],
            'files': [
                'confidence', 'dateAdded',  'id',
                'lastModified', 'md5', 'owner', 'rating', 'sha1', 'sha256',
                'webLink'],
            'hosts': [
                'confidence', 'dateAdded', 'description', 'dnsActive',
                'hostName', 'id', 'lastModified', 'owner', 'rating',
                'source', 'webLink', 'whoisActive'],
            'urls': [
                'confidence', 'dateAdded', 'description', 'id',
                'lastModified', 'owner', 'rating', 'text', 'webLink']}

        tr = ThreatResponse(data_structures[indicator_type])
        tr.add_filter(self._data_filter)

        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        # resource_type
        resource_type = "indicators"

        # request uri
        request_uri = self._resource_types[resource_type]['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator

        return self._api_response_owners(tr, request_uri, owners)

    def get_indicator_type(self, indicator):
        """Get indicators type from indicator.

        Args:
            indicator: (string) The user provided indicator.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        for indicator_type in self.indicator_types:
            for indicator_re in self.indicator_types[indicator_type]['regex']:
                if indicator_re.match(indicator):
                    return indicator_type

        return None

    def get_indicators(self, indicator_type=None, owners=None):
        """Get indicators

        /v1/indicator?owner=<owner>
        /v1/indicator/<indicator type>?owner=<owner>

        Args:
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        # resource_type
        resource_type = "indicators"

        # indicator type
        if indicator_type is None:
            data_structure = [
                'confidence', 'dateAdded', 'description', 'id', 'lastModified',
                'ownerName', 'rating', 'summary', 'type', 'webLink']
        else:
            data_structures = {
                'addresses': [
                    'confidence', 'dateAdded', 'id', 'ip', 'lastModified',
                    'ownerName', 'rating', 'webLink'],
                'emailAddresses': [
                    'address', 'confidence', 'dateAdded', 'description', 'id',
                    'lastModified', 'ownerName', 'rating', 'webLink'],
                'files': [
                    'confidence', 'dateAdded', 'id', 'lastModified', 'md5',
                    'ownerName', 'rating', 'sha1', 'sha256', 'webLink'],
                'hosts': [
                    'confidence', 'dateAdded', 'description', 'hostName', 'id',
                    'lastModified', 'ownerName', 'rating', 'webLink'],
                'urls': [
                    'confidence', 'dateAdded', 'description', 'id',
                    'lastModified', 'ownerName', 'rating', 'text', 'webLink']}

            data_structure = data_structures[indicator_type]

            # validate indicator type
            if not self._validate_indicator_type(indicator_type):
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator_type)
                return tr

        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)

        # build request uri
        request_uri = self._resource_types[resource_type]['request_uri']

        # append user defined indicator type
        if indicator_type is not None:
            request_uri += "/%s" % indicator_type

        return self._api_response_pagination(tr, request_uri, owners)

    def get_indicators_by_group(self, group_type, group_id, indicator_type=None, owners=None):
        """Get indicators by group.

        /v1/groups/<group type>/<group id>/indicators?owner=<owner>
        /v1/groups/<group type>/<group id>/indicators/<indicator type>?owner=<owner>

        Args:
            group_type: (string) The predefined group type.
            group_id: (string) The ThreatConnect group ID.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        # indicator type
        if indicator_type is None:
            data_structure = ['dateAdded', 'id', 'lastModified', 'ownerName', 'summary', 'type', 'webLink']
        else:
            data_structures = {
                'addresses': [
                    'confidence', 'dateAdded', 'id', 'ip', 'lastModified', 'ownerName', 'webLink'],
                'emailAddresses': [
                    'address', 'confidence', 'dateAdded', 'description', 'id',
                    'lastModified', 'ownerName', 'rating', 'webLink'],
                'files': [
                    'confidence', 'dateAdded', 'id', 'lastModified', 'md5',
                    'ownerName', 'sha1', 'sha256', 'webLink'],
                'hosts': [
                    'confidence', 'dateAdded', 'description', 'hostName', 'id',
                    'lastModified', 'ownerName', 'rating', 'webLink'],
                'urls': [
                    'confidence', 'dateAdded', 'description', 'id',
                    'lastModified', 'ownerName', 'rating', 'text', 'webLink']}

            data_structure = data_structures[indicator_type]

            # validate indicator type
            if not self._validate_indicator_type(indicator_type):
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator_type)
                return tr

        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)

        # build request uri
        request_uri = self._resource_types['groups']['request_uri']
        request_uri += "/%s" % group_type.replace(" ", "%20")
        request_uri += "/%s" % group_id
        request_uri += "/indicators"

        # append user define indicator type
        if indicator_type is not None:
            request_uri += "/%s" % indicator_type

        return self._api_response_pagination(tr, request_uri, owners)

    def get_indicators_by_tag(self, tag_name, indicator_type=None, owners=None):
        """Get indicators by tag.

        /v1/tags/<tag name>/indicators?owner=<owner>
        /v1/tags/<tag name>/indicators/<indicator type>?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        if owners is None or not owners:
            # default owner
            owners = [self._api_org]

        # indicator type
        if indicator_type is None:
            data_structure = ['dateAdded', 'id', 'lastModified', 'ownerName', 'summary', 'type', 'webLink']
        else:
            data_structures = {
                'addresses': [
                    'confidence', 'dateAdded', 'id', 'ip', 'lastModified', 'ownerName', 'webLink'],
                'emailAddresses': [
                    'address', 'confidence', 'dateAdded', 'description', 'id',
                    'lastModified', 'ownerName', 'rating', 'webLink'],
                'files': [
                    'confidence', 'dateAdded', 'id', 'lastModified', 'md5',
                    'ownerName', 'webLink'],
                'hosts': [
                    'confidence', 'dateAdded', 'description', 'hostName', 'id',
                    'lastModified', 'ownerName', 'rating', 'webLink'],
                'urls': [
                    'confidence', 'dateAdded', 'description', 'id',
                    'lastModified', 'ownerName', 'rating', 'text', 'webLink']}

            data_structure = data_structures[indicator_type]

            # validate indicator type
            if not self._validate_indicator_type(indicator_type):
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator_type)
                return tr

        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)

        # build request uri
        request_uri = self._resource_types['tags']['request_uri']
        request_uri += "/%s" % tag_name.replace(" ", "%20")
        request_uri += "/indicators"

        # append user define indicator type
        if indicator_type is not None:
            request_uri += "/%s" % indicator_type

        return self._api_response_pagination(tr, request_uri, owners)

    def get_owners(self):
        """Get all owners.

        /v1/groups/owners

        Returns:
            Threat Response object.
        """
        data_structure = ['id', 'name', 'type']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "owners"
        owners = []
        return self._get_resource(tr, resource_type, owners)

    def get_owners_by_indicator(self, indicator, indicator_type=None):
        """Get all owners by indicator.

        /v1/indicators/<indicator type>/<indicator>/owners?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.

        Returns:
            Threat Response object.
        """
        data_structure = ['id', 'name', 'type']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "owners"
        owners = []
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)
        
    def get_securityLabels_for_attribute(self, main_branch, main_val, attribute_id, owners=None):
        # validate attribute id
        if not isinstance(int(attribute_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Attribute ID must be an integer")   #todo make thsi configurable
            return tr

        # indicators
        if main_branch in self.indicator_types:
            indicator_type = main_branch
            indicator = main_val
            
            # indicator type
            if indicator_type is None:
                indicator_type = self.get_indicator_type(indicator)
            elif not self._validate_indicator_type(indicator_type):
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator_type)
                return tr 

            # indicator val
            if not self._validate_indicator(indicator):
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_indicator)
                return tr

            if indicator_type == 'urls':
                indicator = urllib.quote(indicator, safe='~')

            request_uri = self._resource_types['indicators']['request_uri']
            request_uri += "/%s" % indicator_type
            request_uri += "/%s" % indicator
            request_uri += "/attributes/%d" % int(attribute_id)
            request_uri += "/securityLabels"

        # groups
        elif main_branch in self.group_types:
            group_type = main_branch
            group_id = main_val
            # validate group type
            if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
                return tr

            # validate group id
            if not isinstance(int(group_id), int):
                tr = ThreatResponse([])
                tr.add_request_status(self._failure_status)
                tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
                return tr

            request_uri = self._resource_types[group_type]['request_uri']
            request_uri += "/%d" % int(group_id)
            request_uri += "/attributes/%d" % int(attribute_id)
            request_uri += "/securityLabels"

        else:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Invalid main branch")   #todo make thsi configurable
            return tr

        tr = ThreatResponse(self._data_structures['securityLabels'])

        return self._api_response_owners(tr, request_uri, owners)
        
    def get_securityLabels_for_indicator(self, indicator_type, indicator, owners=None):
        # validate indicator
        if not self._validate_indicator(indicator):
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        # indicator type
        if indicator_type is None:
            indicator_type = self.get_indicator_type(indicator)
        elif not self._validate_indicator_type(indicator_type):
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        tr = ThreatResponse(self._data_structures['securityLabels'])

        return self._get_resource_by_indicator(tr, 'securityLabels', indicator, indicator_type, owners=owners)

    def get_securityLabels_for_group(self, group_type, group_id, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse(self._data_structures['securityLabels'])

        # build request uri
        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % int(group_id)
        request_uri += "/securityLabels"

        return self._api_response_owners(tr, request_uri, owners)

    def get_signature_by_id(self, resource_id):
        """Get signatures by id.

        /v1/groups/signatures/<ID>

        Args:
            resource_id: (string) The adversary id.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'fileName', 'fileType', 'id', 'name', 'owner', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "signatures"
        return self._get_resource_by_id(tr, resource_type, resource_id)

    def get_signature_download_by_id(self, resource_id):
        """Get signature download by id.

        /v1/groups/signatures/<ID>/download

        Args:
            resource_id: (string) The adversary id.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'fileType', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "signatures_download"
        return self._get_resource_by_id(tr, resource_type, resource_id)

    def get_signatures(self, owners=None):
        """Get all signatures.

        /v1/groups/signatures?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'fileType', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "signatures"
        return self._get_resource(tr, resource_type, owners)

    def get_signatures_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all signatures by indicator.

        /v1/indicators/<indicator type>/<indicator>/group/signatures?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'fileType', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "signatures"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)

    def get_signatures_by_tag(self, tag_name, owners=None):
        """Get all signatures by tag.

        /v1/tags/<tag name>/groups/signatures?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = [
            'dateAdded', 'fileType', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "signatures"
        return self._get_resource_by_tag(tr, resource_type, tag_name, owners)

    def get_tags(self, owners=None):
        """Get all tags.

        /v1/groups/tags?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['name', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "tags"
        return self._get_resource(tr, resource_type, owners)

    def get_tags_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all tags by indicator.

        /v1/indicators/<indicator type>/<indicator>/tags?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['name', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "tags"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)

    def get_tags_by_group(self, group_type, group_id, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse(self._data_structures['tags'])

        # build request uri
        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % int(group_id)
        request_uri += "/tags"

        return self._api_response_owners(tr, request_uri, owners)

    def get_tag_by_name(self, tag_name, owners=None):
        """Get tag by name.

        /v1/tags/<tag name>?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['name', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)

        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        # resource type
        resource_type = "tags"

        # request uri
        request_uri = self._resource_types[resource_type]['request_uri']
        request_uri += "/%s" % tag_name.replace(" ", "%20")

        # get results
        return self._api_response_owners(tr, request_uri, owners)

    def get_threat_by_id(self, resource_id):
        """Get threat by id.

        /v1/groups/threats/<ID>

        Args:
            resource_id: (string) The adversary id.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'owner', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "threats"
        return self._get_resource_by_id(tr, resource_type, resource_id)

    def get_threats(self, owners=None):
        """Get all tags.

        /v1/groups/threats?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "threats"
        return self._get_resource(tr, resource_type, owners)

    def get_threats_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all threats by indicator.

        /v1/indicators/<indicator type>/<indicator>/group/threats?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "threats"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)

    def get_threats_by_tag(self, tag_name, owners=None):
        """Get all threats by tag.

        /v1/tags/<tag name>/groups/threats?owner=<owner>

        Args:
            tag_name: (string) The predefined ThreatConnect tag name.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['dateAdded', 'id', 'name', 'ownerName', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "threats"
        return self._get_resource_by_tag(tr, resource_type, tag_name, owners)
        
        
    def get_victims(self, owners=None):
        """Get all victims.

        /v2/victims?owner=<owner>

        Args:
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['id', 'name', 'org', 'suborg', 'workLocation', 'nationality', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "victims"
        return self._get_resource(tr, resource_type, owners)
        
    def get_victim_by_id(self, resource_id):
        """Get victim by specified id

        /v2/victims/<ID>?owner=<owner>

        Args:
            ID: the id of this victim to retrieve
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['id', 'name', 'org', 'suborg', 'workLocation', 'nationality', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "victims"
        return self._get_resource_by_id(tr, resource_type, resource_id)
        
    def get_victims_by_group(self, group_type, group_id, owners=None):
        """Get victims by group.

        /v2/groups/<group type>/<group id>/victims?owner=<owner>
        
        Args:
            group_type: (string) The predefined group type.
            group_id: (string) The ThreatConnect group ID.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        # set owner to default org
        if owners is None or not owners:
            owners = [self._api_org]

        data_structure = ['id', 'name', 'org', 'suborg', 'workLocation', 'nationality', 'webLink']

        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)

        # build request uri
        request_uri = self._resource_types['groups']['request_uri']
        request_uri += "/%s" % group_type.replace(" ", "%20")
        request_uri += "/%s" % group_id
        request_uri += "/victims"

        return self._api_response_pagination(tr, request_uri, owners)
    
    def get_victims_by_indicator(self, indicator, indicator_type=None, owners=None):
        """Get all victims by indicator.

        /v2/indicators/<indicator type>/<indicator>/victims?owner=<owner>

        Args:
            indicator: (string) The user provided indicator.
            indicator_type: (string) The indicator type.
            owners: (list) List of owners to request threat data.

        Returns:
            Threat Response object.
        """
        data_structure = ['id', 'name', 'org', 'suborg', 'workLocation', 'nationality', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        resource_type = "victims"
        return self._get_resource_by_indicator(tr, resource_type, indicator, indicator_type, owners)
        
        
    def get_victimAssets(self, victimId):
        data_structure = ['id', 'name', 'type', 'webLink']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        
        request_uri = self._resource_types['victims']['request_uri']
        request_uri += "/%s" % victimId
        request_uri += "/victimAssets"
        
        return self._api_response_pagination(tr, request_uri)
        
    def get_victimEmailAddresses(self, victimId):
        data_structure = ['id', 'type', 'webLink', 'address', 'addressType']
        tr = ThreatResponse(data_structure)
        tr.add_filter(self._data_filter)
        
        request_uri = self._resource_types['victims']['request_uri']
        request_uri += "/%s" % victimId
        request_uri += "/victimAssets/emailAddresses"
        
        return self._api_response_pagination(tr, request_uri)

    def set_max_results(self, max_results):
        """Set max results for API pagination request.

        Args:
            max_results: (string) The number of results per request.
        """
        # validate the max_results is an integer
        if self._validate_integer(max_results):
            print self._bad_max_results
        else:
            self._api_max_results = max_results
            
    def update_address(self, ip, rating=None, confidence=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr

        body = {}
        if rating is not None:
            body['rating'] = rating
        if confidence is not None:
            body['confidence'] = confidence

        return self._update_indicator('addresses', ip, body=body, owners=owners)
        
    def update_email(self, group_id, name, fromField, subject, header, emailBody, toField=None, owners=None):
        body = {}
        
        if name is not None and name:
            body['name'] = name

        if fromField is not None and fromField:
            body['from'] = fromField

        if subject is not None and subject:
            body['subject'] = subject

        if header is not None and header:
            body['header'] = header

        if emailBody is not None and emailBody:
            body['body'] = emailBody

        if toField is not None:
            body['to'] = toField

        return self._update_group('emails', group_id, body=body, owners=owners)

    def update_emailAddress(self, emailAddress, rating=None, confidence=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr

        body = {}
        if rating is not None:
            body['rating'] = rating
        if confidence is not None:
            body['confidence'] = confidence

        return self._update_indicator('emailAddresses', emailAddress, body=body, owners=owners)
        
    def update_file(self, hash, rating=None, confidence=None, size=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr
            
        if size is not None and not isinstance(size, int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("The size variable must be an integer.")   #todo configurable
            return tr

        body = {}
        if rating is not None:
            body['rating'] = rating
        if confidence is not None:
            body['confidence'] = confidence
        if size is not None:
            body['size'] = size
            
            
        return self._update_indicator('files', hash, body=body, owners=owners)
        
    def update_fileOccurrence(self, hash, id, fileName=None, path=None, date=None, owners=None):
        # validate indicator
        if not self._validate_indicator(hash):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    
            tr.add_error_message(self._bad_indicator)
            return tr
            
        # validate fileOccurrence id
        if not id or not isinstance(id, int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)    
            tr.add_error_message("Bad fileOccurrence ID, must be an integer")
            return tr
        
        #todo validate date
        
        body = {}
        if fileName is not None:
            body['fileName'] = fileName
        if path is not None:
            body['path'] = path
        if date is not None:
            body['date'] = date
                      
        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/files" 
        request_uri += "/%s" % hash
        request_uri += "/fileOccurrences"
        request_uri += "/%d" % int(id)
        
        tr = ThreatResponse(['id', 'fileName', 'path', 'date'])
        
        return self._api_response_owners(tr, request_uri, owners=owners, method="PUT", body=body)
            
    def update_group_attribute(self, group_type, group_id, attribute_id, attribute_value, displayed=None, owners=None):
        # validate group type
        if group_type not in ['adversaries', 'emails', 'incidents', 'signatures', 'threats']:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_group_type)   #todo make thsi configurable
            return tr

        # validate group id
        if not isinstance(int(group_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Group ID must be an integer")   #todo make thsi configurable
            return tr

        # validate attribute id
        if not isinstance(int(attribute_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Attribute ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])
        
        body = {'value' : attribute_value}
        if displayed is not None and displayed in ['true', 'false', True, False]:
            body['displayed'] = displayed

        # create request uri
        request_uri = self._resource_types[group_type]['request_uri']
        request_uri += "/%d" % group_id
        request_uri += "/attributes/%d" % attribute_id

        return self._api_response_owners(tr, request_uri, owners=owners, body=body, method="PUT")
    
    def update_host(self, host, rating=None, confidence=None, whois=None, dns=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)
            return tr
            
        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr

        body = {}
        if rating is not None:
            body['rating'] = rating
        if confidence is not None:
            body['confidence'] = confidence
        if whois is not None and isinstance(whois, bool):
            body['whoisActive'] = whois
        if dns is not None and isinstance(dns, bool):
            body['dnsActive'] = dns

        return self._update_indicator('hosts', host, body=body, owners=owners)
    
    def update_incident(self, incident_id, name=None, eventDate=None, owners=None):
        if name is None and eventDate is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Please provide valid updated fields") #todo - fix this

        #todo - validate date or eventDate

        body = {}
        if name is not None:
            body['name'] = name
        if eventDate is not None:
            body['eventDate'] = eventDate

        return self._update_group('incidents', incident_id, body, owners)
    
    def update_indicator_attribute(self, indicator_type, indicator, attribute_id, attribute_value, displayed=None, owners=None):
        # indicator type
        if not self._validate_indicator_type(indicator_type):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator_type)
            return tr

        # validate indicator
        if not self._validate_indicator(indicator):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_indicator)
            return tr

        # validate attribute id
        if not isinstance(int(attribute_id), int):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Attribute ID must be an integer")   #todo make thsi configurable
            return tr

        tr = ThreatResponse([])
        body = {'value' : attribute_value}

        if displayed is not None and isinstance(displayed, bool):
            body['displayed'] = displayed

        if indicator_type == 'urls':
            indicator = urllib.quote(indicator, safe='~')

        request_uri = self._resource_types['indicators']['request_uri']
        request_uri += "/%s" % indicator_type
        request_uri += "/%s" % indicator
        request_uri += "/attributes/%d" % attribute_id

        return self._api_response_owners(tr, request_uri, owners=owners, body=body, method="PUT")

    def update_signature(self, group_id, name, fileName, fileType, fileText, owners=None):
        body = {}

        if name is not None and name:
            body['name'] = name

        if fileName is not None and fileName:
            body['from'] = fromField

        if fileType is not None and fileType:
            body['subject'] = subject

        if fileText is not None and fileText:
            body['header'] = header

        return self._update_group('signatures', group_id, body=body, owners=owners)


    def update_threat(self, threat_id, name, owners=None):
        if name is None:
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message("Please provide valid updated fields") #todo - fix this

        body = {'name' : name}

        return self._update_group('threats', threat_id, body, owners)
    
    def update_url(self, url, rating=None, confidence=None, owners=None):
        if rating is not None and not self._validate_rating(rating):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_rating)
            return tr

        if confidence is not None and not self._validate_confidence(confidence):
            tr = ThreatResponse([])
            tr.add_request_status(self._failure_status)
            tr.add_error_message(self._bad_confidence)
            return tr

        body = {}
        if rating is not None:
            body['rating'] = rating
        if confidence is not None:
            body['confidence'] = confidence

        return self._update_indicator('urls', url, body=body, owners=owners)

class ThreatResponse(object):
    """API Threat Response Object"""

    def __init__(self, data_structure):
        self._api_response = []
        self._count = 0
        self._data = ResultData(data_structure)
        self.data_structure = data_structure
        self._data_type = None
        # dictionary of classes
        self._data_types = {
            'address': AddressIndicatorData,
            'adversary': AdversaryData,
            'attribute': AttributeData,
            'email': EmailData,
            'emailAddress': EmailIndicatorData,
            'file': FileIndicatorData,
            'fileOccurrence': FileOccurrenceData,
            'group': GroupData,
            'host': HostIndicatorData,
            'incident': IncidentData,
            'indicator': IndicatorData,
            'owner': OwnerData,
            'securityLabel' : SecurityLabelData,
            'signatureDownload' : SignatureDownload,
            'signature': SignatureData,
            'tag': TagData,
            'threat': ThreatData,
            'url': UrlIndicatorData,
            'victim' : VictimData,
            'victimAsset' : VictimAssetData,
            'victimEmailAddress' : VictimEmailAddressData}
        self._error_message_list = []
        self._filters = None
        self._max_results = 0
        self._response_class = None
        self._status = None
        self._uris = []

    def _filter_data(self, data):
        """Filter data using user defined filters."""

        filtered_data = []
        if not self._filters:
            return data

        for dat in data:
            add_data = True
            for filter in self._filters:
                if filter['name'] not in dat.keys():
                    if not filter['missing_allowed']:
                        add_data = False
                        break
                elif filter['name'] in dat.keys():
                    cleanName = str(dat[filter['name']]).replace("'", "")
                    cleanVal = str(filter['value']).replace("'", "")

                    myexpression = "'%s' %s '%s'" % (cleanName, filter['expression'], cleanVal)
                    
                    if not eval(myexpression):
                        add_data = False
                        break

            if add_data:
                filtered_data.append(dat)

        return filtered_data

    def add_api_response(self, api_response):
        self._api_response.append(api_response)

    def add_error_message(self, error_message):
        self._error_message_list.append(error_message)

    def add_filter(self, filters):
        self._filters = filters

    def add_max_results(self, max_results):
        self._max_results = max_results

    def add_request_uri(self, request_uri):
        self._uris.append(request_uri)

    def add_request_status(self, request_status):
        # once one successful result is found the
        # status is "Success"
        if self._status != "Success":
            self._status = request_status

    def add_response_class(self, response_class):
        self._response_class = response_class

    def add_result_count(self, result_count):
        self._count += result_count

    def add_response_data(self, response_data):
        """Add response data to ResultData Object."""
        # data type
        for data_type in response_data.keys():
            if data_type in self._data_types.keys():
                self._data_type = data_type

        # handle different data types
        if isinstance(response_data[self._data_type], list):
            data = response_data[self._data_type]
        else:
            data = [response_data[self._data_type]]

        # set data count
        if self._count == 0:
            self._count = len(data)

        # instantiate class
        if not isinstance(self._data, self._data_types[self._data_type]):
            self._data = self._data_types[self._data_type](self.data_structure)

        # add/append data to object
        self._data.add_data(self._filter_data(data))

    def api_response(self):
        return self._api_response

    def count(self):
        return self._count

    def data(self):
        return self._data

    def error_message_list(self):
        return self._error_message_list

    def max_results(self):
        return self._max_results

    def single_result(self):
        if not self.data() or not self.data().json():
            return None

        if not json.loads(self.data().json()):
            return None

        return json.loads(self.data().json())[0]

    def status(self):
        return self._status

    def uris(self):
        return self._uris


class ResultData(object):
    """Result Data from ThreatConnect API call."""

    def __init__(self, data_structure):
        self._body_list = []
        self._count = 0
        self._data = []
        self.data_structure = data_structure
        self._dateAdded_list = []
        self._eventDate_list = []
        self._fileName_list = []
        self._fileType_list = []
        self._from_list = []
        self._header_list = []
        self._id_list = []
        self._lastModified_list = []
        self._name_list = []
        self._owner_list = []
        self._ownerName_list = []
        self._score_list = []
        self._subject_list = []
        self._type_list = []
        self._webLink_list = []
        self._value_list = []

    def add_data(self, data):
        self._data += data

    def body_list(self):
        for data in self._data:
            if 'body' in data.keys():
                self._body_list.append(data['body'])

        return self._body_list

    def count(self):
        return len(self._data)

    def csv(self):
        csvout = io.BytesIO()

        csvdata = csv.writer(csvout, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONNUMERIC)

        # header
        csvdata.writerow(self.data_structure)

        # empty data
        if len(self._data) <= 0:
            return None

        # rows
        for data in self._data:
            csvrow = []
            for header in self.data_structure:

                if header not in data.keys():
                    csvrow.append("")
                elif header == 'fileOccurrence':
                    if len(data[header]) > 0:
                        occurence_data = ""
                        for occurence in data[header]:
                            file_data = ""
                            for key, value in occurence.iteritems():
                                file_data += "%s=%s " % (key, value)
                            occurence_data += "%s|" % file_data
                        csvrow.append(file_data.rstrip(' '))
                    else:
                        csvrow.append("")
                elif header == 'owner':
                    owner_data = "type=%s " % str(data[header]['type'])
                    owner_data += "id=%s " % str(data[header]['id'])
                    owner_data += "name=%s" % str(data[header]['name'])
                    csvrow.append(owner_data)
                elif isinstance(data[header], (int, long, float)):
                    csvrow.append(str(data[header]))
                else:
                    if data[header] is None:
                        csvrow.append("")
                    else:
                        mydata = str(data[header].encode('utf-8'))
                        csvrow.append(mydata)

            csvdata.writerow(csvrow)

        return csvout.getvalue()

    def keyval(self):

        # empty data
        if len(self._data) <= 0:
            return None

        keyval_data = []

        # rows
        for data in self._data:
            data_list = []
            for header in self.data_structure:
                if header not in data.keys() or data[header] is None:
                    edata = '%s=""' % header
                    data_list.append(edata)
                elif isinstance(data[header], list):
                    """
                    handle nested list
                    """
                    if len(data[header]) == 0:
                        ddata = '%s=""' % header
                        data_list.append(ddata)
                        continue

                    for item in data[header]:
                        """
                        handle nested dict
                        """
                        if isinstance(item, dict):
                            for dkey, dval in item.iteritems():
                                ddata = '%s_%s="%s"' % (header, dkey, dval)
                                data_list.append(ddata)

                elif isinstance(data[header], dict):
                    """
                    handle nested dict
                    """
                    if len(data[header]) == 0:
                        ddata = '%s=""' % header
                        data_list.append(ddata)
                        continue

                    for dkey, dval in data[header].iteritems():
                        ddata = '%s_%s="%s"' % (header, dkey, dval)
                        data_list.append(ddata)
                elif isinstance(data[header], (int, long, float)):
                    edata = '%s="%s"' % (header, data[header])
                    data_list.append(edata)
                else:
                    edata = '%s="%s"' % (header, str(data[header].encode('utf-8')).replace('"', '\\"'))
                    data_list.append(edata)

            keyval_data.append(" ".join(data_list))

        return "\n".join(keyval_data)

    def data(self):
        return self._data

    def dateAdded_list(self):
        for data in self._data:
            if 'dateAdded' in data.keys():
                self._dateAdded_list.append(data['dateAdded'])

        return self._dateAdded_list

    def eventDate_list(self):
        for data in self._data:
            if 'eventDate' in data.keys():
                self._eventDate_list.append(data['eventDate'])

        return self._eventDate_list

    def fileName_list(self):
        for data in self._data:
            if 'fileName' in data.keys():
                self._fileName_list.append(data['fileName'])

        return self._fileName_list

    def fileType_list(self):
        for data in self._data:
            if 'fileType' in data.keys():
                self._fileType_list.append(data['fileType'])

        return self._fileType_list

    def from_list(self):
        for data in self._data:
            if 'from' in data.keys():
                self._from_list.append(data['from'])

        return self._from_list

    def header_list(self):
        for data in self._data:
            if 'header' in data.keys():
                self._header_list.append(data['header'])

        return self._header_list

    def id_list(self):
        for data in self._data:
            if 'id' in data.keys():
                self._id_list.append(data['id'])

        return self._id_list

    def json(self):
        return json.dumps(self._data)

    def lastModified_list(self):
        for data in self._data:
            if 'lastModified' in data.keys():
                self._lastModified_list.append(data['lastModified'])

        return self._lastModified_list

    def name_list(self):
        for data in self._data:
            if 'name' in data.keys():
                self._name_list.append(data['name'])

        return self._name_list

    def owner_list(self):
        for data in self._data:
            if 'owner' in data.keys():
                self._owner_list.append(data['owner'])

        return self._owner_list

    def ownerName_list(self):
        for data in self._data:
            if 'ownerName' in data.keys():
                self._ownerName_list.append(data['ownerName'])

        return self._ownerName_list

    def score_list(self):
        for data in self._data:
            if 'score' in data.keys():
                self._score_list.append(data['score'])

        return self._score_list

    def subject_list(self):
        for data in self._data:
            if 'subject' in data.keys():
                self._subject_list.append(data['subject'])

        return self._subject_list

    def type_list(self):
        for data in self._data:
            if 'type' in data.keys():
                self._type_list.append(data['type'])

        return self._type_list

    def value_list(self):
        for data in self._data:
            if 'value' in data.keys():
                self._value_list.append(data['value'])

        return self._value_list

    def webLink_list(self):
        for data in self._data:
            if 'webLink' in data.keys():
                self._webLink_list.append(data['webLink'])

        return self._webLink_list


class AdversaryData(ResultData):
    """Adversary Data

    * single result structure
    u'adversary': {
        u'dateAdded': u'2014-05-30T15:08:24Z',
        u'id': 76308,
        u'name': u'joinr0ot',
        u'owner': {
            u'id': 689,
            u'name': u'Subscriber Community',
            u'type': u'Community'},
        u'webLink': u'https://app.threatconnect.com/tc/auth/adversary/
            adversary.xhtml?adversary=76308'}

    * multiple result structure
    u'adversary': [{
        u'dateAdded': u'2013-12-17T21:33:58Z',
        u'id': 47328,
        u'name': u'Adversary Name',
        u'ownerName': u'Acme Corp',
        u'webLink': u'https://app.threatconnect.com/tc/auth/adversary/adversary.xhtml?adversary=47328'}

    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []


class AttributeData(ResultData):
    """Attribute Data

    u'attribute': [{
        u'dateAdded': u'2013-12-13T21:22:15Z',
        u'id': 2120,
        u'type': u'Description',
        u'value': u'test'}],
    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []
        
class FileOccurrenceData(ResultData):
    """
    
    "fileOccurrence" : [ {
      "id" : 8211,
      "fileName" : "test.dll",
      "path" : "C:\\Windows",
      "date" : "2014-11-09T19:00:00-05:00"}]
    """
    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []

class EmailData(ResultData):
    """Email Data

    * single result structure
    u'email': {
        u'body': u"By Sarah Serizawa\r\nAugust 2, 2012\r\<truncated>
        u'dateAdded': u'2013-11-14T20:35:24Z',
        u'from': u'nbr@nbr.org',
        u'header': u'Delivered-To: defense@contractor.us\r\nReceived: by 10.58.179.69 with SMTP id de5csp35632vec; Fri, 3 Aug 2012 07:34:12 -0700 (PDT)\r\nReceived: by 10.42.114.4 with SMTP id e4mr3030874icq.25.1344004450779; Fri, 03 Aug 2012 07:34:10 -0700 (PDT)\r\nReturn-Path: <nbr@nbr.org>\r\nReceived: from nbr.org ([64.71.190.46]) by mx.google.com with ESMTP id vy3si17927985igb.22.2012.08.03.07.34.08;        Fri, 03 Aug 2012 07:34:10 -0700 (PDT)\r\nReceived-SPF: softfail (google.com: domain of transitioning nbr@nbr.org does not designate 64.71.190.46 as permitted sender) client-ip=64.71.190.46;\r\nAuthentication-Results: mx.google.com; spf=softfail (google.com: domain of transitioning nbr@nbr.org does not designate 64.71.190.46 as permitted sender) smtp.mail=nbr@nbr.org\r\nMessage-Id: <501be162.c39b320a.1c98.ffffe2c8SMTPIN_ADDED@mx.google.com>\r\nFrom: "The National Bureau of Asian Research (NBR)" <nbr@nbr.org>\r\nSubject: China\'s Military Modernization and Implications for Northeast Asia\r\nTo: defense@contractor.us; civilian@agency.us\r\nContent-Type: multipart/mixed; boundary="=_NextPart_2rfkindysadvnqw3nerasdf";charset="US-ASCII"\r\nMIME-Version: 1.0\r\nReply-To: nbr@nbr.org\r\nDate: Fri, 3 Aug 2012 22:28:55 +0800\r\nX-Priority: 3\r\nX-Mailer: Microsoft Outlook Express 5.00.2615.200\r\n\r\n\r\nTel. +1 206.632.7370\r\nFax: +1 206.632.7487\r\nnbr@nbr.org',
        u'id': 45621,
        u'name': u"China's Military Modernization and Implications for Northeast Asia",
        u'owner': {
            u'id': 665,
            u'name': u'Acme Corp',
            u'type': u'Organization'},
        u'score': 1390,
        u'subject': u"China's Military Modernization and Implications for Northeast Asia",
        u'webLink': u'https://app.threatconnect.com/tc/auth/email/email.xhtml?email=45621'}

    * multiple result structure
    u'email': [{
        u'dateAdded': u'2013-11-14T20:35:24Z',
        u'id': 45621,
        u'name': u"China's Military Modernization and Implications for Northeast Asia",
        u'ownerName': u'Acme Corp',
        u'score': 1390,
        u'webLink': u'https://app.threatconnect.com/tc/auth/email/email.xhtml?email=45621'},

    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []


class GroupData(ResultData):
    """Group Data

    * multiple result structure
    u'group': [{
        u'dateAdded': u'2013-12-17T21:33:58Z',
        u'id': 47328,
        u'name': u'Adversary Name',
        u'ownerName': u'Acme Corp',
        u'type': u'Adversary',
        u'webLink': u'https://app.threatconnect.com/tc/auth/adversary/
            adversary.xhtml?adversary=47328'}

    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []


class IncidentData(ResultData):
    """Incident Data

    * single result structure
    u'incident': {
        u'dateAdded': u'2013-11-23T05:17:45Z',
        u'eventDate': u'2012-12-25T00:00:00Z',
        u'id': 46011,
        u'name': u'20121225A: Zegost',
        u'owner': {
            u'id': 631,
            u'name': u'Common Community',
            u'type': u'Community'},
        u'webLink': u'https://app.threatconnect.com/tc/auth/incident/
            incident.xhtml?incident=46011'}}

    * multiple result structure
    u'incident': [{
        u'dateAdded': u'2014-01-05T17:17:48Z',
        u'eventDate': u'2013-01-30T00:00:00Z',
        u'id': 48411,
        u'name': u'201301012A:Bit9',
        u'ownerName': u'Acme Corp',
        u'webLink': u'https://app.threatconnect.com/tc/auth/incident/incident.xhtml?incident=4841

    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []


class OwnerData(ResultData):
    """Owner Data

    u'owner': [{
        u'id': 665,
        u'name': u'Acme Corp',
        u'type': u'Organization'}
    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []

class SecurityLabelData(ResultData):
    """SecurityLabel Data

    u'securityLabel': [{
        u'name' : u'Example Label',
        u'description' : u'Label means this',
        u'dateAdded' : '2014-11-07T13:41:52-05:00'
    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []

class SignatureData(ResultData):
    """Signature Data

    * single result structure
    u'signature': {
        u'dateAdded': u'2014-07-24T21:25:35Z',
        u'fileName': u'20131217B.yara',
        u'fileType': u'YARA',
        u'id': 86086,
        u'name': u'Ash_Yara',
        u'owner': {
            u'id': 1626,
            u'name': u'Test Community',
            u'type': u'Community'},
        u'webLink': u'https://app.threatconnect.com/tc/auth/signature/
            signature.xhtml?signature=86086'}

    * multiple result structure
    u'signature': [{
        u'dateAdded': u'2013-12-08T20:43:31Z',
        u'fileType': u'YARA',
        u'id': 46350,
        u'name': u'APT1_hkcmd_SMAgent',
        u'ownerName': u'Acme Corp',
        u'webLink': u'https://app.threatconnect.com/tc/auth/signature/
            signature.xhtml?signature=46350'},
    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []
        
class SignatureDownload(ResultData):
    """Signature Data

    * single result structure
    u'signature': {
        u'dateAdded': u'2014-07-24T21:25:35Z',
        u'fileName': u'20131217B.yara',
        u'fileType': u'YARA',
        u'id': 86086,
        u'name': u'Ash_Yara',
        u'owner': {
            u'id': 1626,
            u'name': u'Test Community',
            u'type': u'Community'},
        u'webLink': u'https://app.threatconnect.com/tc/auth/signature/
            signature.xhtml?signature=86086'}

    * multiple result structure
    u'signature': [{
        u'dateAdded': u'2013-12-08T20:43:31Z',
        u'fileType': u'YARA',
        u'id': 46350,
        u'name': u'APT1_hkcmd_SMAgent',
        u'ownerName': u'Acme Corp',
        u'webLink': u'https://app.threatconnect.com/tc/auth/signature/
            signature.xhtml?signature=46350'},
    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []


class TagData(ResultData):
    """Tag Data

    u'tag': {
        u'name': u'adam',
        u'webLink': u'https://app.threatconnect.com/tc/auth/tags/tag.xhtml
            ?tag=adam&owner=Acme Corp'}
    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []


class ThreatData(ResultData):
    """Threat Data

    * single result structure
    u'threat': {
        u'dateAdded': u'2014-07-23T16:03:12Z',
        u'id': 85526,
        u'name': u'Whao.exe',
        u'owner': {
            u'id': 1626,
            u'name': u'Test Community',
            u'type': u'Community'},
        u'webLink': u'https://app.threatconnect.com/tc/auth/threat/
            threat.xhtml?threat=85526'}},

    * multiple result structure
    u'threat': [{
        u'dateAdded': u'2014-03-05T13:19:57Z',
        u'id': 63359,
        u'name': u'2104-03-05:Threat',
        u'ownerName': u'Acme Corp',
        u'webLink': u'https://app.threatconnect.com/tc/auth/threat/threat.xhtml?threat=63359'},

    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []


class VictimData(ResultData):
    """Victim Data
         "victim" : {
          "id" : 543,
          "name" : "Jon Q Doe",
          "org" : "Payroll",
          "suborg" : "Disbursements",
          "workLocation" : "Seattle, WA",
          "nationality" : "American",
          "webLink" : "https://app.threatconnect.com/tc/auth/victim/victim.xhtml?victim=543"
        }
    """
    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []
        
class VictimAssetData(ResultData):
    """VictimAsset Data
     "victimAsset" : [ {
          "id" : 739,
          "name" : "johnqdoe@viccorp.org",
          "type" : "EmailAddress",
          "webLink" : "https://app.threatconnect.com/tc/auth/victim/victim.xhtml?victim=543"
        }, 
    """
    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []
        
class VictimEmailAddressData(ResultData):
    """VictimAsset Data
     "victimEmailAddress" : {
          "id" : 739,
          "type" : "EmailAddress",
          "webLink" : "https://app.threatconnect.com/tc/auth/victim/victim.xhtml?victim=543",
          "address" : "johnqdoe@viccorp.org",
          "addressType" : "work"
        }

    """
    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._data = []
        
class IndicatorData(ResultData):
    """Indicator Data

    * multiple result structure
    u'indicator': [{
        u'dateAdded': u'2014-08-09T11:23:26Z',
        u'id': 241482,
        u'lastModified': u'2014-08-09T11:23:26Z',
        u'ownerName': u'Acme Corp',
        u'summary': u'115.162.65.54',
        u'type': u'Address',
        u'webLink': u'https://app.threatconnect.com/tc/auth/indicators/details/
            address.xhtml?address=115.162.65.54&owner=Acme+Corp'},

    """

    def __init__(self, data_structure):
        ResultData.__init__(self, data_structure)
        self._address_list = []
        self._confidence_list = []
        self._description_list = []
        self._dnsActive_list = []
        self._fileOccurence_list = []
        self._hostName_list = []
        self._ip_list = []
        self._lastModified_list = []
        self._md5_list = []
        self._sha1_list = []
        self._sha256_list = []
        self._rating_list = []
        self._source_list = []
        self._summary_list = []
        self._text_list = []
        self._whoisActive_list = []

    def address_list(self):
        for data in self._data:
            if 'address' in data.keys():
                self._address_list.append(data['address'])

        return self._address_list

    def confidence_list(self):
        for data in self._data:
            if 'confidence' in data.keys():
                self._confidence_list.append(data['confidence'])

        return self._confidence_list

    def description_list(self):
        for data in self._data:
            if 'description' in data.keys():
                self._description_list.append(data['description'])

        return self._description_list

    def dnsActive_list(self):
        for data in self._data:
            if 'dnsActive' in data.keys():
                self._dnsActive_list.append(data['dnsActive'])

        return self._dnsActive_list

    #todo, this no longer works
    def fileOccurence_list(self):
        for data in self._data:
            if 'fileOccurence' in data.keys():
                self._fileOccurence_list.append(data['fileOccurence'])

        return self._fileOccurence_list

    def hostName_list(self):
        for data in self._data:
            if 'hostName' in data.keys():
                self._hostName_list.append(data['hostName'])

        return self._hostName_list

    def ip_list(self):
        for data in self._data:
            if 'ip' in data.keys():
                self._ip_list.append(data['ip'])

        return self._ip_list

    def lastModified_list(self):
        for data in self._data:
            if 'lastModified' in data.keys():
                self._lastModified_list.append(data['lastModified'])

        return self._lastModified_list

    def md5_list(self):
        for data in self._data:
            if 'md5' in data.keys():
                self._md5_list.append(data['md5'])

        return self._md5_list

    def sha1_list(self):
        for data in self._data:
            if 'sha1' in data.keys():
                self._sha1_list.append(data['sha1'])

        return self._sha1_list

    def sha256_list(self):
        for data in self._data:
            if 'sha256' in data.keys():
                self._sha256_list.append(data['sha256'])

        return self._sha256_list

    def rating_list(self):
        for data in self._data:
            if 'rating' in data.keys():
                self._rating_list.append(data['rating'])

        return self._rating_list

    def source_list(self):
        for data in self._data:
            if 'source' in data.keys():
                self._source_list.append(data['source'])

        return self._source_list

    def summary_list(self):
        for data in self._data:
            if 'summary' in data.keys():
                self._summary_list.append(data['summary'])

        return self._summary_list

    def text_list(self):
        for data in self._data:
            if 'text' in data.keys():
                self._text_list.append(data['text'])

        return self._text_list

    def whoisActive_list(self):
        for data in self._data:
            if 'whoisActive' in data.keys():
                self._whoisActive_list.append(data['whoisActive'])

        return self._whoisActive_list


class AddressIndicatorData(IndicatorData):
    """Address Indicator Data

    * single result structure
    indicator': [{
        u'confidence': 0,
        u'dateAdded': u'2014-08-13T15:01:36Z',
        u'id': 271218,
        u'lastModified': u'2014-08-13T19:46:36Z',
        u'ownerName': u'Acme Corp',
        u'rating': 4.0,
        u'summary': u'50.63.202.73',
        u'type': u'Address',
        u'webLink': u'https://app.threatconnect.com/tc/auth/indicators/
            details/address.xhtml?address=50.63.202.73&owner=Acme+Corp'},
    """

    def __init__(self, data_structure):
        IndicatorData.__init__(self, data_structure)


class HostIndicatorData(IndicatorData):
    """Host Indicator Data

    * single result structure
    u'host': {
        u'confidence': 62,
        u'dateAdded': u'2013-09-11T19:35:48Z',
        u'description': u'test',
        u'dnsActive': u'true',
        u'hostName': u'mail.gxdet.com',
        u'id': 90515,
        u'lastModified': u'2013-09-11T19:35:48Z',
        u'owner': {
            u'id': 665,
            u'name': u'Acme Corp',
            u'type': u'Organization'},
        u'rating': 3.0,
        u'source': u'report source',
        u'webLink': u'https://app.threatconnect.com/tc/auth/indicators/details/
            host.xhtml?host=mail.gxdet.com&owner=Acme+Corp',
        u'whoisActive': u'true'}
    """

    def __init__(self, data_structure):
        IndicatorData.__init__(self, data_structure)


class EmailIndicatorData(IndicatorData):
    """Email Indicator Data

    * single result structure
    u'emailAddress': {
        u'address': u'shen.tienhao@tecro.us',
        u'confidence': 100,
        u'dateAdded': u'2014-01-28T19:32:05Z',
        u'description': u'Malicious spearphishing email address impersonating
            an account from the Taipei Economic and Cultural Representative
            Office (TECRO).',
        u'id': 153710,
        u'lastModified': None,
        u'owner': {
            u'id': 689,
            u'name': u'Subscriber Community',
            u'type': u'Community'},
        u'rating': 5.0,
        u'source': u'ThreatConnect Intelligence Research Team Partner Tipper',
        u'webLink': u'https://app.threatconnect.com/tc/auth/indicators/details/
            emailaddress.xhtml?emailaddress=shen.tienhao%40tecro.us&owner=
            Subscriber+Community'}}
    """

    def __init__(self, data_structure):
        IndicatorData.__init__(self, data_structure)


class FileIndicatorData(IndicatorData):
    """File Indicator Data

    * single result structure
    u'file': {
        u'dateAdded': u'2013-09-02T15:08:39Z',
        u'fileOccurence': [],
        u'id': 87606,
        u'lastModified': u'2013-09-02T15:08:39Z',
        u'md5': u'ABC87739E816DCB2D8D33AABFAADC6A7',
        u"sha1" : "0000C7967DD11AB20805EA04E6706B33FE13AD4F",
        u"sha256" : "000E8B5CF5FA80F1087FE2620372EC3E31B63515B32A7F89DB87B2F6B8F5ED40",
        u'owner': {
            u'id': 665,
            u'name': u'Acme Corp',
            u'type': u'Organization'},
        u'webLink': u'https://app.threatconnect.com/tc/auth/indicators/details/
            file.xhtml?file=ABC87739E816DCB2D8D33AABFAADC6A7&owner=Acme+Corp'}
    """

    def __init__(self, data_structure):
        IndicatorData.__init__(self, data_structure)


class UrlIndicatorData(IndicatorData):
    """URL Indicator Data

    * single result structure
    u'url': [{
        u'confidence': 52,
        u'dateAdded': u'2014-07-28T18:36:28Z',
        u'id': 238498,
        u'lastModified': u'2014-07-28T18:36:28Z',
        u'ownerName': u'Acme Corp',
        u'rating': 3.0,
        u'text': u'http://mirefocus.com/kb2484033.exe',
        u'webLink': u'https://app.threatconnect.com/tc/auth/indicators/details/url.xhtml?orgid=238498'},
    """

    def __init__(self, data_structure):
        IndicatorData.__init__(self, data_structure)
