TCPy_V2
=========================

TCPy_V2 is a Python implementation of the ThreatConnect V2 API.  It will allow you to instantiate an object to retrieve data from ThreatConnect, as well as put data into ThreatConnect.  Please note that this is an extension of the [V1 Python Client](https://github.com/Cyber-Squared-Inc/ThreatConnectPythonClient), and uses similar syntax and naming conventions.  However, some things have been changed to reflect certain enhancements made to the V2 API.

Requirements
------
The ThreatConnectPythonClient requires Python 2.7, and the [Requests module](http://docs.python-requests.org/en/latest/).  It will also require a set of API credentials with a ThreatConnect instance.

Configuration
-----
The ThreatConnectPythonClient contains two important files:
  1.  ```tc.conf``` contains the configuration for your API Access ID and Secret Key, as well as your Organization and ThreatConnect instance you'd like to access.
  2.  ```ThreatConnect/_config.py``` contains the paths of your API resources (e.g. "/v2/owners").  If your ThreatConnect instance contains something else in the path (e.g. "/api/v2/owners") you will need to update these paths in this file.  
  3.  ```ThreatConnect/_config.py``` also contains a field that specifies whether or not the request module should enforce SSL certificate validation.  If you are using an invalid or self-signed certificate (which should only be for on-premise deployments) then you will want to set ```verify_ssl_certs``` to ```False``` instead of its default value of ```True```.
  
Instantiation
-----
To instantiate the ThreatConnectPythonClient, simply load the ```working_init``` module in the root directory (i.e. alongside ```working_init.py```.  For example:

```
from working_init import *

results = tc.get_indicators()

if results.status() == "Success":
  print "{} Indicators retrieved.".format(results.count())
```

Usage
-----
The usage for ThreatConnectPythonClient varies depending on what you're trying to accomplish.  You can query for indicators and groups, you can filter by rating and confidence, and you can also retrieve tags and conduct pivots programmatically.  The TCPy_V2 client also allows you to create indicators.

For examples of "read" functionality, you can use the same syntax and functions that you would use from the V1 client.  These are documented in the `working_with` files, such as the following excerpt from the `working_with_indicators.py` file:
```
  tc.add_filter('rating', '>', '4', False)
  tc.add_filter('confidence', '>', '25')

  # get all indicators by user defined indicator type for default owner
  tc.set_max_results("350")  # optionally override default max results
  indicator_type = 'addresses'
  results = tc.get_indicators(indicator_type=indicator_type)
```

For examples of "write" functionality, please see the `v2_examples.py` file.  It contains examples of the supported V2 "write" functionality, to include the following excerpt which creates a Host indicator and applies the tag "test indicator tag":
```
host = "testhost-%d-%d.net" % (randint(1,1000), randint(1,1000))
results = tc.create_host(host)
tag_name = "test indicator tag"
results = tc.add_tag_to_indicator("hosts", host, tag_name)
```

**Note:** The example scripts contain a variety of code samples segmented into blocks by "If" statements.  This allows you to test specific segments of code with some degree fo granularity.  These If statements are all set by default to `if False` and must be toggled on individually by changing the respective line to `if True`.

Contact
-----
If you have any questions, bugs, or requests please contact support@threatconnect.com
