from easy_print import *
from working_init import *


def main():
    """
    Working With Threats

    """

    # optionally set max results
    tc.set_max_results("500")

    """
    Get Threat by ID

    Method:
    get_threat_by_id(id)
      id -> threat id #

    Use this method to return a single threat result by passing
    an threat id.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get threat by id
        threat_id = 85526
        results = tc.get_threat_by_id(threat_id)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Success":

            # get indicator keys for data type
            data_methods = ["%s_list" % item for item in results.data().data_structure]

            # get data object
            results_data = results.data()

            # loop through all data methods
            for meth in data_methods:
                easy_print(meth, getattr(results_data, meth)())

            # count (int)
            easy_print('count', results_data.count())

            # json (string)
            easy_print('json', results_data.json())

            # csv (string)
            easy_print('csv', results_data.csv())

            # keyval (string)
            easy_print('keyval', results_data.keyval())

    """
    Get Threats

    Method:
    get_threats(owners=<list of owners>)
      owners -> (optional) list of owners

    Use this method to return threat results.  A list of owners can be
    optionally provided.  If no owners are provided the default owner
    organization is automatically used.

    The "tc.get_owners()" function can be used to get a list of owners.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get all threats for default owner
        tc.set_max_results("50")  # optionally override default max results
        results = tc.get_threats()

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Success":

            # get indicator keys for data type
            data_methods = ["%s_list" % item for item in results.data().data_structure]

            # get data object
            results_data = results.data()

            # loop through all data methods
            for meth in data_methods:
                easy_print(meth, getattr(results_data, meth)())

            # count (int)
            easy_print('count', results_data.count())

            # json (string)
            easy_print('json', results_data.json())

            # csv (string)
            easy_print('csv', results_data.csv())

            # keyval (string)
            easy_print('keyval', results_data.keyval())

    if False:
        # get all threats for all owner
        tc.set_max_results("100")  # optionally override default max results
        requested_owners = tc.get_owners().data().name_list()
        results = tc.get_threats(requested_owners)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Success":

            # get indicator keys for data type
            data_methods = ["%s_list" % item for item in results.data().data_structure]

            # get data object
            results_data = results.data()

            # loop through all data methods
            for meth in data_methods:
                easy_print(meth, getattr(results_data, meth)())

            # count (int)
            easy_print('count', results_data.count())

            # json (string)
            easy_print('json', results_data.json())

            # csv (string)
            easy_print('csv', results_data.csv())

            # keyval (string)
            easy_print('keyval', results_data.keyval())

    """
    Get Threats by Indicator

    Method:
    get_threats_by_indicator(indicator, indicator_type=None, owners=[]):
      indicator -> any indicator
      indicator_type -> (optional) indicator type
      owners -> (optional) list of owners

    Use this method to return threats by a user provided indicator.
    Optionally provide the indicator type.  If no indicator type is provided
    the indicator type will be automatically determined.  A list of owners can
    be optionally provided. If no owners are provided the default owner
    organization is used.

    The "tc.get_owners()" function can be used to get a list of owners.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get groups by threats for default owner
        indicator = "218.65.4.171"
        results = tc.get_threats_by_indicator(indicator)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Success":

            # get indicator keys for data type
            data_methods = ["%s_list" % item for item in results.data().data_structure]

            # get data object
            results_data = results.data()

            # loop through all data methods
            for meth in data_methods:
                easy_print(meth, getattr(results_data, meth)())

            # count (int)
            easy_print('count', results_data.count())

            # json (string)
            easy_print('json', results_data.json())

            # csv (string)
            easy_print('csv', results_data.csv())

            # keyval (string)
            easy_print('keyval', results_data.keyval())

    if False:
        # get groups by threats for all owners
        indicator = "218.65.4.171"
        requested_owners = tc.get_owners().data().name_list()
        results = tc.get_threats_by_indicator(indicator, owners=requested_owners)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Success":

            # get indicator keys for data type
            data_methods = ["%s_list" % item for item in results.data().data_structure]

            # get data object
            results_data = results.data()

            # loop through all data methods
            for meth in data_methods:
                easy_print(meth, getattr(results_data, meth)())

            # count (int)
            easy_print('count', results_data.count())

            # json (string)
            easy_print('json', results_data.json())

            # csv (string)
            easy_print('csv', results_data.csv())

            # keyval (string)
            easy_print('keyval', results_data.keyval())

    """
    Get Threats by Tag

    Method:
    get_threats_by_tag(tag_name, owners=[]):
      tag_name -> a tag name
      owners -> (optional) list of owners

    Use this method to return threats by a user provided tag name. A
    list of owners can be optionally provided. If no owners are provided
    the default owner organization is used.

    The "tc.get_owners()" function can be used to get a list of owners.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get threats by tag for default owner
        tag = "adam"
        results = tc.get_threats_by_tag(tag)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Success":

            # get indicator keys for data type
            data_methods = ["%s_list" % item for item in results.data().data_structure]

            # get data object
            results_data = results.data()

            # loop through all data methods
            for meth in data_methods:
                easy_print(meth, getattr(results_data, meth)())

            # count (int)
            easy_print('count', results_data.count())

            # json (string)
            easy_print('json', results_data.json())

            # csv (string)
            easy_print('csv', results_data.csv())

            # keyval (string)
            easy_print('keyval', results_data.keyval())

    if False:
        # get threats by tag for all owners
        tag = "Advanced Persistent Threat"
        requested_owners = tc.get_owners().data().name_list()
        results = tc.get_threats_by_tag(tag, requested_owners)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Success":

            # get indicator keys for data type
            data_methods = ["%s_list" % item for item in results.data().data_structure]

            # get data object
            results_data = results.data()

            # loop through all data methods
            for meth in data_methods:
                easy_print(meth, getattr(results_data, meth)())

            # count (int)
            easy_print('count', results_data.count())

            # json (string)
            easy_print('json', results_data.json())

            # csv (string)
            easy_print('csv', results_data.csv())

            # keyval (string)
            easy_print('keyval', results_data.keyval())


if __name__ == "__main__":
    main()
