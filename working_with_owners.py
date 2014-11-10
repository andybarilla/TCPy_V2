from easy_print import *
from working_init import *


def main():
    """
    Working With Owners

    """

    # optionally set max results
    tc.set_max_results("500")

    """
    Get Owners

    Method:
    get_owners()

    Use this method to return all owners.

    The "tc.get_owners()" function can be used to get a list of owners.

    To run sample code change the "False" value to "True"

    """
    if True:
        # get all owners
        results = tc.get_owners()

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
    Get Owners by Indicator

    Method:
    get_owners_by_indicator(indicator, indicator_type=None, owners=[]):
      indicator -> any indicator
      indicator_type -> (optional) indicator type
      owners -> (optional) list of owners

    Use this method to return owners by a user provided indicator.
    Optionally provide the indicator type.  If no indicator type is provided
    the indicator type will be automatically determined.  A list of owners can
    be optionally provided. If no owners are provided the default owner
    organization is used.

    The "tc.get_owners()" function can be used to get a list of owners.

    To run sample code change the "False" value to "True"

    """

    if False:
        # find owner for indicator
        indicator = '218.65.4.171'
        results = tc.get_owners_by_indicator(indicator)

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
        # find owner for indicator
        indicator = '1.2.3.4'
        results = tc.get_owners_by_indicator(indicator)

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
        # find indicator with wrong indicator type
        # result data should be empty
        indicator = '1.2.3.4'
        indicator_type = 'files'
        results = tc.get_owners_by_indicator(indicator, indicator_type)

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
        # failure test
        # good indicator with bad type
        indicator = '1.2.3.4'
        indicator_type = 'addressX'
        results = tc.get_owners_by_indicator(indicator, indicator_type)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Failure":
            easy_print('Error Message', results.error_message_list())

    if False:
        # bad indicator with bad type
        indicator = 'X.2.3.4'
        indicator_type = 'addressX'
        results = tc.get_owners_by_indicator(indicator, indicator_type)

        # Request Status (string)
        easy_print('Request Status', results.status())

        # Request URIs (list)
        easy_print('Request URIs', results.uris())

        # Response Count (int)
        easy_print('Response Count', results.count())

        # API Response (dict)
        easy_print('API Response', results.api_response())

        if results.status() == "Failure":
            easy_print('Error Message', results.error_message_list())


if __name__ == "__main__":
    main()
