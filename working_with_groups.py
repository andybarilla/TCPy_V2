from easy_print import *
from working_init import *


def main():
    """
    Working With Groups

    """

    # optionally set max results
    tc.set_max_results("500")

    """
    Get Group Attributes

    Method:
    get_group_attributes(group_type, group_id):
      group_type -> predefined group type
      group_id -> predefined group id

    Use this method to return a groups attributes using user provided group type
    and group id.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get group attributes
        tc.set_max_results("100")  # optionally override default max results
        group_type = "signatures"
        group_id = "47259"
        results = tc.get_group_attributes(group_type, group_id)

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
    Get Groups

    Method:
    get_groups(owners=<list of owners>)
      owners -> (optional) list of owners

    Use this method to return group data. A list of owners can be optionally
    provided. If no owners are provided the default owner organization is
    automatically used.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get all groups for default owner
        tc.set_max_results("5")  # optionally override default max results
        results = tc.get_groups()

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
        # get all groups for all owner
        tc.set_max_results("500")  # optionally override default max results
        requested_owners = tc.get_owners().data().name_list()
        results = tc.get_groups(requested_owners)

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
    Get Groups by Indicator

    Method:
    get_groups_by_indicator(indicator, indicator_type=None, owners=[]:
      indicator -> any indicator
      indicator_type -> (optional) indicator type
      owners -> (optional) list of owners

    Use this method to return groups by a user provided indicator. Optionally
    provide the indicator type.  If no indicator type is provided the indicator
    type will be automatically determined.  A list of owners can be optionally
    provided. If no owners are provided the default owner organization is used.

    The "tc.get_owners()" function can be used to get a list of owners.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get groups by indicator for default owner
        indicator = "218.65.4.171"
        results = tc.get_groups_by_indicator(indicator)

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
        # get groups by indicator for all owners
        indicator = "218.65.4.171"
        requested_owners = tc.get_owners().data().name_list()
        results = tc.get_groups_by_indicator(indicator, owners=requested_owners)

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
    Get Groups by Tag

    Method:
    get_groups_by_tag(tag_name, owners=[]):
      tag_name -> a tag name
      owners -> (optional) list of owners

    Use this method to return groups by a user provided tag name. A
    list of owners can be optionally provided. If no owners are provided
    the default owner organization is used.

    The "tc.get_owners()" function can be used to get a list of owners.

    To run sample code change the "False" value to "True"

    """

    if False:
        # get groups by tag for default owner
        tag = "adam"
        results = tc.get_groups_by_tag(tag)

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
        # get groups by tag for all owners
        tag = "Advanced Persistent Threat"
        requested_owners = tc.get_owners().data().name_list()
        results = tc.get_groups_by_tag(tag, requested_owners)

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
