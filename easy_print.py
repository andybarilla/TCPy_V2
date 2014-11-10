import pprint


def easy_print(name, data):
    # border character
    border_char = "#"

    # print formatted name
    print border_char * (len(name) + 4)
    print "%s %s %s" % (border_char, name, border_char)
    print border_char * (len(name) + 4)

    if isinstance(data, list):
        pprint.pprint(data)
    elif isinstance(data, dict):
        pprint.pprint(data)
    else:
        print "%s" % data

    print "\n"
