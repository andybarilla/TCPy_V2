from easy_print import *
from working_init import *
from random import randint
import hashlib
import json

def main():
    # optionally set max results
    tc.set_max_results("500")

    """
    To run sample code change the "False" value to "True"

    """

    # Create IP address indicator
    if False:
        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))

        results = tc.create_address(ip, rating="5.0", confidence=50)
        printout(results)

    # Create Email Address indicator
    if False:
        email = "testemail_%d_%d@test.net" % (randint(1,1000), randint(1,1000))

        results = tc.create_emailAddress(email, rating="3.0", confidence=85)
        printout(results)

    # Create Host indicator
    if False:
        host = "testhost-%d-%d.net" % (randint(1,1000), randint(1,1000))
        results = tc.create_host(host, rating="1.0", confidence=25)
        printout(results)

    # Create URL indicator
    if False:
        url = "https://badguy.net/%d/ok.php?id=%d" % (randint(1,1000), randint(1,1000))
        results = tc.create_url(url, rating="4.0", confidence=44)
        printout(results)

    # Create File indicator
    # NOTE: you cannot resolve associations as you can in the GUI (no linking/unlinking
    #       hashes, no adding a hash if it's already linked to other hashes)
    if False:
        randval = str(randint(1,10000000000))
        md5 = hashlib.md5()
        md5.update(randval)
        md5_hash = md5.hexdigest()

        sha1 = hashlib.sha1()
        sha1.update(randval)
        sha1_hash = sha1.hexdigest()

        sha256 = hashlib.sha256()
        sha256.update(randval)
        sha256_hash = sha256.hexdigest()

        hashes = {'md5' : md5_hash, 'sha1':sha1_hash, 'sha256':sha256_hash}
        results = tc.create_file(hashes, rating="2.0", confidence=22)
        printout(results)

    # Create adversary group
    if False:
        adversary_name = "Test Adversary %d" % randint(1,1000000)
        results = tc.create_adversary(adversary_name)
        printout(results)

    # Create email
    if False:
        name = "Test email %d" % randint(1,1000000)
        to = "toguy@victim.com"
        fromField = "badguy@evil.org"
        subject = "Phishing attempt message"
        header = """Delivered-To: MrSmith@gmail.com
Received: by 10.36.81.3 with SMTP id e3cs239nzb; Tue, 29 Mar 2005 15:11:47 -0800 (PST)
Return-Path: 
Received: from mail.emailprovider.com (mail.emailprovider.com [111.111.11.111]) by mx.gmail.com with SMTP id h19si826631rnb.2005.03.29.15.11.46; Tue, 29 Mar 2005 15:11:47 -0800 (PST)
Message-ID: <20050329231145.62086.mail@mail.emailprovider.com>
Received: from [11.11.111.111] by mail.emailprovider.com via HTTP; Tue, 29 Mar 2005 15:11:45 PST
Date: Tue, 29 Mar 2005 15:11:45 -0800 (PST)
From: Mr Jones 
Subject: Hello
To: Mr Smith """
        body = "Hello mr victim, open my link buddy"

        results = tc.create_email(name, fromField, subject, header, body, toField=to)
        if results.status() == "Success":
            print "Email created successfully"
        else:
            print results.error_message_list()

        # Note that the results contain the newly-created email!
        new_email = results.single_result()
        results = tc.update_email(new_email['id'], "Updated email", "newfrom@bad.com", "newsubject", header=None, emailBody="new body")
        if results.status() == "Success":
            print "Email updated successfully"
        else:
            print results.error_message_list()

    # Create test incident
    if False:
        incident_name = "Test Incident %d" % randint(1,1000000000)
        date = "2014-06-08T00:00:00-04:00"
        results = tc.create_incident(incident_name, date)
        printout(results)

    # Create signature
    if False:
        signame = "Test signature %d" % randint(1,1000000)
        sigtype = "YARA"
        sigtext = """rule silent_banker : banker
                    {
                        meta:
                        description = "This is just an example"

                        strings:
                            $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
                            $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
                            $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

                        condition:
                            $a or $b or $c
                    }"""

        results = tc.create_signature(signame, signame + ".txt", sigtype, sigtext)
        if results.status() == "Success":
            print "Signature created successfully"
        else:
            print results.error_message_list()

    # Create threat and associate
    if False:
        threat_name = "Test Threat %d" % randint(1,1000000)
        results = tc.create_threat(threat_name)
        data = results.data()
        new_threat = json.loads(data.json())[0]
        print "created threat '{0}', id# {1}".format(new_threat['name'], new_threat['id'])
        
        email_address = "assocemail_%d@test.com" % randint(1,1000000)
        print "creating email address {}".format(email_address)
        tc.create_emailAddress(email_address)


        # Create association between threat+indicator
        # NOTE: Group-to-group not supported via V2 at this time
        # NOTE: You can go group-to-indicator or indicator-to-group
        # NOTE: You must specify the branch as it exists in the API for group/indicator types
        #       (e.g. 'emailAddresses' or 'threats')
        #res = tc.associate_group_to_indicator("threats", new_threat['id'], "emailAddresses", email_address)
        res = tc.associate_indicator_to_group("emailAddresses", email_address, "threats", new_threat['id'])
        if res.status() == "Success":
            print "...associated!"
        else:
            easy_print('err', res.error_message_list())

    # Add tag to indicator
    if False:
        host = "testhost-%d-%d.net" % (randint(1,1000), randint(1,1000))
        results = tc.create_host(host)
        tag_name = "test indicator tag"
        results = tc.add_tag_to_indicator("hosts", host, tag_name)

    # Add tag to group
    if False:
        incident_name = "Test Tag Incident %d" % randint(1,1000000)
        date = "2014-06-08T00:00:00-04:00"

        results = tc.create_incident(incident_name, date)
        new_incident = json.loads(results.data().json())[0]
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        results = tc.add_tag_to_group("incidents", new_incident['id'], "api test tag")
   
    # Delete tags from groups/indicators
    if False:
        host = "testhost-%d-%d.net" % (randint(1,1000), randint(1,1000))
        results = tc.create_host(host)
        tag_name = "deletable indicator tag"
        results = tc.add_tag_to_indicator("hosts", host, tag_name)

        incident_name = "Test Tag Incident %d" % randint(1,1000000)
        date = "2014-06-08T00:00:00-04:00"

        results = tc.create_incident(incident_name, date)
        new_incident = json.loads(results.data().json())[0]
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        results = tc.add_tag_to_group("incidents", new_incident['id'], "deletable api test tag")

        tc.delete_tag_from_indicator("hosts", host, tag_name)
        tc.delete_tag_from_group("incidents", new_incident['id'], "deletable api test tag")
 
    # Delete indicator
    if False:
        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))
        results = tc.create_address(ip, rating="5.0", confidence=50)

        print "IP {0} created? {1}".format(ip, results.status())
        
        res = tc._delete_indicator("addresses", ip)
        print "IP {0} deleted? {1}".format(ip, results.status())

    # Delete group
    if False:
        incident_name = "Test Attribute Incident %d" % randint(1,100000000)
        date = "2014-06-08T00:00:00-04:00"
        results = tc.create_incident(incident_name, date)
        new_incident = json.loads(results.data().json())[0]
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        results = tc._delete_group("incidents", new_incident['id'])
        if results.status() == "Success":
            print "Deleted successfully"
        else:
            print results.error_message_list()        

    # Get indicator attributes
    if True:
        results = tc.get_indicator_attributes("addresses", "142.112.222.37")
        printout(results)

    # Create an indicator + attributes
    if False:
        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))
        results = tc.create_address(ip, rating="5.0", confidence=50)
        print "Working with IP {}".format(ip)

        results = tc.create_indicator_attribute("addresses", ip, "source", "API V2-created source", displayed=True)
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

        results = tc.create_indicator_attribute("addresses", ip, "description", "API V2-created desc", displayed=True)
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

    # Create a group + attributes
    if False:
        incident_name = "Test Attribute Incident %d" % randint(1,100000000)
        date = "2014-06-08T00:00:00-04:00"
        results = tc.create_incident(incident_name, date)
        new_incident = json.loads(results.data().json())[0]
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        results = tc.create_group_attribute("incidents", new_incident['id'], "source", "API V2-created source", displayed=True)
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

        results = tc.create_group_attribute("incidents", new_incident['id'], "description", "API V2-created desc", displayed=True)
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

    # Delete indicator attribute
    if False:
        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))
        results = tc.create_address(ip, rating="5.0", confidence=50)
        print "Working with IP {}".format(ip)

        results = tc.create_indicator_attribute("addresses", ip, "source", "deletable API v2 source", displayed=True)
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

        results = tc.delete_indicator_attribute("addresses", ip, new_att['id'])
        if results.status() == "Success":
            print "Attribute deleted!"
        else:
            print results.error_message_list()

    # Delete group attribute
    if False:
        incident_name = "Test Attribute Incident %d" % randint(1,100000000)
        date = "2014-06-08T00:00:00-04:00"
        results = tc.create_incident(incident_name, date)
        new_incident = json.loads(results.data().json())[0]
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        results = tc.create_group_attribute("incidents", new_incident['id'], "source", "Deletable v2 source", displayed=True)
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

        results = tc.delete_group_attribute("incidents", new_incident['id'], new_att['id'])
        if results.status() == "Success":
            print "Attribute deleted!"
        else:
            print results.error_message_list()

    # Dissociate group from indicator
    if False:
        incident_name = "Test Attribute Incident %d" % randint(1,100000000)
        date = "2014-06-08T00:00:00-04:00"
        results = tc.create_incident(incident_name, date)
        new_incident = json.loads(results.data().json())[0]
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))
        results = tc.create_address(ip, rating="5.0", confidence=50)
        print "Working with IP {}".format(ip)

        results = tc.associate_group_to_indicator("incidents", new_incident['id'], "addresses", ip)
        if results.status() == "Success":
            print "Association created!"
        else:
            print results.error_message_list() 

        results = tc.dissociate_group_from_indicator("incidents", new_incident['id'], "addresses", ip)                
        if results.status() == "Success":
            print "Association deleted!"
        else:
            print results.error_message_list()

    # Update indicators
    if False:
        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))
        results = tc.create_address(ip, rating="1.0", confidence=11)

        email = "editable_email_%d_%d@test.net" % (randint(1,1000), randint(1,1000))
        results = tc.create_emailAddress(email, rating="1.0", confidence=11)

        host = "editablehost-%d-%d.net" % (randint(1,1000), randint(1,1000))
        results = tc.create_host(host, rating="1.0", confidence=11)

        url = "https://editable-badguy.net/%d/ok.php?id=%d" % (randint(1,1000), randint(1,1000))
        results = tc.create_url(url, rating="1.0", confidence=11)
        
        sha256 = hashlib.sha256()
        sha256.update(str(randint(1,100000)))
        sha256_hash = sha256.hexdigest()

        hashes = {'sha256':sha256_hash}
        results = tc.create_file(hashes, rating="1.0", confidence=11)

        results = tc.update_address(ip, rating="5.0", confidence=55)
        if results.status() == "Success":
            print "%s rating and confidence updated!" % ip
        else:
            print results.error_message_list()

        results = tc.update_emailAddress(email, rating="5.0", confidence=55)
        if results.status() == "Success":
            print "%s rating and confidence updated!" % email
        else:
            print results.error_message_list()

        results = tc.update_host(host, rating="5.0", confidence=55)
        if results.status() == "Success":
            print "%s rating and confidence updated!" % host
        else:
            print results.error_message_list()

        results = tc.update_url(url, rating="5.0", confidence=55)
        if results.status() == "Success":
            print "%s rating and confidence updated!" % url
        else:
            print results.error_message_list()
            
        results = tc.update_file(sha256_hash, rating="5.0", confidence=56, size=12345)
        if results.status() == "Success":
            print "%s rating and confidence updated!" % sha256_hash
        else:
            print results.error_message_list()

    # Update groups
    if False:
        incident_name = "Test Editable Incident %d" % randint(1,100000000)
        date = "2014-06-08T00:00:00-04:00"
        results = tc.create_incident(incident_name, date)
        new_incident = json.loads(results.data().json())[0]
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        results = tc.update_incident(new_incident['id'], name="Renamed Editable Incident", eventDate="2014-10-08T00:00:00-04:00")
        if results.status() == "Success":
            print "Incident edited!"
        else:
            print results.error_message_list()

        threat_name = "Test Editable Threat %d" % randint(1,100000000)
        results = tc.create_threat(threat_name)
        new_threat = json.loads(results.data().json())[0]
        print "Created threat '{0}', ID# {1}".format(threat_name, new_threat['id'])

        results = tc.update_threat(new_threat['id'], name="Edited threat")
        if results.status() == "Success":
            print "Threat edited!"
        else:
            print results.error_message_list() 

    # Update attributes
    if False:
        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))
        results = tc.create_address(ip, rating="5.0", confidence=50)
        print "Working with IP {}".format(ip)

        results = tc.create_indicator_attribute("addresses", ip, "source", "API V2-created source", displayed=True)
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

        results = tc.update_indicator_attribute("addresses", ip, new_att['id'], "Edited API v2 source")
        if results.status() == "Success":
            print "Attribute edited!"
        else:
            print results.error_message_list()

        incident_name = "Test Attribute Incident %d" % randint(1,100000000)
        date = "2014-06-08T00:00:00-04:00"
        results = tc.create_incident(incident_name, date)
        new_incident = results.single_result()
        print "Created incident '{0}', ID# {1}".format(incident_name, new_incident['id'])

        results = tc.create_group_attribute("incidents", new_incident['id'], "description", "Pre-edit v2 source", displayed="true")
        if results.status() == "Success":
            new_att = json.loads(results.data().json())[0]
            print "Attribute created with ID {}".format(new_att['id'])
        else:
            print results.error_message_list()

        results = tc.update_group_attribute("incidents", new_incident['id'], new_att['id'], "Edited API v2 source")
        if results.status() == "Success":
            print "Attribute updated!"
        else:
            print results.error_message_list()

    # Security labels for groups
    if False:
        threat_name = "Security Label Threat %d" % randint(1,100000000)
        results = tc.create_threat(threat_name)
        new_threat = results.single_result()

        results = tc.add_securityLabel_to_group("threats", new_threat['id'], "API use only")
        results = tc.add_securityLabel_to_group("threats", new_threat['id'], "Super Secret")
        results = tc.get_securityLabels_for_group("threats", new_threat['id'])
        labels = json.loads(results.data().json())
        print "before: %s" % labels

        results = tc.delete_securityLabel_from_group("threats", new_threat['id'], "Super Secret")
        results = tc.get_securityLabels_for_group("threats", new_threat['id'])
        labels = json.loads(results.data().json())
        print "after: %s" % labels

    # Security labels for indicators
    if False:
        ip = "%d.%d.%d.%d" % (randint(1,255), randint(1,255), randint(1,255), randint(1,255))
        
        tc.create_address(ip)
        tc.add_securityLabel_to_indicator("addresses", ip, "API use only")
        tc.add_securityLabel_to_indicator("addresses", ip, "Super Secret")
        results = tc.get_securityLabels_for_indicator("addresses", ip)
        labels = json.loads(results.data().json())
        print "before: %s" % labels

        tc.delete_securityLabel_from_indicator("addresses", ip, "Super Secret")
        results = tc.get_securityLabels_for_indicator("addresses", ip)
        labels = json.loads(results.data().json())
        print "before: %s" % labels

    # Security labels for indicator attributes
    if False:
        randval = str(randint(1,10000000000))
        md5 = hashlib.md5()
        md5.update(randval)
        md5_hash = md5.hexdigest()

        tc.create_file({'md5':md5_hash})
        results = tc.create_indicator_attribute('files', md5_hash, 'source', 'api v2 created source')
        new_att = results.single_result()
        print "Created attribute {0} on file {1}".format(new_att['id'], md5_hash)

        tc.add_securityLabel_to_attribute('files', md5_hash, new_att['id'], "Super Secret")
        tc.add_securityLabel_to_attribute('files', md5_hash, new_att['id'], "API use only")
        results = tc.get_securityLabels_for_attribute('files', md5_hash, new_att['id'])
        labels = json.loads(results.data().json())
        print "before: %s" % labels

        tc.delete_securityLabel_from_attribute('files', md5_hash, new_att['id'], "Super Secret")
        results = tc.get_securityLabels_for_attribute('files', md5_hash, new_att['id'])
        labels = json.loads(results.data().json())
        print "after: %s" % labels 

    # Security labels for group attributes
    if False:
        threat_name = "Security Label Threat %d" % randint(1,100000000)
        results = tc.create_threat(threat_name)
        new_threat = results.single_result()

        results = tc.create_group_attribute('threats', new_threat['id'], 'source', 'api v2 created source')
        new_att = results.single_result()
        print "Created attribute {0} on threat {1}".format(new_att['id'], new_threat['id'])

        tc.add_securityLabel_to_attribute('threats', new_threat['id'], new_att['id'], "Super Secret")
        tc.add_securityLabel_to_attribute('threats', new_threat['id'], new_att['id'], "API use only")
        results = tc.get_securityLabels_for_attribute('threats', new_threat['id'], new_att['id'])
        labels = json.loads(results.data().json())
        print "before: %s" % labels

        tc.delete_securityLabel_from_attribute('threats', new_threat['id'], new_att['id'], "Super Secret")
        results = tc.get_securityLabels_for_attribute('threats', new_threat['id'], new_att['id'])
        labels = json.loads(results.data().json())
        print "after: %s" % labels     
    
    # file occurrences
    if False:
        randval = str(randint(1,10000000000))
        md5 = hashlib.md5()
        md5.update(randval)
        md5_hash = md5.hexdigest()

        tc.create_file({'md5':md5_hash})
        print "Created file {}".format(md5_hash)

        # Create file occurrence (filename, path, date)
        results = tc.create_fileOccurrence(md5_hash, fileName="API file.exe", path="C:\\Runpath 23", date="2014-11-10T13:09:14-05:00")
        new_occ = results.single_result()
        print "Created occurrence with id {0}, path={1}".format(new_occ['id'], new_occ['path'])
        
        # Update file occurrence 
        results = tc.update_fileOccurrence(md5_hash, new_occ['id'], fileName="Renamed API.exe", path='C:\\Win\\', date="2014-01-10T13:09:14-05:00")
        if results.status() == "Success":
            new_occ = results.single_result()
            print "Occurrence updated successfully with path {}!".format(new_occ['path'])
        else:
            print results.error_message_list()
        
        results = tc.create_fileOccurrence(md5_hash, fileName="deletable_file.exe", path="C:\\deleteme23", date="2014-11-10T13:09:14-05:00")
        new_occ = results.single_result()
        print "Created occurrence with id {0}, path={1}".format(new_occ['id'], new_occ['path'])
        
        # Delete file occurrence
        results = tc.delete_fileOccurrence(md5_hash, new_occ['id'])
        if results.status() == "Success":
            print "Occurrence deleted successfully!"
        else:
            print results.error_message_list()
        


# Easy printout for diagnostics
def printout(results):
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

main()
