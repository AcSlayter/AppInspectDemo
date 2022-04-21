import splunk_appinspect
import re
import logging

report_display_order = 2
logger = logging.getLogger(__name__)

def get_stanza(filename, app):
    print("\n")
    stanza_files = {}
    for dir in ["local", "default"]:
        if app.file_exists(dir, filename):
            stanza_files[dir] = []
            savedsearches_config = app.get_config(filename, dir=dir)
            for section in savedsearches_config.sections():
                stanza_files[dir].append(section)

    return stanza_files

@splunk_appinspect.tags("rule1")
@splunk_appinspect.cert_version(min="1.5.3")
def check_savedsearch_search_query_exists(app,reporter):
    """ Validate search=query
    """
    print("\n")
    stanza_files = get_stanza("savedsearches.conf", app)

    for dir, stanza in stanza_files.items():
        for section in stanza:
            if not section.has_option("search") and section.name != "default"  :
                reporter.fail(f"search= must exist {dir}/savedsearches.conf [{section.name}]")


@splunk_appinspect.tags("rule1")
@splunk_appinspect.cert_version(min="1.5.3")
def check_savedsearch_search_SourceType_value(app,reporter):
    """ Validate sourcetype
    """
    field="sourcetype"
    filename="savedsearches.conf"
    stanza_files = get_stanza("savedsearches.conf", app)

    for dir, stanza in stanza_files.items():
        for section in stanza:
             if section.has_option("search") and section.name != "default"  :
                searchString = section.get_option("search").value
                if field not in searchString :
                    reporter.fail(f"{field} value required {dir}/{filename} [{section.name}]")

@splunk_appinspect.tags("rule1")
@splunk_appinspect.cert_version(min="1.5.3")
def check_savedsearch_search_index_value(app,reporter):
    """ Validate index
    """
    field="index"
    filename="savedsearches.conf"
    stanza_files = get_stanza("savedsearches.conf", app)

    for dir, stanza in stanza_files.items():
        for section in stanza:
             if section.has_option("search") and section.name != "default"  :
                searchString = section.get_option("search").value
                if field not in searchString :
                    reporter.fail(f"{field} value required {dir}/{filename} [{section.name}]")

def regex_check(string,regex) :
    if ( re.search(regex, string) ) :
        return True
    else :
        return False

@splunk_appinspect.tags("rule1")
@splunk_appinspect.cert_version(min="1.5.3")
def check_savedsearch_search_index_star(app,reporter):
    """ Validate index=*
    """
    
    filename="savedsearches.conf"
    stanza_files = get_stanza("savedsearches.conf", app)

    for dir, stanza in stanza_files.items():
        for section in stanza:
            print(dir, section.name)
            if section.has_option("search") and section.name != "default"  :
                searchString = section.get_option("search").value
                regex = "index\s?=\s?\"?\*"
                if regex_check(searchString,regex) :
                    reporter.fail(f"index=* not allowed {dir}/{filename} [{section.name}]")
