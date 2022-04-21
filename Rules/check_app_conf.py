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
def check_app_conf_has_author(app,reporter):
    """ author field is set
    """

    print("\n")
    stanza_files = get_stanza("app.conf", app)

    for dir, stanza in stanza_files.items():
        for section in stanza:
            print(dir, section.name)
            if section.name == "launcher" and not section.has_option("author"):
                reporter.fail(f"author must exist {dir}/app.conf [{section.name}]")
            elif section.name == "launcher" and section.has_option("author"):
                author_value = section.get_option("author").value
                if len(author_value) < 1 :
                    reporter.fail(f"author Needs a value {dir}/app.conf [{section.name}]")

