import splunk_appinspect
import re
import logging

report_display_order = 2
logger = logging.getLogger(__name__)



@splunk_appinspect.tags("rule1")
@splunk_appinspect.cert_version(min="1.5.3")
def check_Examlpe(app,reporter):
    """ Example
    """
    # reporter.fail("FAIL")
    pass