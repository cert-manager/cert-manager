"""
    externalredirect
    ~~~~~~~~~~~~~~~~~~~~~~~

    Generate redirects to external files based on a single 'external_redirects' file
"""

import os

from sphinx.builders import html as builders
from sphinx.builders import linkcheck as linkcheckbuilders
from sphinx.util import logging

TEMPLATE = """<html>
  <head><meta http-equiv="refresh" content="0; url=%s"/></head>
</html>
"""

SRC_TEMPLATE = """==========
File moved
==========

This document has moved to %s.
This placeholder file will be removed in a later release.
"""

def generate_external_redirects(app, exception):
    logger = logging.getLogger(__name__)

    path = os.path.join(app.srcdir, app.config.external_redirects_file)
    if not os.path.exists(path):
        logger.info("Could not find redirects file at '%s'" % path)
        return

    in_suffix = app.config.source_suffix
    if isinstance(in_suffix, list):
        in_suffix = in_suffix[0]
    if isinstance(in_suffix, dict):
        logger.info("app.config.source_suffix is a dictionary type. "
                 "Defaulting source_suffix to '.rst'")
        in_suffix = ".rst"

    if type(app.builder) == linkcheckbuilders.CheckExternalLinksBuilder:
        logger.info("Detected 'linkcheck' builder in use so skipping generating redirects")
        return

    dirhtml = False
    if type(app.builder) == builders.DirectoryHTMLBuilder:
        dirhtml = True

    with open(path) as redirects:
        for line in redirects.readlines():
            from_path, to_url = line.rstrip().split(' ')
            orig_from_path = from_path
            logger.info("Redirecting '%s' to '%s'" % (from_path, to_url))

            if dirhtml:
                from_path = from_path.replace(in_suffix, '/index.html')
            else:
                from_path = from_path.replace(in_suffix, '.html')

            logger.info("Resolved redirect '%s' to '%s'" % (from_path, to_url))

            redirected_filename = os.path.join(app.builder.outdir, from_path)
            redirected_directory = os.path.dirname(redirected_filename)
            if not os.path.exists(redirected_directory):
                os.makedirs(redirected_directory)

            logger.info("Writing to '%s'" % redirected_filename)
            with open(redirected_filename, 'w') as f:
                f.write(TEMPLATE % to_url)

            input_rst_filename = os.path.join(app.srcdir, orig_from_path)
            with open(input_rst_filename, 'w') as f:
                f.write(SRC_TEMPLATE % to_url)


def setup(app):
    app.add_config_value('external_redirects_file', 'external_redirects', 'env')
    app.connect('build-finished', generate_external_redirects)
