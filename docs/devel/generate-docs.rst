=====================
Generating Documentation
=====================

The documentation uses `Sphinx <http://www.sphinx-doc.org/>` (via
`Read The Docs <https://readthedocs.org/>`) to generate markdown from
`reStructured Text <http://www.sphinx-doc.org/en/master/usage/restructuredtext/index.html>`.

Installation instructions
=========================

To install the sphinx tools, you'll need ``python`` (and ``pip``) installed.::

.. code-block: shell

   pip install --user -r requirements.txt

Generating documentation locally
================================

You can generate the documentation locally with the following command:

.. code-block: shell

   make html

This will create documentation in the ``_build`` directory which you can
open with your browser.

Note that you do not need to add these files to your git client, as
*Read The Docs* will generate the HTML on the fly.