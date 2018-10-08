=====================
Generating Documentation
=====================

The documentation uses `Sphinx`_ (via `Read The Docs`_) to generate markdown
 rom `reStructured Text`_.

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

.. _`Sphinx`: http://www.sphinx-doc.org/
.. _`Read The Docs`: https://readthedocs.org/
.. _`reStructured Text`: http://www.sphinx-doc.org/en/master/usage/restructuredtext/index.html