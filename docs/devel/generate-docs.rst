========================
Generating Documentation
========================

The documentation is generated from `reStructured Text`_ by `Sphinx`_
(via `Read The Docs`_). If you're unfamiliar with `reStructured Text`_,
the files typically have the extension `.rst`. You can find more details
in the `reStructured Text Basics`_.

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

.. code-block: shell

   open _build/html/index.html

Note that you do not need to add these files to your git client, as
*Read The Docs* will generate the HTML on the fly.

.. _`Sphinx`: https://www.sphinx-doc.org/
.. _`Read The Docs`: https://readthedocs.org/
.. _`reStructured Text`: https://www.sphinx-doc.org/en/master/usage/restructuredtext/index.html
.. _`reStructured Text Basics`: https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
