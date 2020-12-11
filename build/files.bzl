# Copyright 2020 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# concat_files concatenates a list of file contents together into a single
# file, separated by the given separator.
# If a specific output filename is desired, it can be specified using the arg
# 'out'. Otherwise the output file will be named 'name.out'.
def concat_files(name, srcs, separator, out = None, **kwargs):
    if not out:
        out = "%s.out" % name

    native.genrule(
        name = name,
        cmd = """
for each in $(SRCS); do
    cat $$each >> $@
    echo -e "%s" >> $@
done
""" % separator,
        srcs = srcs,
        outs = [out],
        **kwargs
    )

# modify_file will modify a file by prepending 'prefix' and appending 'suffix'
# to the contents of the file.
# The 'prefix' and the 'suffix' must not contain single quote (') characters.
def modify_file(name, src, out, prefix, suffix, **kwargs):
    native.genrule(
        name = name,
        cmd = """
echo -e '%s' >> $@
cat $(location %s) >> $@
echo -e '%s' >> $@
""" % (prefix, src, suffix),
        srcs = [src],
        outs = [out],
        **kwargs
    )
