# Copyright (c) 2014, FTW Forschungszentrum Telekommunіkation Wien
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# # Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# # Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# # Neither the name of FTW nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
*
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL FTW
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE

from setuptools import setup

setup(name='pydnsmap',
    version='0.1',
    description='',
    author='Andreas Berger',
    author_email='berger@ftw.at',
    packages=['pydnsmap'],
    long_description="""\
    pydnsmap processes DNS FQDN-to-IP mappings extracted from DNS traffic and
    reveals FQDNs and IPs which may used for cybercrime activities. It
    builds and maintains an efficient data structure which represents these
    mappings (i.e., the map). It ignores mappings which are sufficiently
    similar to previously seen ones, and outputs those ones which are not. By
    further analyzing those using simple graph analysis, malicious mappings are
    identified.
    """,
    classifiers=[
	"License :: OSI Approved :: GNU General Public License (GPL)",
	"Programming Language :: Python",
	"Development Status :: 4 - Beta",
	"Intended Audience :: Developers",
	"Topic :: Internet",
    ],
    keywords='',
    license='GPL',
    install_requires=[
      'setuptools',
    ],
    )
