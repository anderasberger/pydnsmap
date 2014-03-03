from setuptools import setup
#from setuptools.extension import Extension
#from Cython.Distutils import build_ext

setup(name='pydnsmap',
    version='0.1',
    description='',
    author='Andreas Berger',
    author_email='berger@ftw.at',
    url='http://www.ftw.at',
    packages=['pydnsmap'],
    long_description="""\
    pydnsmap is a ...
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
