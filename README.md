

#zcutter, compatible with zeek-cut (formerly bro-cut)

	This is a python script that, like zeek-cut, handles the 
task of extracting specific columns from zeek-logs.  Primary differences:


- zcutter is a standalone python script with no dependencies other than
python3 (which should be on all Linuxes.)

- zeek-cut only reads uncompressed TSV delimited zeek logs.  zcutter will
read TSV and json format.

- The "-r" command line parameter accepts any number of input files, and
these can be any mix of gz compressed, bzip2 compressed, uncompressed,
TSV, and json.  Compressed files will be automatically decompressed on
the fly and deleted when done.


#Notes
- For Python 3.5, use zcutter-stripped.py .  (Python 3.6 and above use zcutter.py)


References:
https://github.com/activecm/zcutter/
https://github.com/zeek/zeek-aux/



