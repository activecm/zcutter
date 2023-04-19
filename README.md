

# zcutter, compatible with zeek-cut (formerly bro-cut)

This is a python script that, like zeek-cut, handles the task of
extracting specific columns from zeek-logs.  It can also be used to
convert between TSV and json format log files.

## Primary differences
- zcutter is a standalone python script with no dependencies other than
python3 (which should be on all Linuxes.)

- zeek-cut only reads uncompressed TSV delimited zeek logs.  zcutter will
read TSV and json format.

- The "-r" command line parameter accepts any number of input files, and
these can be any mix of gz compressed, bzip2 compressed, uncompressed,
TSV, and json.  Compressed files will be automatically decompressed on
the fly and deleted when done.


# Quickstart
```
mkdir -p ~/bin/
cd ~/bin/
wget https://raw.githubusercontent.com/activecm/zcutter/main/zcutter.py -O zcutter.py
chmod 755 zcutter.py
if ! type zeek-cut >/dev/null 2>&1 ; then ln -s zcutter.py zeek-cut ; fi
```

To see the command line options:

`zcutter.py -h`


# Notes
- For Python 3.5, use zcutter-stripped.py .  (Python 3.6 and above use zcutter.py)


# References

[zcutter repository](https://github.com/activecm/zcutter/)

[zeek-cut repository](https://github.com/zeek/zeek-aux/)



