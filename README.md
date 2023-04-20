

# zcutter, compatible with zeek-cut (formerly bro-cut)

This is a python script that, like zeek-cut, handles the task of
extracting specific columns from zeek-logs.  It can also be used to
convert between TSV and json format log files.

## Primary differences
- zcutter is a standalone python script with no dependencies other than
python3 (which should be on all Linuxes.)

- zeek-cut only reads uncompressed TSV delimited zeek logs.  zcutter will
read and write TSV and json format.

- The "-r" command line parameter accepts any number of input files, and
these can be any mix of gz compressed, bzip2 compressed, uncompressed,
TSV, and json.  Compressed files will be automatically decompressed on
the fly and deleted when done.

- zcutter will write out the (converted) files to an output directory,
allowing you to bulk convert zeek logs.


# Quickstart
```
mkdir -p ~/bin/
cd ~/bin/
wget https://raw.githubusercontent.com/activecm/zcutter/main/zcutter.py -O zcutter.py
chmod 755 zcutter.py
if ! type zeek-cut >/dev/null 2>&1 ; then ln -s zcutter.py zeek-cut ; fi
```
- For Python 3.5, use zcutter-stripped.py .  (Python 3.6 and above use zcutter.py)


# Example commands

- To see the command line options:
`zcutter.py -h`


- Look at the source IP, method, host, and URI fields from an http log:
`zcat http.00\:00\:00-01\:00\:00.log.gz | nice zcutter.py id.orig_h method host uri -C | less -S -x 20`


- Same as above, but automatically decompress input logs
`nice zcutter.py id.orig_h method host uri -C -r http.00\:00\:00-01\:00\:00.log.gz | less -S -x20`


- Convert all gzip compressed logs (except conn-summary logs) in this
directory to json and save the uncompressed json logs in ~/json-out/ :
`zcutter.py -j -o ~/json-out/ -r *.log.gz`


- Like above, but compress the output logs at the end if successful:
`zcutter.py -j -o ~/json-out/ -r *.log.gz && gzip -9 ~/json-out/*.log`


# References

[zcutter repository](https://github.com/activecm/zcutter/)

[zeek-cut repository](https://github.com/zeek/zeek-aux/)



