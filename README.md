
![zcutter](zcutter_icon_tag.png)

# zcutter, compatible with zeek-cut (formerly bro-cut)

This is a python script that, like zeek-cut, handles the task of
extracting specific columns from zeek-logs.  It can also be used to
convert between TSV and json format log files.

## Primary differences
- zcutter is a standalone python script with no dependencies other than
python3 (which should be on all Linuxes and MacOS.)

- zeek-cut only reads uncompressed TSV delimited zeek logs.  zcutter will
read and write TSV and json format.

- The "-r" command line parameter accepts any number of input files, and
these can be any mix of gz compressed, bzip2 compressed, uncompressed,
TSV, and json.  Compressed files will be automatically decompressed on
the fly and the temporary files will be deleted when done.

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


- Look at the source IP, method, host, and URI fields from an http log:

`zcat http.00\:00\:00-01\:00\:00.log.gz | nice zcutter.py id.orig_h method host uri -C | less -S -x 20`


- Same as above, but automatically decompress input logs

`nice zcutter.py id.orig_h method host uri -C -r http.00\:00\:00-01\:00\:00.log.gz | less -S -x20`


- Convert all gzip compressed logs (except conn-summary logs) in this
directory to json and save the uncompressed json logs in ~/json-out/ :

`zcutter.py -j -o ~/json-out/ -r *.log.gz`


- Like above, but compress the output logs at the end if successful:

`zcutter.py -j -o ~/json-out/ -r *.log.gz && gzip -9 ~/json-out/*.log`


- Like above, but preserve the paths under /V/source in /V/dest/ and compress with bzip2.  The file glob after -r needs to match the number of levels down where the .log files are found:

```
cd /V/source/
zcutter.py -o /V/dest/ -j -r */*/*.log.gz
find /V/dest/ -mmin +1 -iname '*.log' -print0 | xargs -r -n 50 -0 nice -n 19 bzip2 -9
```



- To see the command line options:

`zcutter.py -h`

The current help text:

```
usage: zcutter.py [-h] [-n] [-c] [-C] [-m] [-M] [-F FIELDSEPARATOR] [-d] [-D DATEFORMAT] [-t] [-j] [-v] [-o OUTPUTDIR] [-r [READ ...]] [fields ...]

zcutter.py version 0.1.8: returns fields from zeek log files.

positional arguments:
  fields                fields to display

options:
  -h, --help            show this help message and exit
  -n, --negate          Negate test; show all columns EXCEPT those specified.
  -c, --firstheaders    Include first format header blocks in the output.
  -C, --allheaders      Include all format header blocks in the output.
  -m, --firstminheaders
                        Include first format header blocks in the output in minimal view.
  -M, --allminheaders   Include all format header blocks in the output in minimal view.
  -F FIELDSEPARATOR, --fieldseparator FIELDSEPARATOR
                        character that separates output fields.
  -d, --readabledate    Conert ts to readable format.
  -D DATEFORMAT, --dateformat DATEFORMAT
                        Format to use for date output.
  -t, --tsv             Force TSV output
  -j, --json            Force json output
  -v, --verbose         Be verbose
  -o OUTPUTDIR, --outputdir OUTPUTDIR
                        Directory in which to place corresponding (uncompressed) output files
  -r [READ ...], --read [READ ...]
                        Log file(s) from which to read logs (place this option last)
```


# References

[zcutter repository](https://github.com/activecm/zcutter/)

[zeek-cut repository](https://github.com/zeek/zeek-aux/)



