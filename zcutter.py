#!/usr/bin/env python3
"""Python replacement for zeek-cut.  Handles tsv and json input files."""

#Copyright 2023 William Stearns <william.l.stearns@gmail.com>
#Released under the GPL


__version__ = '0.1.1'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2016-2023, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Development'				#Prototype, Development or Production


#Sample uses:
#ZZZZ


#======== External libraries
import os				#File access
import sys				#Used for reading from stdin/writing to stdout
import tempfile				#Creating temporary files for working with stdin or compressed files
import bz2				#Opening bzip2 compressed files
import datetime				#Date formatting
import gzip				#Opening gzip compressed files
import json				#Reading json formatted files
from typing import Dict, List


#======== Functions
def Debug(DebugStr: str) -> None:
	"""Prints a note to stderr"""

	if args['verbose']:
		sys.stderr.write(DebugStr + '\n')
		sys.stderr.flush()


def fail(fail_message: str) -> None:
	"""Print a failure notice and exit."""

	sys.stderr.write(str(fail_message) + ', exiting.\n')
	sys.stderr.flush()
	sys.exit(1)


def open_bzip2_file_to_tmp_file(bzip2_filename: str) -> str:
	"""Open up a bzip2 file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, bz2.BZ2File(bzip2_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding bzip2 file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def open_gzip_file_to_tmp_file(gzip_filename: str) -> str:
	"""Open up a gzip file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, gzip.GzipFile(gzip_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding gzip file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def process_log_lines(log_file: str, requested_fields: List[str], cl_args: Dict):
	"""Will process all the lines in an uncompressed log file."""

	if 'data_line_seen' not in process_log_lines.__dict__:
		process_log_lines.data_line_seen = False

	file_type: str = ''

	field_location: Dict[str, int] = {}							#Remembers in which column we can find a given field name.

	Debug("Processing: " + log_file)
	with open(log_file, 'r', encoding='utf8') as log_h:
		limited_fields = []
		for _, raw_line in enumerate(log_h):						#_ is the line count
			raw_line = raw_line.rstrip()
			if not file_type:
				#FIXME - handle case where we stdin gets both TSV and json input lines
				if raw_line == r'#separator \x09':				#Use raw string so python won't turn \x09 into an actual tab
					file_type = 'tsv'
				elif raw_line.startswith('{'):
					file_type = 'json'
					limited_fields = requested_fields.copy()
				elif raw_line.startswith('#separator'):
					fail('Unrecognized separator in ' + log_file)
				else:
					fail('Unrecognized starting line in ' + log_file)

			out_line = ''
			if raw_line.startswith('#'):
				#Process header lines
				if raw_line.startswith('#fields'):
					#read fields into dictionary (fieldname->adjusted column number)
					field_location = {}
					field_line_fields = raw_line.split('\t')[1:]			#List of the fields in the #fields line.  We have to use [1:] to skip over '#fields'
					for field_num, one_field in enumerate(field_line_fields):
						field_location[one_field] = field_num
					limited_fields = []
					if requested_fields == []:
						limited_fields = field_line_fields.copy()
					elif cl_args['negate']:
						for one_field in field_location:
							if not one_field in requested_fields:
								limited_fields.append(one_field)
					else:
						for one_field in requested_fields:
							if one_field in field_location:
								limited_fields.append(one_field)
					out_line = cl_args['fieldseparator'].join(limited_fields)
					if not (cl_args['allminheaders'] or cl_args['firstminheaders']):		#Prepend "#fields" unless we're doing minimal headers
						out_line = '#fields' + cl_args['fieldseparator'] + out_line

				elif raw_line.startswith('#types'):
					#FIXME - warn/fail/handle case where #types shows up before #fields
					type_list = ['#types', ]
					type_line_fields = raw_line.split('\t')[1:]			#List of the fields in the #types line.  We have to use [1:] to skip over '#types'
					if requested_fields == []:
						type_list = raw_line.split('\t')			#Grab everything, including the leading "#types"
					elif cl_args['negate']:
						for line_index, one_type in enumerate(type_line_fields):
							if line_index not in field_location.values():
								type_list.append(one_type)
					else:
						for one_label in requested_fields:
							field_index = field_location.get(one_label)
							if field_index is not None:
								type_list.append(type_line_fields[field_index])
					if not (cl_args['allminheaders'] or cl_args['firstminheaders']):
						out_line = cl_args['fieldseparator'].join(type_list)
				else:
					if not (cl_args['allminheaders'] or cl_args['firstminheaders']):
						out_line = raw_line

				if not (cl_args['allheaders'] or cl_args['allminheaders'] or ((cl_args['firstheaders'] or cl_args['firstminheaders']) and process_log_lines.data_line_seen is False)):
					out_line = ''
				if cl_args['json']:
					out_line = ''
			else:
				process_log_lines.data_line_seen = True
				#Process non-header lines
				if file_type == 'tsv':
					if not field_location:
						fail("Warning, field_location is not set as we enter live data lines")
					#process tsv line
					data_fields = raw_line.split('\t')
					out_fields = []
					#FIXME - handle case where no fields were requested.
					for one_field in limited_fields:
						try:
							#FIXME - we can't force str if we later output to json format
							extracted_field = str(data_fields[field_location[one_field]])
						except IndexError:
							extracted_field = '-'

						if one_field == 'ts' and cl_args['readabledate']:
							out_fields.append(datetime.datetime.fromtimestamp(float(extracted_field)).strftime(cl_args['dateformat']))
						else:
							out_fields.append(extracted_field)
					out_line = data_line_of(limited_fields, out_fields, file_type, cl_args)
				elif file_type == 'json':
					#Process json line
					#FIXME - negate won't work right now because the list of available fields can change on each json line
					field_dict = json.loads(raw_line)
					out_fields = []
					#FIXME - handle case where no fields were requested.
					for one_field in limited_fields:
						if one_field in field_dict:
							#No need to convert timestamp as the 'ts' field is already human readable in json
							#if one_field == 'ts' and cl_args['readabledate']:
							#	out_fields.append(datetime.datetime.fromtimestamp(float(field_dict[one_field])).strftime(cl_args['dateformat']))
							#else:
							#FIXME - we can't force str if we later output to json format
							out_fields.append(str(field_dict[one_field]))
						else:
							out_fields.append('-')

					out_line = data_line_of(limited_fields, out_fields, file_type, cl_args)
				else:
					fail('Unrecognized file type: ' + file_type)

			if out_line:
				try:
					print(out_line)
				except (BrokenPipeError, KeyboardInterrupt):
					sys.stderr.close()					#To avoid printing the BrokenPipeError warning
					sys.exit(0)

	sys.stderr.flush()


def data_line_of(field_name_list, field_value_list, input_type, cl_args):
	"""Provide a formatted output line from the raw data fields."""

	output_line = ''
	if cl_args['tsv']:
		output_line = cl_args['fieldseparator'].join(field_value_list)
	elif cl_args['json']:
		out_dict = dict(zip(field_name_list, field_value_list))
		output_line = json.dumps(out_dict)
	elif input_type == 'tsv':
		output_line = cl_args['fieldseparator'].join(field_value_list)
	elif input_type == 'json':
		out_dict = dict(zip(field_name_list, field_value_list))
		output_line = json.dumps(out_dict)

	return output_line


def process_log(log_source, fields: List[str], cl_args: Dict):
	"""Process a single source file or stdin."""

	source_file = ''
	close_temp = False
	delete_temp = False

	#Read from stdin
	if log_source in ('-', '', None):
		Debug('Reading log lines from stdin.')
		tmp_log = tempfile.NamedTemporaryFile(delete=True)											# pylint: disable=consider-using-with
		tmp_log.write(sys.stdin.buffer.read())
		tmp_log.flush()
		source_file = tmp_log.name
		close_temp = True
	#Set up source packet file; next 2 sections check for and handle compressed file extensions first, then final "else" treats the source as an uncompressed log file
	elif log_source.endswith('.bz2'):
		Debug('Reading bzip2 compressed logs from file ' + log_source)
		source_file = open_bzip2_file_to_tmp_file(log_source)
		delete_temp = True
	elif log_source.endswith('.gz'):
		Debug('Reading gzip compressed logs from file ' + log_source)
		source_file = open_gzip_file_to_tmp_file(log_source)
		delete_temp = True
	else:
		Debug('Reading logs from file ' + log_source)
		source_file = log_source

	#Try to process file first
	if source_file:
		if os.path.exists(source_file) and os.access(source_file, os.R_OK):
			try:
				process_log_lines(source_file, fields, cl_args)
			except (FileNotFoundError, IOError):
				sys.stderr.write("Unable to open file " + str(log_source) + ', exiting.\n')
				raise
		else:
			sys.stderr.write("Unable to open file " + str(source_file) + ', skipping.\n')

	if close_temp:
		tmp_log.close()

	if delete_temp and source_file != log_source and os.path.exists(source_file):
		os.remove(source_file)


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description='zcutter.py version ' + str(__version__) + ': returns fields from zeek log files.')
	parser.add_argument('fields', help='fields to display', default=[], nargs='*')
	parser.add_argument('-n', '--negate', help='Negate test; show all columns EXCEPT those specified.', required=False, default=False, action='store_true')
	parser.add_argument('-c', '--firstheaders', help='Include first format header blocks in the output.', required=False, default=False, action='store_true')
	parser.add_argument('-C', '--allheaders', help='Include all format header blocks in the output.', required=False, default=False, action='store_true')
	parser.add_argument('-m', '--firstminheaders', help='Include first format header blocks in the output in minimal view.', required=False, default=False, action='store_true')
	parser.add_argument('-M', '--allminheaders', help='Include all format header blocks in the output in minimal view.', required=False, default=False, action='store_true')
	parser.add_argument('-F', '--fieldseparator', help='character that separates output fields.', required=False, default='\t')
	parser.add_argument('-d', '--readabledate', help='Conert ts to readable format.', required=False, default=False, action='store_true')
	parser.add_argument('-D', '--dateformat', help='Format to use for date output.', required=False, default='%FT%T+0000')		#Should be using %z , but it comes up empty.  need to force +0000  https://docs.python.org/3/library/datetime.html
	parser.add_argument('-t', '--tsv', help='Force TSV output', required=False, default=False, action='store_true')
	parser.add_argument('-j', '--json', help='Force json output', required=False, default=False, action='store_true')
	parser.add_argument('-v', '--verbose', help='Be verbose', required=False, default=False, action='store_true')
	parser.add_argument('-r', '--read', help='Log file(s) from which to read logs (place this option last)', required=False, default=[], nargs='*')
	#May need to manually transfer params misplaced as files into the fields array.  Perhaps by extension?
	args = vars(parser.parse_args())

	if args['tsv'] and args['json']:
		fail("Cannot force both tsv and json output at the same time.")

	if args['dateformat'] != '%FT%T+0000':
		args['readabledate'] = True

	field_list: list = args['fields']
	Debug('Requesting these columns: ' + str(field_list))

	#MissingFieldWarning: str = ''

	if not args['read']:										#If no files specified, force reading from stdin
		args['read'].append('')

	for one_file in args['read']:
		process_log(one_file, field_list, args)

	#if MissingFieldWarning:
	#	sys.stderr.write(MissingFieldWarning)
