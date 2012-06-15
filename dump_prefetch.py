#!/usr/bin/env python
# written by James Zhang @2012

import sys
import time
import struct

#############################################################################
# the following code is copied from:
# http://libforensics.googlecode.com/hg-history/a41c6dfb1fdbd12886849ea3ac91de6ad931c363/code/lf/utils/time.py
# convert filetime to datetime
#############################################################################

from datetime import datetime, date, time
from calendar import isleap

# Number of 100ns ticks per clock tick (second).
TICKS_PER_MIN = 600000000
TICKS_PER_SEC = 10000000
TICKS_PER_MSEC = 10000
SECS_PER_DAY = 86400
SECS_PER_HOUR = 3600
SECS_PER_MIN = 60
MINS_PER_HOUR = 60
HOURS_PER_DAY = 24
EPOCH_WEEKDAY = 1
EPOCH_YEAR = 1601
DAYS_PER_NORMAL_YEAR = 365
DAYS_PER_LEAP_YEAR = 366
MONTHS_PER_YEAR = 12

_YearLengths = [ DAYS_PER_NORMAL_YEAR, DAYS_PER_LEAP_YEAR ]
_MonthLengths = [
    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
    [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
]

def filetime_to_datetime(filetime):
    """
    Converts a Microsoft FILETIME timestamp to a Python datetime object.

    :parameters:
        The time in FILETIME format.

    :raises:
        ValueError
            If filetime is an invalid value.

    :rtype: datetime
    :returns: The timestamp as a datetime object.
    """

    # This algorithm was adapted from ReactOS's FileTimeToSystemTime function
    # so it's a bit more precise than just doing
    # utcfromtimestamp(filetime_to_unix_time(filetime)).

    if filetime & 0x8000000000000000:
        raise ValueError("invalid filetime {0}".format(filetime))
    # end if

    # RtlTimeToFileFields
    milli_secs =  0xFFFF & ((filetime % TICKS_PER_SEC) // TICKS_PER_MSEC)
    filetime = filetime // TICKS_PER_SEC

    days = filetime // SECS_PER_DAY
    seconds_in_day = filetime % SECS_PER_DAY

    while seconds_in_day < 0:
        seconds_in_day += SECS_PER_DAY
        days -= 1
    # end while

    while seconds_in_day >= SECS_PER_DAY:
        seconds_in_day -= SECS_PER_DAY
        days += 1
    # end while

    hours = 0xFFFF & (seconds_in_day // SECS_PER_HOUR)
    seconds_in_day = seconds_in_day % SECS_PER_HOUR
    mins = 0xFFFF & (seconds_in_day // SECS_PER_MIN)
    secs = 0xFF & (seconds_in_day % SECS_PER_MIN)

    year = EPOCH_YEAR
    year += days // DAYS_PER_LEAP_YEAR

    year_temp = year - 1
    days_since_epoch = (
        (year_temp * DAYS_PER_NORMAL_YEAR) + (year_temp // 4) -
        (year_temp // 100) + (year_temp // 400)
    )

    epoch_temp = EPOCH_YEAR - 1
    days_since_epoch -= (
        (epoch_temp * DAYS_PER_NORMAL_YEAR) + (epoch_temp // 4) -
        (epoch_temp // 100) + (epoch_temp // 400)
    )

    days -= days_since_epoch
    while 1:
        leap_year = isleap(year)
        if days < _YearLengths[leap_year]:
            break
        # end if

        year += 1
        days -= _YearLengths[leap_year]
    # end while

    leap_year = isleap(year)
    months = _MonthLengths[leap_year]
    month = 0
    while days >= months[month]:
        days -= months[month]
        month += 1
    # end while

    month += 1
    days += 1

    return datetime(year, month, days, hours, mins, secs, milli_secs * 1000)

#############################################################################
# end copy
#############################################################################

CHUNK_SIZE	= 0x1000
MAX_STRING_LENGTH	= 0x1000

PF_SIGNATURE		= 0x41434353
PF_NEW_VERSION		= 0x17

PF_VERSION_OFFSET	= 0x00
PF_SIGNATURE_OFFSET	= 0x04
PF_SIZE_OFFSET		= 0x0C
PF_NAME_OFFSET		= 0x10
PF_HASH_OFFSET		= 0x4C

PF_EXECUTION_COUNT_FROM_TIME	= 0x18
PF_FILE_PATH_ITEM_SIZE_NEW		= 0x20
PF_FILE_PATH_ITEM_SIZE_OLD		= 0x14
PF_FILE_PATH_ITEM_OFFSET_NEW	= 0x0C
PF_FILE_PATH_ITEM_OFFSET_OLD	= 0x08
PF_FILE_PATH_ITEM_TABLE_OFFSET	= 0x54
PF_FILE_PATH_ITEM_TABLE_COUNT	= 0x58
PF_FILE_PATH_STRING_TABLE_OFFSET	= 0x64
PF_LAST_EXECUTION_TIME_OFFSET_NEW	= 0x80
PF_LAST_EXECUTION_TIME_OFFSET_OLD	= 0x78

class BinaryReader:
	def __init__(self, filename):
		self._filename = filename
		self._data = self._read_content()
		self._size = len(self._data)
		
	def _read_content(self):
		chunks = list()
		try:
			fp = open(self._filename, "rb")
			while True:
				chunk = fp.read(CHUNK_SIZE)
				if not chunk:
					break
				chunks.append(chunk)
			fp.close()
		except:
			pass
		return ''.join(chunks)
	
	def _is_valid_offset(self, offset):
		if offset<self._size:
			return True
		return False
	
	def _unpack(self, fmt, offset):
		v = None
		if self._is_valid_offset(offset):
			v = struct.unpack_from(fmt, self._data, offset)[0]
		return v
		
	def read_byte(self, offset):
		return self._unpack('=B', offset)
		
	def read_word(self, offset):
		return self._unpack('=H', offset)
		
	def read_dword(self, offset):
		return self._unpack('=L', offset)
	
	def read_qword(self, offset):
		return self._unpack('=Q', offset)
		
	def read_ascii_string(self, offset, max_length=MAX_STRING_LENGTH):
		s = list()
		for i in range(max_length):
			c = self.read_byte(offset+i)
			if not c:
				break
			s.append(c)
		
		return ''.join(map(lambda x: chr(x & 0xFF), s))
	
	def read_unicode_string(self, offset, max_length=MAX_STRING_LENGTH):
		s = list()
		for i in range(max_length):
			c = self.read_word(offset+(i<<1))
			if not c:
				break
			s.append(c)
		
		return ''.join(map(lambda x: unichr(x & 0xFFFF), s))

	def length(self):
		return self._size
		
class PrefetchReader:
	def __init__(self):
		self._reader = None
		
	def load(self, filename):
		self._reader = BinaryReader(filename)
		self._pf_ver = self._reader.read_dword(PF_VERSION_OFFSET)
		sig = self._reader.read_dword(PF_SIGNATURE_OFFSET)
		fsize = self._reader.read_dword(PF_SIZE_OFFSET)
		if (sig!=PF_SIGNATURE) or (fsize!=self._reader.length()):
			return False
		
		self._pf_name = self._reader.read_unicode_string(PF_NAME_OFFSET)
		self._pf_hash = self._reader.read_dword(PF_HASH_OFFSET)
		return True
	
	def is_new_version(self):
		if self._pf_ver<PF_NEW_VERSION:
			return False
		return True
	
	def _get_last_execution_time_offset(self):
		if self.is_new_version():
			return PF_LAST_EXECUTION_TIME_OFFSET_NEW
		return PF_LAST_EXECUTION_TIME_OFFSET_OLD
		
	def get_last_execution_time(self):
		return filetime_to_datetime(self._reader.read_qword(self._get_last_execution_time_offset()))
		
	def get_execution_count(self):
		return self._reader.read_dword(self._get_last_execution_time_offset() + PF_EXECUTION_COUNT_FROM_TIME)
	
	def _get_file_path_item_size(self):
		if self.is_new_version():
			return PF_FILE_PATH_ITEM_SIZE_NEW
		return PF_FILE_PATH_ITEM_SIZE_OLD
	
	def _get_file_path_item_offset(self):
		if self.is_new_version():
			return PF_FILE_PATH_ITEM_OFFSET_NEW
		return PF_FILE_PATH_ITEM_OFFSET_OLD
		
	def get_file_paths(self):
		file_paths = list()
		item_offset = self._reader.read_dword(PF_FILE_PATH_ITEM_TABLE_OFFSET)
		item_count = self._reader.read_dword(PF_FILE_PATH_ITEM_TABLE_COUNT)
		path_offset = self._reader.read_dword(PF_FILE_PATH_STRING_TABLE_OFFSET)
		if not item_offset or not item_count:
			return file_paths
		for i in range(item_count):
			offset = self._reader.read_dword(item_offset + i * self._get_file_path_item_size() + self._get_file_path_item_offset())
			file_paths.append(self._reader.read_unicode_string(path_offset + offset))
		
		return file_paths
		
	def test(self):
		print "version: 0x%lX" % (self._pf_ver)
		print "size: %lu" % (self._reader.length())
		print "name: %s-%08lX.pf" % (self._pf_name, self._pf_hash)
		print "execution count: %lu" %(self.get_execution_count())
		print "last execution time:", self.get_last_execution_time()
		print '-' * 70
		print 'file paths:'
		print '-' * 70
		file_paths = self.get_file_paths()
		print "Index\tPath"
		for i, file_path in enumerate(file_paths):
			print "%-6d %s" % (i, file_path)
		
def dump_prefetch_file(filename):
	r = PrefetchReader()
	if r.load(filename):
		r.test()
	else:
		print "Corrupted or invalid prefetch file:", filename
	
def main(args):
	if len(args)<2:
		print "Missing input argument, try -h or --help!"
		sys.exit(-1)
	
	for filename in args[1:]:
		dump_prefetch_file(filename)
	
if __name__=='__main__':
	main(sys.argv)
