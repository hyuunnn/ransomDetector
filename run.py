import pyevtx
import xmltodict
import os.path

import pyfsntfs
import requests
#import uuid

from regex_filter import ransomHandler
import re
import pdb

from dfdatetime import filetime as dfdatetime_filetime
from dfdatetime import semantic_time as dfdatetime_semantic_time
from dfdatetime import uuid_time as dfdatetime_uuid_time

import definitions

import csv
from datetime import datetime
import argparse

class EvtxParser:
    def __init__(self, date_time):
        self.date_time = date_time
        self.f = open(date_time+"_Sysmon.csv", 'w', encoding='utf-8-sig', newline='')
        self.wr = csv.writer(self.f)
        self.wr.writerow(["SystemTime", "CommandLine", "ParentCommandLine"])

        self.f2 = open(date_time+"_PowerShell.csv", 'w', encoding='utf-8-sig', newline='')
        self.wr2 = csv.writer(self.f2)
        self.wr2.writerow(["SystemTime", "data"])

        self.f3 = open(date_time+"_PowerShell_Operational.csv", 'w', encoding='utf-8-sig', newline='')
        self.wr3 = csv.writer(self.f3)
        self.wr3.writerow(["SystemTime", "ScriptBlockText"])

    def run(self, evtx_PATH):
        self.evtx_PATH = evtx_PATH
        file_object = open(self.evtx_PATH, "rb")
        evtx_file = pyevtx.file()

        try:
            evtx_file.open_file_object(file_object)
        except IOError as exception:
            print(exception)
            return

        for idx in range(0, evtx_file.number_of_records):
            try:
                record = evtx_file.get_record(idx)
            except OSError as exception:
                continue

            try:
                data = xmltodict.parse(record.xml_string)['Event']

                if os.path.basename(self.evtx_PATH) == "Microsoft-Windows-Sysmon%4Operational.evtx":

                    if data['System']['EventID'] == "1":
                        SystemTime = data['System']['TimeCreated']['@SystemTime']

                        for j in data['EventData']['Data']:
                            if j['@Name'] == "CommandLine":
                                CommandLine = j['#text']

                            elif j['@Name'] == "ParentCommandLine":
                                ParentCommandLine = j['#text']

                        if any(s in CommandLine for s in ["system32\\net", "system32\\net1", "powershell.exe", "vssadmin.exe"]):
                            self.wr.writerow([SystemTime, CommandLine, ParentCommandLine])

                        elif any(s in ParentCommandLine for s in ["system32\\net", "system32\\net1", "powershell.exe", "vssadmin.exe"]):
                            self.wr.writerow([SystemTime, CommandLine, ParentCommandLine])  

                elif os.path.basename(self.evtx_PATH) == "Windows PowerShell.evtx":

                    if data['System']['EventID']['#text'] in ("400", "600"):
                        SystemTime = data['System']['TimeCreated']['@SystemTime']
                        data = data['EventData']['Data'][-1]
                        self.wr2.writerow([SystemTime, data])

                elif os.path.basename(self.evtx_PATH) == "Microsoft-Windows-PowerShell%4Operational.evtx":

                    if data['System']['EventID'] in ("4100", "4103", "4104"):
                        for j in data['EventData']['Data']:
                            if j['@Name'] == "ScriptBlockText":
                                SystemTime = data['System']['TimeCreated']['@SystemTime']
                                ScriptBlockText = j['#text']
                                self.wr3.writerow([SystemTime, ScriptBlockText])

            except Exception as exception:
                print(exception)
    
    def close(self):
        self.f.close()
        self.f2.close()
        self.f3.close()

class NTFSFileStatEventData():

    DATA_TYPE = 'fs:stat:ntfs'

    def __init__(self):
        """Initializes event data."""
        self.attribute_type = None
        self.display_name = None
        self.file_attribute_flags = None
        self.file_reference = None
        self.file_system_type = 'NTFS'
        self.filename = None
        self.is_allocated = None
        self.name = None
        self.parent_file_reference = None
        self.path_hints = None
        self.creation_time = None
        self.modification_time = None
        self.access_time = None
        self.entry_modification_time = None

class MFTParser:

    _MFT_ATTRIBUTE_STANDARD_INFORMATION = 0x00000010
    _MFT_ATTRIBUTE_FILE_NAME = 0x00000030
    _MFT_ATTRIBUTE_OBJECT_ID = 0x00000040
    _MFT_ATTRIBUTE_DATA = 0x00000080

    _NAMESPACE_DOS = 2

    def __init__(self, date_time):
        self.date_time = date_time

        self.f = open(date_time+"_MFT.csv", 'w', encoding='utf-8-sig', newline='')
        self.wr = csv.writer(self.f)
        self.wr.writerow(["path", "filename", "creation_time", "modification_time", "access_time", "entry_modification_time"])

        ransom = ransomHandler()
        a = ransom.getExtensionList()
        a.append("[HOW TO RECOVER FILES].TXT") # 아직 fsrm 사이트에 등록되어있지 않아서 append
        self.regex_extension_list = [re.compile(ransom.replaceSpecialSymbol(result), re.IGNORECASE) for result in a]

    def PlasoTimetoDateTime(self, timestamp):
        return datetime.fromtimestamp(timestamp/1000000)

    def DateTimeValuesEvent(self, date_time, date_time_description, time_zone=None):
        timestamp = date_time.GetPlasoTimestamp()
        #if date_time.is_local_time and time_zone:
        #    timestamp = timelib.Timestamp.LocaltimeToUTC(timestamp, time_zone)

        #return timestamp, date_time_description
        return timestamp

    def _GetDateTime(self, filetime):
        if filetime == 0:
            return dfdatetime_semantic_time.NotSet()
            
        return dfdatetime_filetime.Filetime(timestamp=filetime)

    #def _ParseDistributedTrackingIdentifier(self, uuid_string, origin):
    #    uuid_object = uuid.UUID(uuid_string)

    #    if uuid_object.version == 1:
    #        date_time = dfdatetime_uuid_time.UUIDTime(timestamp=uuid_object.time)
    #        event = self.DateTimeValuesEvent(
    #            date_time, definitions.TIME_DESCRIPTION_CREATION)
    #        print(event, origin)
    #    else:
    #        print(uuid_string, origin)

    def _ParseFileStatAttribute(self, mft_entry, mft_attribute, path_hints):
        event_data = NTFSFileStatEventData()
        event_data.attribute_type = mft_attribute.attribute_type
        #event_data.display_name = parser_mediator.GetDisplayName() // dfvfs 핸들에서 데이터 가져오는 것 같음
        event_data.display_name = ""
        event_data.file_reference = mft_entry.file_reference
        #event_data.filename = parser_mediator.GetRelativePath() // dfvfs 핸들에서 데이터 가져오는 것 같음
        event_data.filename = ""
        event_data.is_allocated = mft_entry.is_allocated()
        event_data.path_hints = path_hints
        
        if mft_attribute.attribute_type == self._MFT_ATTRIBUTE_FILE_NAME:
            event_data.file_attribute_flags = mft_attribute.file_attribute_flags
            event_data.name = mft_attribute.name
            event_data.parent_file_reference = mft_attribute.parent_file_reference
            
        try:
            creation_time = mft_attribute.get_creation_time_as_integer()
        except OverflowError as exception:
            print(mft_attribute.attribute_type, exception)
            creation_time = None
            
        if creation_time is not None:
            date_time = self._GetDateTime(creation_time)
            event = self.DateTimeValuesEvent(
                date_time, definitions.TIME_DESCRIPTION_CREATION)
            event_data.creation_time = event

        try:
            modification_time = mft_attribute.get_modification_time_as_integer()
        except OverflowError as exception:
            print(mft_attribute.attribute_type, exception)
            modification_time = None
            
        if modification_time is not None:
            date_time = self._GetDateTime(modification_time)
            event = self.DateTimeValuesEvent(
                date_time, definitions.TIME_DESCRIPTION_MODIFICATION)
            event_data.modification_time = event
 
        try:
            access_time = mft_attribute.get_access_time_as_integer()
        except OverflowError as exception:
            print(exception, mft_attribute.attribute_type)
            access_time = None
            
        if access_time is not None:
            date_time = self._GetDateTime(access_time)
            event = self.DateTimeValuesEvent(
                date_time, definitions.TIME_DESCRIPTION_LAST_ACCESS)
            event_data.access_time = event

        try:
            entry_modification_time = (
                mft_attribute.get_entry_modification_time_as_integer())
        except OverflowError as exception:
            print(mft_attribute.attribute_type, exception)
            entry_modification_time = None
            
        if entry_modification_time is not None:
            date_time = self._GetDateTime(entry_modification_time)
            event = self.DateTimeValuesEvent(
                date_time, definitions.TIME_DESCRIPTION_ENTRY_MODIFICATION)
            event_data.entry_modification_time = event

        # Compare Extension #
        for path in event_data.path_hints:
            for regex in self.regex_extension_list:
                filename = path.split("\\")[-1]
                if regex.match(filename):
                    self.wr.writerow([path, filename, self.PlasoTimetoDateTime(event_data.creation_time), \
                        self.PlasoTimetoDateTime(event_data.modification_time), \
                        self.PlasoTimetoDateTime(event_data.access_time), \
                        self.PlasoTimetoDateTime(event_data.entry_modification_time)])
                    continue

    #def _ParseObjectIDAttribute(self, mft_entry, mft_attribute):
    #    display_name = '$MFT: {0:d}-{1:d}'.format(
    #        mft_entry.file_reference & 0xffffffffffff,
    #        mft_entry.file_reference >> 48)
            
    #    if mft_attribute.droid_file_identifier:
    #        try:
    #            self._ParseDistributedTrackingIdentifier(
    #                mft_attribute.droid_file_identifier, display_name)
    #        except (TypeError, ValueError) as exception:
    #            print(mft_attribute.attribute_type, exception)
                
    #    if mft_attribute.birth_droid_file_identifier:
    #        try:
    #            self._ParseDistributedTrackingIdentifier(
    #                mft_attribute.droid_file_identifier, display_name)
                    
    #        except (TypeError, ValueError) as exception:
    #            print(mft_attribute.attribute_type, exception)

    def parseMFT(self, mft_entry):
        data_stream_names = []
        path_hints = []
        standard_information_attribute = None
        standard_information_attribute_index = None

        for attribute_index in range(0, mft_entry.number_of_attributes):
            try:
                mft_attribute = mft_entry.get_attribute(attribute_index)
                if mft_attribute.attribute_type == (
                    self._MFT_ATTRIBUTE_STANDARD_INFORMATION):
                    standard_information_attribute = mft_attribute
                    standard_information_attribute_index = attribute_index
            
                elif mft_attribute.attribute_type == self._MFT_ATTRIBUTE_FILE_NAME:
                    path_hint = mft_entry.get_path_hint(attribute_index)
                    self._ParseFileStatAttribute(mft_entry, mft_attribute, [path_hint])
                    #if mft_attribute.name_space != self._NAMESPACE_DOS:
                    #    path_hints.append(path_hint)

                #elif mft_attribute.attribute_type == self._MFT_ATTRIBUTE_OBJECT_ID:
                #    self._ParseObjectIDAttribute(mft_entry, mft_attribute)

                elif mft_attribute.attribute_type == self._MFT_ATTRIBUTE_DATA:
                    data_stream_names.append(mft_attribute.attribute_name)

            except IOError as exception:
                print(attribute_index, exception)

        if standard_information_attribute:
            path_hints_with_data_streams = []
            for path_hint in path_hints:
                if not path_hint:
                    path_hint = '\\'
                
                if not data_stream_names:
                    path_hints_with_data_streams.append(path_hint)
                else:
                    for data_stream_name in data_stream_names:
                        if not data_stream_name:
                            path_hint_with_data_stream = path_hint
                        else:
                            path_hint_with_data_stream = '{0:s}:{1:s}'.format(
                                path_hint, data_stream_name)
                                
                        path_hints_with_data_streams.append(path_hint_with_data_stream)
                        
        try:
            self._ParseFileStatAttribute(mft_entry, standard_information_attribute,
            path_hints_with_data_streams)
        except IOError as exception:
            print(standard_information_attribute_index, exception)


    def run(self, MFT_PATH):
        mft_metadata_file = pyfsntfs.mft_metadata_file()
        file_object = open(MFT_PATH, "rb")

        try:
            mft_metadata_file.open_file_object(file_object)
        except IOError as exception:
            print(exception)
            return

        for entry_index in range(0, mft_metadata_file.number_of_file_entries):
            try:
                mft_entry = mft_metadata_file.get_file_entry(entry_index)
                if (not mft_entry.is_empty() and
                    mft_entry.base_record_file_reference == 0):
                    self.parseMFT(mft_entry)

            except IOError as exception:
                print(entry_index, exception)

            #print("{}/{}".format(entry_index, mft_metadata_file.number_of_file_entries))
        
        mft_metadata_file.close()

if __name__ == "__main__":
    '''
    # Test PATH variables
    MFT_PATH = "E:\\DF2020\\305\\305 - ran_some\\2020-06-02_Win10_1909\\ntfs_\\$MFT"
    #LogFile_PATH = "E:\\DF2020\\305\\305 - ran_some\\2020-06-02_Win10_1909\\ntfs_\\$LogFile"
    #UsnJrnl_PATH = "E:\\DF2020\\305\\305 - ran_some\\2020-06-02_Win10_1909\\ntfs_\\$J"
    evtx_PATH = "E:\\DF2020\\305\\305 - ran_some\\2020-06-02_Win10_1909\\C\\windows\\system32\\winevt\\logs\\"
    #prefetch_PATH = "E:\\DF2020\\305\\305 - ran_some\\2020-06-02_Win10_1909\\C\\Windows\\prefetch"
    '''
    parser = argparse.ArgumentParser(description='ransomDetector')
    parser.add_argument('--mft',  help='mft', required=True)
    parser.add_argument('--evtx_path', help='evtx_path', required=True)

    args = parser.parse_args()

    MFT_PATH = args.mft
    evtx_PATH = args.evtx_path

    now = datetime.now()
    date_time = now.strftime("%Y-%m-%d_%H-%M-%S")

    a = MFTParser(date_time)
    a.run(MFT_PATH)

    a = EvtxParser(date_time)
    a.run(evtx_PATH + "Microsoft-Windows-Sysmon%4Operational.evtx")
    # https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
    a.run(evtx_PATH + "Windows PowerShell.evtx")
    a.run(evtx_PATH + "Microsoft-Windows-PowerShell%4Operational.evtx")
    a.close()