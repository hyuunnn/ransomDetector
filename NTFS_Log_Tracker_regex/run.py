import sqlite3
from regex_filter import ransomHandler
import re
import csv
from datetime import datetime
import argparse

now = datetime.now()
date_time = now.strftime("%Y-%m-%d_%H-%M-%S")

ransom = ransomHandler()
a = ransom.getExtensionList()
a.append("[HOW TO RECOVER FILES].TXT") # 아직 fsrm 사이트에 등록되어있지 않아서 append
regex_extension_list = [re.compile(ransom.replaceSpecialSymbol(result), re.IGNORECASE) for result in a]

class analyzer:
    def __init__(self, DB_path):
        self.f = open(date_time+"_LogFile.csv", 'w', encoding='utf-8-sig', newline='')
        self.wr = csv.writer(self.f)
        self.wr.writerow(["Event", "FileName", "FullPath", "CreateTime", "ModifiedTime", "MFT_ModifiedTime", "AccessTime"])

        self.f2 = open(date_time+"_UsnJrnl.csv", 'w', encoding='utf-8-sig', newline='')
        self.wr2 = csv.writer(self.f2)
        self.wr2.writerow(["Event", "FileName", "FullPath", "TimeStamp", "FileAttr"])

        self.conn = sqlite3.connect(DB_path)
        self.cur = self.conn.cursor()

    def parseDB(self, query):
        self.cur.execute(query)
        rows = self.cur.fetchall()
        return rows

    def run(self):
        rows = self.parseDB("select Event, FileName, FullPath, CreateTime, ModifiedTime, MFT_ModifiedTime, AccessTime from LogFile")
        for row in rows:
            for regex in regex_extension_list:
                if regex.match(row[1]):
                    self.wr.writerow([row[0], row[1], row[2], row[3], row[4], row[5], row[6]])

        rows = self.parseDB("select Event, FileName, FullPath, TimeStamp, FileAttr from UsnJrnl")
        for row in rows:
            for regex in regex_extension_list:
                if regex.match(row[1]):
                    self.wr2.writerow([row[0], row[1], row[2], row[3], row[4]])

        self.f.close()
        self.f2.close()
        self.conn.close()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='ransomDetector')
    parser.add_argument('--db_path',  help='NTFS Log Tracker db file', required=True)

    args = parser.parse_args()
    DB_PATH = args.db_path

    a = analyzer(DB_PATH)
    a.run()
