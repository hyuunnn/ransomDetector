import argparse
import os
from datetime import datetime
import csv
import json
import xmltodict

now = datetime.now()
date_time = now.strftime("%Y-%m-%d_%H-%M-%S")

class Tasks:
    def __init__(self, path):
        self.TASKS_PATH = path
        self.f = open(date_time+"_Tasks.csv", 'w', encoding='utf-8-sig', newline='')
        self.wr = csv.writer(self.f)
        self.wr.writerow(["Path", "Triggers", "Command"])

    def parseXML(self, path):
        Triggers = []
        command = ""
        try:
            with open(path, "r", encoding="utf-16") as f:
                data = xmltodict.parse(f.read())
                if data['Task']['Triggers'] != None:
                    for i, j in data['Task']['Triggers'].items():
                        if j != None and "Enabled" in j:
                            Triggers.append("{}:{}".format(i, j['Enabled']))
                else:
                    Triggers.append("")

                if "Exec" in data['Task']['Actions']:
                    command = data['Task']['Actions']['Exec']['Command']

                self.wr.writerow([path, Triggers, command])
        except:
            print("[*] Error {}".format(path))

    def run(self):
        for root, dirs, filenames in os.walk(self.TASKS_PATH):
            for filename in filenames:
                self.parseXML(os.path.join(root, filename))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ransomDetector')
    parser.add_argument('--tasks_path',  help='Tasks Path', required=True)

    args = parser.parse_args()
    TASKS_PATH = args.tasks_path

    a = Tasks(TASKS_PATH)
    a.run()
