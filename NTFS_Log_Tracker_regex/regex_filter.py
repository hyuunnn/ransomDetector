from requests import get
from re import sub, escape


class ransomHandler():

    def __init__(self):
        self.extensionApiUrl = "https://fsrm.experiant.ca/api/v1/combined"

    def getExtensionList(self):
        try:
            extensionListJSON = get(self.extensionApiUrl).json()
            return extensionListJSON["filters"]
        except:
            print("[!] Error Occured : Load Extension List by API")

    def replaceSpecialSymbol(self, regex):
        try:
            preRegex = escape(regex)
            midRegex = sub(r'\\\*', "*", preRegex)
            postRegex = sub("\*", "([\\\\\\\\ws\\\S]*)", midRegex).replace("…",".*")
            return postRegex + "$"
        except Exception as err:
            print("[!] Replace Regex error : ", err)


if(__name__ == "__main__"):
    ransom = ransomHandler()
    a = ransom.getExtensionList()
    for result in a:
        print(ransom.replaceSpecialSymbol(result))
