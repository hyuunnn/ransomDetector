#include <iostream>
#include <regex>
#include <vector>
#include "sqlite3.h"
#include "cpr/cpr.h"
#include "nlohmann/json.hpp"

#include <fstream>
#include <iostream>
using Json = nlohmann::json;

using namespace std;

int callback(void* NotUsed, int argc, char** argv, char** azColName) {
	//for (reg in regex_list){
	//	if (regex_match(argv[2], reg))
	//		cout << "good" << endl;
	//	else
	//		cout << "no" << endl;
	//}
	for (int i = 0; i < argc; i++) {
		cout << azColName[i] << ": " << argv[i] << endl;
	}
	cout << endl;
	return 0;
}

int main() {
	list<regex> regex_list;
	cpr::Response r = cpr::Get(cpr::Url{ "https://fsrm.experiant.ca/api/v1/combined" });
	Json j = Json::parse(r.text);

	for (string i : j["filters"]) {
		regex reg(i);
		regex_list.push_back(reg);
	}

	//ifstream openFile("regex_list.txt");
	//if (openFile.is_open()) {
	//	string line;
	//	while (getline(openFile, line)) {
	//		regex reg(line);
	//		regex_list.push_back(reg); // 에러 발생 (정규식 처리가 조금 다른듯..)
	//	}
	//	openFile.close();
	//}

	sqlite3* db;
	char *err_msg = 0;
	int rc = sqlite3_open("NLT_2020-09-22 13-17-16.db", &db);

	if (rc != SQLITE_OK)
	{
		sqlite3_close(db);
		return 0;
	}

	// (4)event (2)filename (3)fullpath (1)timestamp (6)fileattr
	string sql = "select * from UsnJrnl";
	rc = sqlite3_exec(db, sql.c_str(), callback, 0, &err_msg);

	// event filename fullpath createtime modifiedtime MFT_modifiedtime accesstime
	string sql = "select * from LogFile";
	rc = sqlite3_exec(db, sql.c_str(), callback, 0, &err_msg);
	if (rc != SQLITE_OK) {
		sqlite3_free(err_msg);
		sqlite3_close(db);
	}

	return 0;


}