#include "RuleParsing.h"


RuleList::RuleList(const char* file_name){
	ifstream ruleFile;
	ruleFile.open(file_name);
	
	string line;
	size = 0;
	getline(ruleFile, line);
	while (!ruleFile.eof()){
		
		OneRule a = parseAline((line));
		if (a.srcIP_i[0] == 167772160 && a.srcIP_i[1] == 12)
			if(a.dstIP_i[0] == 0 && a.dstIP_i[1] == 1)
				if(a.srcP_i[0] == 0 && a.srcP_i[1]==65535)
					if(a.dstP_i[0] == 0 && a.dstP_i[1] == 65535)
						cout<<"bitch constructor"<<endl;
		
		size++;
		handle.push_back(parseAline(line));
		getline(ruleFile, line);
	}

	ruleFile.close();
}


OneRule RuleList::parseAline(string line){
	typedef vector<string> Split_T;

	Split_T fields;

	OneRule rule;
	
	boost::split( fields, line, boost::is_any_of("\t"));
		
	// parse source
	fields[0].erase(0,1);
	Split_T ipmaskF;
	boost::split(ipmaskF, fields[0], boost::is_any_of("/"));	
	rule.srcIP_i[0] = maskIP(ipmaskF[0], atoi(ipmaskF[1].c_str()));
	rule.srcIP_i[1] = atoi(ipmaskF[1].c_str());

	// parse destine
	boost::split(ipmaskF, fields[1], boost::is_any_of("/"));
	rule.dstIP_i[0] = maskIP(ipmaskF[0], atoi(ipmaskF[1].c_str()));
	rule.dstIP_i[1] = atoi(ipmaskF[1].c_str());
	
	// parse src port
	Split_T portRange;
	boost::split(portRange, fields[2], boost::is_any_of(":"));
	rule.srcP_i[0] = atoi(portRange[0].c_str());
	rule.srcP_i[1] = atoi(portRange[1].c_str());

	// parse dst port
	boost::split(portRange, fields[3], boost::is_any_of(":"));
	rule.dstP_i[0] = atoi(portRange[0].c_str());
	rule.dstP_i[1] = atoi(portRange[1].c_str());
	
	// parse protocol
	Split_T proto;
	boost::split(proto, fields[4], boost::is_any_of("/"));
	rule.protocol = strtol(proto[0].c_str(),NULL,0) & strtol(proto[1].c_str(), NULL, 0);
	
	return rule;
}

void RuleList::removeRedundant(){
	for(int i = 0; i<size; i++){
		for(int j = size-1; j>i; j--){
			if (handle[i] == handle[j]){
				handle.erase(handle.begin()+j);
				size--;
			}
		}
	}
}


RuleList::~RuleList(){
}
