#include "RuleParsing.h"


RuleList::RuleList(string file_name){
	ifstream ruleFile;
	ruleFile.open(file_name.c_str());
	
	string line;
	size = 0;
	getline(ruleFile, line);
	while (!ruleFile.eof()){
		
		
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

void RuleList::condense(string net_s, size_t sqBits = 0){
	size_t subnet[2];
	nettoi(net_s, subnet);
	// find the most condensed subnet
	size_t curSubNet[2];
	size_t & pref = curSubNet[0];
	size_t & mask = curSubNet[1];
	mask = subnet[1]-sqBits;
	
	size_t MaxCounter = 0;
	size_t MaxSubNet[2];

	for (size_t counter = 0; counter <= ((~size_t(0)) >> (32 - mask)); counter++){
		pref = counter << (32-mask);

		size_t rCount = 0;	
		for (auto it = handle.begin(); it != handle.end(); it++){
			if (match( (*it).srcIP_i, (*it).dstIP_i, curSubNet, curSubNet))
				rCount++;
		}

		if (rCount > MaxCounter){
			MaxSubNet[0] = curSubNet[0];
			MaxSubNet[1] = curSubNet[1];
			MaxCounter = rCount;
		}
	}

	// shrink the rules to be exactly that subnet;
	auto it = handle.begin();
	size_t maskAnd = (~(size_t(0)) >> subnet[1]);
	while( it != handle.end()){
		if (match((*it).srcIP_i, (*it).dstIP_i, MaxSubNet, MaxSubNet)){
			if ((*it).srcIP_i[1] < MaxSubNet[1]){  // truncate
				(*it).srcIP_i[0] = MaxSubNet[0];
				(*it).srcIP_i[1] = MaxSubNet[1];
			}
			
			if ((*it).dstIP_i[1] < MaxSubNet[1]){
				(*it).dstIP_i[0] = MaxSubNet[0];
				(*it).dstIP_i[1] = MaxSubNet[1];
			}
			
			(*it).srcIP_i[0] = (((*it).srcIP_i[0] >> sqBits) & maskAnd) + subnet[0];
			(*it).srcIP_i[1] = (*it).srcIP_i[1] + sqBits;
			if ((*it).srcIP_i[1] > 32)
				(*it).srcIP_i[1] = 32;
			(*it).dstIP_i[0] = (((*it).dstIP_i[0] >> sqBits) & maskAnd) + subnet[0];
			(*it).dstIP_i[1] = (*it).dstIP_i[1] + sqBits;
			if ((*it).dstIP_i[1] > 32)
				(*it).dstIP_i[1] = 32;
			
			it++;
		}
		else{
			it = handle.erase(it);
		}
	}
}

RuleList::~RuleList(){
}

// for debug
void RuleList::writeEachRule(string file_name){
	ofstream file;
	file.open(file_name.c_str());
	for (auto it = handle.begin(); it != handle.end(); ++it){
		file << get_dotDeci( (*it).srcIP_i) << " "<< get_dotDeci( (*it).dstIP_i) << " ";
		file << (*it).srcP_i[0] << ":" << (*it).srcP_i[1] << " " << (*it).dstP_i[0] << ":" << (*it).dstP_i[1]<<endl;
	}

	file.close();
}
