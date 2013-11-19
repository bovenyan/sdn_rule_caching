#include "tools.h"
#include "RuleParsing.h"
#include "RedRemoval.h"
#include "BucketTree.h"
//#include "OFswitch.h"

using namespace std;
using Z::Rule;

int main(){
	/*for (size_t cc = 1; cc<=20; cc++){
		string cc_s = to_string(cc*500);
	string ruleDir = "../classbench/rulesets/rule"+cc_s;
	RuleList RuleRec(ruleDir);
	cout<<"Rule got a size of "<< RuleRec.size <<endl;
	size_t total_counter = 0;
	for (auto iter = RuleRec.handle.begin(); iter != RuleRec.handle.end(); iter++){
		size_t match_counter = 0;
		for (auto iter_o = RuleRec.handle.begin(); iter_o != RuleRec.handle.end(); iter_o++){
			if (iter->match_rule(iter_o->srcIP_i, iter_o->dstIP_i)){
				match_counter ++;
			}
		
		}
		total_counter += match_counter;
	}
	cout<<"Each rule is on average overlapped with "<< total_counter/RuleRec.size<< " other rules"<<endl;
	}
	
	return 0;*/
	
	
	
	string ruleDir = "../classbench/db_generator/MyFilters300";
	RuleList RuleRec(ruleDir);
	BucketTree BuckTree( &RuleRec);
	BucketTree BuckTree2;
	BuckTree2.ruleList = &RuleRec;
	BuckTree.serializeTree("testSeri.txt");
	BuckTree2.deserializeTree("testSeri.txt");

	if (BuckTree == BuckTree2)
		cout<<"equal"<<endl;
	else
		cout<<"inequal"<<endl;

	/*
	cout<<"Finish bucket and tree construction"<<endl;
	
	configuration config;
	config.trace_file = "../classbench/db_generator/MyFilters300_trace";
	config.testDur = 2000;
	config.samplingTime = 10;
	config.tokenGenInt = 1.0;
	config.maxTokenNo = 5;
	config.bandwidth = 9999;
	config.buckTimeOut = 5;
	config.buckMaxSize = 300;
	config.lambda = 1.0;

	statistics stat;
	stat.hitNo = 0;
	stat.missNo = 0;
	stat.pck_qDelay = 0.0;
	stat.rule_downNo = 0;
	stat.total_reqNo_sampT = 0;
	*/



	/*
	OFswitch ofs(&RuleRec, &BuckTree);
	ofs.ProcTrace_s(config, stat);

	cout<< "finish all:"<<endl;
	cout<< stat.hitNo+stat.missNo <<  "  packets are dealt" <<endl;
	cout<< "packet queuing delay is " << stat.pck_qDelay/(stat.hitNo+stat.missNo) <<endl;
	cout<< stat.rule_downNo/config.testDur<< " policy rules are downloaded per unit time" <<endl;
	cout<< stat.total_reqNo_sampT/config.testDur << " bucket rules are downloaded per unit time"<<endl;
	*/
	/*	
	string ruleDir = "../classbench/db_generator/Filters10k";
	string subnet_s = "10.2.0.0/16";
	RuleList RuleRec(ruleDir);
	RuleRec.condense(subnet_s, 8);
	cout<<"ruleNo:"<<RuleRec.handle.size()<<endl;
	RuleRec.writeEachRule("ruleTest");
	*/
	//BucketTree BuckTree(&RuleRec, subnet_s);
	


	// test trace processing
	/*string ruleDir = "../classbench/db_generator/Filters10k";
	string subnet_s = "10.2.0.0/16";
	
	RuleList RuleRec(ruleDir);
	RuleRec.condense(subnet_s, 8);
	BucketTree BuckTree( &RuleRec, subnet_s);
	
	string trace_dir = "/mnt/hgfs/VMSharedFolder/RawDataGenerator/packData";
	OFswitch ofs(&RuleRec, &BuckTree);
	ofs.ProcTrace(trace_dir, 200, 1, 5, subnet_s); 
	*/
	// test tree generation
	/*
	string ruleDir = "../classbench/db_generator/Filters10k";
	string subnet_s = "10.0.0.0/8";
	
	RuleList RuleRec(ruleDir.c_str());
	BucketTree BuckTree( &RuleRec, subnet_s);
	*/


	// test redundancy removal
	/*
	
	string ruleDir = "../classbench/db_generator/Filters10k";
	//string ruleDir = "FiltersErr";
	
	RuleList ruleRec(ruleDir.c_str());
	
	
	// ruleRec.removeRedundant();
	cout<<"raw rule no: "<<ruleRec.size<<endl;
	vector<Rule> ruleVec;
	vector<unsigned short> idxList;
	for(int i = 0; i < ruleRec.size; ++i)
		idxList.push_back((unsigned short)(i));
		
	ORtoR( &ruleRec, idxList, ruleVec);
	cout<<"tranfered size: "<<ruleVec.size()<<endl;	
	Rule bucketRange;
	bucketRange.S[0][0] = 0x0a000000;
	bucketRange.S[0][1] = 0x0affffff;
	bucketRange.S[1][0] = 0x0a000000;
	bucketRange.S[1][1] = 0x0affffff;
	bucketRange.S[2][0] = 0x00000000;
	bucketRange.S[2][1] = 0x0000ffff;
	bucketRange.S[3][0] = 0x00000000;
	bucketRange.S[3][1] = 0x0000ffff;
	vector<size_t> rule_no_red;
	Redundancy_Filter(ruleVec, bucketRange, rule_no_red);
	cout<<"no red rule no: "<<rule_no_red.size()<<endl;
	
	ifstream input;
	input.open(ruleDir.c_str());
	ofstream output;
	output.open("FilterLog");

	string line;
	size_t idx = 0;
	size_t curIdx = 0;
	while(!input.eof()){
		getline(input, line);
		if(idx == rule_no_red[curIdx]){
			curIdx ++ ;
			output<<line<<endl;
		}
		idx++;
	}
	input.close();
	output.close();
	
	
	for(unsigned int i = 0; i < 0xff; i++){
		bucketRange.S[0][0] = 0x00000000 + (i << 24);
		bucketRange.S[0][1] = 0x00ffffff + (i << 24);
		bucketRange.S[1][0] = 0x00000000 + (i << 24);
		bucketRange.S[1][1] = 0x00ffffff + (i << 24);
		bucketRange.S[2][0] = 0x00000000;
		bucketRange.S[2][1] = 0x0000ffff;
		bucketRange.S[3][0] = 0x00000000;
		bucketRange.S[3][1] = 0x0000ffff;
		
		vector<size_t> rule_no_red;
		Redundancy_Filter(ruleVec, bucketRange, rule_no_red);
		cout<< i <<": no red rule no: "<<rule_no_red.size()<<endl;
		
	}*/

	// test combination generator
	/*
	int PAR = 2;

	vector<bool> v(4);
	fill(v.begin()+PAR, v.end(), false);
	fill(v.begin()+PAR, v.end(), true);


	do{
		for(int i = 0; i<4; ++i){
			if(!v[i]){
				cout<<(i+1)<< " ";
			}
		}
		cout<<endl;
	}while(next_permutation(v.begin(), v.end()));
	*/
	
	// test gzip read
	/*
	std::ifstream file("testGZ.gz", std::ios_base::in | std::ios_base::binary);
	try{
		boost::iostreams::filtering_istream in;
		in.push(boost::iostreams::gzip_decompressor());
		in.push(file);
		int counter = 0;
		for(std::string str; std::getline(in,str); )
		{
			if (counter == 10)
				break;
			std::cout<<"PL: "<< str << '\n';
			counter++;
		}
	}
	catch(const boost::iostreams::gzip_error& e){
		std::cout<< e.what() << '\n';
	}
	*/

	return 0;
};
