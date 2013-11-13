#ifndef __PARSER_H
#define __PARSER_H

#include "tools.h"

using namespace std;


class OneRule;


// parsing the rule file into a OneRule type vector, remove redundancy
class RuleList{
	typedef vector<OneRule> RuleRec_T;

	private:
	OneRule parseAline (string); // parse each line of rule file
	
	public:
	int size;
	RuleRec_T handle; // rule vector handle
	RuleList(const char*);
	void removeRedundant(); // remove the redundant rules
	~RuleList();
};

// structure for one rule
class OneRule{
	public:
	unsigned int srcIP_i[2];
	unsigned int dstIP_i[2];
	unsigned int srcP_i[2];
	unsigned int dstP_i[2];
	unsigned int protocol;

	OneRule(){
		srcIP_i[0] = 0;
		srcIP_i[1] = 0;
		dstIP_i[0] = 0;
		dstIP_i[1] = 0;
		srcP_i[0] = 0;
		srcP_i[1] = 0;
		dstP_i[0] = 0;
		dstP_i[1] = 0;
		protocol = 0;
	}

	// comparing equal rules
	bool operator==(const OneRule& rule){
		if (srcIP_i[0] != rule.srcIP_i[0])
			return false;
		if (srcIP_i[1] != rule.srcIP_i[1])
			return false;

		if (dstIP_i[0] != rule.dstIP_i[0])
			return false;
		if (dstIP_i[1] != rule.dstIP_i[1])
			return false;

		if (srcP_i[0] != rule.srcP_i[0])
			return false;
		if (srcP_i[1] != rule.srcP_i[1])
			return false;
		if (dstP_i[0] != rule.dstP_i[0])
			return false;
		if (dstP_i[1] != rule.dstP_i[1])
			return false;
		if (protocol != rule.protocol)
			return false;

		return true;
	}
	
	bool match_rule(const unsigned int (&src_preMsk)[2], const unsigned int (&dst_preMsk)[2]) const{
		return match(src_preMsk, dst_preMsk, srcIP_i, dstIP_i);
	}
	
	bool match_rule_defaultCheck(const unsigned int (&src_preMsk)[2], const unsigned int (&dst_preMsk)[2], bool & is_def_rule) const{
		return match_check(src_preMsk, dst_preMsk, srcIP_i, dstIP_i, is_def_rule);
	}
	
	bool bucket_red(const unsigned int (&bucketSrc)[2], const unsigned int (&bucketDst)[2], const OneRule & hiRule) const{
		return rule_bucket_redu(bucketSrc, bucketDst, hiRule.srcIP_i, hiRule.dstIP_i, srcIP_i, dstIP_i);
	}


	// for debug: print out parsed rule
	void print(){
		cout << "srcIP:" << get_dotDeci(srcIP_i);
		cout << " dstIP:" << get_dotDeci(dstIP_i);
		cout << " srcPort:["<<srcP_i[0]<<","<<srcP_i[1]<<"]";
		cout << " dstPort:["<<dstP_i[0]<<","<<dstP_i[1]<<"]";
		cout << " proto:" << protocol;
		cout << endl;
	}
};

#endif
