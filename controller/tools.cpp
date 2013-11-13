#include "tools.h"
using namespace std;

string get_dotDeci(const unsigned int (&ip_i)[2]){
	string dotdeci = "";
	dotdeci = boost::lexical_cast<string>((ip_i[0] >> 24) & 0xff);
	for(int i =1; i < 4; i++){
		dotdeci += ".";
		dotdeci += boost::lexical_cast<string>((ip_i[0] >> (24-8*i)) & 0xff);
	}
	return dotdeci + "/" + boost::lexical_cast<string>(ip_i[1]);
}



unsigned int maskIP(string ip_s, unsigned int mask){
	vector<string> splitedStr;
	boost::split(splitedStr, ip_s, boost::is_any_of("."));
	unsigned int ip_i = 0;
	for (unsigned int i = 0; i < 4; i++){
		ip_i += (boost::lexical_cast<int>(splitedStr[0]) << (24-8*i));
	}

	if (mask == 0)
		return ip_i;

	unsigned int maskAnd = (~unsigned(0)) << (32-mask);
	return ip_i & maskAnd;
}

bool classPack(const unsigned int (&packPred) [4], const unsigned int (&buckPred)[4][2]){
	for (int i = 0; i<4; i++){
		if (buckPred[i][1] == 0)
			continue;
		if ( i < 2){ //ip
			unsigned int maskAnd = (~unsigned(0)) << (32-buckPred[i][1]);
			if ((packPred[i] & maskAnd) != buckPred[i][0])
				return false;
		}
		else{ // port
			unsigned int maskAnd = (~unsigned(0)) << (16-buckPred[i][1]);
			if ((packPred[i] & maskAnd) != buckPred[i][0])
				return false;
		}
	}

	return true;
}

bool match(const unsigned int (&bucket_src)[2] , const unsigned int (&bucket_dst)[2], const unsigned int (&rule_src)[2], const unsigned int (&rule_dst)[2]){
	// obtain the shorter mask of rule mask and bucket mask. 
	unsigned int srcMsk = 0;
	(bucket_src[1] > rule_src[1])?(srcMsk = rule_src[1]):(srcMsk = bucket_src[1]);
	unsigned int dstMsk = 0;
	(bucket_dst[1] > rule_dst[1])?(dstMsk = rule_dst[1]):(dstMsk = bucket_dst[1]);
	

	if ( (bucket_src[0] & ((~unsigned(0)) << (32-srcMsk))) != (rule_src[0] & ((~unsigned(0)) << (32-srcMsk))))
		if (srcMsk!= 0)
			return false;
	
	if ( (bucket_dst[0] & ((~unsigned(0)) << (32-dstMsk))) != (rule_dst[0] & ((~unsigned(0)) << (32-dstMsk))))
		if (dstMsk!= 0)
			return false;

	return true;
}


bool match_check(const unsigned int (&bucket_src)[2], const unsigned int (&bucket_dst)[2], const unsigned int (&rule_src)[2], const unsigned int (&rule_dst)[2], bool &default_rule){
	unsigned int srcMsk = 0;
	(bucket_src[1] > rule_src[1])?(srcMsk = rule_src[1]):(srcMsk = bucket_src[1]);
	unsigned int dstMsk = 0;
	(bucket_dst[1] > rule_dst[1])?(dstMsk = rule_dst[1]):(dstMsk = bucket_dst[1]);


	if ( (bucket_src[0] & ((~unsigned(0)) << (32-srcMsk))) != (rule_src[0] & ((~unsigned(0)) << (32-srcMsk))))
		if (srcMsk!= 0)
			return false;
	
	if ( (bucket_dst[0] & ((~unsigned(0)) << (32-dstMsk))) != (rule_dst[0] & ((~unsigned(0)) << (32-dstMsk))))
		if (dstMsk!= 0)
			return false;
	
	if ((srcMsk == rule_src[1]) && (dstMsk == rule_dst[1]))
		default_rule = true; // this rule is covering the whole bucket
	else
		default_rule = false;
	return true;
}

bool rule_bucket_redu(const unsigned int (&bucketSrc)[2], const unsigned int (&bucketDst)[2], const unsigned int (&hiRule_src)[2], const unsigned int (&hiRule_dst)[2], const unsigned int (&rule_src)[2], const unsigned int (&rule_dst)[2]){
	unsigned int srcMsk = 0;
	unsigned int ruleSrcMsk = 0;
	unsigned int hiRuleSrcMsk = 0;
	(bucketSrc[1] > rule_src[1])?(ruleSrcMsk = bucketSrc[1]):(ruleSrcMsk = rule_src[1]);
	(bucketSrc[1] > hiRule_src[1])?(hiRuleSrcMsk = bucketSrc[1]):(hiRuleSrcMsk = hiRule_src[1]);
	(ruleSrcMsk > hiRuleSrcMsk)?(srcMsk = ruleSrcMsk):(srcMsk = hiRuleSrcMsk);

	
	unsigned int dstMsk = 0;
	unsigned int ruleDstMsk = 0;
	unsigned int hiRuleDstMsk = 0;
	(bucketDst[1] > rule_dst[1])?(ruleDstMsk = bucketDst[1]):(ruleDstMsk = rule_dst[1]);
	(bucketDst[1] > hiRule_dst[1])?(hiRuleDstMsk = bucketDst[1]):(hiRuleDstMsk = hiRule_dst[1]);
	(ruleDstMsk > hiRuleDstMsk)?(dstMsk = ruleDstMsk):(dstMsk = hiRuleDstMsk);

	if (srcMsk != 0){
		if ( (rule_src[0] & (~unsigned(0) << (32 - srcMsk))) != (hiRule_src[0] & (~unsigned(0) << (32 - srcMsk))) )
			return false;
	}
	else{
		if (rule_src[0] != hiRule_src[0])
			return false;
	}

	
	if (dstMsk != 0){
		if ( (rule_dst[0] & (~unsigned(0) << (32 - dstMsk))) != (hiRule_dst[0] & (~unsigned(0) << (32 - dstMsk))) )
			return false;
	}
	else{
		if (rule_dst[0] != hiRule_dst[0])
			return false;
	}

	return true;
}

void to_range(const unsigned int (&prefmsk)[2], unsigned int (&range)[2]){
	range[0] = prefmsk[0];
	if(prefmsk[1] != 0)
		range[1] = (prefmsk[0] + ((~unsigned(0)) >> (32 - prefmsk[0])));
	else
		range[1] = (~unsigned(0));
}
