#include "RuleParsing.h"
#include "tools.h"
#include "QuadTree.h"

int main(int argc, char* argv[]){
	int max_bucketSize = 50;
	int min_bucketScope = 10;
	string ruleDir= "Filters10k";
	string bucketDir = "BucketList";
	for(int i = 0; i<argc; i++){
		if ( !strcmp(argv[i], "-maxsize"))
			max_bucketSize = boost::lexical_cast<int>(argv[i+1]);
		if ( !strcmp(argv[i], "-minscope"))
			min_bucketScope = boost::lexical_cast<int>(argv[i+1]);
		if ( !strcmp(argv[i], "-input"))
			ruleDir = argv[i+1];
		if ( !strcmp(argv[i], "-output"))
			bucketDir = argv[i+1];
	}
	
	if (max_bucketSize < 2)
		return 1;
	if (min_bucketScope > 32)
		return 32;
	if (min_bucketScope <0)
		return 0;

	RuleList ruleRec(ruleDir.c_str());
	ruleRec.removeRedundant();
	
	cout<<"Non-redundant rule records in the rule file is: "<<ruleRec.size<<endl;

	BucketRec bucketGen(ruleRec, max_bucketSize, min_bucketScope); //NOTE: SETTING HERE TO CUSTOMIZE BUCKET SIZE AND MINIMUM SCOPE. advice: do not use bucket scope larger than 11, given 10k rules this will exhaust your memory

	bucketGen.writeBucket(bucketDir);	

	return 0;
}
