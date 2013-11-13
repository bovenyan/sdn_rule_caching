#include "QuadTree.h"

/// BucketNode CLASS
BucketNode::BucketNode(){
	prefMsk_src[0] = 0;
	prefMsk_src[1] = 0;
	prefMsk_dst[0] = 0;
	prefMsk_dst[1] = 0;
	is_def_rule = false;
}

BucketNode::BucketNode(unsigned int (&srcPM)[2], unsigned int (&dstPM)[2], vector<short int> rLst, bool def_rule){
	prefMsk_src[0] = srcPM[0];
	prefMsk_src[1] = srcPM[1];
	prefMsk_dst[0] = dstPM[0];
	prefMsk_dst[1] = dstPM[1];
	rule_list = rLst;
	is_def_rule = def_rule;
}

void BucketNode::remove_low_prior(const RuleList & ruleRec){
	// consider union $$ HERE IS A BUG
	for (int i = rule_list.size()-1; i>=0; i--){
		for (int j = rule_list.size()-1; j>=i+1; j--){
			if (ruleRec.handle[j].bucket_red(prefMsk_src, prefMsk_dst, ruleRec.handle[i]))
				rule_list.erase(rule_list.begin() + j);
		}
	}
}

void BucketNode::quadCut(const RuleList& ruleRec, vector<BucketNode*> &cutNodeList){
	unsigned int cutSize = 4;

	bool effective = false; // if there's no change by cutting things, then it's not effective

	unsigned int maxCheck = rule_list.size(); // don't save defalut rule to lower nodes
	if (is_def_rule)
		maxCheck = maxCheck - 1;

	for (unsigned int idx = 0; idx < cutSize; idx++){
		unsigned int newPref_src = prefMsk_src[0] + ((idx/2) << (31-prefMsk_src[1]));
		unsigned int newPref_dst = prefMsk_dst[0] + ((idx - (idx/2)*2) << (31-prefMsk_dst[1]));
			
		
		unsigned int newPrefM_src[2];
		unsigned int newPrefM_dst[2];
		newPrefM_src[0] = newPref_src; 
		newPrefM_src[1] = prefMsk_src[1]+1;
		newPrefM_dst[0] = newPref_dst;
		newPrefM_dst[1] = prefMsk_dst[1]+1;

		vector<short int> newRule_list;
		bool new_is_def_rule = false;
		// split the parent node and find matched rules in son buckets
		for (unsigned int ruleIdx = 0; ruleIdx < maxCheck; ruleIdx++){
			// check whether it's a default rule in this bucket (covering whole)
			if ((ruleRec.handle[rule_list[ruleIdx]]).match_rule_defaultCheck(newPrefM_src, newPrefM_dst, new_is_def_rule))
				newRule_list.push_back(rule_list[ruleIdx]);
			else
				effective = true; // if there's some rule not included, then cutting reduce rule 
			if (new_is_def_rule)
				break; // there exist a covering default rule, no need to check lower-priority one.
		}
		
		if (newRule_list.size() != 0) // exclude empty bucket
			cutNodeList[idx] = new BucketNode(newPrefM_src, newPrefM_dst, newRule_list, new_is_def_rule);
		else
			cutNodeList[idx] = NULL;
	}

	if (!effective) // cut does not split the rules. abort the cut
		for (unsigned int idx = 0; idx < cutSize; idx++){
			delete cutNodeList[idx];
			cutNodeList[idx] = NULL;
		}
}

void BucketNode::printNode(bool leaf_node, ofstream & file){
	if (leaf_node)
		file << get_dotDeci(prefMsk_src) + "\t" + get_dotDeci(prefMsk_dst) + "\t" + boost::lexical_cast<string> (rule_list.size()) <<endl;
	else{
		if (is_def_rule)
			file << get_dotDeci(prefMsk_src) + "\t" + get_dotDeci(prefMsk_dst) + "\t" <<"def" <<endl; 

	}
}

/// BucketRec CLASS
BucketRec::BucketRec(const RuleList& ruleRec, const int &max_size, const int & min_scope):ruleRecord(ruleRec), THRESHOLD(max_size), MIN_BUCKET_SCOPE(min_scope){
	rootBucket = new BucketNode(); // setting this part can resize the beginning scope
	
	for (unsigned short int ruleIdx = 0; ruleIdx < (unsigned) ruleRec.size; ruleIdx ++){
		rootBucket->rule_list.push_back(ruleIdx);
	}

}

void BucketRec::obtainBuckets(ofstream & bucketFile, BucketNode * dealNode){
	
	// delete redundant rules in this node
	dealNode->remove_low_prior(ruleRecord);		
	
	bool isLeafNode = true; 

	if ((dealNode->prefMsk_src[1] <= MIN_BUCKET_SCOPE-1) && (dealNode->rule_list.size() > THRESHOLD)){ // max_size or min_scope reached, do not cut
		vector<BucketNode *> sonBucket_lst;
		for (int i = 0; i<4; i++)
			sonBucket_lst.push_back(NULL);

		dealNode->quadCut(ruleRecord, sonBucket_lst);
		for (int i = 0; i<4; i++){ 
			if (sonBucket_lst[i]!=NULL){ // has son, valid cut
				obtainBuckets(bucketFile, sonBucket_lst[i]); // DFS search
				isLeafNode = false;
			}
		}
	}
	
	dealNode->printNode(isLeafNode, bucketFile);

	delete dealNode; // release the dynamic alloc son;
}

void BucketRec::writeBucket(string fileName){
	ofstream bucketFile;
	bucketFile.open(fileName.c_str());
	obtainBuckets(bucketFile, rootBucket);
	bucketFile.close();
}

