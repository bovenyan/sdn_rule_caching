#ifndef __QUADTREE_H
#define __QUADTREE_H

#include <stack>
//#include <list>
#include "RuleParsing.h"

using namespace std;

// typedef vector<unsigned int> Pref_Msk_T;

/// BucketNode class covers the intermediate nodes when constructing quad tree
class BucketNode{
	public:
		unsigned int prefMsk_src[2];
		unsigned int prefMsk_dst[2];
		vector<short int> rule_list; // can only manage upto 65536 rules;
		bool is_def_rule; // exist a default rule in this bucket

		BucketNode();
		BucketNode(unsigned int (&)[2], unsigned int (&)[2], vector<short int>, bool);
		
		void quadCut(const RuleList&, vector<BucketNode*> &);
		void printNode(bool, ofstream &);
		void remove_low_prior(const RuleList &);

};

/// BucketRec covers constructing and recording quadtree
class BucketRec{
	private:
		const RuleList& ruleRecord; // Parsed rule
		unsigned int THRESHOLD; // maximum bucket size, upper bound of rules in a bucket (SEE README for detail) 
		unsigned int MIN_BUCKET_SCOPE; // minimum tree scope. i.e. /8 /8 scope defines that bucket 
		BucketNode * rootBucket; // original bucket to cut. default /0 /0.
		
	public:	
		BucketRec(const RuleList&, const int &, const int &); // constructor which determines all the members
		
		void obtainBuckets(ofstream &, BucketNode *); // for constructing and recording buckets

		void writeBucket(string); // start record the buckets

};
#endif

