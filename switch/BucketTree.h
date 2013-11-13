#ifndef BUCKET_TREE_H
#define BUCKET_TREE_H

#include "tools.h"
#include "RuleParsing.h"
#include "RedRemoval.h"

class OneBucket;

static const int SONNO = 4;
static const int PAR = 2;
static const int CombiSize = 6; // C 4 2;

class OneBucket{
	private:
	void init(){
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 2; j++)
				predicate[i][j] = 0;
		}
	
		relaRules.reserve(0);
		for (int i = 0; i < SONNO; i++)
			sonList[i] = NULL;
	}
	
	public:
	unsigned int predicate[4][2]; // prefix/mask
	vector<unsigned short> relaRules;// corre rules
	OneBucket * sonList[SONNO];// son 
	
	OneBucket(){
		init();
	}

	OneBucket(const OneBucket& buck){
		init();
		for (int i = 0; i < 4; i++){
			for (int j = 0; j < 2; j++)
				predicate[i][j] = buck.predicate[i][j];
		}
		relaRules = buck.relaRules;
	}
	
	OneBucket(string subNet_s){
		init();
		vector<string> fields;
		boost::split(fields, subNet_s, boost::is_any_of("/"));
		predicate[0][0] = maskIP(fields[0], atoi(fields[1].c_str()));
		predicate[0][1] = atoi(fields[1].c_str());
		predicate[1][0] = maskIP(fields[0], atoi(fields[1].c_str()));
		predicate[1][1] = atoi(fields[1].c_str());
	}

	void RedRemove(RuleList *);

	friend class boost::serialization::access;// serialization
	
	template<class Archive>
		void serialize(Archive & ar, const unsigned int ){	
			ar & predicate; // array
			ar & relaRules;
			ar & sonList; // array
		}


	// debug
	void printInfo(){ 
		cout<<"src:"<<get_dotDeci(predicate[0])<<" dst:"<<get_dotDeci(predicate[1])<<" srcP:";
		cout<<predicate[2][0]<<"-"<< (predicate[2][0] + (1 << (16 - predicate[2][1])) - 1)<<" dstP:";
		cout<<predicate[3][0]<<"-"<< (predicate[3][0] + (1 << (16 - predicate[2][1])) - 1) <<endl;
		cout<<"ruleInv:";
		for (size_t i = 0; i<relaRules.size(); i ++)
			cout<<relaRules[i] << " ";
		cout<<endl;
	}
};

class BucketTree{
	public:
	OneBucket * bucketRoot;
	RuleList * ruleList;
	const int MAX_RULE; 
	const int MAX_LEVEL;

	// debug;
	size_t bucketNo;
	size_t avgRuleNo;
	unordered_map<size_t, size_t> permRuleID;

	BucketTree(): MAX_RULE(0), MAX_LEVEL(0){
		bucketRoot = NULL;
	}
	
	BucketTree(RuleList* rl, string subnet_s = "0.0.0.0/0", int maxrule = 10, int maxlev = 30): MAX_RULE(maxrule), MAX_LEVEL(maxlev){
		ruleList = rl;
		bucketNo = 0; // debug
		avgRuleNo = 0; // debug

		bucketRoot = new OneBucket(subnet_s);

		for (int i = 0; i< ruleList->size; i++){
			bucketRoot->relaRules.push_back(i);
		}

		bucketRoot->RedRemove(ruleList);
		cout<<"root ruleNo: "<<bucketRoot->relaRules.size()<<endl; 
		// compute deci space
		vector<bool> v(4);
		fill(v.begin()+PAR, v.end(), false);
		fill(v.begin()+PAR, v.end(), true);
		int idxP = 0;
		int idxC = 0;
		do{
			idxP = 0;
			for(int i = 0; i<4; ++i){
				if(!v[i]){
					deciSpace[idxC][idxP] = i;
					idxP++;
				}
			}
			idxC ++;
		}while(next_permutation(v.begin(), v.end()));

		dfsTreeCon(bucketRoot, MAX_RULE, MAX_LEVEL-1);

		cout<<"Bucket No: "<< bucketNo<<endl;
		cout<<"avg rule no: "<<avgRuleNo/bucketNo<<endl;
	}
	/*	
	BucketTree(RuleList *rl, const char* file_name, int maxrule = 10, int maxlev = 10): MAX_RULE(maxrule), MAX_LEVEL(maxlev){
		ruleList = rl;
		ifstream ifs(file_name);
		boost::archive::text_iarchive ia(ifs);
		ia >> bucketRoot; // after this? 
	}*/

	OneBucket * searchBucket( const unsigned int (&packPred)[4], OneBucket * root){
		for(int i = 0; i< SONNO; i++){
			if (root->sonList[i] == NULL){
				return root;
			}

			if (classPack(packPred, root->sonList[i]->predicate))
				return searchBucket(packPred, root->sonList[i]);
		}
		return NULL;
	}
	
	void dfsTreeCon(OneBucket *, const size_t, const size_t);

	void levTreeCon(OneBucket *, const size_t, const size_t);

	~BucketTree(){
		delBucket(bucketRoot);
	}

	private:
	int deciSpace [CombiSize][PAR];
	bool partition(OneBucket *, const size_t, const size_t);
	void delBucket(OneBucket * bucketPtr){
		for(int i = 0; i<SONNO; i++){
			if (bucketPtr->sonList[i] != NULL )
				delBucket(bucketPtr->sonList[i]);
		}
		delete bucketPtr;
	}
	
	void serializeTree(string file_name){
		ofstream ofs(file_name.c_str());
		boost::archive::text_oarchive oa(ofs);
		oa << bucketRoot;
	}

};

class BuckArray{
	public:
		OneBucket** buckArray;
		RuleList * ruleList;
		size_t arrayWid;

		BuckArray(RuleList*, size_t, string);

		OneBucket * searchBucket( const size_t (&packPred)[4]);
		
		~BuckArray(); 

};
#endif
