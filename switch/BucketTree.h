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
	void init();

	public:
	unsigned int predicate[4][2]; // prefix/mask
	vector<unsigned short> relaRules;// corre rules
	OneBucket * sonList[SONNO];// son 
	
	OneBucket();
	OneBucket(const OneBucket&);
	OneBucket(string subNet_s);

	void RedRemove(RuleList *);

	// serialization
	friend class boost::serialization::access;
	
	template<class Archive> 
		void serialize(Archive &, const size_t);


	// debug
	void printInfo(); 
};

class BucketTree{
	// member
	public:
	OneBucket * bucketRoot;
	RuleList * ruleList;
	const int MAX_RULE; 
	const int MAX_LEVEL;
	int deciSpace [CombiSize][PAR];

	size_t bucketNo;
	size_t avgRuleNo;

	// func
	private:
	bool partition(OneBucket *, const size_t, const size_t);
	
	void delBucket(OneBucket *);
		
	public:
	BucketTree();
	BucketTree(RuleList*, string = "0.0.0.0/0", int = 10, int = 30);
	
	void dfsTreeCon(OneBucket *, const size_t, const size_t);
	void levTreeCon(OneBucket *, const size_t, const size_t);
	
	OneBucket* searchBucket(const size_t (&)[4], OneBucket*);

	void serializeTree(string);
	void deserializeTree(string);

	~BucketTree(){
		delBucket(bucketRoot);
	}

	// debug func
	public:	
	bool operator==(const BucketTree&) const; 

};

class BuckArray{
	public:
		OneBucket** buckArray;
		RuleList * ruleList;
		size_t arrayWid;

		BuckArray(RuleList*, size_t, string = "0.0.0.0/0");

		OneBucket * searchBucket( const size_t (&packPred)[4]);
		
		~BuckArray(); 

};
#endif
