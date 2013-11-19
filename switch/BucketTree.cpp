#include "BucketTree.h"

using Z::Rule; using Z::Redundancy_Filter; using Z::ORtoR;

/* ------------------- Class OneBucket -------------------------------------------------------------------
 *
*/

// Constructors:
OneBucket::OneBucket(){
	init();
}

OneBucket::OneBucket(const OneBucket & buck){
	init();
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 2; j++)
			predicate[i][j] = buck.predicate[i][j];
	}
	relaRules = buck.relaRules;
}

OneBucket::OneBucket(string subNet_s){
	init();
	vector<string> fields;
	boost::split(fields, subNet_s, boost::is_any_of("/"));
	predicate[0][0] = maskIP(fields[0], atoi(fields[1].c_str()));
	predicate[0][1] = atoi(fields[1].c_str());
	predicate[1][0] = maskIP(fields[0], atoi(fields[1].c_str()));
	predicate[1][1] = atoi(fields[1].c_str());
}


// Initialize each bucket
void OneBucket::init(){
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 2; j++)
			predicate[i][j] = 0;
	}

	relaRules.reserve(0);
	for (int i = 0; i < SONNO; i++)
		sonList[i] = NULL;
}

// Redundancy removal of overlapped rule
void OneBucket::RedRemove(RuleList * ruleObj){
	vector<Rule> fdd_ruleList;
	ORtoR(ruleObj, relaRules, fdd_ruleList);
	// parse bucket to rule
	Rule bucket_boundary;
	if (predicate[0][1] == 0){
		bucket_boundary.S[0][0] = 0;
		bucket_boundary.S[0][1] = 0xffffffff;
	}
	else{
		bucket_boundary.S[0][0] = predicate[0][0];
		bucket_boundary.S[0][1] = predicate[0][0] + ( 1 << (32 - predicate[0][1])) - 1;
	}

	if (predicate[1][1] == 0){
		bucket_boundary.S[1][0] = 0;
		bucket_boundary.S[1][1] = 0xffffffff;
	}
	else{
		bucket_boundary.S[1][0] = predicate[1][0];
		bucket_boundary.S[1][1] = predicate[1][0] + ( 1 << (32 - predicate[1][1])) - 1;
	}

	bucket_boundary.S[2][0] = predicate[2][0];
	bucket_boundary.S[2][1] = predicate[2][0] + ( 1 << (16 - predicate[2][1])) - 1;
	
	bucket_boundary.S[3][0] = predicate[3][0];
	bucket_boundary.S[3][1] = predicate[3][0] + ( 1 << (16 - predicate[3][1])) - 1;
	
	vector<size_t> relaID;
	

	Redundancy_Filter(fdd_ruleList, bucket_boundary, relaID);
	
	vector<unsigned short> noRedRuleID;
	for(size_t i = 0; i < relaID.size(); i ++){
		noRedRuleID.push_back(relaRules[relaID[i]]);
	}

	relaRules = noRedRuleID;
}

// serialization
template<class Archive>
void OneBucket::serialize(Archive &ar, const size_t version){
	ar & predicate; // array
	ar & relaRules;
	ar & sonList; // array
}

// debug
void OneBucket::printInfo(){
	cout<<"src:"<<get_dotDeci(predicate[0])<<" dst:"<<get_dotDeci(predicate[1])<<" srcP:";
	cout<<predicate[2][0]<<"-"<< (predicate[2][0] + (1 << (16 - predicate[2][1])) - 1)<<" dstP:";
	cout<<predicate[3][0]<<"-"<< (predicate[3][0] + (1 << (16 - predicate[2][1])) - 1) <<endl;
	cout<<"ruleInv:";
	for (size_t i = 0; i<relaRules.size(); i ++)
		cout<<relaRules[i] << " ";
	cout<<endl;
}

/* ------------------- Class BucketTree -------------------------------------------------------------------
 *
*/

// Constructors:
BucketTree::BucketTree(): MAX_RULE(0), MAX_LEVEL(0){
	bucketRoot = NULL;
	ruleList = NULL;
}

BucketTree::BucketTree(RuleList* rl, string subnet_s, int maxrule, int maxlev):MAX_RULE(maxrule), MAX_LEVEL(maxlev){
	ruleList = rl;
	bucketNo = 0; 
	avgRuleNo = 0;

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

OneBucket* BucketTree::searchBucket( const size_t (&packPred)[4], OneBucket * root){
	for(int i = 0; i< SONNO; i++){
		if (root->sonList[i] == NULL){
			return root;
		}
		if (classPack(packPred, root->sonList[i]->predicate))
			return searchBucket(packPred, root->sonList[i]);
	}
	return NULL;
}


// Tree construction using Depth-First-Search
void BucketTree::dfsTreeCon(OneBucket * parentPtr, const size_t MaxRuleNo, const size_t restDept){
	if (partition(parentPtr, MaxRuleNo, restDept)){
		for (int i = 0; i < SONNO; i++)
			dfsTreeCon(parentPtr->sonList[i] , MaxRuleNo, restDept-1);
	}
}

// Tree construction using Level-Order-Traversal
void BucketTree::levTreeCon(OneBucket * parentPtr, const size_t MaxRuleNo, const size_t deptLim){
	list<OneBucket*> levQue;
	levQue.push_back(parentPtr);
	size_t curLevToDeal = 1;
	size_t nextLevToDeal = 0;
	size_t currentLev = 0;
	OneBucket * dealingBuck;
	
	vector <unsigned short> preAllocRules = parentPtr->relaRules; 

	while (!levQue.empty()){
		dealingBuck = levQue.front();
		
		if (partition(dealingBuck, MaxRuleNo, deptLim-currentLev)){
			for(size_t i = 0; i <SONNO; i++)
				levQue.push_back(dealingBuck->sonList[i]);
			nextLevToDeal += SONNO;
		}

		levQue.pop_front();
		curLevToDeal--;

		if (curLevToDeal == 0){
			curLevToDeal = nextLevToDeal;
			nextLevToDeal = 0;
			currentLev ++;
			
			if (currentLev == deptLim/3){ // delete rules with large range
				cout<<"cur son no: " << levQue.size()<<endl;
				size_t rulerem = 0;
				for (auto rule_iter = preAllocRules.begin(); rule_iter != preAllocRules.end();){
					size_t sharedNo = 0;
					for (auto buck_iter = levQue.begin(); buck_iter != levQue.end(); buck_iter ++){
						for (auto find_iter = (*buck_iter)->relaRules.begin(); find_iter != (*buck_iter)->relaRules.end(); find_iter++){
							if (*find_iter == *rule_iter)
								sharedNo ++;
						}
					}

					if ( double(sharedNo)/levQue.size() > 0.5 ){
						rule_iter = preAllocRules.erase(rule_iter);
						rulerem ++;
					}
					else
						rule_iter++;
				}
				cout<<"rule removed: "<< rulerem <<endl;
				
				for (auto rule_iter = preAllocRules.begin(); rule_iter != preAllocRules.end(); rule_iter++){
					for (auto buck_iter = levQue.begin(); buck_iter != levQue.end(); buck_iter ++){
						for (auto find_iter = (*buck_iter)->relaRules.begin(); find_iter != (*buck_iter)->relaRules.end();){
							if (*find_iter == *rule_iter)
								find_iter = (*buck_iter)->relaRules.erase(find_iter);
							else 
								find_iter++;
						}
					}
				}

			}

		}
	}
}



// Partition the node and get the lowest avg rule count
// return: true if cut sucess, otherwise false
bool BucketTree::partition(OneBucket * parentPtr, const size_t MaxRuleNo, const size_t restDept){
	
	if (parentPtr->relaRules.size() <= MaxRuleNo || restDept == 0){ // stop condition 1
		if (parentPtr ->relaRules.size() > 20){
			cout<<"stop condition 1"<<endl;
		}
		avgRuleNo += parentPtr->relaRules.size();
		bucketNo ++;
		return false;
	}

	unsigned int avgRule = parentPtr->relaRules.size() + 1;

	for (int i = 0; i < CombiSize; i++){ // check all possible cut combination
		// determine reach end	
		bool effective = true;
		for (int k = 0; k <PAR; k++){
			if(deciSpace[i][k] < 2){ // ip
				if (parentPtr->predicate[deciSpace[i][k]][1] == 32)
					effective = false;
			}
			else{ // port
				if (parentPtr->predicate[deciSpace[i][k]][1] == 16)
					effective = false;
			}
		}

		if(!effective)
			continue;
		
		// generate buckets according to cut
		size_t avgRule_c = 0;
		OneBucket * tempSon[SONNO];
		for (int j = 0; j < SONNO; j++){
			tempSon[j] = new OneBucket(*parentPtr); // copy from paremt
			bitset<PAR> jbit (j);
			for (int k = 0; k < PAR; k++){ 
				unsigned int incre = 1;
				unsigned int & pref = tempSon[j]->predicate[deciSpace[i][k]][0];
				unsigned int & mask = tempSon[j]->predicate[deciSpace[i][k]][1];

				if ( deciSpace[i][k] < 2){ // ip
					incre = (incre << (31 - mask));
				}
				else // port
					incre = (incre << (15 - mask));

				if (jbit.test(k))
					pref += incre;	// pref + 1;
				
				mask += 1;	 // mask+1
			}

			tempSon[j]->RedRemove(ruleList);
			
			avgRule_c += tempSon[j]->relaRules.size();
		}

		if (avgRule_c/4 < avgRule){
			for (int j = 0; j < SONNO; j ++){
				delete parentPtr->sonList[j];
				parentPtr->sonList[j] = tempSon[j];
			}
			avgRule = avgRule_c/4;
		}
		else{
			for (int j = 0; j < SONNO; j ++)
				delete tempSon[j];
		}
	}
	
	if (avgRule >= parentPtr->relaRules.size()){ // stop condition 2 
		//avgRuleNo += parentPtr->relaRules.size();
		//cout<<"  rl no:" << parentPtr->relaRules.size();
		if (parentPtr ->relaRules.size() > 20){
			cout<<"stop condition 2"<<endl;
		}
		bucketNo ++;
		for (int j = 0; j < SONNO; j++)
			delete parentPtr->sonList[j];
		return false;
	}
	else{	// DFS
		return true;

	}
}

// serialization
void BucketTree::serializeTree(string file_name){
	ofstream ofs(file_name.c_str());
	boost::archive::text_oarchive oa(ofs);
	oa << bucketRoot;
}

// de-serialization
void BucketTree::deserializeTree(string file_name){
	ifstream ifs(file_name.c_str());
	boost::archive::text_iarchive ia(ifs);
	ia >> bucketRoot;
}

void BucketTree::delBucket(OneBucket * bucketPtr){
	for(int i = 0; i<SONNO; i++){
		if (bucketPtr->sonList[i] != NULL )
			delBucket(bucketPtr->sonList[i]);
	}
	delete bucketPtr;
}

// debug function
bool BucketTree::operator==(const BucketTree& other) const{
	queue<OneBucket*> buffer;
	queue<OneBucket*> buffer_other;

	buffer.push(bucketRoot);
	buffer_other.push(other.bucketRoot);

	while(!buffer.empty()){
		// compare predicate
		for (int i= 0; i<4; i++){
			for (int j=0; j<2; j++){
				if (buffer.front()->predicate[i][j] != buffer_other.front()->predicate[i][j])
					return false;
			}
		}
		
		// compare relaRules
		if (buffer.front()->relaRules.size()!=buffer_other.front()->relaRules.size())
			return false;
		for(size_t i = 0; i < buffer.front()->relaRules.size(); i++){
			if (buffer.front()->relaRules[i] != buffer_other.front()->relaRules[i])
				return false;
		}
		// compare and push son
		
		for (int i = 0; i<SONNO; i++){
			if (buffer.front()->sonList[i] == NULL){
				if (buffer_other.front()->sonList[i] != NULL)
					return false;
				continue;
			}

			if (buffer_other.front()->sonList[i] == NULL){
				if (buffer.front()->sonList[i] != NULL)
					return false;
				continue;
			}
			buffer.push(buffer.front()->sonList[i]);
			buffer_other.push(buffer_other.front()->sonList[i]);
		}
		
		buffer.pop();
		buffer_other.pop();
	}
	return true;
}


/* ------------------- Class BuckArray -------------------------------------------------------------------
 *
*/

BuckArray::BuckArray(RuleList* rl, size_t buckNo, string subnet_s){
	ruleList = rl;
	arrayWid = (size_t)pow(buckNo, 0.5) + 1;
	buckArray = new OneBucket* [arrayWid];
	for (int i = 0; i< arrayWid; i++){
		buckArray[i] = new OneBucket[arrayWid];
		
		for (int j = 0; j < arrayWid; j++){
			for (int k = 0; k < ruleList->size; k++)
				buckArray[i][j].relaRules.push_back(k);

			buckArray[i][j].RedRemove(ruleList);
		}

	}
}


OneBucket * BuckArray::searchBucket(const unsigned int (&packPred)[4]){
	size_t idx_x = packPred[0] >> (33-arrayWid);
	size_t idx_y = packPred[1] >> (33-arrayWid);
	return & buckArray[idx_x][idx_y];
}

BuckArray::~BuckArray(){
	for (int i = 0; i< arrayWid; i++){
		delete [] buckArray[i];
	}
	delete [] buckArray;
}

