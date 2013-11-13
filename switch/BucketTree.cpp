#include "BucketTree.h"

using Z::Rule; using Z::Redundancy_Filter; using Z::ORtoR;

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

// ------------------- BucketTree

//basic tree construction
void BucketTree::dfsTreeCon(OneBucket * parentPtr, const size_t MaxRuleNo, const size_t restDept){
	if (partition(parentPtr, MaxRuleNo, restDept)){
		cout<<"rest"<< restDept<<endl;
		for (int i = 0; i < SONNO; i++)
			dfsTreeCon(parentPtr->sonList[i] , MaxRuleNo, restDept-1);
	}
}

//tree constrction with large rule removal
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



// partition the node and get the lowest avg rule count
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

// BuckArray

BuckArray::BuckArray(RuleList* rl, size_t buckNo, string subnet_s = "0.0.0.0/0"){
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

// deprecated...

/*
void BucketTree::partition(OneBucket * parentPtr, const size_t MaxRuleNo, const size_t restDept){
	// parentPtr->printInfo();
	avgRuleNo += parentPtr->relaRules.size();
	if (parentPtr->relaRules.size() <= MaxRuleNo || restDept == 0){ // stop condition 1
		bucketNo += 1;
		return;
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
		bucketNo += 1;
		for (int j = 0; j < SONNO; j++)
			delete parentPtr->sonList[j];
	}
	else{	// DFS
		for (int i = 0; i < SONNO; i++)
			partition(parentPtr->sonList[i] , MaxRuleNo, restDept-1);

	}
}


*/
