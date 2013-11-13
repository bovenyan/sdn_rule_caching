#include "trace_mapping.h"

using namespace std;

void Pack_mapping(const char* dst_file, const char* header_file, const char* trace_dir, size_t max_size){
	
}

size_t Flow_mapping(const char* dst_file, const char* header_file, const char* flow_dir, size_t max_size, bool map_intv, double interval){
	char dir_str[strlen(flow_dir)+20];
	strcpy(dir_str, flow_dir);
	strcat(dir_str, "/stimes.txt");
	ifstream flow_st (dir_str);
	strcpy(dir_str, flow_dir);
	strcat(dir_str, "/etimes.txt");
	ifstream flow_et (dir_str);

	priority_queue<flow> timestamp;
	string st_str;
	string et_str;

	ifstream header_f (header_file);
	size_t lineNo = 0;
	string line;
	
	// get line no of the header_file

	while (!header_f.eof()){
		getline(header_f, line);
		lineNo++;
	}
	if (max_size == 0 || max_size > lineNo){
		max_size = lineNo;
	}
	default_random_engine generator;
	exponential_distribution<double> distribution(interval);
	// get top max_size timestamp
	
	getline(flow_st, st_str);
	getline(flow_et, et_str);
	
	while (!flow_st.eof() || !flow_et.eof()){
		
		double interv = 0.0;
		if (map_intv)
			interv = stod(st_str);
		else
			interv = distribution(generator);
			
		flow term(interv, stod(et_str)-stod(st_str));
			
		if (term.dur > 1000.0 || term.dur < 10e-5){
			getline(flow_st, st_str);
			getline(flow_et, et_str);
			continue;
		}
	
		timestamp.push(term);

		if (timestamp.size() > max_size)
			timestamp.pop();
		
		getline(flow_st, st_str);
		getline(flow_et, et_str);
	}
	
	// get the right order
	stack<flow> timestamp_list;
	
	while (!timestamp.empty()){
		timestamp_list.push(timestamp.top());
		timestamp.pop();
	}

	ofstream flow_rec(dst_file);
	flow_rec.precision(10);
	//flow_rec.precision(18);
	header_f.clear();
	header_f.seekg(ios::beg);
	size_t counter = 0;
	string header_str;

	getline(header_f, header_str);
	while (counter < max_size && !timestamp_list.empty() && !header_f.eof()){
		flow_rec<<timestamp_list.top().stime<<"\t"<<timestamp_list.top().dur<<"\t"<<header_str<<endl;
		counter ++;
		timestamp_list.pop();
		getline(header_f, header_str);
	}
	
	flow_st.close();
	flow_et.close();
	flow_rec.close();
	return counter;
}
