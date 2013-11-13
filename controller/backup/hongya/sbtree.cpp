//
//  File.c
//
//
//  Created by Luo Wang on 3/4/13.
//
//

#include <iostream>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <cstdio>
#include <deque>
#include <math.h>


#include <fstream>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <arpa/inet.h>

#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


// ---- Macros ----

#define MAX_PORT    65535       // Max port number (min is 0)
#define MAX_STRING  1000        // Max length of matching string


#define MAXRULES  10001

#define BUCKETDEFAULT  5
#define SHOW 0

using namespace std;



struct node
{
    
    struct node *child[2][2][2][2];//一个节点拥有的子节点
    struct node *parent;
    int count; 
    int ruleID[MAXRULES];
    int src[32];
    int dst[32];
    int srcp[16];
    int dstp[16];
    int src_port_up;
    int src_port_low;
    int dst_port_up;
    int dst_port_low;
    int masklen;

    
};
typedef struct node Node;


struct cidr_t{
    unsigned char   buf[sizeof(struct in_addr)];
    /*
     * IP converted into an array of
     * unsigned bytes. Note that unsigned
     * char is actually used as 1-byte
     * integer here.
     */
    unsigned int    pre_len;
    /*
     * Prefix length.
     * Should be 0 <= pre_len <= 32
     */
}; /* Parse char[] into this data structure */

struct port_t{
    unsigned int    upper;
    unsigned int    lower;
}; /* Parse char[] into this port range structure */

struct rule_t{
    int             id;
    cidr_t *        src_ip;
    port_t *        src_port;
    cidr_t *        dst_ip;
    port_t *        dst_port;
    char *          protocol;
    char *          match_str;
    int            bisrc_ip[32];
    int            bidst_ip[32];
    int             same;
}; /* Data structure for storing the whole rule */

typedef struct{
    int             id;
    cidr_t *        src_ip;
    port_t *        src_port;
    cidr_t *        dst_ip;
    port_t *        dst_port;
    char *          protocol;
    int             bsrc_ip[32];
    int             bdst_ip[32];

}header_t;

cidr_t *    parse_cidr(char * in_str);
port_t *    parse_port(char * in_str);
char *      parse_protocol(char * in_str);
char *      parse_match_string(char * in_str);

vector<struct rule_t> rule_vec;


Node *root = (Node *)malloc(sizeof(Node));


int ruleCnt = 0;
int BUCKET_SIZE = BUCKETDEFAULT;

void insert(rule_t rule,Node *root,int ruleID, int* bsrc_ip, int* bdst_ip);
void build_bucket(Node *root);
void mergeBelow(Node *node);
void splitCurnt(Node *node);
void printBucket(Node *root);
int addRule(Node *node, rule_t rule, int ruleCase);


void createChild(Node *node, int flag);
void compare(Node *node, int count);
int power(int base, int n);
void matchNum(Node *child, Node * parent);


int main(int argc, char * argv[]){
    
   
    int         i, res;
    string          line;
    ifstream        config_file(argv[1]);
    int             rid = 1;
    
    root->parent = NULL;
    root->count = 0;
    for(int j = 0; j < MAXRULES; j++)
        root->ruleID[j] = -1;
    for(int i=0; i<32; i++){
        root->src[i]=-1;
        root->dst[i]=-1;
    }
    for(int i=0; i<16; i++){
        root->srcp[i]=-1;
        root->dstp[i]=-1;
    }
    
    root->masklen=0;
    root->src_port_low=0;
    root->src_port_up=65535;
    root->dst_port_low=0;
    root->dst_port_up=65535;

    
    if(argv[2]!=NULL){
        BUCKET_SIZE= atoi(argv[2]);
    }
    

    
    if(config_file.is_open()){
        while(getline(config_file, line)){
            stringstream strs(line);
            rule_t rule;
            char  src_ip_str[20]        = "";
            char  src_port_str[20]      = "";
            char  src_port_str1[20]     = "";
            char  src_port_com[1]      = "";
            char  dst_ip_str[20]        = "";
            char  dst_port_str[20]      = "";
            char  dst_port_str1[20]     = "";
            char  dst_port_com[1]      = "";
            char  protocol_str[20]      = "";
            char  match_str[MAX_STRING] = "";
            
            strs >> src_ip_str >> dst_ip_str >> src_port_str >> src_port_com >> src_port_str1 >> dst_port_str >> dst_port_com >> dst_port_str1 >>  protocol_str;
            strs.getline(match_str, MAX_STRING);
            
       //     printf("%d, %d\n",  atoi(src_port_str),  atoi(src_port_str1));
       //     printf("%d, %d\n",  atoi(dst_port_str),  atoi(dst_port_str1));
            /* Stop if line is empty. */
            if(strcmp(match_str, "\0") == 0) { break; }
            
            
            rule.id = rid;
            
#ifdef DEBUG
            cout << "Rule ID: " << rule->id << endl;
#endif
            
            char src_ip_str1[20] = "";
            for(int i=1;i<=strlen(src_ip_str);i++){
                src_ip_str1[i-1]=src_ip_str[i];
            }
            
        //    printf("%d, %d\n",  atoi(src_port_str),  atoi(src_port_str1));
            
            rule.src_ip = parse_cidr(src_ip_str1);
                                         
            rule.src_port = parse_port(src_port_str);
            rule.src_port->lower = atoi(src_port_str);
        //        printf("%d, %d\n",  atoi(src_port_str),  atoi(src_port_str1));
            rule.src_port->upper = atoi(src_port_str1);
   
            rule.dst_ip = parse_cidr(dst_ip_str);
            rule.dst_port = parse_port(dst_port_str);
            rule.dst_port->lower = atoi(dst_port_str);
            rule.dst_port->upper = atoi(dst_port_str1);

            rule.protocol = parse_protocol(protocol_str);
            

            rule.match_str = parse_match_string(match_str);
            
            cidr_t * tmpSrc = (cidr_t *)malloc(sizeof(cidr_t));
            *tmpSrc= *rule.src_ip;
            cidr_t * tmpDst = (cidr_t *)malloc(sizeof(cidr_t));
            *tmpDst= *rule.dst_ip;
            
            
            
            int bsrc_ip[32];
            int bdst_ip[32];
            
            for(int i=0;i<4;i++)
            {
                for(int j=0; j<8; j++)
                {
                    bsrc_ip[(i+1)*8-j-1]=tmpSrc->buf[i]%2;
                    tmpSrc->buf[i]=tmpSrc->buf[i]/2;
                    
                    bdst_ip[(i+1)*8-j-1]=tmpDst->buf[i]%2;
                    tmpDst->buf[i]=tmpDst->buf[i]/2;
                }
            }
            
            
            free(tmpSrc);
            free(tmpDst);
            
            int* bsrc, *bdst;
            bsrc= &bsrc_ip[0];
            bdst= &bdst_ip[0];
            
            for(int i=0;i<32;i++){
                rule.bisrc_ip[i]=bsrc_ip[i];
                rule.bidst_ip[i]=bdst_ip[i];
            }

          
     //       insert(rule,root, rule.id, bsrc, bdst);
            
            
            
            
            /*
             * We parse each line of the configuration file into a rule
             * strucutre, and push it to the back of a vector. It is up to
             * you to make use of this vector.
             */
            rule_vec.push_back(rule);
            rid ++;
            
            
            
#ifdef DEBUG
            cout << endl;
#endif
        }
    }
    
    
    vector<struct rule_t>::iterator it;
    
    
    cout << endl << "Rules in the rule vector (after parsing): " << endl;
    
    
    
    for(it = rule_vec.begin() ; it < rule_vec.end() ; it++){
        
        ruleCnt++;
        
       cout << "#";
        cout << it->id << "  ";
        cout << (int) it->src_ip->buf[0]  << "." <<
        (int) it->src_ip->buf[1]  << "." <<
        (int) it->src_ip->buf[2]  << "." <<
        (int) it->src_ip->buf[3]  << "/" <<
        it->src_ip->pre_len       << "  ";
        
        cout << (int) it->dst_ip->buf[0]  << "." <<
        (int) it->dst_ip->buf[1]  << "." <<
        (int) it->dst_ip->buf[2]  << "." <<
        (int) it->dst_ip->buf[3]  << "/" <<
        it->dst_ip->pre_len       << "  ";
        
        cout << it->src_port->lower << ":" <<
        it->src_port->upper << "  ";
        
        cout << it->dst_port->lower << ":" <<
        it->dst_port->upper << "  ";
        cout << it->protocol        << "  ";
        cout << "\"" << it->match_str << "\"" << endl;
        
 /*       int bsrc_ip[32];
        int bdst_ip[32];
        
        for(int i=0;i<4;i++)
        {
            for(int j=0; j<8; j++)
            {
                bsrc_ip[(i+1)*8-j-1]=it->src_ip->buf[i]%2;
                it->src_ip->buf[i]=it->src_ip->buf[i]/2;
                
                bdst_ip[(i+1)*8-j-1]=it->dst_ip->buf[i]%2;
                it->dst_ip->buf[i]=it->dst_ip->buf[i]/2;
            }
        }
        
        for(int i=0; i<32; i++){
            it->bisrc_ip += bsrc_ip[i];
            (it->bisrc_ip) << 1;
            
            it->bidst_ip += bdst_ip[i];
            (it->bidst_ip) << 1;
        }   */
        

        
        
    }
  

  
 /*   vector<struct rule_t>::iterator out;
    
    
    for(out = rule_vec.begin() ; out < rule_vec.end() ; out++){
        
        out->same =0 ;
        vector<struct rule_t>::iterator in;
        
        for(in = rule_vec.begin() ; in < rule_vec.end() ; in++){
                if(strcmp(out->protocol,in->protocol) == 0){
                    if(out->dst_port->upper == in->dst_port->upper && out->dst_port->lower == in->dst_port->lower){
                        if(out->src_port->upper == in->src_port->upper && out->src_port->lower == in->src_port->lower){
                            if(out->src_ip->pre_len == in->src_ip->pre_len && out->dst_ip->pre_len == in->dst_ip->pre_len){
                                if(out->bidst_ip == in->bidst_ip&& out->bisrc_ip == in->bisrc_ip){
                                    (out->same)++;
                                }
                            }
                        }
                    }
                }
            
             

            
       //     printf("rule %d has %d rules match\n", out->id, out->same);
        }
        
    }   */
    
    
    printf("rule: %d\n", ruleCnt);

 //   build_bucket(root);
    
    
    compare(root, ruleCnt);
 
    
    printBucket(root);

    
}



void matchNum(Node *child, Node * parent){
    
    
  //  printf("=================================\n");
    
    for(int i=0;i<parent->count;i++){
        int isOverlap=1;
    //    printf("rule ID: %d\n", parent->ruleID[i]);
        rule_t *rule= &rule_vec[parent->ruleID[i]-1];
    //    printf("sport high: %d, sport low: %d\n", rule->src_port->upper,rule->src_port->lower);
        
        if(rule->src_port->upper < child->src_port_low || rule->src_port->lower > child->src_port_up){
            isOverlap=0;
        }
         
        
        if(isOverlap==1){
     //       printf("rule %d pass s port\n", parent->ruleID[i]);
            if(rule->dst_port->upper < child->dst_port_low || rule->dst_port->lower > child->dst_port_up){
                isOverlap=0;
            }
        }
        
        if(isOverlap==1){
     //       printf("rule %d pass d port\n", parent->ruleID[i]);
            if(rule->src_ip->pre_len <= child->masklen){
                for(int m=0;m<rule->src_ip->pre_len; m++){
                    if(rule->bisrc_ip[m]!=child->src[m]){
                        isOverlap=0;
                    }
                }
            }
            else if(child->masklen < rule->src_ip->pre_len){
                for(int m=0;m<child->masklen;m++){
                    if(rule->bisrc_ip[m]!=child->src[m]){
                        isOverlap=0;
                    }
                }
            }
        }
        
        if(isOverlap==1){
      //      printf("rule %d pass s ip\n", parent->ruleID[i]);
            if(rule->dst_ip->pre_len <= child->masklen){
                for(int m=0;m<rule->dst_ip->pre_len; m++){
                    if(rule->bidst_ip[m]!=child->dst[m]){
                        isOverlap=0;
                    }
                }
            }
            else if(child->masklen < rule->dst_ip->pre_len){
                for(int m=0;m<child->masklen;m++){
                    if(rule->bidst_ip[m]!=child->dst[m]){
                        isOverlap=0;
                    }
                }
            }
        }
        
        if(isOverlap==1){
       //     printf("rule %d pass d ip\n", parent->ruleID[i]);
       //     printf("match rule %d\n", rule->id);
            child->ruleID[child->count]=rule->id;
            child->count++;
            
        }
        
    }
    
}


void createChild(Node * node, int flag){
    Node * currnt = node;
    
    
    if(flag == 0){
        //////////////////////////////////////////////////////
        for(int i=0; i<2; i++){
            for(int j=0; j<2;j++){
                for(int k=0; k<2;k++){
                    for(int l=0; l<2;l++){
                        Node *newnode= (Node *)malloc(sizeof(Node));
                        
                        for(int m=0; m<32; m++){
                            newnode->src[m]=-1;
                            newnode->dst[m]=-1;
                        }
                        for(int m=0; m<16; m++){
                            newnode->srcp[m]=-1;
                            newnode->dstp[m]=-1;
                        }
                        
                        newnode->src_port_low=0;
                        newnode->dst_port_low=0;
                        
                        
                        
                        for (int m= 0; m<MAXRULES; m++)
                            newnode->ruleID[m] = -1;
                        newnode->masklen=currnt->masklen+1;
                        
                        
                        for(int m=0;m<newnode->masklen-1;m++){
                            newnode->dst[m]=currnt->dst[m];
                            newnode->src[m]=currnt->src[m];
                            newnode->dstp[m]=currnt->dstp[m];
                            newnode->srcp[m]=currnt->srcp[m];
                        }
                        newnode->src[newnode->masklen-1]= i;
                        newnode->dst[newnode->masklen-1]= j;
                        newnode->srcp[newnode->masklen-1]= k;
                        newnode->dstp[newnode->masklen-1]= l;
                        
                        for(int m=0;m<newnode->masklen-1;m++){
                            newnode->src_port_low += newnode->srcp[m]*power(2,16-m);
                        }
                        if(k==1){
                            newnode->src_port_low +=power(2, 16- newnode->masklen);
                        }
                        
                        newnode->src_port_up = newnode->src_port_low + power(2, 16-newnode->masklen)-1;
                        
                        
                        for(int m=0;m<newnode->masklen-1;m++){
                            newnode->dst_port_low += newnode->dstp[m]*power(2,16-m);
                        }
                        
                        if(l==1){
                            newnode->dst_port_low +=power(2, 16- newnode->masklen);
                        }
                        
                        newnode->dst_port_up = newnode->dst_port_low + power(2, 16-newnode->masklen)-1;
                        
                        
                        newnode->count =0;
                        
                        
                        matchNum(newnode,currnt);
                        
                        
                        
                        
                        currnt->child[i][j][k][l]=newnode;
                    }
                    
                }
            }
        }
        
        
        //////////////////////////////////////////////////////
    }
    
    else if(flag==1){
        //////////////////////////////////////////////////////
        int k = currnt->srcp[currnt->masklen-1];
        int l = currnt->dstp[currnt->masklen-1];
        
        for(int i=0; i<2; i++){
            for(int j=0; j<2;j++){

                        Node *newnode= (Node *)malloc(sizeof(Node));
                        
                        for(int m=0; m<32; m++){
                            newnode->src[m]=-1;
                            newnode->dst[m]=-1;
                        }
                        for(int m=0; m<16; m++){
                            newnode->srcp[m]=-1;
                            newnode->dstp[m]=-1;
                        }
                        
                        newnode->src_port_low=0;
                        newnode->dst_port_low=0;
                        
                        
                        
                        for (int m= 0; m<MAXRULES; m++)
                            newnode->ruleID[m] = -1;
                        newnode->masklen=currnt->masklen+1;
                        
                        
                        for(int m=0;m<newnode->masklen;m++){
                            newnode->dst[m]=currnt->dst[m];
                            newnode->src[m]=currnt->src[m];
                            newnode->dstp[m]=currnt->dstp[m];
                            newnode->srcp[m]=currnt->srcp[m];
                        }
                        newnode->src[newnode->masklen-1]= i;
                        newnode->dst[newnode->masklen-1]= j;
                        

                        newnode->src_port_low = currnt->src_port_low;

                        
                        newnode->src_port_up = currnt->src_port_up;
                
                        newnode->dst_port_low = currnt->dst_port_low;
                
                
                        newnode->dst_port_up = currnt->dst_port_up;
                
                        
                        
                        
                        newnode->count =0;
                        
                        
                        matchNum(newnode,currnt);
                        
                        
                        
                        
                        currnt->child[i][j][k][l]=newnode;

            }
        }
        
        
        
        
        //////////////////////////////////////////////////////
    }
    
    
    
    for(int i=0;i<currnt->count;i++){
        currnt->ruleID[i]=-1;
    }
    
    currnt->count=0;   
    
}




void compare(Node * node, int count){
    Node *currnt= node;
    
    if(currnt->masklen==0){
        
        currnt->count=count;
        
        for(int i=0;i<count;i++){
            currnt->ruleID[i]=rule_vec[i].id;
        }
        
        
    }
    
    
    if(currnt->count > BUCKET_SIZE){
        
        if(currnt-> masklen <16){
            
            createChild(currnt, 0);
            
            
            for(int i=0; i<2; i++){
                for(int j=0; j<2;j++){
                    for(int k=0; k<2;k++){
                        for(int l=0; l<2;l++){
                            if(currnt->child[i][j][k][l]->count>BUCKET_SIZE){
                                compare(currnt->child[i][j][k][l],currnt->count);
                            }
                        }
                    }
                }
            }
            
        }
        
        else if(currnt->masklen >=16){
            
            createChild(currnt, 1);
            
            for(int i=0;i<2;i++){
                for(int j=0;j<2;j++){
                    if(currnt->child[i][j][currnt->srcp[currnt->masklen]-1][currnt->dstp[currnt->masklen-1]]);
                }
            }
            printf("still have too many rules in buckets\n");
            
            return;
        }
        
    }
    
    if(currnt->count<=BUCKET_SIZE){
        return;
    }
    
    
}




int power(int base, int n)
{
    int i, p;
    p = 1;
    for (i = 1; i <= n; ++i)
        p = p * base;
    return p;
}







/*int addRule(Node *node, rule_t rule, int ruleCase){
    
  //  printf("rule: %d case: %d\n", rule.id, ruleCase);
    Node *currnt = node;
    int flag =1;
    int tmpCount =currnt->count;
    

    
    for(int i=0; i< currnt->count; i++){
        if(currnt->ruleID[i]> rule.id){
            
            
            
            int tmpflag=0;
            
            if(ruleCase==1){  // 4 block src dst equal mask
                if(rule.src_ip->pre_len <= currnt->masklen && rule.dst_ip->pre_len <= currnt->masklen){
              //      printf("rule: %d cover %d (%dth rule) successfully\n", rule.id, currnt->ruleID[i], i );

                    flag=2;
                    tmpflag=1;
                    tmpCount--;
                    
                }
            }
            else if(ruleCase==2){  // src mask longer than dst, only deal with src
                if(rule.src_ip->pre_len <= rule_vec[currnt->ruleID[i]-1].src_ip->pre_len && rule.dst_ip->pre_len <= currnt->masklen){
                    int srcflag =1;
                    for(int j=currnt->masklen; j< rule.src_ip->pre_len; j++ ){
                        if(rule_vec[currnt->ruleID[i]-1].bisrc_ip[j] != rule.bisrc_ip[j]){
                            srcflag=0;
                            break;
                        }
                    }
                    if(srcflag==1){
                //       printf("rule: %d cover %d (%dth rule) successfully\n", rule.id, currnt->ruleID[i], i );

                        
                        flag=2;
                         tmpCount--;
                        tmpflag=1;
                    }
                    
                    
                }
                
            }
            else if(ruleCase==3){  // dst mask longer than src, only deal with dst
                if(rule.dst_ip->pre_len <= rule_vec[currnt->ruleID[i]-1].dst_ip->pre_len && rule.src_ip->pre_len <= currnt->masklen){
                    
             //      printf("rule: %d cover %d (%dth rule) successfully\n", rule.id, currnt->ruleID[i], i );
             //       printf("mask level %d\n", currnt->masklen);
                    int dstflag =1;
                    for(int j=currnt->masklen; j<= rule.dst_ip->pre_len; j++ ){
         
                        
                        if(rule_vec[currnt->ruleID[i]-1].bidst_ip[j] != rule.bidst_ip[j]){
                            dstflag=0;
     
                            break;
                        }
                    }
                    if(dstflag==1){
                  //      printf("rule: %d cover %d successfully\n", rule.id, currnt->ruleID[i] );
                        
                        flag=2;
                        tmpflag=1;
   
                         tmpCount--;
                    }
                    
                    
                }
                
            }
            else{
                
                printf("worng rule case, %d\n", ruleCase);
            }
            
            
            if(tmpflag==1){
                currnt->ruleID[i]= -1;

            }
        }
        
        

        
        
    }
 

    if(flag==2){

        int p1=0,p2=0;
        int dif= currnt->count-tmpCount;
        while(p2<tmpCount){
            if( currnt->ruleID[p2]!= -1){
                p1++;
                p2++;

                
            }
            else if(currnt->ruleID[p1]==-1&&currnt->ruleID[p2]==-1){
                p1++;

            }
            else if(currnt->ruleID[p1]!=-1 && currnt->ruleID[p2]==-1){
                currnt->ruleID[p2]=currnt->ruleID[p1];
                currnt->ruleID[p1] =-1;
                p2++;
                p1++;
   
            }
        }
        currnt->count=tmpCount;
        currnt->ruleID[currnt->count]=rule.id;
        currnt->count ++;
        
    
        dif--;
 
        return dif;
    } 
    

    
    
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    if(flag==1){
        
        ////////////////////////////////////
        
        for(int i=0;i<currnt->count; i++){
            if(currnt->ruleID[i]< rule.id){
                if(ruleCase==1){  // 4 block src dst equal mask
                    if(rule_vec[currnt->ruleID[i]-1].src_ip->pre_len <= currnt->masklen && rule_vec[currnt->ruleID[i]-1].dst_ip->pre_len <= currnt->masklen){
                        
                        flag=0;
                        
                        
                    }
                }
                else if(ruleCase==2){  // src mask longer than dst, only deal with src
                    if(rule_vec[currnt->ruleID[i]-1].src_ip->pre_len <= rule.src_ip->pre_len && rule_vec[currnt->ruleID[i]-1].dst_ip->pre_len <= currnt->masklen){
                        int srcflag =1;
                        for(int j=currnt->masklen; j< rule_vec[currnt->ruleID[i]-1].src_ip->pre_len; j++ ){
                            if(rule_vec[currnt->ruleID[i]-1].bisrc_ip[j] != rule.bisrc_ip[j]){
                                srcflag=0;
                                break;
                            }
                        }
                        if(srcflag==1){
                            flag=0;
                        }
                        
                        
                    }
                    
                }
                else if(ruleCase==3){  // dst mask longer than src, only deal with dst
                    if(rule_vec[currnt->ruleID[i]-1].dst_ip->pre_len <= rule.dst_ip->pre_len && rule_vec[currnt->ruleID[i]-1].src_ip->pre_len <= currnt->masklen){
                        
                    //    printf("rule: %d try to prevent %d happen\n", currnt->ruleID[i],  rule.id);
                   //     printf("mask level %d\n", currnt->masklen);
    
                        int dstflag =1;
                        
                        for(int j=currnt->masklen; j<= rule_vec[currnt->ruleID[i]-1].dst_ip->pre_len; j++ ){
                            //        printf("rule %d: %d rule %d: %d, mask: %d\n", currnt->ruleID[i],rule_vec[currnt->ruleID[i]-1].bidst_ip[j] ,  rule.id,rule.bidst_ip[j], j);
                            
                            
                            if(rule_vec[currnt->ruleID[i]-1].bidst_ip[j] != rule.bidst_ip[j]){
                                dstflag=0;
                                //               printf("rule: %d prevent %d happen\n", currnt->ruleID[i],  rule.id);
                                break;
                            }
                        }
                        if(dstflag==1){
                      //      printf("rule: %d prevent %d successfully\n", currnt->ruleID[i],  rule.id);
                            
                            flag=0;
                        }
                        
                        
                    }
                    
                }
                else{
                    
                    printf("worng rule case, %d\n", ruleCase);
                }
            }
        }
        
        
        /////////////////////////////////////
    }
    


    if(flag==1){
     //   printf("rule: %d case: %d\n", rule.id, ruleCase);
        currnt->ruleID[currnt->count]=rule.id;
        currnt->count ++;
        
        
        return 0;
        
    }
 
    
    return -1;
    
}




void insert(rule_t rule,Node *root,int ruleID, int* bsrc_ip, int* bdst_ip)
{

    Node *p1 = root;
    int mask=0, i=0;
    int ruleCase = 0;
    

    if(rule.src_ip->pre_len < rule.dst_ip->pre_len){
        mask = rule.src_ip->pre_len;
        ruleCase=3;
        
    }else if(rule.src_ip->pre_len == rule.dst_ip->pre_len){
        mask = rule.src_ip->pre_len;
        ruleCase=1;
        
    }else{
        mask = rule.dst_ip->pre_len;
        ruleCase=2;
    }


    if(mask==0){
       int flag= addRule(root,rule,ruleCase);

      //  root->ruleID[root->count]=ruleID;
      //  root->count++;
        
      if(flag==-1){
            
            root->totalCount = root->totalCount --;
        }
      else if(flag>0){

            root->totalCount = root->totalCount -flag;
        }

    }

   root->totalCount++;
    
    while(i<mask)
    {
        int index= bsrc_ip[i]*2+bdst_ip[i];
        if (p1->child[index] == NULL)
        {
      

            Node *newnode;
            int j;
            newnode = (Node *)malloc(sizeof(Node));
            for (j = 0; j < 4; j++)
                newnode->child[j] = NULL;
            for (j= 0; j<MAXRULES; j++)
                newnode->ruleID[j] = -1;
            newnode->masklen=i+1;
            newnode->totalCount = 0;
            newnode->totalCount++;
            
            for(int m=0;m<newnode->masklen-1;m++){
                newnode->dst[m]=p1->dst[m];
                newnode->src[m]=p1->src[m];
            }
            newnode->src[newnode->masklen-1]= bsrc_ip[i];
            newnode->dst[newnode->masklen-1]= bdst_ip[i];
            newnode->isCover =0;
            newnode->count =0;
            

            if(i==mask-1){
                
                int flag= addRule(newnode,rule,ruleCase);
                
                if(flag==-1){
                    Node *tmp= newnode->parent;
                    
                    while(tmp!=NULL){
                        tmp->totalCount --;
                        tmp=tmp->parent;
                    }
                    
                   
                }
                
                if(flag>0){
                    Node *tmp= newnode->parent;
                    
                    while(tmp!=NULL){
                        tmp->totalCount =tmp->totalCount -flag;
                        tmp=tmp->parent;
                    }
                    
             
                }
  
           //     newnode->ruleID[newnode->count]=ruleID;
           //     newnode->count ++;

            }
            p1->child[index] = newnode;
            
        }
        else{
            
            
            
            p1->child[index]->totalCount++;
            if(i==mask-1){
                
                
                 int flag = addRule(p1->child[index],rule,ruleCase);
                
                if(flag==-1){
                    Node *tmp= p1;
                    
                    while(tmp!=NULL){
                        tmp->totalCount --;
                        tmp=tmp->parent;
                    }
                    
       
                }
                else if(flag>0){
                    Node *tmp= p1;
                    
                    while(tmp!=NULL){
                        tmp->totalCount = tmp->totalCount - flag;
                        tmp=tmp->parent;
                    }
                    
                
                }
  
           //     p1->child[index]->ruleID[(p1->child[index]->count)]=ruleID;
           //     p1->child[index]->count++;
            }
            
        }
        
        
        p1 = p1->child[index];
        
        
        i++;
    }
    
    
}




void build_bucket(Node * node){
    
    Node *currnt = node;
    int testTotal=0;
    
    
    testTotal += currnt->totalCount;
    
    if(currnt->count >testTotal){
        testTotal = currnt->count;
    }
   
    
    if(testTotal>BUCKET_SIZE){
                
        splitCurnt(currnt);
        
        for(int i=0;i<4;i++){
            if(currnt->child[i]!=NULL){
                build_bucket(currnt->child[i]);
            }
        }
        
    }
    
    else{
        
        mergeBelow(currnt);
    }
    
    
}




void splitCurnt(Node *node){
    
    Node *currnt = node;
    
    for(int j=0; j<currnt->count; j++){
    
        if(rule_vec[currnt->ruleID[j]-1].src_ip->pre_len == rule_vec[currnt->ruleID[j]-1].dst_ip->pre_len){
            
            for(int k=0;k<4;k++){
                if(currnt->child[k]==NULL){
                    Node *newnode;
                   
                    newnode = (Node *)malloc(sizeof(Node));
                    for (int m = 0; m < 4; m++)
                        newnode->child[m] = NULL;
                    for (int m= 0; m<MAXRULES; m++)
                        newnode->ruleID[m] = -1;
                    
                    newnode->totalCount = 0;
                    newnode->masklen=currnt->masklen+1;
                    
                    for(int i=0;i<newnode->masklen-1;i++){
                        newnode->dst[i]=currnt->dst[i];
                        newnode->src[i]=currnt->src[i];
                    }
                    newnode->dst[(newnode->masklen)-1]= k%2;
                    newnode->src[(newnode->masklen)-1]= (k- newnode->dst[(newnode->masklen)-1])/2;
                    
                    newnode->isCover =0;
                    newnode->count =0;
                    
                    currnt->child[k]=newnode;
                }
                
                int flag = addRule(currnt->child[k],rule_vec[currnt->ruleID[j]-1],1);
                
                if(flag==-1){
                    Node *tmp= currnt->child[k];
                    
                    while(tmp!=NULL){
                        tmp->totalCount --;
                        tmp=tmp->parent;
                    }
                    
                   
                }
                else if(flag>0){
                    Node *tmp= currnt->child[k];
                    
                    while(tmp!=NULL){
                        tmp->totalCount = tmp->totalCount - flag;
                        tmp=tmp->parent;
                    }
                    
                
                }

                
                
              //  currnt->child[k]->ruleID[(currnt->child[k]->count)]=currnt->ruleID[j];
              //  currnt->child[k]->count++;
            }
        }
        else if(rule_vec[currnt->ruleID[j]-1].src_ip->pre_len < rule_vec[currnt->ruleID[j]-1].dst_ip->pre_len){
            


            for(int x=0;x<2;x++){
                int index = x*2+rule_vec[currnt->ruleID[j]-1].bidst_ip[(currnt->masklen)];
          //      printf("=====rule %d==mask %d==%d==========\n",currnt->ruleID[j],(currnt->masklen), rule_vec[currnt->ruleID[j]-1].bidst_ip[(currnt->masklen)]);
                if(currnt->child[index]==NULL){
                    Node *newnode;
                    
                    newnode = (Node *)malloc(sizeof(Node));
                    for (int m = 0; m < 4; m++)
                        newnode->child[m] = NULL;
                    for (int m= 0; m<MAXRULES; m++)
                        newnode->ruleID[m] = -1;
                    
                    newnode->totalCount = 0;
                    newnode->totalCount++;
                    newnode->masklen=currnt->masklen+1;
                    
                    for(int i=0;i<newnode->masklen-1;i++){
                        newnode->dst[i]=currnt->dst[i];
                        newnode->src[i]=currnt->src[i];
                    }
                    
                    
                    newnode->src[newnode->masklen-1]= x;
                    newnode->dst[newnode->masklen-1]= rule_vec[currnt->ruleID[j]-1].bidst_ip[(currnt->masklen)];
                //     printf("rule %d try to split to %d%d block\n", currnt->ruleID[j], newnode->src[newnode->masklen-1],newnode->dst[newnode->masklen-1]);
                    
                    
                    newnode->isCover =0;
                    newnode->count =0;
                    
                    currnt->child[index]=newnode;
                }
                
               
               int flag = addRule(currnt->child[index],rule_vec[currnt->ruleID[j]-1],3);
       //         printf("rule %d try to add\n",currnt->ruleID[j]);
                
                if(flag==0){
         //          printf("rule %d added\n",currnt->ruleID[j]);
                }
                if(flag==-1){
                    Node *tmp= currnt->child[index];
                    
                    while(tmp!=NULL){
                        tmp->totalCount --;
                        tmp=tmp->parent;
                    }
                    
                    
         //           printf("rule %d add failed\n",currnt->ruleID[j]);
                }
                else if(flag>0){
                    Node *tmp= currnt->child[index];
                    
                    while(tmp!=NULL){
                        tmp->totalCount = tmp->totalCount - flag;
                        tmp=tmp->parent;
                    }
                    
           
                    
            //        printf("rule %d cover %d rules\n",currnt->ruleID[j], flag);
                }

                
              //  currnt->child[index]->ruleID[(currnt->child[index]->count)]=currnt->ruleID[j];
              //  currnt->child[index]->count++;
            }
        }
        else{
            
            for(int x=0;x<2;x++){
                
                int index = rule_vec[currnt->ruleID[j]-1].bisrc_ip[(currnt->masklen)]*2+x;
                if(currnt->child[index]==NULL){
                    Node *newnode;
                  
                    newnode = (Node *)malloc(sizeof(Node));
                    for (int m = 0; m< 4; m++)
                        newnode->child[m] = NULL;
                    for (int m= 0; m<MAXRULES; m++)
                        newnode->ruleID[m] = -1;
                    
                    newnode->totalCount = 0;
                    newnode->totalCount++;
                    newnode->masklen=currnt->masklen+1;
                    
                    for(int i=0;i<newnode->masklen-1;i++){
                        newnode->dst[i]=currnt->dst[i];
                        newnode->src[i]=currnt->src[i];
                    }
                    
                    newnode->src[newnode->masklen-1]= rule_vec[currnt->ruleID[j]-1].bisrc_ip[(currnt->masklen)];
                    newnode->dst[newnode->masklen-1]= x;
                    
                    newnode->isCover =0;
                    newnode->count =0;
                    
                    currnt->child[index]=newnode;
                }
                int flag = addRule(currnt->child[index],rule_vec[currnt->ruleID[j]-1],2);
                
                if(flag==-1){
                    Node *tmp= currnt->child[index];
                    
                    while(tmp!=NULL){
                        tmp->totalCount --;
                        tmp=tmp->parent;
                    }
                    
          
                }
                else if(flag>0){
                    Node *tmp= currnt->child[index];
                    
                    while(tmp!=NULL){
                        tmp->totalCount = tmp->totalCount - flag;
                        tmp=tmp->parent;
                    }
          
                }

             //   currnt->child[index]->ruleID[(currnt->child[index]->count)]=currnt->ruleID[j];
             //   currnt->child[index]->count++;
            }
            
        }
        
        currnt->ruleID[j]=-1;
        
    }
    currnt->count = 0;
    
    
}



void mergeBelow(Node * root){
    
    Node *currnt = root;
    
    for(int i=0;i<4;i++){
        if(currnt->child[i]!=NULL){
            mergeBelow(currnt->child[i]);
        }
    }
    
    for(int i=0;i<4;i++){
        if(currnt->child[i]!=NULL){
            for(int j=0;j<currnt->child[i]->count;j++){
                
                
                currnt->ruleID[currnt->count]= currnt->child[i]->ruleID[j];
                currnt->child[i]->ruleID[j] = -1;
                currnt->count ++;
            }
            currnt->child[i]->count=0;
            currnt->child[i]->totalCount=0;
        }
    }
    
}   */



void printBucket(Node *root){
    
    
    FILE *fp0=NULL;
    fp0= fopen("sbtree.txt","w");
    fclose(fp0);
    
    
    deque<Node*> queue;
    
    queue.push_back(root);
    
    FILE *fp=NULL;
    fp= fopen("sbtree.txt","at");
    
    Node *test;
    int bucketCnt=0;
    
    while(!queue.empty()){
        test=queue.front();
        queue.pop_front();
        
        if(test->count>0){
            bucketCnt++;

            
            fprintf(fp, "bucket %d:  ", bucketCnt);
 
            
            fprintf(fp, "src prefix: ");
            for(int i=0;i<test->masklen;i++){
                fprintf(fp, "%d", test->src[i]);
            }         
            fprintf(fp, "*/%d   dst prefix: ", test->masklen);
            for(int i=0;i<test->masklen;i++){
                fprintf(fp, "%d", test->dst[i]);
            }
            
            fprintf(fp, "*/%d  ", test->masklen);
            fprintf(fp, "src port: %d:%d  ", test->src_port_low, test->src_port_up);
            fprintf(fp, "dst port: %d:%d  ", test->dst_port_low, test->dst_port_up);
            
            fprintf(fp, "rule num: %d  ", test->count);
            for(int m=0;m<test->count;m++){
                fprintf(fp, "rule ID: %d, ",  test->ruleID[m]);
            }
            fprintf(fp, "\n");
            
        }
        
        if(test->masklen<16){
            
            
            for(int i=0; i<2; i++){
                for(int j=0; j<2;j++){
                    for(int k=0; k<2;k++){
                        for(int l=0; l<2;l++){
                            if(test->child[i][j][k][l]!=NULL){
                                queue.push_back(test->child[i][j][k][l]);
                            }
                        }
                    }
                }
            }
            
        }
        
        
        else if(test->masklen>=16){
            
            int k=test->srcp[test->masklen-1];
            int l=test->dstp[test->masklen-1];
            
            for(int i=0; i<2; i++){
                for(int j=0; j<2;j++){

                            if(test->child[i][j][k][l]!=NULL){
                                queue.push_back(test->child[i][j][k][l]);
                            }
                }
            }
            
            
            
        }
        
        
        
        
        
    }
    
    printf("bucket: %d\n",bucketCnt);
    
    fclose(fp);
    
}   







/*
 * cidr_t * parse_cidr(char * in_str)
 * Parse an input char[] into CIDR data type.
 * If in_str is not a legal representation of CIDR, return 0.0.0.0/0, i.e.
 * all-wildcard prefix.
 */
cidr_t * parse_cidr(char * in_str){
    unsigned int   i;
    unsigned char   temp_buf[sizeof(struct in_addr)] = {0};
    int             prefix_length;
    char *          str_ip;
    char *          str_plength;
    int             wildcard = 0;
    
    
    cidr_t * res = (cidr_t *) malloc(sizeof(cidr_t));
    
    
    
    
    if(strcmp(in_str, "*") == 0) { wildcard = 1; }
    
    else{
        /*
         * Split in_str into two parts: the part before '/' should be a valid
         * IPv4 expression, and the part after '/' should be an integer
         * between 0 and 32.
         */
        str_ip = strtok(in_str, "/");
        str_plength = strtok(NULL, "");
        
        /*
         * Parse and check validity of str_ip.
         */
        
        int valid_ip = inet_pton(AF_INET, str_ip, temp_buf);
        
        /*
         * If the IP string is not a valid IPv4 expression, we will return a
         * wildcard parsing result (0.0.0.0/0).
         */
        if(valid_ip <= 0) { wildcard = 1; }
        
        /*
         * Parse and check validity of str_plength
         */
        if(str_plength == NULL) { prefix_length = 32; }
        
        else{
            char * ptr;
            strtol(str_plength, &ptr, 10);
            if(*ptr != 0)   wildcard = 1;
            /*
             * str_plength not in numerical form
             */
            else{
                prefix_length = atoi(str_plength);
                /*
                 * Check if the number represented by str_plength is a valid
                 * prefix length number.
                 */
                if(prefix_length > 32 || prefix_length < 0) { wildcard = 1; }
            }
        }
    }
    
    
    /*
     * Copy values to res.
     */
    if(wildcard == 0){
        for(i=0 ; i<sizeof(struct in_addr) ; i++){
            res->buf[i] = temp_buf[i];
        }
        res->pre_len = prefix_length;
    }
    
    else{
        for(i=0 ; i<sizeof(struct in_addr) ; i++){
            res->buf[i] = 0;
        }
        res->pre_len = 0;
    }
    
    
    
#ifdef DEBUG
    cout << "Parsed CIDR: ";
    for(i=0 ; i<sizeof(struct in_addr) - 1 ; i++){
        printf("%d.", res->buf[i]);
    }
    printf("%d/", res->buf[sizeof(struct in_addr)-1]);
    printf("%d\n", res->pre_len);
#endif
    
    return res;
    
}




/*
 * port_t * parse_port(char * in_str)
 * Parse an input char[] into port range data type.
 * If not a legal expression of port range, return 0:65535
 */
port_t * parse_port(char * in_str){
    int     i;
    char *  tok_strs[2];
    unsigned long int   tok_nums[2];
    int     legal = 1;
    int     exact_match = 0;
    port_t * res = (port_t *) malloc(sizeof(port_t));
    
    /* If in_str = "*", we will return all-wildcard. */
    if(strcmp(in_str, "*") == 0)    legal = 0;
    
    /* Initialize token strings. */
    for(i=0 ; i<2 ; i++)    tok_strs[i] = NULL;
    
    
    /* The case where in_str starts with ":" */
    if(in_str[0] == ':'){
        tok_strs[1] = strtok(in_str + 1, "");
        tok_nums[0] = 0;
        
        /* tok_strs[1] must be a 10-base integer. */
        char * ptr;
        strtol(tok_strs[1], & ptr, 10);
        if(*ptr != 0)            legal = 0;
        else{
            tok_nums[1] = atoi(tok_strs[1]);
            if(tok_nums[1] < 0 || tok_nums[1] > MAX_PORT)     legal = 0;
        }
    }
    
    
    /* The case where in_str ends with ":" */
    else if(in_str[strlen(in_str) - 1] == ':'){
        tok_strs[0] = strtok(in_str, ":");
        tok_nums[1] = MAX_PORT;
        
        /* tok_strs[0] must be a 10-base integer. */
        char * ptr;
        strtol(tok_strs[0], &ptr, 10);
        if(*ptr != 0)           legal = 0;
        else{
            tok_nums[0] = atoi(tok_strs[0]);
            if(tok_nums[0] < 0 || tok_nums[0] > MAX_PORT)   legal = 0;
        }
    }
    
    /* Other cases*/
    else{
        tok_strs[0] = strtok(in_str, ":");
        tok_strs[1] = strtok(NULL, "");
        
        if(tok_strs[1] == NULL) { exact_match = 1; }
        
        /* tok_strs[0-1] must be a 10-base integer. */
        for(i=0 ; i<2 ; i++){
            if(tok_strs[i] != NULL)
            {
                char * ptr;
                strtol(tok_strs[i], &ptr, 10);
                if(*ptr != 0)           legal = 0;
                else{
                    tok_nums[i] = atoi(tok_strs[i]);
                    if(tok_nums[i] < 0 || tok_nums[i] > MAX_PORT)   legal = 0;
                }
            }
        }
        
        if(exact_match == 1)    { tok_nums[1] = tok_nums[0]; }
        else if(tok_nums[0] > tok_nums[1])  { legal = 0; }
    }
    
    
    /*
     * If the in_str is a legal CIDR expression, copy the parsed numerical data
     * to return data structure. If not legal, return 0.0.0.0/0.
     */
    if(legal){
        res->lower = tok_nums[0];
        res->upper = tok_nums[1];
    }
    
    else{
        res->lower = 0;
        res->upper = MAX_PORT;
    }
    
#ifdef DEBUG
    cout << "Parsed port range: ";
    cout << res->lower      << ":"   <<
    res->upper      << endl  ;
#endif
    
    return res;
}




/*
 * char * parse_protocol(char * in_str)
 * Parse an input char[] into protocol string.
 * Input is case-insensitive, but the output protocol name will be in lower-case.
 * If not a legal expression of protocol, return "*", i.e. wildcard.
 */
char * parse_protocol(char * in_str1){
    int  i;
    char * res = (char *) malloc(10 * sizeof(char));
    char * in_str;
    char * in_strp;
    
    in_str = strtok(in_str1, "/");
    in_strp = strtok(NULL, "");
    
    char temp[strlen(in_str)];
    
    for(i=0 ; temp[i] ; i++){
        temp[i] = tolower(in_str[i]);
    }
    
    if(strcmp(temp, "*") == 0)          { strcpy(res, "*"); }
    
    else if(strcmp(temp, "tcp") == 0)   { strcpy(res, "tcp"); }
    
    else if(strcmp(temp, "udp") == 0)   { strcpy(res, "udp"); }
    
    else if(strcmp(temp, "icmp") == 0)  { strcpy(res, "icmp"); }
    
    else{ strcpy(res, in_str); }
    
#ifdef DEBUG
    cout << "Parsed protocol: ";
    cout << res << endl;
#endif
    
    return res;
}




/*
 * char * parse_match_string(char * in_str)
 * Parse an input char[] into matching string.
 * Input string can include spaces, but shall be enclosed in " ".
 */
char * parse_match_string(char * in_str){
    int  i;
    int  n_st_sp = 0;       /* Number of leading white spaces */
    int  n_ed_sp = 0;       /* Number of trailing white spaces */
    int  n_chars = 0;
    int  len = strlen(in_str);
    char * res = (char *) malloc(sizeof(char) * MAX_STRING);
    
    
    /*
     * Count the number of leading and trailing white spaces of in_str.
     */
    for(i=0 ; i<len ; i++){
        if(in_str[i] == ' ') { n_st_sp ++; }
        else break;
    }
    
    for(i=len-1 ; i>=0 ; i--){
        if(in_str[i] == ' ') { n_ed_sp ++; }
        else break;
    }
    
    
    /*
     * Check validity of the string, which means, after removing leading and
     * trailing white spaces, the rest of in_str must be enclosed in " ". If
     * not, in_str is not a legal expression, and we shall return a null
     * matching string.
     */
    
    /*
     * If the part of string after trimming is less than two characters long,
     * then the string must be illegal.
     */
    if(n_st_sp >= len - n_ed_sp - 1){
        strcpy(res, "");
    }
    
    /*
     * Check if the trimmed string is enclosed in quotation marks.
     */
    else if(in_str[n_st_sp] != '\"' ||
            in_str[len - n_ed_sp - 1] != '\"'){
        strcpy(res, "");
    }
    
    /*
     * Extract the string between quotation marks.
     */
    else{
        n_chars = len - n_st_sp - n_ed_sp - 2;
        if(n_chars == 0){
            strcpy(res, "");
        }
        else{
            strncpy(res, in_str + (n_st_sp+sizeof(char)), n_chars);
        }
    }
    
#ifdef DEBUG
    cout << "Parsed matching string (quote marks truncated): ";
    cout << res << endl ;
#endif
    
    return res;
}

