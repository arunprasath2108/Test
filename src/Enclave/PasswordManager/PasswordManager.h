#ifndef PASS_H
#define PASS_H

#include <vector>
#include <set>
#include <string>
#include <unordered_map>
#include "sstream"
 
#include "../Enclave.h"
  
typedef std::set<std::string> stringSet; 

static stringSet g_userPasswords;
static stringSet g_breachedPasswords;
static std::unordered_map<std::string, std::string> g_result_map;


#endif
 