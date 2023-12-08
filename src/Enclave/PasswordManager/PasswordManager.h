#ifndef PASS_H
#define PASS_H

#include <vector>
#include <set>
#include <string>
#include <unordered_map>
 
#include "../Enclave.h"
  
static std::vector<std::string> g_userPasswords;
static std::set<std::string> g_breachedPasswords;
static std::unordered_map<std::string, std::string> g_result_map;


#endif
