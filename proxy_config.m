#include <Foundation/Foundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#pragma GCC diagnostic ignored "-Wobjc-method-access"

static int set_proxy(NSMutableDictionary *(^makeProxyConfigDict)()) {
  AuthorizationFlags authFlags = 
    kAuthorizationFlagDefaults |
    kAuthorizationFlagExtendRights |
    kAuthorizationFlagInteractionAllowed |
    kAuthorizationFlagPreAuthorize;
  AuthorizationRef authRef;
  OSStatus authStatus = AuthorizationCreate(nil, kAuthorizationEmptyEnvironment, authFlags, &authRef);
  if (authStatus != errAuthorizationSuccess) {
    NSLog(@"auth failed %@", @(authStatus));
    return FALSE;
  }

  SCPreferencesRef prefRef = SCPreferencesCreateWithAuthorization(NULL, CFSTR("lightning"), NULL, authRef);

  NSMutableArray *ethernetKeyArray = [[NSMutableArray alloc] init];
  NSDictionary *allNetworkServiceDict = (__bridge NSDictionary *)SCPreferencesGetValue(prefRef, kSCPrefNetworkServices);
  for (NSString *key in [allNetworkServiceDict allKeys]) {
    NSDictionary *networkServiceDict = (__bridge NSDictionary *)[allNetworkServiceDict objectForKey:key];
    NSString *type = [networkServiceDict valueForKeyPath:@"Interface.Type"];
    if ([type isEqualToString:@"Ethernet"]) {
      [ethernetKeyArray addObject: key];
    }
  }

  BOOL result = FALSE;
  for (NSString *key in ethernetKeyArray) {
      NSMutableDictionary *proxyConfigDict = makeProxyConfigDict();
      key = [NSString stringWithFormat:@"/%@/%@/%@", kSCPrefNetworkServices, key, kSCEntNetProxies];
      result = SCPreferencesPathSetValue(prefRef, (__bridge CFStringRef)key, (__bridge CFDictionaryRef)proxyConfigDict);
  }

  SCPreferencesCommitChanges(prefRef);
  SCPreferencesApplyChanges(prefRef);
  SCPreferencesSynchronize(prefRef);
  return result;
}

int set_global_proxy(const char *host, int port) {
  return set_proxy(^() {
      NSMutableDictionary *proxyConfigDict = [[NSMutableDictionary alloc] init];
      [proxyConfigDict setObject:[NSString stringWithUTF8String: host]
                          forKey:(NSString *) kCFNetworkProxiesSOCKSProxy];
      [proxyConfigDict setObject:@(port) forKey:(NSString*) kCFNetworkProxiesSOCKSPort];
      [proxyConfigDict setObject:@(1) forKey:(NSString*) kCFNetworkProxiesSOCKSEnable];
      return proxyConfigDict;
      });
}

int set_proxy_with_pac_file_url(const char *pac_file_url) {
  return set_proxy(^() { 
      NSString *url = [NSString stringWithUTF8String: pac_file_url];
      if ([url hasPrefix:@"/"]) {
        url = [@"file://" stringByAppendingString:url];
      }
      NSMutableDictionary *proxyConfigDict = [[NSMutableDictionary alloc] init];
      [proxyConfigDict setObject:url
                          forKey:(NSString *)kCFNetworkProxiesProxyAutoConfigURLString];
      [proxyConfigDict setObject:@(1) forKey:(NSString *)kCFNetworkProxiesProxyAutoConfigEnable];
      return proxyConfigDict;
      });
}

int disable_proxy() {
  return set_proxy(^() {
      NSMutableDictionary *proxyConfigDict = [[NSMutableDictionary alloc] init];
      [proxyConfigDict setObject:@(0) forKey:(NSString *)kCFNetworkProxiesProxyAutoConfigEnable];
      [proxyConfigDict setObject:@(0) forKey:(NSString*) kCFNetworkProxiesSOCKSEnable];
      return proxyConfigDict;
      });
}
