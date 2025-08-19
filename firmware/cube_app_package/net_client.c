#include "net_client.h"
#include "util.h"
#include <string.h>
#include <stdio.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"
uint32_t now_epoch_seconds(){ extern uint32_t sys_now(void); return sys_now()/1000; }
int http_post_ingest(const char *host,uint16_t port,const char *path,const char *device_id,const char *timestamp_str,const char *hmac_hex,const char *json_body,int timeout_ms){ int sock=-1, rc=-1; struct hostent *he=gethostbyname(host); if(!he){ logf("RESOLVE FAIL %s",host); return -1;} struct sockaddr_in addr={0}; addr.sin_family=AF_INET; addr.sin_port=htons(port); memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length); sock=socket(AF_INET,SOCK_STREAM,0); if(sock<0){ logf("SOCK FAIL"); return -1;} struct timeval tv={ .tv_sec=timeout_ms/1000, .tv_usec=(timeout_ms%1000)*1000 }; setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv); setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv); if(connect(sock,(struct sockaddr*)&addr,sizeof addr)<0){ logf("CONN FAIL"); goto done; } int body_len=(int)strlen(json_body); char hdr[256]; int n=snprintf(hdr,sizeof hdr,"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Device-Id: %s\r\nX-Timestamp: %s\r\nX-Signature: %s\r\nConnection: close\r\n\r\n", path, host, body_len, device_id, timestamp_str, hmac_hex); if(n<=0||n>=(int)sizeof hdr){ logf("HDR OVR"); goto done; } if(write(sock,hdr,n)!=n){ logf("HDR SEND FAIL"); goto done; } if(write(sock,json_body,body_len)!=body_len){ logf("BODY SEND FAIL"); goto done; } char resp[128]; int got=read(sock,resp,sizeof(resp)-1); if(got>0){ resp[got]='\0'; if(strstr(resp," 200 ")) rc=0; else rc=-2; }
 done: if(sock>=0) close(sock); return rc; }
