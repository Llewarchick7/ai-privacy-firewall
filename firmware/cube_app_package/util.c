#include "util.h"
#include <stdarg.h>
#include <stdio.h>
void logf(const char *fmt,...){ char buf[256]; va_list ap; va_start(ap,fmt); vsnprintf(buf,sizeof buf,fmt,ap); va_end(ap); for(char *p=buf; *p; ++p) uart_tx_char(*p); uart_tx_char('\r'); uart_tx_char('\n'); }
void hexdump(const void *data,int len){ const unsigned char *p=(const unsigned char*)data; char line[8]; int col=0; for(int i=0;i<len;i++){ int n=snprintf(line,sizeof line,"%02x ",p[i]); for(int j=0;j<n;j++) uart_tx_char(line[j]); if(++col==16){ uart_tx_char('\r'); uart_tx_char('\n'); col=0; }} if(col){ uart_tx_char('\r'); uart_tx_char('\n'); }}
