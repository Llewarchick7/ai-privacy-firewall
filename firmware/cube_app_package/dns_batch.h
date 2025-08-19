#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#ifndef RING_CAPACITY
#define RING_CAPACITY 256
#endif
#define DOMAIN_MAX_LEN 96
typedef struct { char domain[DOMAIN_MAX_LEN]; uint32_t ts; } domain_item_t;
typedef struct { domain_item_t buf[RING_CAPACITY]; uint16_t head,tail,count; } domain_ring_t;
void ring_init(domain_ring_t *r);
bool ring_push(domain_ring_t *r, const char *domain, uint32_t ts);
uint16_t ring_pop_batch(domain_ring_t *r, domain_item_t *out, uint16_t max_items);
int build_compact_json(domain_item_t *items, uint16_t n, char *out, size_t out_cap);
