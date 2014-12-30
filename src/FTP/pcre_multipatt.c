#include "mypcre.h"
#include <stdio.h>
#include <string.h>

#define _malloc(p, type, n) \
   do {\
    (p) = (type *)malloc( sizeof(type) * (n) ); \
     memset( (p), 0, sizeof(type) * (n) ); \
   }while(0)
   
#define TRUE 1
#define FALSE 0

#define entry_for_each(head, entry, type) \
    for(entry = head->next; entry != (type *)head; entry = entry->next)

struct pcre_patt_head
{
    int count; 
    struct pcre_patt_t *next;
    struct pcre_patt_t *prev;
}; 

struct pcre_patt_t
{
    char *pattern;
    struct pcre_patt_t *next;
    struct pcre_patt_t *prev;
}; 

struct pcre_patt_head *patt_queue;


#define INIT_PATT(name, patt) \
    struct pcre_patt_t *name; \
    _malloc(name, struct pcre_patt_t, 1); \
    _malloc(name->pattern, char, strlen(patt)+1); \
    strcpy(name->pattern, patt)

#define INIT_HEAD() \
      do {\
        patt_queue->count = 0; \
        patt_queue->next = (struct pcre_patt_t *)patt_queue; \
        patt_queue->prev = (struct pcre_patt_t *)patt_queue; \
       }while(0) \

#define DECLARE_PATT_QUEUE() \
    do { \
      _malloc(patt_queue, struct pcre_patt_head, 1); \
      INIT_HEAD(); \
    }while(0)

void release_patt_queue()
{
    struct pcre_patt_t *pos, *p;
    
    for(pos = patt_queue->next; pos != (struct pcre_patt_t *)patt_queue;)
    {
      p = pos;
      free(p->pattern);
      pos = pos->next;
      free(p);
    }
    free(patt_queue);
    return;
}

#define RELEASE_PATT_QUEUE() \
    release_patt_queue()

int add_patt_queue(struct pcre_patt_t *patt)
{
    if( !patt->pattern )
       return FALSE;
       
    struct pcre_patt_t *pos, *p = patt_queue->prev;
    
    entry_for_each(patt_queue, pos, struct pcre_patt_t)
       if( pos == patt )
         return FALSE;
    
    p->next = patt;
    patt_queue->prev = patt;
    patt->next = (struct pcre_patt_t *)patt_queue;
    patt->prev = p;
    patt_queue->count++;
    
    return TRUE;
}  

#define BITMAP_SIZE 60

int pcre_multipatt(const char *charstream, int length, int (*bitmap)[BITMAP_SIZE], int options)
{
    if( patt_queue->count == 0 )
      return 0;
    
    int ovector[BITMAP_SIZE], rc, count = 1;
    struct pcre_patt_t *pos;
    
    entry_for_each(patt_queue, pos, struct pcre_patt_t)
    {
      int i;
      
      rc = pcre_match(pos->pattern, charstream, length, ovector, BITMAP_SIZE, options);
      if( rc <= 0 )
         return -count;
      
      bitmap[count - 1][0] = rc;
      for(i = 0; i < rc; i++)
      {
         bitmap[count - 1][2*i + 1] = ovector[2*i];
         bitmap[count - 1][2*i + 2] = ovector[2*i + 1];
      }
      count++;
    }
    
    return count - 1;
}

int main()
{
   DECLARE_PATT_QUEUE();
   INIT_PATT(patt, "(zhou)qing(yu)");
   INIT_PATT(patt2, "(y)(a)(n)(g)(h)(ai)");
   add_patt_queue(patt);
   add_patt_queue(patt2);
   char source[] = ",,.45567zhouqingyu, kdkd \n\n\n yangkkk yanghai\n~\t\ndfjkasdjfkjskdfjksjdfjlkasdjkfjksdjfkjicneinciencienienniecieicekpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkpkjojojojojijihgvgbbhnghvghghnvvgvggojojojojojojojojojojojojojojpkpkpkpk";
   int bitmap[3][BITMAP_SIZE] = {0}, rc;
   int i,j,k = 0;
   rc = pcre_multipatt(source, 100, bitmap, PCRE_MULTILINE|PCRE_DOTALL);
   if( rc > 0 )
   { 
      int i, j;
      for(i = 0; i < rc; i++)
        for(j = 0; j < bitmap[i][0]; j++)
        {
           printf("$%d$%d beg[%2d], end[%2d] : %.*s\n", i, j, bitmap[i][2*j + 1], bitmap[i][2*j + 2], bitmap[i][2*j + 2] -  bitmap[i][2*j + 1], source + bitmap[i][2*j + 1]);
        }
   }
   else printf("rc : %d\n", rc);
   RELEASE_PATT_QUEUE();
}

