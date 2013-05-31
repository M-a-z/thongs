#ifndef MAZ_LIST_H
#define MAZ_LIST_H
#include <string.h>
#include <stdlib.h>
/* This file provides generic list implementation. It can be used to store same type of items in a list. Steps to take are:
 *
 *  1. Create list item struct. Place "struct node_list" as first member, and rest of struct can contain the data.
 *  2. create such a struct and pass pointer to struct in MAZ_LIST_INIT().
 *  Now list is ready to accept members. When you wish to add new member, create new struct and fill the data portions. 
 *  Do not touch the "struct node_list" member. Then pass pointer to inited list and struct being added in MAZ_LIST_ADD(). 
 *  NOTE: MAZ_LIST_ADD() shall allocate and copy data, so struct you passed to MAZ_LIST_ADD() can be released.
 *  MAZ_LIST_FIND(), MAZ_LIST_GET_FIRST() and MAZ_LIST_GET_NEXT() can be used to get added items.
 *  MAZ_LIST_RAWDEL() can be used to remove added node from list. NOTE: RAWDEL performs no checks to item passed to it.
 *  MAZ_LIST_DEL can be used to seek and delete struct containing certain data.
 *  Both MAZ_LIST_RAWDEL and MAZ_LIST_DEL return pointer to stored struct and remove it from the list
 */

typedef struct node_list
{
    struct node_list* head;
    struct node_list* next;
    struct node_list* prev;
}node_list;

#define MAZ_LIST_GET_FIRST(item) ((typeof(item))(((node_list *)(item))->head->next))
#define MAZ_LIST_GET_NEXT(item) ((typeof(item))(((node_list *)(item))->next))
#define for_each_maz_list(listrootptr,itemptr) for((itemptr)=MAZ_LIST_GET_FIRST(listrootptr);(itemptr);(itemptr)=MAZ_LIST_GET_NEXT(itemptr))
#define MAZ_LIST_RAWDEL(origitem) \
({\
    node_list *_item_=(node_list *)(origitem); \
    if(_item_->next) \
        _item_->next->prev=_item_->prev; \
    if(_item_->prev) \
        _item_->prev->next=_item_->next; \
})
        
#define MAZ_LIST_FIND(list,data) \
({ \
    typeof((list)+1) _tmp; \
    for_each_maz_list(list,_tmp) \
/*    for(_tmp=MAZ_LIST_GET_FIRST((list));_tmp;_tmp=MAZ_LIST_GET_NEXT((list))) \ */ \
        if(!memcmp((((char*)(_tmp))+sizeof(node_list)),data,sizeof(*data))) \
        { \
            break; \
        } \
    _tmp; \
})
//    typeof((list)+1) _found; 
#define MAZ_LIST_DEL(list,data) \
({ \
    node_list *_found; \
    _found=(node_list *)MAZ_LIST_FIND((list),(data)); \
    if(_found) \
    { \
        _found->prev->next=_found->next; \
        if(_found->next) \
            _found->next->prev=_found->prev; \
    } \
    _found; \
})

#define MAZ_LIST_INIT(list) \
({\
    memset((list),0,sizeof(*(list))); \
    ((node_list *)(list))->head=(node_list *)(list); \
})
#define MAZ_LIST_ADD(list,data) \
({ \
    typeof((list)+1) _p=calloc(1,sizeof(*_p)); \
    node_list *tmp_=(node_list *)_p; \
    if(_p) \
    {  \
        tmp_->head=(tmp_->prev=((node_list *)(list))->head); \
        tmp_->next=tmp_->head->next; \
        tmp_->head->next=tmp_; \
        if(tmp_->next) \
            tmp_->next->prev=tmp_; \
        memcpy((((char *)_p)+sizeof(node_list)),&(data),sizeof(data)); \
    } \
    !_p; \
})


#endif
