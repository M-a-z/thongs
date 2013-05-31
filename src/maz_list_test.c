#include "maz_list.h"
#include <stdio.h>

typedef struct mydatatype
{
    char arr[4];
    int foo;
}mydatatype;


typedef struct mylist
{
    node_list ignoreme;
    mydatatype dat;
}mylist;

int main()
{
    mylist list;
    mydatatype seeksimilar={"baf",4};
    mylist *dataptr;
    //mylist *data2ptr;
    mydatatype mydata={ "foo",1};
    mydatatype mydata2={"bar",2};
    mydatatype mydata3={"baz",3};
    mydatatype mydata4={"baf",4};
    int data_amount=0;
    /* First you must init list */
    MAZ_LIST_INIT(&list);
    /* Then you can start adding items in list */
    MAZ_LIST_ADD(&list,mydata);
    data_amount++;
    MAZ_LIST_ADD(&list,mydata2);
    data_amount++;
    MAZ_LIST_ADD(&list,mydata3);
    data_amount++;
    MAZ_LIST_ADD(&list,mydata4);
    data_amount++;
    printf("List contains now:\n");

    /* You can iterate list using for_each_maz_list */
    for_each_maz_list(&list,dataptr)
    {
        printf(" %s : %d\n",dataptr->dat.arr,dataptr->dat.foo);
    }

    for_each_maz_list(&list,dataptr)
    {
        printf("for_each: %s : %d\n",dataptr->dat.arr,dataptr->dat.foo);
        /* You can get first item from list */
        printf("list first: %s : %d\n",(MAZ_LIST_GET_FIRST(dataptr))->dat.arr,(MAZ_LIST_GET_FIRST(dataptr))->dat.foo);
        if(MAZ_LIST_GET_NEXT(dataptr))
            printf("list next:  %s : %d\n",MAZ_LIST_GET_NEXT(dataptr)->dat.arr,(MAZ_LIST_GET_NEXT(dataptr))->dat.foo);
        else
            printf("was last item\n");
        data_amount--;
    }
    if(data_amount)
        printf("for_each test FAILED\n");
    else
        printf("for_each test PASSED\n");
    dataptr=MAZ_LIST_FIND(&list,&seeksimilar);
    printf("%s data similar to mydata from list\n",dataptr?"PASSED - FOUND":"FAILED - NOT FOUND");
    printf("FIND returned address %p, mydata address %p\n",dataptr,MAZ_LIST_GET_FIRST(&list));
    if(dataptr != MAZ_LIST_GET_FIRST(&list))
        printf("FIND test FAILED!\n");
    MAZ_LIST_DEL(&list,&seeksimilar);
    if(MAZ_LIST_FIND(&list,&seeksimilar))
        printf("DELETE first item TEST FAILED\n");
    else
        printf("DELETE first item TEST PASSED!\n");


    for_each_maz_list(&list,dataptr)
    {
        printf("for_each results now: %s : %d\n",dataptr->dat.arr,dataptr->dat.foo);
    }

    for_each_maz_list(&list,dataptr)
        data_amount++;
    for_each_maz_list(&list,dataptr)
    {
        if(dataptr->dat.foo==2)
        {
            MAZ_LIST_RAWDEL(dataptr);
            /* you can use break in for_each - loop to exit loop */
            /* Note, you must not continue for each loop if you modify list in the loop */
            break;
        }
        else
            /* You can also use continue in for_each loop to start new iteration - */
            continue;
    }
    for_each_maz_list(&list,dataptr)
        data_amount--;
    if(1!=data_amount)
        printf("RAW DEL middle item test FAILED\n");
    else
        printf("RAW DEL middle item test PASSED\n");
   
    for_each_maz_list(&list,dataptr)
        printf("for_each results now: %s : %d\n",dataptr->dat.arr,dataptr->dat.foo);
    return 0;
}



