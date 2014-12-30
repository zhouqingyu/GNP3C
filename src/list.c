#include <stdio.h> //NULL definition in it
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h> //u_char
#include <string.h>

#include "project.h"
#include "packet.h"
#include "nids.h"
#include "list.h"

extern void wireless_list_init(struct List *list){
 list->head = NULL;
 list->tail = NULL;
}

extern void wireless_list_add(struct List *list,char *data,int length){
   struct List_Node *node = (struct List_Node *)malloc(sizeof(struct List_Node));
   node->data = (char *)malloc(length*sizeof(char));
   memcpy(node->data,data,length);
   node->length = length;
   node->next = NULL;

   if(list->head == NULL && list->tail == NULL){
      list->head = node;
      list->tail = node;
   }else{
      list->tail->next = node;
      list->tail = node;
   }
}

extern void wireless_list_free(struct List *list){

   if(list == NULL)
      return;
   
   struct List_Node *point,*temp;
   point = list->head;
   while(point!=NULL){
       if(point->data != NULL){
            free(point->data);
       }

       temp = point;
       point = point->next;
       free(temp);
   }
}

extern void wireless_list_merge(struct List *mother,struct List *child){
   mother->tail->next = child->head;
   //printf("%x %s\n",mother->tail->next,mother->tail->next->data);
   mother->tail = child->tail;
}

extern struct List *get_one_block_data(struct List *list){
   int total_length = 0,current_size = 0;
   struct List_Node *point;
   point = list->head;
   while(point){
       total_length += point->length;
       point = point->next;
   }

  char *buffer = (char *)malloc(total_length * sizeof(char));

  point = list->head;
   while(point){
       memcpy(buffer+current_size,point->data,point->length);
       current_size += point->length;
       point = point->next;
   }

  struct List *new_block_list = (struct List *)malloc(sizeof(struct List));
  wireless_list_init(new_block_list);
  wireless_list_add(new_block_list,buffer,total_length);
  
  free(buffer);
  return new_block_list;
}

extern void content_attachment_match_list_init(struct Content_Attachment_Match_List *list){
   list->head = NULL;
}

extern void content_attachment_match_list_add(struct Content_Attachment_Match_List *list,\
                                              struct Content_Attachment_Match *cam){
    if(list == NULL)
       return;

     cam->next = NULL;

     if(list->head == NULL){
         list->head = cam;
         return;
     }

     struct Content_Attachment_Match *point;
     point = list->head;
     while(point != NULL){
       if(point->next != NULL){
           point = point->next;
           continue;
       }
       else{ 
           break; 
       }
    }
    
    point->next = cam;
}

extern int content_attachment_match_list_delete(struct Content_Attachment_Match_List *list,\
                                              struct Content_Attachment_Match *cam){
   if(list == NULL){
       return -1;  
   }

   struct Content_Attachment_Match *point,*before;
   point = list->head;
   before = NULL;
   while(point != NULL){
       if(point == cam){

          if(point == list->head){
              //first node
              list->head = point->next;
              free(cam);
              return 0;
          }else{
              before->next = point->next;
              free(cam);
              return 0;
          }
       }
      before = point;
      point = point->next;
   }
   return -1;
}

extern void http_list_init(struct Http_List *list){
   list->head = NULL;
}

extern void http_list_add(struct Http_List *list,struct Http *http){
   if(list == NULL){
     return;
   }

   http->next = NULL;


   if(list->head == NULL){
      list->head = http;
      return;
   }

   struct Http *point;
   point = list->head;
   while(point != NULL){
       if(point->next != NULL){
           point = point->next;
           continue;
       }
       else{ 
           break; 
       }
   }

   point->next = http;
}

extern void http_list_free(struct Http_List *list){
    if(list == NULL)
        return;

    struct Http *point,*temp;
    point = list->head;

    while(point != NULL){
       temp = point;
       point = point->next;
       
       free_http(temp);
       free(temp);
    }
}

extern struct Http_List *http_list_clone(struct Http_List *source_list){
  
   if(source_list == NULL)
      return NULL;

   struct Http_List *target_list = (struct Http_List *)malloc(sizeof(struct Http_List));
   http_list_init(target_list);
   
   struct Http *source_point = source_list->head;
   struct Http *new_point;
   while(source_point != NULL){
       new_point = clone_http(source_point);
       if(new_point != NULL)
           http_list_add(target_list,new_point);
       source_point = source_point->next;
   }
   
   return target_list;
}

extern struct Entity_List *entity_list_clone(struct Entity_List *source_list){
   
   if(source_list == NULL)
      return NULL;

   struct Entity_List *target_list = (struct Entity_List *)malloc(sizeof(struct Entity_List));
   entity_list_init(target_list);

   struct Entity *source_point = source_list->head;
   struct Entity *new_point;
   while(source_point != NULL){
       new_point = clone_entity(source_point);
       if(new_point != NULL)
          entity_list_add(target_list,new_point);
       source_point = source_point->next;
   }
   
   return target_list;
}

extern struct Parameter_List *parameter_list_clone(struct Parameter_List *source_list){
   if(source_list == NULL)
     return NULL;

   struct Parameter_List *target_list = (struct Parameter_List*)malloc(sizeof(struct Parameter_List));
   parameter_list_init(target_list);

   struct Parameter *source_point = source_list->head;
   struct Parameter *new_point;
   while(source_point != NULL){
       new_point = clone_parameter(source_point);
       if(new_point != NULL)
          parameter_list_add(target_list,new_point);
       source_point = source_point->next;
   }

   return target_list;
}


extern void entity_list_init(struct Entity_List *list){
     list->head = NULL;
}

extern void entity_list_add(struct Entity_List *list,struct Entity *entity){
    if(list == NULL)
       return;

    if(entity == NULL)
       return;

    entity->next = NULL;

    if(list->head == NULL){
        list->head = entity;
        return;
    }

    struct Entity *point;
    point = list->head;
    while(point != NULL){
        if(point->next != NULL){
            point = point->next;
            continue;
        }else{
            break;
        }
    }

    point->next = entity;
}

extern void entity_list_free(struct Entity_List *list){

    if(list == NULL)
      return;
    
    struct Entity *point,*temp;
    point = list->head;
    while(point != NULL){
        temp = point;
        point = point->next;

        free_entity(temp);
        free(temp);
    }
}

extern void parameter_list_init(struct Parameter_List *list){
    list->head = NULL;
}

extern void parameter_list_add(struct Parameter_List *list,struct Parameter *parameter){
    if(list == NULL)
       return;

    if(parameter == NULL)
       return;

    parameter->next = NULL;

    if(list->head == NULL){
        list->head = parameter;
        return;
    }

    struct Parameter *point;
    point = list->head;
    while(point != NULL){
        if(point->next != NULL){
            point = point->next;
            continue;
        }else{
            break;
        }
    }

    point->next = parameter;
}

extern void parameter_list_free(struct Parameter_List *list){
    if(list == NULL)
       return;
   
    struct Parameter *point,*temp;
    point = list->head;
    while(point != NULL){
        temp = point;
        point = point->next;

        free_parameter(temp);
        free(temp);
    }
}


extern void ftp_file_list_init(struct FTP_FILE_LIST *list){
     list->head = NULL;
 
}
extern void ftp_file_list_add(struct FTP_FILE_LIST *list,char *user,char *password,char *file_name,char *handle,int desport){

   if(list == NULL)
     return;

   struct FTP_FILE_NODE *one_node = (struct FTP_FILE_NODE *)malloc(sizeof(struct FTP_FILE_NODE));
   memset(one_node,0,sizeof(struct FTP_FILE_NODE));
   if(user != NULL && strlen(user)!=0)
      strcpy(one_node->user,user);
   if(password != NULL && strlen(password)!= 0)
      strcpy(one_node->password,password);
   if(file_name != NULL && strlen(file_name)!=0)
      strcpy(one_node->file_name,file_name);
   if(handle != NULL && strlen(handle)!=0)
      strcpy(one_node->handle,handle);
   one_node->desport = desport;
   one_node->next = NULL;

   if(list->head == NULL){
     list->head = one_node;
     return;
   }

   struct FTP_FILE_NODE *point;
   point= list->head;
   while(point != NULL){
       if(point->next != NULL){
           point = point->next;
           continue;
       }
       else{ 
           break; 
       }
   }

   point->next = one_node;
   
}
extern struct FTP_FILE_NODE *ftp_file_list_find_remove(struct FTP_FILE_LIST *list,int target_desport){
   if(list == NULL){
       return NULL;  
   }


   struct FTP_FILE_NODE *point,*before;
   point = list->head;
   before = NULL;
   while(point != NULL){
       if(point->desport == target_desport){

          if(point == list->head){
              //first node
              list->head = point->next;
              return point;
          }else{
              before->next = point->next;
              return point;
          }
       }
      before = point;
      point = point->next;
   }
   return NULL;
}
