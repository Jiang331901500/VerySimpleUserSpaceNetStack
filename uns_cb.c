#include "uns_cb.h"
#include "stdio.h"

/* ----全连接和半连接的队列操作---- */
static struct tcb_queue rcvd_queue = {0};    // 半连接队列，假设队列中还有一个元素
static struct tcb_queue estb_queue = {0};    // 全连接队列，假设队列中还有一个元素

static int enqueue_tcb(struct tcb_queue* queue, struct tcb* tcb)
{
    if(queue->head == NULL)
        queue->head = tcb;
    else
    {
        struct tcb* t = queue->head;
        struct tcb* p = t;
        while(t != NULL)
        {
            p = t;
            t = t->next;
        }
        p->next = tcb;
    }
    queue->size++;
    return 0;
}

static int remove_tcb(struct tcb_queue* queue, struct tcb* tcb)
{
    if(queue->head == NULL)
        return -1;
    
    if(queue->head == tcb)
    {
        queue->head = queue->head->next;
        queue->size--;
        return 0;
    }

    struct tcb* t = queue->head->next;
    struct tcb* p = queue->head;
    while(t != NULL)
    {
        if(t == tcb)
        {
            p->next = t->next;
            t->next = NULL;
            queue->size--;
            return 0;
        }
        p = t;
        t = t->next;
    }

    return -1;
}

static struct tcb* find_tcb(struct tcb_queue* queue, _u32 remote_ip, _u32 local_ip, _u16 remote_port, _u16 local_port)
{
    struct tcb* t = queue->head;
    while(t != NULL)
    {
        if( t->remote_ip == remote_ip &&
            t->local_ip == local_ip && 
            t->remote_port == remote_port &&
            t->local_port == local_port)
        {
            return t;
        }
        t = t->next;
    }
    return NULL;
}

int add_tcb_to_rcvd_queue(struct tcb* tcb)
{
    return enqueue_tcb(&rcvd_queue, tcb);
}

int add_tcb_to_estb_queue(struct tcb* tcb)
{
    return enqueue_tcb(&estb_queue, tcb);
}

int take_tcb_from_rcvd_queue(struct tcb* tcb)
{
    return remove_tcb(&rcvd_queue, tcb);
}

int take_tcb_from_estb_queue(struct tcb* tcb)
{
    return remove_tcb(&estb_queue, tcb);
}

struct tcb* find_tcb_in_rcvd_queue(_u32 remote_ip, _u32 local_ip, _u16 remote_port, _u16 local_port)
{
    return find_tcb(&rcvd_queue, remote_ip, local_ip, remote_port, local_port);
}

struct tcb* find_tcb_in_estb_queue(_u32 remote_ip, _u32 local_ip, _u16 remote_port, _u16 local_port)
{
    return find_tcb(&estb_queue, remote_ip, local_ip, remote_port, local_port);
}

/* 如果 tcb 是在半连接队列中，则会将其从队列中取出；
   如果 tcb 是在全连接队列中，则只会返回其地址作为引用 */
struct tcb* search_tcb(_u32 remote_ip, _u32 local_ip, _u16 remote_port, _u16 local_port)                                            
{
    // 先到半连接队列中找，找不到则到全连接队列中找
    struct tcb* tcb = find_tcb_in_rcvd_queue(remote_ip, local_ip, remote_port, local_port);
    if(tcb != NULL)
    {
        take_tcb_from_rcvd_queue(tcb);
    }
    else
    {
        tcb = find_tcb_in_estb_queue(remote_ip, local_ip, remote_port, local_port);
    }

    return tcb;
}
/* ----全连接和半连接的队列操作 END---- */