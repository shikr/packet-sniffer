#pragma once

#include <glib.h>

typedef struct _ProtoNode ProtoNode;

struct _ProtoNode {
  char *label;
  GPtrArray *children;
};

ProtoNode *proto_node_new(const char *label);

void proto_node_add_child(ProtoNode *parent, const char *label);

void proto_node_free(ProtoNode *node);
