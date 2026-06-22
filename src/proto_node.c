#include "proto_node.h"
#include <glib.h>

ProtoNode *proto_node_new(const char *label) {
  ProtoNode *node = g_new0(ProtoNode, 1);
  node->label = g_strdup(label);
  node->children =
      g_ptr_array_new_with_free_func((GDestroyNotify)proto_node_free);
  return node;
}

void proto_node_add_child(ProtoNode *parent, const char *label) {
  ProtoNode *child = proto_node_new(label);
  g_ptr_array_add(parent->children, child);
}

void proto_node_free(ProtoNode *node) {
  if (node) {
    g_free(node->label);
    g_ptr_array_free(node->children, TRUE);
    g_free(node);
  }
}
