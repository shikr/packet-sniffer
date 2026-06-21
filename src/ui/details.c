#include "ui/details.h"
#include "glib.h"
#include "packet_info.h"
#include "proto_node.h"
#include "state.h"
#include <gtk/gtk.h>

enum { COL_LABEL, NUM_COLUMNS };

typedef struct {
  GtkTreeStore *store;
  GtkTextBuffer *buffer;
} SignalData;

void packet_fill_tree_store(GtkTreeStore *store, PacketInfo *pkt) {
  gtk_tree_store_clear(store);

  for (guint i = 0; i < pkt->layers->len; i++) {
    ProtoNode *layer = g_ptr_array_index(pkt->layers, i);

    // Nodo raíz de la capa
    GtkTreeIter parent;
    gtk_tree_store_append(store, &parent, NULL);
    gtk_tree_store_set(store, &parent, COL_LABEL, layer->label, -1);

    // Hijos
    for (guint j = 0; j < layer->children->len; j++) {
      ProtoNode *child = g_ptr_array_index(layer->children, j);

      GtkTreeIter child_iter;
      gtk_tree_store_append(store, &child_iter, &parent);
      gtk_tree_store_set(store, &child_iter, COL_LABEL, child->label, -1);
    }
  }

  // Expandir todo
  // GtkTreeView *tree = GTK_TREE_VIEW(/* tu widget */);
  // gtk_tree_view_expand_all(tree);
}

GtkWidget *protocol_tree() {
  GtkTreeStore *store = gtk_tree_store_new(NUM_COLUMNS, G_TYPE_STRING);

  GtkWidget *tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
  GtkCellRenderer *r = gtk_cell_renderer_text_new();
  GtkTreeViewColumn *c =
      gtk_tree_view_column_new_with_attributes("Protocolo", r, "text", 0, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view), c);

  return tree_view;
}

void on_selected(GObject *obj, GParamSpec *pspec, gpointer user_data) {
  SignalData *data = user_data;
  PacketInfo *pkt;
  g_object_get(obj, "selected", &pkt, NULL);
  if (!pkt)
    return;
  GString *str = g_string_new(NULL);
  guint len = pkt->raw_len;

  for (guint i = 0; i < len; i += 16) {
    // Offset
    g_string_append_printf(str, "%04x  ", i);

    // Hex
    for (guint j = 0; j < 16; j++) {
      if (i + j < len)
        g_string_append_printf(str, "%02x ", pkt->raw[i + j]);
      else
        g_string_append(str, "   "); // padding

      if (j == 7)
        g_string_append_c(str, ' '); // separador central
    }

    g_string_append(str, "  ");

    // ASCII
    for (guint j = 0; j < 16 && i + j < len; j++) {
      guint8 c = pkt->raw[i + j];
      g_string_append_printf(str, "%c", g_ascii_isprint(c) ? c : '.');
    }

    g_string_append_c(str, '\n');
  }

  gtk_text_buffer_set_text(data->buffer, str->str, str->len);
  g_string_free(str, TRUE);

  packet_fill_tree_store(data->store, pkt);
}

static void g_signal_data_free(gpointer data, GClosure *_) { g_free(data); }

GtkWidget *details_render(AppState *state) {
  GtkWidget *hpane = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
  GtkWidget *content = gtk_text_view_new();
  GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(content));
  gtk_text_buffer_set_text(buffer, "Packet details will be shown here.", -1);
  GtkWidget *tree = protocol_tree();

  gtk_widget_set_vexpand(tree, TRUE);
  gtk_widget_set_vexpand(content, TRUE);

  gtk_paned_add1(GTK_PANED(hpane), tree);
  gtk_paned_add2(GTK_PANED(hpane), content);

  gtk_paned_set_wide_handle(GTK_PANED(hpane), TRUE);

  SignalData *sig_data = g_new0(SignalData, 1);
  sig_data->store =
      GTK_TREE_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree)));
  sig_data->buffer = buffer;

  g_signal_connect_data(state, "notify::selected", G_CALLBACK(on_selected),
                        sig_data, (GClosureNotify)g_signal_data_free,
                        G_CONNECT_AFTER);

  return hpane;
}
