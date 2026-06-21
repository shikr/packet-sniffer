#include "ui/details.h"
#include "packet_info.h"
#include "state.h"
#include <gtk/gtk.h>

void update(gpointer data) {
  GtkTreeStore *store = GTK_TREE_STORE(data);
  GtkTreeIter iter;
  GtkTreePath *path = gtk_tree_path_new_from_string("0:0:0");

  if (gtk_tree_model_get_iter(GTK_TREE_MODEL(store), &iter, path)) {
    gtk_tree_store_set(store, &iter, 0, "Version: 6", -1);
  }

  gtk_tree_path_free(path);
}

GtkWidget *protocol_tree() {
  GtkTreeStore *store = gtk_tree_store_new(1, G_TYPE_STRING);
  GtkTreeIter eth, ip, tcp;

  gtk_tree_store_append(store, &eth, NULL);
  gtk_tree_store_set(store, &eth, 0, "Ethernet Header", -1);

  gtk_tree_store_append(store, &ip, &eth);
  gtk_tree_store_set(store, &ip, 0, "IP Header", -1);

  GtkTreeIter field;
  gtk_tree_store_append(store, &field, &ip);
  gtk_tree_store_set(store, &field, 0, "Version: 4", -1);
  gtk_tree_store_append(store, &field, &ip);
  gtk_tree_store_set(store, &field, 0, "TTL: 64", -1);

  gtk_tree_store_append(store, &tcp, &ip);
  gtk_tree_store_set(store, &tcp, 0, "TCP Header", -1);

  g_timeout_add_once(5000, update, store);

  GtkWidget *tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
  GtkCellRenderer *r = gtk_cell_renderer_text_new();
  GtkTreeViewColumn *c =
      gtk_tree_view_column_new_with_attributes("Protocolo", r, "text", 0, NULL);
  gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view), c);

  return tree_view;
}

void on_selected(GObject *obj, GParamSpec *pspec, gpointer data) {
  GtkTextBuffer *buffer = GTK_TEXT_BUFFER(data);
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

  gtk_text_buffer_set_text(buffer, str->str, str->len);
  g_string_free(str, TRUE);
}

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

  g_signal_connect(state, "notify::selected", G_CALLBACK(on_selected), buffer);

  return hpane;
}
