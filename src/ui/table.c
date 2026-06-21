#include "ui/table.h"
#include "packet_info.h"
#include "sniffer.h"
#include <gtk/gtk.h>

enum {
  COL_NO,
  COL_TIME,
  COL_SOURCE,
  COL_DEST,
  COL_PROTOCOL,
  COL_LEN,
  COL_INFO,
  COL_INDEX,
  NUM_COLS
};

GtkListStore *store;

void cursor_changed_callback(GtkTreeView *tree_view, gpointer user_data) {
  AppSniffer *sniffer = user_data;
  GtkTreeModel *model;
  GtkTreeIter iter;
  GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);

  if (!gtk_tree_selection_get_selected(selection, &model, &iter))
    return;

  guint index;
  gtk_tree_model_get(model, &iter, COL_INDEX, &index, -1);

  PacketInfo *pkt_info = app_sniffer_get_packet(sniffer, index);

  if (!pkt_info)
    return;

  printf("Selected Packet:\n");
  printf("Protocol: %s\n", pkt_info->protocol);
  printf("Source Address: %s\n", pkt_info->src_ip);
  printf("Destination Address: %s\n", pkt_info->dst_ip);
  printf("Info: %s\n", pkt_info->info);
}

void add_packet_info(AppSniffer *self, guint i, gpointer user_data) {
  PacketInfo *pkt = app_sniffer_get_packet(self, i);
  GtkTreeIter iter;
  gtk_list_store_append(store, &iter);
  gtk_list_store_set(store, &iter, COL_NO, pkt->no, COL_TIME, pkt->time,
                     COL_SOURCE, pkt->src_ip, COL_DEST, pkt->dst_ip,
                     COL_PROTOCOL, pkt->protocol, COL_LEN, pkt->len, COL_INFO,
                     pkt->info, COL_INDEX, i, -1);
}

GtkWidget *table_render(AppSniffer *sniffer) {
  store = gtk_list_store_new(NUM_COLS, G_TYPE_INT, G_TYPE_FLOAT, G_TYPE_STRING,
                             G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT,
                             G_TYPE_STRING, G_TYPE_UINT);
  GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
  GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));

  const char *col_titles[] = {
      "No.",      "Time",   "Source Address", "Destination Address",
      "Protocol", "Length", "Info",           "Index"};
  for (int i = 0; i < NUM_COLS; i++) {
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(
        col_titles[i], r, "text", i, NULL);
    gtk_tree_view_column_set_resizable(c, TRUE);
    gtk_tree_view_column_set_expand(c, TRUE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree), c);
  }

  g_signal_connect(tree, "cursor-changed", G_CALLBACK(cursor_changed_callback),
                   sniffer);

  g_signal_connect(sniffer, "captured", G_CALLBACK(add_packet_info), NULL);

  app_sniffer_start(sniffer);

  app_sniffer_start_timer(sniffer);

  gtk_container_add(GTK_CONTAINER(scroll), tree);
  return scroll;
}
