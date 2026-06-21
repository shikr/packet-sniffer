#include "ui/table.h"
#include "packet_info.h"
#include "state.h"
#include <gtk/gtk.h>

void cursor_changed_callback(GtkTreeView *tree_view, gpointer user_data) {
  AppState *state = user_data;
  GtkTreeModel *model;
  GtkTreeIter iter;
  GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);

  if (!gtk_tree_selection_get_selected(selection, &model, &iter))
    return;

  guint index;
  gtk_tree_model_get(model, &iter, COL_INDEX, &index, -1);

  app_state_set_selected_by_index(state, index);
}

GtkWidget *table_render(AppState *state) {
  GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
  GtkWidget *tree = app_state_create_table_view(state);

  g_signal_connect(tree, "cursor-changed", G_CALLBACK(cursor_changed_callback),
                   state);

  gtk_container_add(GTK_CONTAINER(scroll), tree);
  return scroll;
}
