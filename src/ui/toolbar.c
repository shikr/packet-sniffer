#include "ui/toolbar.h"
#include <gtk/gtk.h>

GtkWidget *toolbar_render() {
  GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
  GtkWidget *entry = gtk_entry_new();
  GtkWidget *start_button = gtk_button_new_with_label("Start");

  gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Filtro: ");
  gtk_box_pack_start(GTK_BOX(toolbar), entry, TRUE, TRUE, 4);
  gtk_box_pack_start(GTK_BOX(toolbar), start_button, FALSE, FALSE, 4);

  return toolbar;
}
