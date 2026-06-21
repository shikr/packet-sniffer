#include "ui/toolbar.h"
#include "state.h"
#include <glib.h>
#include <gtk/gtk.h>

gboolean started = TRUE;

void on_start_button_clicked(GtkButton *button, gpointer user_data) {
  AppState *state = (AppState *)user_data;
  if (started) {
    app_state_stop_sniffer(state);
    gtk_button_set_label(button, "Start");
  } else {
    app_state_start_sniffer(state);
    gtk_button_set_label(button, "Stop");
  }
  started = !started;
}

GtkWidget *toolbar_render(AppState *state) {
  GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
  GtkWidget *entry = gtk_entry_new();
  GtkWidget *start_button = gtk_button_new_with_label("Stop");

  g_signal_connect(start_button, "clicked", G_CALLBACK(on_start_button_clicked),
                   state);

  gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Filtro: ");
  gtk_box_pack_start(GTK_BOX(toolbar), entry, TRUE, TRUE, 4);
  gtk_box_pack_start(GTK_BOX(toolbar), start_button, FALSE, FALSE, 4);

  return toolbar;
}
