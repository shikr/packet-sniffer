#include "ui/toolbar.h"
#include "state.h"
#include <glib.h>
#include <gtk/gtk.h>

void on_start_button_clicked(GtkButton *button, gpointer user_data) {
  AppState *state = (AppState *)user_data;
  if (app_state_is_sniffer_started(state)) {
    app_state_stop_sniffer(state);
    gtk_button_set_label(button, "Start");
  } else {
    app_state_start_sniffer(state);
    gtk_button_set_label(button, "Stop");
  }
}

void on_filter(GtkEntry *_, gpointer user_data) {
  AppState *state = (AppState *)user_data;
  app_state_filter_sniffer(state);
}

GtkWidget *toolbar_render(AppState *state) {
  GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
  GtkWidget *entry = app_state_create_filter_entry(state);
  GtkWidget *start_button = gtk_button_new_with_label("Stop");

  g_signal_connect(start_button, "clicked", G_CALLBACK(on_start_button_clicked),
                   state);

  g_signal_connect(entry, "activate", G_CALLBACK(on_filter), state);

  gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Filter: ");
  gtk_box_pack_start(GTK_BOX(toolbar), entry, TRUE, TRUE, 4);
  gtk_box_pack_start(GTK_BOX(toolbar), start_button, FALSE, FALSE, 4);

  return toolbar;
}
