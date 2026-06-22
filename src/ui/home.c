#include "ui/home.h"
#include "state.h"
#include <gtk/gtk.h>

void on_start_capture_clicked(GtkButton *button, gpointer user_data) {
  AppState *state = user_data;
  app_state_show_sniffer(state);
  app_state_start_sniffer(state);
}

GtkWidget *home_render(AppState *state) {
  GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
  GtkWidget *label = gtk_label_new("Select a device:");
  GtkWidget *combo = app_state_get_device_combo(state);
  GtkWidget *flab = gtk_label_new("Capture filter (optional):");
  GtkWidget *filter_entry = app_state_create_capture_filter_entry(state);
  GtkWidget *start_button = gtk_button_new_with_label("Start");

  gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), combo, FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), flab, FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), filter_entry, FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), start_button, FALSE, FALSE, 0);

  gtk_widget_set_halign(vbox, GTK_ALIGN_CENTER);
  gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);

  g_signal_connect(start_button, "clicked",
                   G_CALLBACK(on_start_capture_clicked), state);

  return vbox;
}
