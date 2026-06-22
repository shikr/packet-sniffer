#include "ui/toolbar.h"
#include "state.h"
#include <glib.h>
#include <gtk/gtk.h>

typedef struct {
  AppState *state;
  GtkWidget *start_button;
} SignalData;

void on_start_button_clicked(GtkButton *_, gpointer user_data) {
  AppState *state = (AppState *)user_data;
  if (app_state_is_sniffer_started(state)) {
    app_state_stop_sniffer(state);
  } else {
    app_state_start_sniffer(state);
  }
}

void on_filter(GtkEntry *_, gpointer user_data) {
  AppState *state = (AppState *)user_data;
  app_state_filter_sniffer(state);
}

void on_started_changed(GObject *obj, GParamSpec *pspec, gpointer user_data) {
  SignalData *sigdata = user_data;
  gboolean started;
  g_object_get(sigdata->state, "started", &started, NULL);
  GtkButton *button = GTK_BUTTON(sigdata->start_button);
  if (button) {
    gtk_button_set_label(button, started ? "Stop" : "Start");
  }
}

GtkWidget *toolbar_render(AppState *state) {
  GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
  GtkWidget *entry = app_state_create_filter_entry(state);
  GtkWidget *start_button = gtk_button_new_with_label("Stop");

  SignalData *sigdata = g_new0(SignalData, 1);
  sigdata->state = state;
  sigdata->start_button = start_button;

  g_signal_connect(start_button, "clicked", G_CALLBACK(on_start_button_clicked),
                   state);

  g_signal_connect(entry, "activate", G_CALLBACK(on_filter), state);

  g_signal_connect(state, "notify::started", G_CALLBACK(on_started_changed),
                   sigdata);

  gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Filter: ");
  gtk_box_pack_start(GTK_BOX(toolbar), entry, TRUE, TRUE, 4);
  gtk_box_pack_start(GTK_BOX(toolbar), start_button, FALSE, FALSE, 4);

  return toolbar;
}
