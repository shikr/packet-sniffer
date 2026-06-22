#include "ui/toolbar.h"
#include "state.h"
#include <glib.h>
#include <gtk/gtk.h>

typedef struct {
  AppState *state;
  GtkWidget *start_button;
  GtkWidget *save_button;
} SignalData;

void on_start_button_clicked(GtkButton *_, gpointer user_data) {
  AppState *state = user_data;
  if (app_state_is_sniffer_started(state)) {
    app_state_stop_sniffer(state);
  } else {
    app_state_start_sniffer(state);
  }
}

void on_filter(GtkEntry *_, gpointer user_data) {
  AppState *state = user_data;
  app_state_filter_sniffer(state);
}

void on_started_changed(GObject *obj, GParamSpec *pspec, gpointer user_data) {
  SignalData *sigdata = user_data;
  gboolean started;
  g_object_get(sigdata->state, "started", &started, NULL);
  GtkButton *button = GTK_BUTTON(sigdata->start_button);
  gtk_button_set_label(button, started ? "Stop" : "Start");
  gtk_widget_set_sensitive(sigdata->save_button, !started);
}

void on_save_clicked(GtkButton *_, gpointer user_data) {
  AppState *state = user_data;

  GtkWidget *dialog = gtk_file_chooser_dialog_new(
      "Save capture", NULL, GTK_FILE_CHOOSER_ACTION_SAVE, "_Cancel",
      GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);

  gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog),
                                                 TRUE);

  gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "capture.csv");

  GtkFileFilter *filter = gtk_file_filter_new();
  gtk_file_filter_set_name(filter, "CSV files");
  gtk_file_filter_add_pattern(filter, "*.csv");
  gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

  GtkFileFilter *all_filter = gtk_file_filter_new();
  gtk_file_filter_set_name(all_filter, "All files");
  gtk_file_filter_add_pattern(all_filter, "*");
  gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), all_filter);

  if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
    char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
    app_state_save_capture(state, filename);
    g_free(filename);
  }

  gtk_widget_destroy(dialog);
}

GtkWidget *toolbar_render(AppState *state) {
  GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
  GtkWidget *entry = app_state_create_filter_entry(state);
  GtkWidget *start_button = gtk_button_new_with_label("Stop");
  GtkWidget *save_button = gtk_button_new_with_label("Save");

  SignalData *sigdata = g_new0(SignalData, 1);
  sigdata->state = state;
  sigdata->start_button = start_button;
  sigdata->save_button = save_button;

  g_signal_connect(start_button, "clicked", G_CALLBACK(on_start_button_clicked),
                   state);
  g_signal_connect(save_button, "clicked", G_CALLBACK(on_save_clicked), state);

  g_signal_connect(entry, "activate", G_CALLBACK(on_filter), state);

  g_signal_connect(state, "notify::started", G_CALLBACK(on_started_changed),
                   sigdata);

  gtk_widget_set_sensitive(save_button, FALSE);

  gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Filter: ");
  gtk_box_pack_start(GTK_BOX(toolbar), entry, TRUE, TRUE, 4);
  gtk_box_pack_start(GTK_BOX(toolbar), start_button, FALSE, FALSE, 4);
  gtk_box_pack_start(GTK_BOX(toolbar), save_button, FALSE, FALSE, 4);

  return toolbar;
}
