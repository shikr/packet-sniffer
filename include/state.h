#pragma once

#include <glib-object.h>
#include <gtk/gtk.h>

G_BEGIN_DECLS

#define APP_TYPE_STATE (app_state_get_type())
G_DECLARE_FINAL_TYPE(AppState, app_state, APP, STATE, GObject)

AppState *app_state_new();
void app_state_start_sniffer(AppState *self);
void app_state_stop_sniffer(AppState *self);
void app_state_filter_sniffer(AppState *self);
void app_state_save_capture(AppState *self, const char *filename);
void app_state_show_sniffer(AppState *self);

gboolean app_state_is_sniffer_started(AppState *self);
void app_state_set_selected_by_index(AppState *self, guint index);

GtkWidget *app_state_create_table_view(AppState *self);
GtkWidget *app_state_create_filter_entry(AppState *self);
GtkWidget *app_state_create_capture_filter_entry(AppState *self);
GtkWidget *app_state_get_device_combo(AppState *self);
GtkWidget *app_state_get_stack(AppState *self);

G_END_DECLS
