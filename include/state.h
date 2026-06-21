#pragma once

#include "packet_info.h"
#include <glib-object.h>
#include <gtk/gtk.h>

G_BEGIN_DECLS

#define APP_TYPE_STATE (app_state_get_type())
G_DECLARE_FINAL_TYPE(AppState, app_state, APP, STATE, GObject)

AppState *app_state_new(char *device, char *filter);
void app_state_start_sniffer(AppState *self);
void app_state_stop_sniffer(AppState *self);
void app_state_set_selected_by_index(AppState *self, guint index);

GtkWidget *app_state_create_table_view(AppState *self);

G_END_DECLS
