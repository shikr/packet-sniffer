#include "state.h"
#include "packet_info.h"
#include "sniffer.h"
#include <glib.h>
#include <gtk/gtk.h>
#include <pcap.h>
#include <stdio.h>

struct _AppState {
  GObject parent;
  PacketInfo *selected;
  gboolean started;
  guint timeout_id;
  GtkListStore *store;
  AppSniffer *sniffer;
  GtkEntryBuffer *filter_buffer;
  GtkEntryBuffer *capture_filter_buffer;
  GtkWidget *combo_device;
  GtkWidget *stack;
};

enum { PROP_0, PROP_SELECTED, PROP_STARTED, N_PROPS };
static GParamSpec *properties[N_PROPS] = {
    NULL,
};

G_DEFINE_TYPE(AppState, app_state, G_TYPE_OBJECT)

static void app_state_init(AppState *self) {
  self->selected = NULL;
  self->started = FALSE;
  self->timeout_id = 0;
  self->store = NULL;
  self->sniffer = NULL;
  self->filter_buffer = gtk_entry_buffer_new(NULL, -1);
  self->capture_filter_buffer = gtk_entry_buffer_new(NULL, -1);
  self->combo_device = gtk_combo_box_text_new();
  self->stack = gtk_stack_new();
}

static void app_state_finalize(GObject *object) {
  AppState *self = APP_STATE(object);
  g_clear_object(&self->store);
  g_clear_object(&self->sniffer);
  G_OBJECT_CLASS(app_state_parent_class)->finalize(object);
}

static void app_state_set_property(GObject *object, guint property_id,
                                   const GValue *value, GParamSpec *pspec) {
  AppState *self = APP_STATE(object);
  switch (property_id) {
  case PROP_SELECTED:
    self->selected = g_value_get_pointer(value);
    g_object_notify_by_pspec(object, properties[PROP_SELECTED]);
    break;
  case PROP_STARTED:
    self->started = g_value_get_boolean(value);
    g_object_notify_by_pspec(object, properties[PROP_STARTED]);
    break;
  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
    break;
  }
}

static void app_state_get_property(GObject *object, guint property_id,
                                   GValue *value, GParamSpec *pspec) {
  AppState *self = APP_STATE(object);
  switch (property_id) {
  case PROP_SELECTED:
    g_value_set_pointer(value, self->selected);
    break;
  case PROP_STARTED:
    g_value_set_boolean(value, self->started);
    break;
  default:
    G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
    break;
  }
}

static void app_state_class_init(AppStateClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = app_state_finalize;
  object_class->set_property = app_state_set_property;
  object_class->get_property = app_state_get_property;

  properties[PROP_SELECTED] =
      g_param_spec_pointer("selected", "Selected Packet",
                           "Currently selected packet info", G_PARAM_READWRITE);
  properties[PROP_STARTED] = g_param_spec_boolean(
      "started", "Started", "Whether the sniffer is started", FALSE,
      G_PARAM_READWRITE);

  g_object_class_install_properties(object_class, N_PROPS, properties);
}

static gboolean match_filter(PacketInfo *pkt, const gchar *filter) {
  if (!filter || filter[0] == '\0') {
    return TRUE;
  }
  return packet_info_match_filter(pkt, filter);
}

static void add_packet_info(AppSniffer *self, guint i, gpointer user_data) {
  AppState *state = user_data;
  PacketInfo *pkt = app_sniffer_get_packet(self, i);

  if (!match_filter(pkt, gtk_entry_buffer_get_text(state->filter_buffer))) {
    return;
  }

  GtkTreeIter iter;

  gtk_list_store_append(state->store, &iter);
  gtk_list_store_set(state->store, &iter, COL_NO, pkt->id, COL_TIME, pkt->time,
                     COL_SOURCE, pkt->src, COL_DEST, pkt->dst, COL_PROTOCOL,
                     pkt->protocol, COL_LEN, pkt->len, COL_INFO, pkt->info,
                     COL_INDEX, i, -1);
}

static gboolean is_ethernet(pcap_if_t *dev) {
  for (pcap_addr_t *a = dev->addresses; a; a = a->next) {
    if (a->addr && a->addr->sa_family == AF_PACKET) {
      return TRUE;
    }
  }
  return FALSE;
}

static void populate_interfaces(GtkComboBoxText *combo) {
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    g_printerr("Error finding devices: %s\n", errbuf);
    return;
  }

  for (pcap_if_t *d = alldevs; d; d = d->next) {
    if (!is_ethernet(d)) {
      continue;
    }
    gtk_combo_box_text_append(combo, d->name, d->name);
  }

  pcap_freealldevs(alldevs);

  gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
}

AppState *app_state_new() {
  AppState *self = g_object_new(APP_TYPE_STATE, NULL);

  populate_interfaces(GTK_COMBO_BOX_TEXT(self->combo_device));

  self->sniffer = app_sniffer_new();
  self->store = gtk_list_store_new(NUM_COLS, G_TYPE_INT, G_TYPE_DOUBLE,
                                   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                                   G_TYPE_UINT, G_TYPE_STRING, G_TYPE_UINT);

  g_signal_connect(self->sniffer, "captured", G_CALLBACK(add_packet_info),
                   self);

  return self;
}

void app_state_start_sniffer(AppState *self) {
  g_return_if_fail(APP_IS_STATE(self));
  gtk_list_store_clear(self->store);
  app_sniffer_start(
      self->sniffer,
      gtk_combo_box_get_active_id(GTK_COMBO_BOX(self->combo_device)),
      gtk_entry_buffer_get_text(self->capture_filter_buffer));
  self->timeout_id = app_sniffer_start_timer(self->sniffer);
  g_object_set(self, "started", TRUE, NULL);
  gtk_list_store_clear(self->store);
}

void app_state_stop_sniffer(AppState *self) {
  g_return_if_fail(APP_IS_STATE(self));
  app_sniffer_stop(self->sniffer);
  g_object_set(self, "started", FALSE, NULL);
  if (self->timeout_id > 0) {
    g_source_remove(self->timeout_id);
    self->timeout_id = 0;
  }
}

void app_state_filter_sniffer(AppState *self) {
  g_return_if_fail(APP_IS_STATE(self));

  gtk_list_store_clear(self->store);

  for (guint i = 0; i < app_sniffer_packets_len(self->sniffer); i++) {
    add_packet_info(self->sniffer, i, self);
  }
}

void app_state_save_capture(AppState *self, const char *filename) {
  g_return_if_fail(APP_IS_STATE(self));
  FILE *file = fopen(filename, "w");
  if (!file) {
    g_printerr("Failed to open file for writing: %s\n", filename);
    return;
  }
  fprintf(file, "id;time;length;src;dest;protocol;info;raw_len;raw\n");
  for (guint i = 0; i < app_sniffer_packets_len(self->sniffer); i++) {
    PacketInfo *pkt = app_sniffer_get_packet(self->sniffer, i);
    fprintf(file, "%d;%.6f;%u;%s;%s;%s;%s;%u;", pkt->id, pkt->time, pkt->len,
            pkt->src, pkt->dst, pkt->protocol, pkt->info, pkt->raw_len);
    for (guint j = 0; j < pkt->raw_len; j++) {
      fprintf(file, "%02x", pkt->raw[j]);
    }
    fprintf(file, "\n");
  }
  fclose(file);
  g_print("Saving capture to: %s\n", filename);
}

void app_state_show_sniffer(AppState *self) {
  g_return_if_fail(APP_IS_STATE(self));
  gtk_stack_set_visible_child_name(GTK_STACK(self->stack), "sniffer");
}

gboolean app_state_is_sniffer_started(AppState *self) {
  g_return_val_if_fail(APP_IS_STATE(self), FALSE);
  return self->started;
}

void app_state_set_selected_by_index(AppState *self, guint index) {
  g_return_if_fail(APP_IS_STATE(self));
  PacketInfo *pkt = app_sniffer_get_packet(self->sniffer, index);

  if (pkt) {
    g_object_set(self, "selected", pkt, NULL);
  }
}

GtkWidget *app_state_create_table_view(AppState *self) {
  g_return_val_if_fail(APP_IS_STATE(self), NULL);
  GtkWidget *table = gtk_tree_view_new_with_model(GTK_TREE_MODEL(self->store));

  const char *col_titles[] = {
      "No.",      "Time",   "Source Address", "Destination Address",
      "Protocol", "Length", "Info",           "Index"};
  for (int i = 0; i < NUM_COLS; i++) {
    GtkCellRenderer *r = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(
        col_titles[i], r, "text", i, NULL);
    gtk_tree_view_column_set_resizable(c, TRUE);
    gtk_tree_view_column_set_expand(c, TRUE);

    if (i == COL_INDEX)
      gtk_tree_view_column_set_visible(c, FALSE);

    gtk_tree_view_append_column(GTK_TREE_VIEW(table), c);
  }

  return table;
}

GtkWidget *app_state_create_filter_entry(AppState *self) {
  g_return_val_if_fail(APP_IS_STATE(self), NULL);
  GtkWidget *entry = gtk_entry_new_with_buffer(self->filter_buffer);
  return entry;
}

GtkWidget *app_state_create_capture_filter_entry(AppState *self) {
  g_return_val_if_fail(APP_IS_STATE(self), NULL);
  GtkWidget *entry = gtk_entry_new_with_buffer(self->capture_filter_buffer);
  return entry;
}

GtkWidget *app_state_get_device_combo(AppState *self) {
  g_return_val_if_fail(APP_IS_STATE(self), NULL);
  return self->combo_device;
}

GtkWidget *app_state_get_stack(AppState *self) {
  g_return_val_if_fail(APP_IS_STATE(self), NULL);
  return self->stack;
}
