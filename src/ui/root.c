#include "ui/root.h"
#include "state.h"
#include "ui/details.h"
#include "ui/table.h"
#include "ui/toolbar.h"
#include <gtk/gtk.h>

void on_paned_realize(GtkWidget *paned, gpointer data) {
  GtkOrientation orientation =
      gtk_orientable_get_orientation(GTK_ORIENTABLE(paned));
  GtkAllocation allocation;

  gtk_widget_get_allocation(paned, &allocation);

  int total_size = (orientation == GTK_ORIENTATION_HORIZONTAL)
                       ? allocation.width
                       : allocation.height;
  gtk_paned_set_position(GTK_PANED(paned), total_size / 2);
}

GtkWidget *root_render() {
  AppState *state = app_state_new("eth0", NULL);

  app_state_start_sniffer(state);

  GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
  GtkWidget *toolbar = toolbar_render();
  GtkWidget *vpane = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
  GtkWidget *table = table_render(state);
  GtkWidget *hpane = details_render(state);

  gtk_paned_add1(GTK_PANED(vpane), table);
  gtk_paned_add2(GTK_PANED(vpane), hpane);

  g_signal_connect(vpane, "realize", G_CALLBACK(on_paned_realize), NULL);
  g_signal_connect(hpane, "realize", G_CALLBACK(on_paned_realize), NULL);

  gtk_box_pack_start(GTK_BOX(vbox), toolbar, FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), vpane, TRUE, TRUE, 0);

  return vbox;
}
