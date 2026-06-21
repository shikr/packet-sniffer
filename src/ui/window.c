#include "ui/window.h"
#include "ui/root.h"
#include <gtk/gtk.h>

void init_window(int *argc, char ***argv) {
  gtk_init(argc, argv);
  GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window), "Packet Sniffer");
  gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
  g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

  GtkWidget *root = root_render();
  gtk_container_add(GTK_CONTAINER(window), root);
  gtk_widget_show_all(window);

  gtk_main();
}
