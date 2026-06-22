#include "ui/window.h"
#include "state.h"
#include "ui/home.h"
#include "ui/root.h"
#include <gtk/gtk.h>

void init_window(int *argc, char ***argv) {
  gtk_init(argc, argv);
  AppState *state = app_state_new();
  GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window), "Packet Sniffer");
  gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
  g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

  GtkWidget *stack = app_state_get_stack(state);
  GtkWidget *root = root_render(state);
  GtkWidget *home = home_render(state);

  gtk_stack_add_named(GTK_STACK(stack), home, "home");
  gtk_stack_add_named(GTK_STACK(stack), root, "sniffer");
  gtk_stack_set_visible_child_name(GTK_STACK(stack), "home");

  gtk_container_add(GTK_CONTAINER(window), stack);
  gtk_widget_show_all(window);

  gtk_main();
}
