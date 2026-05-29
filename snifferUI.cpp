#include <raylib.h>
#include <vector>
#include <string>
#include <cstdio>
#include <stdio.h>
#include <iostream>

const int win_width = 1920;
const int win_height = 1080;

//g++ snifferUI.cpp -o snui -lraylib -lGL -lm -lpthread -ldl -lrt -lX11

//estructura aproximada de los paquetes
struct Packet {
    int no;
    float time;
    std::string source;
    std::string destination;
    std::string protocol;
    int length;
    std::string info;
};

//vector de paquetes
std::vector<Packet> packets;

//scrolls de las ventanas
float scroll_list = 0;
float scroll_info = 0;
float scroll_mem  = 0;
float scroll_hex  = 0;

//ventanas
Rectangle Packet_list     = {10, 100, 1900, 500};
Rectangle Packet_info     = {10, 650, 570, 300};
Rectangle packet_raw_mem  = {600, 650, 700, 300};
Rectangle packet_raw_hex  = {1320, 650, 570, 300};

//funciones
void DrawPanel(Rectangle r);
void ClampScroll(float &scroll, int items, float itemHeight, float panelHeight);
void draw_packet_list();
void draw_simple_panel(Rectangle r, float scroll, const char* prefix);
void draw_titles();

//----------------------------------------------------------------------------------------------------------------------------------//
int main()
{
    InitWindow(win_width, win_height, "UI Refactor");
    SetTargetFPS(60);

    // fake data
    for (int i = 0; i < 50; i++)
    {
        packets.push_back({i,(float)GetRandomValue(1, 999) / 10.0f,"192.168.0.1","192.168.0.2","TCP",GetRandomValue(60, 1500),"Sample packet data"});
    }

    while (!WindowShouldClose())
    {
        Vector2 mouse = GetMousePosition();
        float wheel = GetMouseWheelMove() * 20;

        //scroll solo si el raton esta encima
        if (CheckCollisionPointRec(mouse, Packet_list))
        {
             scroll_list += wheel;
        }
        if (CheckCollisionPointRec(mouse, Packet_info))
        {
            scroll_info += wheel;
        }  
        if (CheckCollisionPointRec(mouse, packet_raw_mem))
        {
            scroll_mem += wheel;
        }
        if (CheckCollisionPointRec(mouse, packet_raw_hex))
        {
            scroll_hex += wheel;
        }   

        //limitar el scroll
        ClampScroll(scroll_list, packets.size(), 30, Packet_list.height);
        ClampScroll(scroll_info, 20, 25, Packet_info.height);
        ClampScroll(scroll_mem, 20, 25, packet_raw_mem.height);
        ClampScroll(scroll_hex, 20, 25, packet_raw_hex.height);

        //dibujar ventanitas
        BeginDrawing();
        ClearBackground(BLACK);

        draw_titles();

        draw_packet_list();
        draw_simple_panel(Packet_info, scroll_info, "-INFO");
        draw_simple_panel(packet_raw_mem, scroll_mem, "-MEM");
        draw_simple_panel(packet_raw_hex, scroll_hex, "-HEX");

        EndDrawing();
    }

    CloseWindow();
    return 0;
}
//----------------------------------------------------------------------------------------------------------------------------------//
void DrawPanel(Rectangle r)
{
    DrawRectangleLinesEx(r, 1, GREEN);
}
//----------------------------------------------------------------------------------------------------------------------------------//
void ClampScroll(float &scroll, int items, float itemHeight, float panelHeight)
{
    float maxScroll = (items * itemHeight) - panelHeight;
    if (maxScroll < 0)
    {
        maxScroll = 0;

    }
    if (scroll > 0)
    {
        scroll = 0;
    }
    if (scroll < -maxScroll)
    {
        scroll = -maxScroll;
    }
}
//----------------------------------------------------------------------------------------------------------------------------------//
void draw_packet_list()
{
    DrawPanel(Packet_list);
    BeginScissorMode(Packet_list.x, Packet_list.y, Packet_list.width, Packet_list.height);

    float itemHeight = 30;

    for (size_t i = 0; i < packets.size(); i++)
    {
        char buffer[256];
        snprintf(buffer, sizeof(buffer),"%d   %.2f   %s   %s   %s   %d   %s",packets[i].no,packets[i].time,packets[i].source.c_str(),packets[i].destination.c_str(),packets[i].protocol.c_str(),packets[i].length,packets[i].info.c_str());

        DrawText(buffer,Packet_list.x + 10,Packet_list.y + 10 + i * itemHeight + scroll_list,18,GREEN);
    }

    EndScissorMode();
}
//----------------------------------------------------------------------------------------------------------------------------------//
void draw_simple_panel(Rectangle r, float scroll, const char* prefix)
{
    DrawPanel(r);
    BeginScissorMode(r.x, r.y, r.width, r.height);

    for (int i = 0; i < 20; i++)
    {
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "%s %d", prefix, i);

        DrawText(buffer,r.x + 10,r.y + 10 + i * 25 + scroll,18, GREEN);
    }

    EndScissorMode();
}
//----------------------------------------------------------------------------------------------------------------------------------//
void draw_titles()
{
    const char *titles[] = {"No", "TIME", "SOURCE", "DESTINATION","PROTOCOL", "LENGTH", "INFO"};

    int x = 20;
    for (int i = 0; i < 7; i++)
    {
        DrawText(titles[i], x, 80, 20, GREEN);
        x += 275;
    }
}
//----------------------------------------------------------------------------------------------------------------------------------//