#include "raylib.h"
#include <iostream>
#include <string>
#include <raylib.hpp>
#include <vector>
#include "tornado.hpp"

#define WIDTH 80
#define HEIGHT 80

typedef enum GameScreen { TITLE, GAMEPLAY, ENDING } GameScreen;
bool isValidPosition(float x, float y) {
    return !std::isnan(x) && !std::isnan(y) && 
           !std::isinf(x) && !std::isinf(y) &&
           x >= 0 && x <= GetScreenWidth() &&
           y >= 0 && y <= GetScreenHeight();
}


class Animal {
    public:
        Vector2 position = { GetScreenWidth()/2.0f, GetScreenHeight()/2.0f };
        Vector2 speed = { 2.0f, 2.0f };
        int radius = WIDTH/2;
        Color color = WHITE;
        int points = 0;
        Texture2D texture;
};

class Cat : public Animal {
    public:
    bool happified = false;
};
class Fish : public Animal{};
class happycat : public Animal{};

class GameState {
    private:
    struct PlayerState : tornado::NetworkData<PlayerState> {
        Vector2 position;
        bool active;
        
        void serialize(std::vector<uint8_t>& buffer) const override {
            size_t offset = buffer.size();
            buffer.resize(offset + sizeof(Vector2) + sizeof(bool));
            memcpy(buffer.data() + offset, &position, sizeof(Vector2));
            memcpy(buffer.data() + offset + sizeof(Vector2), &active, sizeof(bool));
        }
        
        void deserialize(const uint8_t* data, size_t size) override {
            if (size >= sizeof(Vector2) + sizeof(bool)) {
                memcpy(&position, data, sizeof(Vector2));
                memcpy(&active, data + sizeof(Vector2), sizeof(bool));
            }
        }
    };
    
    uint32_t player_state_type;
    PlayerState local_state;
    std::mutex position_mutex;
    tornado::Client* client;

public:
    std::vector<Cat> cats;
    Fish fish;
    GameScreen currentScreen;

    GameState(const char* coordIp) : currentScreen(TITLE) {
        client = new tornado::Client(coordIp);
        
        if (!client->initialize()) {
            throw std::runtime_error("Client initialization failed");
        }

        fish.position = { GetScreenWidth()/2.0f, GetScreenHeight()/2.0f };
        local_state.position = fish.position;
        local_state.active = true;

        player_state_type = client->register_sync_type<PlayerState>(
            [this](const PlayerState& state) {
                if (!client->is_session_host()) {
                    std::lock_guard<std::mutex> lock(position_mutex);
                    fish.position = state.position;
                    std::cout << "Received position update: " << state.position.x << ", " << state.position.y << std::endl;
                }
            }
        );

        if (!client->connect_to_coordinator()) {
            throw std::runtime_error("Failed to connect to coordinator");
        }
    }

    void update() {
        client->update();
        
        if (client->is_session_host()) {
            Vector2 mousePos = GetMousePosition();
            if (mousePos.x != local_state.position.x || mousePos.y != local_state.position.y) {
                std::cout << "Host has " << client->get_remote_peers().size() << " connected peers" << std::endl;
                local_state.position = mousePos;
                local_state.active = true;
                client->broadcast_data(player_state_type, local_state);
            }
        }
    }

    void updateFishPosition(const Vector2& pos) {
        if (client->is_session_host()) {
            std::lock_guard<std::mutex> lock(position_mutex);
            local_state.position = pos;
            fish.position = pos;
            client->broadcast_data(player_state_type, local_state);
        }
    }

    bool isGameHost() const {
        return client->is_session_host();
    }
};


int main()
{
    const int screenWidth = 800;
    const int screenHeight = 450;

    if (enet_initialize() != 0) {
        std::cerr << "Failed to initialize ENet" << std::endl;
        return -1;
    }
    std::cout << "ENet initialized" << std::endl;

    GameState gameState("127.0.0.1");
    std::cout << "Game state created" << std::endl;

    InitWindow(screenWidth, screenHeight, "tornado");
    std::cout << "Window initialized" << std::endl;
    Image catimg = LoadImage("generated/cat.png");
    Image catblue = LoadImage("generated/catb.png");
    Image catred = LoadImage("generated/catr.png");
    Image catwhite = LoadImage("generated/catw.png");
    Image fishimg = LoadImage("generated/fish.png");
    Image happycat = LoadImage("generated/happycat.png");
    Image reno = LoadImage("generated/reno.png");
    ImageResize(&catimg, 80, 80);
    ImageResize(&catblue, 80, 80); 
    ImageResize(&catwhite, 80, 80);
    ImageResize(&catred, 80, 80);
    ImageResize(&fishimg, 50, 20);
    ImageResize(&happycat, 200, 200);   
    ImageResize(&reno, 800, 450);
    Texture2D catd = LoadTextureFromImage(catimg);
    Texture2D catb = LoadTextureFromImage(catblue);
    Texture2D catr = LoadTextureFromImage(catred);
    Texture2D catw = LoadTextureFromImage(catwhite);
    Texture2D renoTxt = LoadTextureFromImage(reno);
    Texture2D fishTexture = LoadTextureFromImage(fishimg);
    Texture2D happycatTexture = LoadTextureFromImage(happycat);

    enum color{
        normal,
        red,
        blue,
        white
    };

    gameState.fish.texture = fishTexture;
    gameState.fish.radius = WIDTH/2;
    
    std::vector<Cat> cats;
    if (gameState.isGameHost()) {
        for(int i = 0; i < 10; i++) {
            Cat cat;
            cat.position.x = GetRandomValue(0, GetScreenWidth());
            cat.position.y = GetRandomValue(0, GetScreenHeight());
            cat.radius = WIDTH/2;
            
            int sw = color(rand() % 4);
            switch(sw) {
                case normal: cat.texture = catd; break;
                case red: cat.texture = catr; break;
                case blue: cat.texture = catb; break;
                case white: cat.texture = catw; break;
                default: cat.texture = catd; break;
            }
            gameState.cats.emplace_back(cat);
        }
    }

    Fish fish;
    fish.position.x = GetRandomValue(0, GetScreenWidth());
    fish.position.y = GetRandomValue(0, GetScreenHeight());
    fish.radius = fish.radius;
    fish.texture = fishTexture;
    gameState.fish.texture = fishTexture;
    gameState.fish.radius = WIDTH/2;
    gameState.fish.position = { GetScreenWidth()/2.0f, GetScreenHeight()/2.0f }; // Set initial position
    std::cout << "Initial fish position: " << gameState.fish.position.x << ", " 
          << gameState.fish.position.y << std::endl;



    UnloadImage(catimg);
    UnloadImage(catblue);
    UnloadImage(catred);
    UnloadImage(catwhite);
    UnloadImage(fishimg);
    UnloadImage(happycat);
    UnloadImage(reno);

    Rectangle catBox = { 0};
    Rectangle fishBox = { 0 };

    GameScreen currentScreen = TITLE;

    bool collision = false;
    while(!WindowShouldClose()) {
        gameState.update();
        std::cout << "Is host: " << (gameState.isGameHost() ? "yes" : "no") << "\r" << std::flush;

        BeginDrawing();
        ClearBackground(RAYWHITE);

        switch(gameState.currentScreen) {
            case TITLE: {
                DrawRectangle(0, 0, screenWidth, screenHeight, GREEN);
                DrawText("FEED CATS AND MAKE THEM HAPPY", 20, 20, 40, DARKGREEN);
                DrawText("PRESS ENTER to JUMP to GAMEPLAY SCREEN", 120, 220, 20, DARKGREEN);
                
                if (IsKeyPressed(KEY_ENTER)) {
                    gameState.currentScreen = GAMEPLAY;
                }
            } break;
            
            case GAMEPLAY: {
                DrawTexture(renoTxt, GetScreenWidth()/2 - 800/2, 
                           GetScreenHeight()/2 - 450/2, WHITE);
                if (gameState.isGameHost()) {
                    Vector2 mousePos = GetMousePosition();
                    gameState.updateFishPosition(mousePos);
                    std::cout << "Host mouse position: " << mousePos.x << ", " << mousePos.y << std::endl;
                    for(Cat& cat : gameState.cats) {
                        cat.position.x += cat.speed.x;
                        cat.position.y += cat.speed.y;
                        if ((cat.position.x >= (GetScreenWidth() - cat.radius)) || 
                            (cat.position.x <= cat.radius)) cat.speed.x *= -1.0f;
                        if ((cat.position.y >= (GetScreenHeight() - cat.radius)) || 
                            (cat.position.y <= cat.radius)) cat.speed.y *= -1.0f;
                    }
                } else {
                    std::cout << "Client fish position: " << gameState.fish.position.x << ", " 
              << gameState.fish.position.y << std::endl;
                }
                for(const Cat& cat : gameState.cats) {
                    DrawTexture(cat.texture, cat.position.x, cat.position.y, WHITE);
                }
                DrawTexture(gameState.fish.texture, 
                           gameState.fish.position.x, 
                           gameState.fish.position.y, WHITE);
                
                if (gameState.isGameHost()) {
                    for(Cat& cat : gameState.cats) {
                        Rectangle catBox = { cat.position.x, cat.position.y, 
                                          static_cast<float>(cat.radius), 
                                          static_cast<float>(cat.radius) };
                        Rectangle fishBox = { gameState.fish.position.x, 
                                           gameState.fish.position.y,
                                           static_cast<float>(gameState.fish.radius),
                                           static_cast<float>(gameState.fish.radius) };
                        
                        if (CheckCollisionRecs(fishBox, catBox)) {
                            cat.texture = happycatTexture;
                            cat.happified = true;
                            DrawText("MEOW!", cat.position.x / 2 - 50, 
                                   GetScreenHeight() / 2 - 20, 100, RED);
                        }
                    }
                }
            } break;
            
            case ENDING: {
                DrawRectangle(0, 0, screenWidth, screenHeight, BLUE);
                DrawText("gaming!", 120, 220, 20, DARKBLUE);
            } break;
        }
        
        EndDrawing();
    }

    CloseWindow();
    enet_deinitialize();
    return 0;
}
