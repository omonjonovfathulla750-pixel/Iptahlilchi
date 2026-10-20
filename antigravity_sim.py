import pygame
import sys

# Pygame-ni ishga tushirish
pygame.init()

# Ekran o'lchamlari
WIDTH, HEIGHT = 600, 500
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Antigravitatsiya Simulyatsiyasi")

# Ranglar
WHITE = (255, 255, 255)
BLUE = (50, 150, 255)
BLACK = (0, 0, 0)

# Obyekt xususiyatlari
x = WIDTH // 2
y = HEIGHT // 2
radius = 20
velocity_y = 0

# Fizika parametrlari
GRAVITY = 0.5          # Oddiy tortishish kuchi (pastga)
ANTIGRAVITY = -1.2     # Antigravitatsiya kuchi (yuqoriga)
DAMPING = -0.7         # Urilganda sakrash koeffitsiyenti

clock = pygame.time.Clock()

running = True
while running:
    clock.tick(60)
    
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False

    # Tugmani tekshirish (Space bosib turilsa — antigravitatsiya)
    keys = pygame.key.get_pressed()
    if keys[pygame.K_SPACE]:
        velocity_y += ANTIGRAVITY
    else:
        velocity_y += GRAVITY

    # Harakatni yangilash
    y += velocity_y

    # Pol va shiftga urilish fizikasi
    if y + radius >= HEIGHT:
        y = HEIGHT - radius
        velocity_y *= DAMPING
    elif y - radius <= 0:
        y = radius
        velocity_y *= DAMPING

    # Ekranni chizish
    screen.fill(WHITE)
    pygame.draw.circle(screen, BLUE, (int(x), int(y)), radius)
    
    # Ko'rsatma matni
    font = pygame.font.SysFont("Arial", 18)
    text = font.render("Antigravitatsiya uchun SPACE tugmasini bosing", True, BLACK)
    screen.blit(text, (20, 20))

    pygame.display.flip()

pygame.quit()
sys.exit()
