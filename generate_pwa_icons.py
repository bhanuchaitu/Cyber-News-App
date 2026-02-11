#!/usr/bin/env python3
"""
PWA Icon Generator for MDR Threat Intelligence
Generates 192x192 and 512x512 PNG icons for PWA installation
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_pwa_icons():
    """Create PWA icons with MDR threat intelligence branding"""
    
    # Create static directory if it doesn't exist
    os.makedirs('static', exist_ok=True)
    
    # Define icon sizes
    sizes = [192, 512]
    
    for size in sizes:
        # Create image with dark background
        img = Image.new('RGB', (size, size), color='#0e1117')
        draw = ImageDraw.Draw(img)
        
        # Draw circle background (red gradient effect)
        circle_radius = size // 2 - 20
        circle_center = (size // 2, size // 2)
        
        # Draw filled circle
        draw.ellipse(
            [
                circle_center[0] - circle_radius,
                circle_center[1] - circle_radius,
                circle_center[0] + circle_radius,
                circle_center[1] + circle_radius
            ],
            fill='#ff4444',
            outline='#ff6666',
            width=4
        )
        
        # Add emoji/text in center
        try:
            # Try to use system font
            font_size = size // 3
            font = ImageFont.truetype("arial.ttf", font_size)
        except Exception:
            # Fallback to default font
            font = ImageFont.load_default()
        
        # Draw MDR text in center
        text = "MDR"
        
        # Use text for better cross-platform compatibility
        text_bbox = draw.textbbox((0, 0), text, font=font)
        text_width = text_bbox[2] - text_bbox[0]
        text_height = text_bbox[3] - text_bbox[1]
        
        text_position = (
            (size - text_width) // 2,
            (size - text_height) // 2 - text_height // 4
        )
        
        draw.text(text_position, text, fill='white', font=font)
        
        # Save icon
        filename = f'static/icon-{size}.png'
        img.save(filename, 'PNG')
        print(f"✅ Created {filename}")
    
    print("\n🎯 PWA icons generated successfully!")
    print("📁 Location: static/icon-192.png, static/icon-512.png")
    print("\n💡 Next steps:")
    print("1. (Optional) Replace with custom icons using design tool")
    print("2. Deploy app to HTTPS hosting (Streamlit Cloud/Render/Railway)")
    print("3. Visit on mobile browser to see 'Install app' prompt")

if __name__ == '__main__':
    try:
        create_pwa_icons()
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n📝 Alternative methods:")
        print("1. Use online tool: https://realfavicongenerator.net/")
        print("2. Use any 512x512 image and name it icon-512.png")
        print("3. Resize to 192x192 for icon-192.png")
        print("4. Place both in static/ directory")
