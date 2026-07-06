#!/bin/bash

echo "[*] Installing EXE-GUARDIAN..."

# 1. Install required Python packages
echo "[*] Installing dependencies (pefile, rich)..."
pip install pefile rich -q

# 2. Get the current directory of the cloned repo
DIR=$(pwd)

# 3. Create a small wrapper script to act as the global command
echo "#!/bin/bash" > guardian
echo "python $DIR/guardian.py \"\$@\"" >> guardian

# 4. Make the wrapper executable
chmod +x guardian

# 5. Move the wrapper to the system's global binary folder
echo "[*] Setting up global command 'guardian'..."
if [ -d "$PREFIX/bin" ]; then
    # This runs if the user is using Termux
    mv guardian $PREFIX/bin/
else
    # This runs if the user is on a standard Linux distro (like a laptop)
    sudo mv guardian /usr/local/bin/
fi

echo "[+] Installation complete! You can now type 'guardian <file_path>' from anywhere."
