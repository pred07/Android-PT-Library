# Android Penetration Testing - Complete Guide

## 📋 Android PT Methodology

```
Information Gathering → Static Analysis → Dynamic Analysis → Exploitation → Privilege Escalation → Report
```

### Phase 1: Information Gathering
- Check app in Google Play Store or alternative stores
- Review app permissions and ratings
- Analyze developer information
- Check app version history
- Review user reviews for security concerns

---

## 🏗️ Android Architecture

```
┌─────────────────────────────────┐
│        Applications             │
├─────────────────────────────────┤
│    Application Framework        │
├─────────────────────────────────┤
│  Android Runtime  │  Libraries  │
├─────────────────────────────────┤
│         Linux Kernel            │
└─────────────────────────────────┘
```

### Android App Compilation Flow
```
Java/Kotlin → Compiler → Java Bytecode → DEX Compiler → Dalvik Bytecode → DVM/ART
```

---

## 🔧 Essential Tools Setup

### Core Tools
| Tool | Purpose |
|------|---------|
| **Genymotion** | Android emulator (faster than AVD) |
| **Burp Suite** | HTTP proxy and interceptor |
| **ADB** | Android Debug Bridge |
| **JADX** | DEX to Java decompiler |
| **APKTool** | APK decompile/recompile |
| **MobSF** | Mobile Security Framework (automated analysis) |
| **Drozer** | Android security assessment framework |
| **Frida** | Dynamic instrumentation toolkit |
| **Objection** | Runtime mobile exploration (built on Frida) |

### Additional Tools
- **SQLite Browser** - Database analysis
- **apk-mitm** - Automatic SSL pinning bypass
- **Xposed Framework** - Runtime modification framework
- **RootCloak** - Hide root from apps
- **Inspeckage** - Dynamic analysis tool

---

## 🔍 Static Analysis

### 1. Initial APK Extraction
```bash
# Pull APK from device
adb shell pm list packages | grep <app_name>
adb shell pm path com.example.app
adb pull /data/app/com.example.app-xxx/base.apk
```

### 2. Decompile APK
```bash
# Using APKTool (for resources, manifest, smali)
apktool d app.apk -o app_decompiled

# Using JADX (for Java source code)
jadx app.apk -d app_jadx
jadx-gui app.apk  # GUI version
```

### 3. Analyze AndroidManifest.xml

**Critical Checks:**

#### Debug Mode
```xml
<!-- VULNERABLE if true -->
<application android:debuggable="true">
```
- Allows attackers to attach debugger
- Extract runtime data
- Modify app behavior

#### Backup Enabled
```xml
<!-- VULNERABLE if true -->
<application android:allowBackup="true">
```
- Allows `adb backup` to extract app data
- May leak sensitive information

#### Cleartext Traffic
```xml
<!-- VULNERABLE if true -->
<application android:usesCleartextTraffic="true">
```
- Allows HTTP (non-HTTPS) communication
- Enables MITM attacks

#### Exported Components
```xml
<!-- VULNERABLE if exported without proper protection -->
<activity android:name=".SecretActivity" android:exported="true"/>
<service android:name=".ApiService" android:exported="true"/>
<receiver android:name=".PaymentReceiver" android:exported="true"/>
<provider android:name=".DataProvider" android:exported="true"/>
```
- `exported="true"` allows other apps to invoke components
- Can lead to unauthorized access

#### Dangerous Permissions
Check for unnecessary permissions:
- `READ_EXTERNAL_STORAGE`
- `WRITE_EXTERNAL_STORAGE`
- `ACCESS_FINE_LOCATION`
- `CAMERA`
- `READ_CONTACTS`
- `SEND_SMS`

### 4. Framework-Specific Analysis

#### Flutter Apps
```bash
cd app_decompiled
cd lib/
# Contains compiled Dart code (difficult to reverse)
```

#### React Native Apps
```bash
cd app_decompiled
cd assets/
# Look for index.android.bundle (JavaScript code)
cat index.android.bundle | grep -i "api\|key\|secret\|password"
```

### 5. Resource Analysis

#### Strings.xml
```bash
cd app_decompiled/res/values/
cat strings.xml
```

**Look for:**
- API keys
- Firebase URLs
- Google Maps API keys
- AWS credentials
- Backend URLs
- Hardcoded passwords

#### Firebase Vulnerability Check
```bash
# If you find Firebase URL in strings.xml
# Format: https://project-name.firebaseio.com

# Test unauthorized access:
curl https://project-name.firebaseio.com/.json
```
If JSON data is returned, Firebase database is publicly accessible! 🔥

#### Google API Key Testing
If you find Google API keys, test them:
```bash
# Google Maps API
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=YOUR_API_KEY"

# YouTube Data API
curl "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=YOUR_API_KEY"
```

### 6. Assets Folder Analysis
```bash
cd app_decompiled/assets/
ls -la
```
**Search for:**
- Configuration files
- Database files
- Embedded certificates
- JavaScript files
- Sensitive documentation

### 7. Code Search for Sensitive Data
```bash
cd app_jadx/

# Search for sensitive patterns
grep -r "password" .
grep -r "secret" .
grep -r "api_key" .
grep -r "aws_" .
grep -r "https://" .
grep -r "http://" .
grep -i -r "token" .
grep -i -r "auth" .
grep -i -r "private_key" .
```

### 8. WebView Security Check
Search for WebView configurations:
```java
// VULNERABLE if JavaScript is enabled
webView.getSettings().setJavaScriptEnabled(true);

// VULNERABLE - allows file access
webView.getSettings().setAllowFileAccess(true);

// VULNERABLE - allows universal access from file URLs
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

### 9. Automated Static Analysis
```bash
# Using MobSF (Mobile Security Framework)
# Start MobSF server
python manage.py runserver 0.0.0.0:8000

# Upload APK via web interface
# Review automated findings
```

---

## 🔄 Dynamic Analysis Setup

### 1. Environment Setup

#### Step 1: Start Genymotion Emulator
```bash
# Launch Genymotion
# Select Android 8.0+ device (rooted)
```

#### Step 2: Install APK
```bash
adb devices
adb install app.apk
```

#### Step 3: Setup Burp Suite Proxy

**A. Export Burp Certificate**
1. Burp → Proxy → Options → Import/Export CA Certificate
2. Export as DER format: `burp-cert.der`

**B. Convert to PEM (for Android 7+)**
```bash
openssl x509 -inform DER -in burp-cert.der -out burp-cert.pem

# Get certificate hash
openssl x509 -inform PEM -subject_hash_old -in burp-cert.pem | head -1

# Rename certificate (example: hash is 9a5ba575)
mv burp-cert.pem 9a5ba575.0
```

**C. Install Certificate on Device**
```bash
# Push certificate to device
adb push 9a5ba575.0 /data/local/tmp/

# Install as system certificate (requires root)
adb shell
su
mount -o rw,remount /system
cp /data/local/tmp/9a5ba575.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/9a5ba575.0
reboot
```

**D. Configure Proxy on Device**
1. Settings → WiFi → Long press network → Modify Network
2. Advanced options → Manual Proxy
3. Proxy hostname: `<Your IP>` (e.g., 192.168.1.10)
4. Proxy port: `8080`

#### Step 4: Setup Frida (for SSL Pinning Bypass)

**Download Frida Server:**
```bash
# Check device architecture
adb shell getprop ro.product.cpu.abi
# Output: x86, x86_64, armeabi-v7a, or arm64-v8a

# Download matching Frida server from:
# https://github.com/frida/frida/releases
# Example: frida-server-16.1.4-android-x86_64.xz

# Extract and push to device
unxz frida-server-16.1.4-android-x86_64.xz
adb push frida-server-16.1.4-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
```

**Start Frida Server:**
```bash
adb shell
su
cd /data/local/tmp/
./frida-server &
exit
exit
```

**Install Frida Tools (on your PC):**
```bash
pip install frida-tools
pip install objection
```

### 2. SSL Pinning Bypass Methods

#### Method 1: Using Frida with Universal Script

**Create `frida-ssl-bypass.js`:**
```javascript
Java.perform(function() {
    console.log("[*] Bypassing SSL Pinning");
    
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManagerImpl = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[*] SSL Pinning bypassed");
            this.init(keyManager, [TrustManagerImpl.$new()], secureRandom);
        };
});
```

**Run Frida:**
```bash
# List running apps
frida-ps -U

# Spawn app with bypass script
frida -U -f com.example.app -l frida-ssl-bypass.js --no-pause

# Or attach to running app
frida -U com.example.app -l frida-ssl-bypass.js
```

#### Method 2: Using Objection (Easiest)
```bash
# Connect to app
objection -g com.example.app explore

# Disable SSL pinning
android sslpinning disable

# Run app normally, traffic will be captured in Burp
```

#### Method 3: Using apk-mitm (Automatic)
```bash
# Install apk-mitm
npm install -g apk-mitm

# Uninstall original app from device
adb uninstall com.example.app

# Process APK (disables SSL pinning and re-signs)
apk-mitm app.apk
# Creates: app-patched.apk

# Install patched APK
adb install app-patched.apk
```

---

## 🔍 Dynamic Analysis - Testing

### 1. Data in Transit (Network Analysis)

#### Capture Traffic
```bash
# Start Burp Suite
# Configure proxy and SSL pinning bypass
# Open app and perform actions
# Review HTTP History in Burp
```

**Check for:**
- Sensitive data in URL parameters
- Hardcoded API keys in headers
- Unencrypted HTTP requests
- Weak authentication tokens
- Session tokens in URLs
- API responses leaking sensitive info

### 2. Data at Rest (Storage Analysis)

#### Access App Data Directory
```bash
adb shell
su
cd /data/data/com.example.app/
ls -la
```

#### Shared Preferences (XML files)
```bash
cd shared_prefs/
ls -la
cat *.xml
```
**Look for:**
- Plain text passwords
- Authentication tokens
- API keys
- User session data
- Sensitive user information

**Privilege Escalation Test:**
```bash
# Modify values to gain privileges
vi user_prefs.xml
# Change: <boolean name="isPremium" value="false" />
# To: <boolean name="isPremium" value="true" />

# Restart app and check if privilege escalated
```

#### Databases (SQLite)
```bash
cd databases/
ls -la
```

**Pull and Analyze:**
```bash
# Pull database to PC
adb pull /data/data/com.example.app/databases/user.db

# Open with SQLite Browser (GUI)
# Or use command line:
sqlite3 user.db
.tables
.schema users
SELECT * FROM users;
```

**Check for:**
- Plain text passwords
- Sensitive user data
- Payment information
- Personal identifiable information (PII)

#### Files Directory
```bash
cd files/
ls -la
cat *
```
**Look for:**
- Configuration files
- Temporary files
- Cache files
- Sensitive documents

#### Cache Directory
```bash
cd cache/
ls -la
```
**Check for:**
- Cached images (may contain sensitive info)
- Temporary tokens
- API responses

### 3. Log Analysis

#### Real-time Logging
```bash
# Clear logs first
adb logcat -c

# Start monitoring logs
adb logcat

# Or filter by app
adb logcat | grep "com.example.app"

# Better tool: mLogcat
# Install from Play Store for better filtering
```

**Check for:**
- Plain text credentials in logs
- API keys
- Tokens
- Error messages with sensitive data
- SQL queries
- Debug information

---

## 🛠️ Drozer - Component Testing

### Setup Drozer

**Install Drozer Agent on Android:**
```bash
# Download drozer-agent.apk
# Install on device
adb install drozer-agent.apk

# Open Drozer app on device and click "Enable"
```

**Setup Port Forwarding:**
```bash
adb forward tcp:31415 tcp:31415
```

**Connect Drozer Console:**
```bash
drozer console connect
```

### Drozer Commands

#### 1. Identify Attack Surface
```bash
run app.package.attacksurface com.example.app
```
**Output shows:**
- Exported Activities
- Exported Broadcast Receivers
- Exported Content Providers
- Exported Services
- Debuggable: Yes/No

#### 2. Enumerate Activities
```bash
# List all activities
run app.activity.info -a com.example.app

# Launch exported activity
run app.activity.start --component com.example.app/.AdminActivity
```

**Example Attack:**
```bash
# Bypass PIN check by directly launching activity
adb shell am start -n com.example.app/.SecureActivity
```

**Advanced Activity Launch with Parameters:**
```bash
adb shell am start \
  -n com.example.app/.SecureActivity \
  -a com.example.app.action.VIEW_CREDS \
  --ez check_pin false \
  --es user_role "admin"
```
- `-n`: Component name
- `-a`: Action
- `--ez`: Boolean extra (check_pin = false)
- `--es`: String extra (user_role = "admin")

#### 3. Content Provider Testing
```bash
# Find content providers
run app.provider.info -a com.example.app

# Find accessible URIs
run scanner.provider.finduris -a com.example.app

# Query content provider
run app.provider.query content://com.example.app.provider/users

# SQL Injection in content provider
run scanner.provider.injection -a com.example.app

# Path traversal in content provider
run scanner.provider.traversal -a com.example.app
```

**Manual Content Provider Query:**
```bash
adb shell content query --uri content://com.example.app.provider/users
```

#### 4. Service Testing
```bash
# List services
run app.service.info -a com.example.app

# Start service
run app.service.start --component com.example.app/.PaymentService
```

#### 5. Broadcast Receiver Testing
```bash
# List receivers
run app.broadcast.info -a com.example.app

# Send broadcast
run app.broadcast.send --component com.example.app/.PaymentReceiver --action android.intent.action.PAYMENT
```

### Automated Drozer Scanning
```bash
# Use drozscan for automated testing
# https://github.com/themalwarenews/drozscan
python drozscan.py -p com.example.app
```

---

## 🔥 OWASP Mobile Top 10

### M1: Improper Platform Usage

**Description:** Misuse of platform features or failure to use platform security controls

**Testing:**
- Review use of platform features (TouchID, Keychain)
- Check for violation of Android guidelines
- Test for unintentional misuse of APIs

**Common Issues:**
- Not using Android Keystore for sensitive keys
- Storing sensitive data in SharedPreferences instead of EncryptedSharedPreferences
- Not implementing proper permissions

### M2: Insecure Data Storage

**Description:** Insecure storage of sensitive data on device

**Testing Locations:**
```bash
# Shared Preferences
/data/data/com.example.app/shared_prefs/

# Databases
/data/data/com.example.app/databases/

# Internal Storage
/data/data/com.example.app/files/

# External Storage (SD Card)
/sdcard/Android/data/com.example.app/

# Temporary Files
/data/data/com.example.app/cache/

# Logs
adb logcat
```

**What to Look For:**
- Plain text passwords
- Authentication tokens
- Credit card numbers
- Personal information
- API keys
- Session data

**Pull Database:**
```bash
adb pull /data/data/com.example.app/databases/user.db
# Open with DB Browser for SQLite
```

### M3: Insecure Communication

**Description:** Transferring sensitive data over insecure channels

**Testing:**
- Enable Burp Suite proxy
- Bypass SSL pinning
- Monitor all network traffic

**Check for:**
- HTTP instead of HTTPS
- Weak SSL/TLS versions (SSLv3, TLS 1.0)
- Certificate validation issues
- Sensitive data in URLs
- Weak cipher suites
- Missing certificate pinning
- Cleartext traffic allowed

### M4: Insecure Authentication

**Description:** Weak authentication mechanisms

**Testing:**
- Test for rate limiting on login
- Check OTP implementation
- Test for bypass mechanisms
- SQL injection in login
- User enumeration
- Weak password policy

**Test Cases:**
```bash
# Rate limiting test
# Send multiple login requests rapidly

# User enumeration
# Compare responses for valid vs invalid usernames

# Weak passwords
# Try: 123456, password, admin

# SQL Injection
# Username: admin'--
# Password: anything
```

### M5: Insufficient Cryptography

**Description:** Weak encryption algorithms or poor key management

**Testing:**
- Review encryption algorithms in code
- Check for hardcoded encryption keys
- Look for weak crypto (MD5, SHA1, DES)
- Test for predictable encryption keys

**Code Search:**
```bash
grep -r "DES" .
grep -r "MD5" .
grep -r "ECB" .
grep -r "SecretKey" .
```

### M6: Insecure Authorization

**Description:** Improper authorization checks

**Testing:**
```bash
# Find activities from manifest or logcat
adb logcat | grep "ActivityManager"

# Launch restricted activity directly
adb shell am start -n com.example.app/.AdminActivity

# Bypass PIN/authentication check
adb shell am start \
  -n com.example.app/.SecretActivity \
  --ez check_pin false
```

**Test for:**
- Direct activity access
- Parameter manipulation (isAdmin=true)
- Token tampering
- IDOR vulnerabilities
- Horizontal privilege escalation
- Vertical privilege escalation

### M7: Client Code Quality

**Description:** Code-level implementation issues

**Testing:**
- Code review for vulnerabilities
- Check for SQL injection
- Test for buffer overflows
- Memory corruption issues
- Format string vulnerabilities

### M8: Code Tampering

**Description:** App susceptible to modification

**Testing:**
- Check for root detection
```java
// Look for root detection code
RootBeer rootBeer = new RootBeer(context);
if (rootBeer.isRooted()) {
    // App blocks rooted devices
}
```

- Bypass root detection with RootCloak (Xposed module)
- Check for signature verification
- Test emulator detection
- Recompile APK with modifications

**APK Tampering:**
```bash
# Decompile
apktool d app.apk

# Modify smali code or resources
vi app_decompiled/smali/com/example/MainActivity.smali

# Recompile
apktool b app_decompiled -o modified.apk

# Sign APK
keytool -genkey -v -keystore my-key.keystore -alias app_key -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-key.keystore modified.apk app_key

# Install
adb install modified.apk
```

### M9: Reverse Engineering

**Description:** Easy to decompile and understand app logic

**Testing:**
- Decompile APK with JADX
- Check for code obfuscation (ProGuard/R8)
- Look for string encryption
- Test for anti-debugging mechanisms

**Obfuscation Check:**
```bash
# Good obfuscation: class names like a.b.c.d
# Bad obfuscation: clear class names like LoginActivity
```

### M10: Extraneous Functionality

**Description:** Hidden functionality left by developers

**Testing:**
- Look for commented code
- Search for test/debug endpoints
- Check for hidden admin features
- Review logs for developer comments

**Search in Code:**
```bash
grep -r "test" .
grep -r "debug" .
grep -r "TODO" .
grep -r "FIXME" .
grep -r "admin" .
```

---

## 🔐 Advanced Techniques

### Xposed Framework

**Description:** Framework for runtime modification without recompiling APK

**Modules:**
- **RootCloak:** Bypass root detection
- **SSLUnpinning:** Bypass SSL pinning
- **Inspeckage:** Dynamic analysis and hooking
- **TrustMeAlready:** Bypass certificate checks

**Installation:**
```bash
# Install Xposed Framework on device
# Install Xposed Installer APK
# Flash Xposed framework ZIP in custom recovery
# Install Xposed modules from installer
```

### App Backup Exploitation

**If `allowBackup="true"`:**
```bash
# Backup app data
adb backup -f backup.ab com.example.app

# Convert to tar
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar

# Extract
tar -xvf backup.tar

# Browse extracted data
cd apps/com.example.app/
```

### Intent Fuzzing
```bash
# Fuzz intent extras
am start -n com.example/.Activity --es key1 "$(python -c 'print("A"*10000)')"
```

---

## 📱 Alternative Tools

### Web-based Testing
- **Appetize.io:** Cloud-based Android emulator
- No setup required, browser-based testing

### Mobile Security Frameworks
- **MobSF:** Comprehensive automated analysis
- **QARK:** Quick Android Review Kit
- **AndroBugs:** Automated vulnerability scanner

---

## 📝 Reporting Template

### Vulnerability Report Structure:
1. **Title:** Clear, descriptive vulnerability name
2. **Severity:** Critical/High/Medium/Low/Info
3. **OWASP Category:** M1-M10 classification
4. **Description:** Technical explanation
5. **Steps to Reproduce:** Detailed step-by-step
6. **Proof of Concept:** Screenshots, code snippets
7. **Impact:** Business and technical impact
8. **Remediation:** How to fix
9. **References:** CWE, OWASP links

---

## 🎯 Quick Reference Commands

```bash
# List packages
adb shell pm list packages

# Get package path
adb shell pm path com.example.app

# Pull APK
adb pull /path/to/base.apk

# Install APK
adb install app.apk

# Uninstall APK
adb uninstall com.example.app

# Launch app
adb shell monkey -p com.example.app 1

# Start activity
adb shell am start -n com.example.app/.MainActivity

# Access app directory
adb shell
su
cd /data/data/com.example.app/

# View logs
adb logcat

# Clear logs
adb logcat -c

# Backup app
adb backup -f backup.ab com.example.app

# Forward port
adb forward tcp:8080 tcp:8080

# Push file
adb push file.txt /sdcard/

# Pull file
adb pull /sdcard/file.txt

# Grant permission
adb shell pm grant com.example.app android.permission.READ_CONTACTS

# Revoke permission
adb shell pm revoke com.example.app android.permission.READ_CONTACTS

# Kill app
adb shell am force-stop com.example.app

# Clear app data
adb shell pm clear com.example.app
```

---

## 🚀 Testing Checklist

### Static Analysis ✓
- [ ] Decompile APK with APKTool and JADX
- [ ] Review AndroidManifest.xml for misconfigurations
- [ ] Check for hardcoded credentials/API keys
- [ ] Analyze strings.xml and other resources
- [ ] Test Firebase URL for public access
- [ ] Search code for sensitive patterns
- [ ] Check for weak cryptography
- [ ] Review exported components
- [ ] Check WebView security settings
- [ ] Run automated scan with MobSF

### Dynamic Analysis ✓
- [ ] Setup Burp Suite proxy
- [ ] Bypass SSL pinning
- [ ] Capture and analyze HTTP traffic
- [ ] Test authentication mechanisms
- [ ] Test authorization controls
- [ ] Check data storage (SharedPreferences, DB, files)
- [ ] Monitor logs for sensitive data
- [ ] Test with Drozer for component vulnerabilities
- [ ] Test IDOR and privilege escalation
- [ ] Test injection vulnerabilities
- [ ] Check for insecure cryptography implementation
- [ ] Test backup functionality
- [ ] Analyze WebView vulnerabilities

### Exploitation ✓
- [ ] Attempt privilege escalation
- [ ] Test for code tampering possibilities
- [ ] Bypass security controls
- [ ] Chain multiple vulnerabilities

---

**Happy Testing! 🔐**