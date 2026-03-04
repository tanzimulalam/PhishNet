# 🔑 API Keys Setup Guide

## ✅ Your API Keys (Keep These Safe!)

### **URLscan.io API Key:**
```
019c8302-f2b6-7494-bcb2-361642fc4cef
```

### **Have I Been Pwned API Key:**
```
59ae36dd1b314b12904b8c9aeb2653a9
```

---

## 📝 **How to Add Your API Keys**

### **Step 1: Build and Load Extension**
```bash
npm run build
```
Then load `build/chrome-mv3-prod` in Chrome

### **Step 2: Open Settings**
1. Click the PhishNet extension icon
2. Click the ⚙️ Settings gear icon
3. Scroll to "API Keys" section

### **Step 3: Add Your Keys**
1. **URLscan.io API Key:**
   - Find "URLscan.io API Key" field
   - Paste: `019c8302-f2b6-7494-bcb2-361642fc4cef`
   - Click "Test" to verify
   - ✅ Should show "✓ Valid"

2. **Have I Been Pwned API Key:**
   - Find "Have I Been Pwned API Key" field
   - Paste: `59ae36dd1b314b12904b8c9aeb2653a9`
   - Click "Test" to verify
   - ✅ Should show "✓ Valid"

### **Step 4: Enable Features**
Make sure these toggles are ON:
- ✅ Enable URLscan.io Analysis
- ✅ Enable WHOIS (optional, works without key)

### **Step 5: Save Settings**
Click "Save Settings" button at the bottom

---

## 🔒 **Security Reminders**

✅ **DO:**
- Add keys through the Settings UI (they're stored securely in Chrome)
- Keep your keys private
- Use the extension's built-in key storage

❌ **DON'T:**
- Commit API keys to Git (already in .gitignore)
- Share your keys publicly
- Hardcode keys in source code

---

## 🧪 **Testing Your Keys**

### **Test URLscan.io:**
1. Go to any website
2. Click PhishNet icon
3. Click "Deep Scan"
4. You should see URLscan.io card with results

### **Test HIBP:**
1. Open Gmail
2. Open any email
3. Click "🔍 HIBP" button next to sender email
4. Should show breach results (or "No breaches found")

---

## ✅ **Verification Checklist**

- [ ] URLscan.io API key added in Settings
- [ ] HIBP API key added in Settings
- [ ] URLscan.io toggle enabled
- [ ] Settings saved
- [ ] Tested Deep Scan (should show URLscan results)
- [ ] Tested HIBP button in Gmail (should work)

---

**Your keys are ready to use!** 🚀
