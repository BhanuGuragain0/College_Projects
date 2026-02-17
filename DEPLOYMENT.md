# Git Deployment Commands

## Deploy Chat_App to GitHub Repository

### Step 1: Navigate to Your Local Repository

```bash
cd /home/bhanu/Desktop/Final_Production_Version1/WorkPlace/College_Projects
```

### Step 2: Stage All Changes

```bash
git add Chat_App/
```

### Step 3: Commit Changes

```bash
git commit -m "feat: Modernize Chat App v2.0 with SSE and Cyberpunk UI

- Replace polling with Server-Sent Events (SSE) for real-time messaging
- Implement cyberpunk terminal theme with JetBrains Mono font
- Add CSRF protection and rate limiting on all endpoints
- Upgrade password hashing to bcrypt (cost 12)
- Convert backend to JSON API responses
- Add comprehensive security headers
- Modernize all CSS with electric green/cyan accents
- Update JavaScript with Fetch API and proper error handling
- Create production-ready documentation
- Add test verification procedures"
```

### Step 4: Push to Remote Repository

```bash
git push origin master
```

### Alternative: Force Push (if needed)

```bash
git push origin master --force
```

## Verify Deployment

```bash
# Check remote URL
git remote -v

# Verify last commit
git log -1

# Check status
git status
```

## Repository Details

- **Repository**: https://github.com/BhanuGuragain0/College_Projects
- **Branch**: master
- **Directory**: College_Projects/Chat_App

## Post-Deployment Steps

1. **Verify files on GitHub**: https://github.com/BhanuGuragain0/College_Projects/tree/master/Chat_App
2. **Clone to production server**:
   ```bash
   git clone https://github.com/BhanuGuragain0/College_Projects.git
   cd College_Projects/Chat_App
   ```
3. **Setup environment**: Copy .env.example to .env and configure
4. **Import database**: `mysql -u root -p < chat_app.sql`
5. **Set permissions**: `chmod 755 php/images/`

## Rollback Commands (if needed)

```bash
# View commit history
git log --oneline -10

# Revert to previous commit
git revert HEAD

# Or reset to specific commit
git reset --hard <commit-hash>
git push origin master --force
```

## Complete Deployment Script

```bash
#!/bin/bash
# deploy.sh - Complete deployment script

cd /home/bhanu/Desktop/Final_Production_Version1/WorkPlace/College_Projects

echo "Staging changes..."
git add Chat_App/

echo "Committing..."
git commit -m "feat: Modernize Chat App v2.0 with SSE and Cyberpunk UI"

echo "Pushing to GitHub..."
git push origin master

echo "Deployment complete!"
echo "Verify at: https://github.com/BhanuGuragain0/College_Projects/tree/master/Chat_App"
```

Run with: `bash deploy.sh`
