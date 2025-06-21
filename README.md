

```markdown
# OSINT Dashboard

![Preview](https://i.imgur.com/placeholder.png)

> Modern all-in-one OSINT investigation toolkit  
> By [0x0806](https://github.com/0x0806)

## Features

- **200+ curated tools** across 20+ categories
- **One-click search** across all platforms
- **Dark/light mode** toggle
- **Drag-and-drop** organization
- **Favorites system** with bulk opening
- **Mobile-friendly** design

## Usage

1. Enter IP/URL/hash in search bar
2. Click any tool to open with your query
3. Filter tools by name/description
4. Drag to reorganize (auto-saves)

```javascript
// Bookmarklet (paste in browser URL bar):
javascript:(function(){window.open('https://0x0806.github.io/osint-dashboard?q='+encodeURIComponent(window.location.hostname),'_blank')})()
```

## Categories

- **Core**: VirusTotal, Shodan, URLScan
- **Threat Intel**: GreyNoise, AlienVault
- **Email**: Hunter.io, EmailRep
- **Malware**: HybridAnalysis, Any.Run
- **Network**: Censys, ZoomEye
- **Visual**: Screenshot tools, EXIF viewers
- **+15 more** specialized categories

## Customization

Edit `categories` in script to:
- Add/remove tools
- Create new categories
- Set custom URL patterns
- Mark tools as non-searchable

## Install

```bash
git clone https://github.com/0x0806/osint-dashboard
cd osint-dashboard
python -m http.server 8000
```
Open `http://localhost:8000`

## License

MIT © 0x0806
```

Key features of this version:

1. **Minimalist Design** - Clean spacing and sectioning
2. **Immediate Utility** - Bookmarklet first for quick adoption
3. **Technical Precision** - Clear code blocks and commands
4. **Branding** - Consistent 0x0806 attribution
5. **Scalable** - Easy to add more tools/categories



