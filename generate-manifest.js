// generate-manifest.js
const fs = require('fs');
const path = require('path');

const imageDirectory = path.join(__dirname, 'watermarked');
const manifestPath = path.join(__dirname, 'gallery-manifest.json');

// Mapping from filename category to the data-category attribute in your HTML
const categoryMap = {
    'Landschaft': 'landscapes',
    'Vogel': 'birds',
    'Tier': 'animals'
};

try {
    const files = fs.readdirSync(imageDirectory);
    const imageManifest = [];

    files.forEach(file => {
        if (!/\.(jpg|jpeg|png|webp)$/i.test(file)) {
            return; // Skip non-image files
        }

        const parts = path.parse(file).name.split('_');
        // The new format requires at least 4 parts: Sort, Category, Title, AspectRatio
        if (parts.length < 4) {
            console.warn(`⚠️  Skipping ${file}: Filename does not match the format Sort_Category_Title_AspectRatio.`);
            return;
        }
        
        // --- NEW: Extract sorting number ---
        const sortKeyRaw = parts[0];
        const sortKey = parseInt(sortKeyRaw, 10);
        if (isNaN(sortKey)) {
            console.warn(`⚠️  Skipping ${file}: Sorting prefix "${sortKeyRaw}" is not a valid number.`);
            return;
        }

        // Category is now the second part
        const categoryKey = parts[1];
        const category = categoryMap[categoryKey];
        if (!category) {
            console.warn(`⚠️  Skipping ${file}: Unknown category "${categoryKey}".`);
            return;
        }
        
        const aspectRaw = parts.pop(); // Aspect ratio is still the last part
        
        // Title is now everything between the category and the aspect ratio
        const title = parts.slice(2).join(' ').replace(/-/g, ' ');

        const aspectMatch = aspectRaw.match(/(\d+)x(\d+)/);
        if (!aspectMatch) {
            console.warn(`⚠️  Skipping ${file}: Invalid aspect ratio format "${aspectRaw}". Expected "WxH".`);
            return;
        }
        // Format for CSS aspect-ratio property
        const aspect = `${aspectMatch[1]} / ${aspectMatch[2]}`;

        imageManifest.push({
            file: file.normalize('NFC'),
            sort: sortKey, // Add sort key to the object
            category: category,
            title: title,
            aspect: aspect,
        });
    });
    
    // --- NEW: Sort the manifest by the sort key in ascending order ---
    imageManifest.sort((a, b) => a.sort - b.sort);

    fs.writeFileSync(manifestPath, JSON.stringify(imageManifest, null, 2));
    console.log(`✅ Successfully generated gallery-manifest.json with ${imageManifest.length} images.`);

} catch (error) {
    console.error('❌ Error generating image manifest:', error);
    process.exit(1);
}