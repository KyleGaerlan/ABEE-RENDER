const citySeasons = {
    "Tokyo": {
        "country": "Japan",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Seoul": {
        "country": "South Korea",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Paris": {
        "country": "France",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Summer"]
    },
    "New York": {
        "country": "United States",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Sydney": {
        "country": "Australia",
        "seasons": ["Summer", "Fall", "Winter", "Spring"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "London": {
        "country": "United Kingdom",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Summer"]
    },
    "Rome": {
        "country": "Italy",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Dubai": {
        "country": "United Arab Emirates",
        "seasons": ["Winter", "Summer"],
        "bestSeasons": ["Winter"]
    },
    "Singapore": {
        "country": "Singapore",
        "seasons": ["Wet Season", "Dry Season"],
        "bestSeasons": ["Dry Season"]
    },
    "Bangkok": {
        "country": "Thailand",
        "seasons": ["Wet Season", "Dry Season"],
        "bestSeasons": ["Dry Season"]
    },
    "Barcelona": {
        "country": "Spain",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Amsterdam": {
        "country": "Netherlands",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Summer"]
    },
    "Berlin": {
        "country": "Germany",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Summer"]
    },
    "Cairo": {
        "country": "Egypt",
        "seasons": ["Summer", "Winter"],
        "bestSeasons": ["Winter"]
    },
    "Istanbul": {
        "country": "Turkey",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Bali": {
        "country": "Indonesia",
        "seasons": ["Rainy Season", "Dry Season"],
        "bestSeasons": ["Dry Season"]
    },
    "Phuket": {
        "country": "Thailand",
        "seasons": ["Wet Season", "Dry Season"],
        "bestSeasons": ["Dry Season"]
    },
    "Venice": {
        "country": "Italy",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Santorini": {
        "country": "Greece",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    },
    "Kyoto": {
        "country": "Japan",
        "seasons": ["Winter", "Spring", "Summer", "Fall"],
        "bestSeasons": ["Spring", "Fall"]
    }
};

const countrySeasons = {
    "Afghanistan": ["Winter", "Spring", "Summer", "Fall"],
    "Albania": ["Winter", "Spring", "Summer", "Fall"],
    "Algeria": ["Winter", "Spring", "Summer", "Fall"],
    "Andorra": ["Winter", "Spring", "Summer", "Fall"],
    "Angola": ["Rainy Season", "Dry Season"],
    "Antigua and Barbuda": ["Wet Season", "Dry Season"],
    "Argentina": ["Summer", "Fall", "Winter", "Spring"],
    "Armenia": ["Winter", "Spring", "Summer", "Fall"],
    "Australia": ["Summer", "Fall", "Winter", "Spring"],
    "Austria": ["Winter", "Spring", "Summer", "Fall"],
    "Azerbaijan": ["Winter", "Spring", "Summer", "Fall"],
    "Bahamas": ["Wet Season", "Dry Season"],
    "Bahrain": ["Summer", "Winter"],
    "Bangladesh": ["Summer", "Monsoon", "Winter"],
    "Barbados": ["Wet Season", "Dry Season"],
    "Belarus": ["Winter", "Spring", "Summer", "Fall"],
    "Belgium": ["Winter", "Spring", "Summer", "Fall"],
    "Belize": ["Wet Season", "Dry Season"],
    "Benin": ["Wet Season", "Dry Season"],
    "Bhutan": ["Winter", "Spring", "Summer", "Fall"],
    "Bolivia": ["Rainy Season", "Dry Season"],
    "Bosnia and Herzegovina": ["Winter", "Spring", "Summer", "Fall"],
    "Botswana": ["Rainy Season", "Dry Season"],
    "Brazil": ["Summer", "Fall", "Winter", "Spring"],
    "Brunei": ["Wet Season", "Dry Season"],
    "Bulgaria": ["Winter", "Spring", "Summer", "Fall"],
    "Burkina Faso": ["Wet Season", "Dry Season"],
    "Burundi": ["Wet Season", "Dry Season"],
    "Cabo Verde": ["Wet Season", "Dry Season"],
    "Cambodia": ["Wet Season", "Dry Season"],
    "Cameroon": ["Wet Season", "Dry Season"],
    "Canada": ["Winter", "Spring", "Summer", "Fall"],
    "Chile": ["Summer", "Fall", "Winter", "Spring"],
    "China": ["Winter", "Spring", "Summer", "Fall"],
    "Colombia": ["Wet Season", "Dry Season"],
    "Costa Rica": ["Wet Season", "Dry Season"],
    "Croatia": ["Winter", "Spring", "Summer", "Fall"],
    "Cuba": ["Wet Season", "Dry Season"],
    "Cyprus": ["Winter", "Spring", "Summer", "Fall"],
    "Czech Republic": ["Winter", "Spring", "Summer", "Fall"],
    "Denmark": ["Winter", "Spring", "Summer", "Fall"],
    "Ecuador": ["Wet Season", "Dry Season"],
    "Egypt": ["Summer", "Winter"],
    "France": ["Winter", "Spring", "Summer", "Fall"],
    "Germany": ["Winter", "Spring", "Summer", "Fall"],
    "Greece": ["Winter", "Spring", "Summer", "Fall"],
    "India": ["Winter", "Summer", "Monsoon", "Post-Monsoon"],
    "Indonesia": ["Rainy Season", "Dry Season"],
    "Iran": ["Winter", "Spring", "Summer", "Fall"],
    "Iraq": ["Winter", "Summer"],
    "Ireland": ["Winter", "Spring", "Summer", "Fall"],
    "Israel": ["Winter", "Summer"],
    "Italy": ["Winter", "Spring", "Summer", "Fall"],
    "Japan": ["Winter", "Spring", "Summer", "Fall"],
    "Kenya": ["Long Rains", "Short Rains", "Dry Season"],
    "Malaysia": ["Wet Season", "Dry Season"],
    "Mexico": ["Wet Season", "Dry Season"],
    "Netherlands": ["Winter", "Spring", "Summer", "Fall"],
    "New Zealand": ["Summer", "Fall", "Winter", "Spring"],
    "Nigeria": ["Wet Season", "Dry Season"],
    "Norway": ["Winter", "Spring", "Summer", "Fall"],
    "Pakistan": ["Winter", "Spring", "Summer", "Monsoon"],
    "Peru": ["Wet Season", "Dry Season"],
    "Philippines": ["Wet Season", "Dry Season"],
    "Poland": ["Winter", "Spring", "Summer", "Fall"],
    "Portugal": ["Winter", "Spring", "Summer", "Fall"],
    "Russia": ["Winter", "Spring", "Summer", "Fall"],
    "Saudi Arabia": ["Winter", "Summer"],
    "Singapore": ["Wet Season", "Dry Season"],
    "South Africa": ["Summer", "Fall", "Winter", "Spring"],
    "South Korea": ["Winter", "Spring", "Summer", "Fall"],
    "Spain": ["Winter", "Spring", "Summer", "Fall"],
    "Sweden": ["Winter", "Spring", "Summer", "Fall"],
    "Switzerland": ["Winter", "Spring", "Summer", "Fall"],
    "Thailand": ["Wet Season", "Dry Season"],
    "Turkey": ["Winter", "Spring", "Summer", "Fall"],
    "United Arab Emirates": ["Winter", "Summer"],
    "United Kingdom": ["Winter", "Spring", "Summer", "Fall"],
    "United States": ["Winter", "Spring", "Summer", "Fall"],
    "Venezuela": ["Wet Season", "Dry Season"],
    "Vietnam": ["Wet Season", "Dry Season"],
    "Zambia": ["Wet Season", "Dry Season"],
    "Zimbabwe": ["Wet Season", "Dry Season"]
};

module.exports = { citySeasons, countrySeasons };
