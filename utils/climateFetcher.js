// utils/climateFetcher.js
const fetch = require("node-fetch");

// Optional: coordinates for some popular destinations (extend as needed)
const cityCoords = {
  "Tokyo": { lat: 35.68, lon: 139.69 },
  "Seoul": { lat: 37.56, lon: 126.97 },
  "Bangkok": { lat: 13.75, lon: 100.5 },
  "London": { lat: 51.51, lon: -0.13 },
  "New York": { lat: 40.71, lon: -74.01 },
  "Sydney": { lat: -33.87, lon: 151.21 },
  "Manila": { lat: 14.6, lon: 120.98 },
  "Paris": { lat: 48.85, lon: 2.35 },
  "Dubai": { lat: 25.2, lon: 55.27 },
  "Singapore": { lat: 1.35, lon: 103.82 }
};

async function getClimateData(city, country, date) {
  try {
    let coords = cityCoords[city];
    if (!coords) {
      console.warn(`⚠️ No coordinates for ${city}, skipping climate data.`);
      return null;
    }

    const isoDate = date.toISOString().split("T")[0];
    const url = `https://api.open-meteo.com/v1/forecast?latitude=${coords.lat}&longitude=${coords.lon}&daily=temperature_2m_max,temperature_2m_min,precipitation_sum&timezone=auto&start_date=${isoDate}&end_date=${isoDate}`;
    
    const response = await fetch(url);
    const data = await response.json();

    const avgTemp = ((data.daily.temperature_2m_max[0] + data.daily.temperature_2m_min[0]) / 2).toFixed(1);
    const rainfall = data.daily.precipitation_sum[0];

    return {
      avgTemperature: parseFloat(avgTemp),
      rainfall
    };
  } catch (err) {
    console.error("❌ Error fetching climate data:", err.message);
    return null;
  }
}

module.exports = getClimateData;
