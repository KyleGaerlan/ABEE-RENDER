const { citySeasons, countrySeasons } = require('../config/seasons');

function detectSeason({ country, city, date }) {
  if (!date) return "Unknown";
  const month = date.getMonth() + 1;

  let seasons;
  if (city && citySeasons[city]) {
    seasons = citySeasons[city].seasons;
  } else if (country && countrySeasons[country]) {
    seasons = countrySeasons[country];
  } else {
    seasons = ["Winter", "Spring", "Summer", "Fall"];
  }

  const southernHemisphere = [
    "Australia", "New Zealand", "Argentina", "South Africa",
    "Chile", "Peru", "Uruguay", "Brazil", "Paraguay", "Namibia"
  ];

  const isSouthern = southernHemisphere.includes(country);

  if (seasons.includes("Wet Season") || seasons.includes("Dry Season")) {
    if (month >= 5 && month <= 10) return "Wet Season";
    return "Dry Season";
  }

  if (seasons.includes("Monsoon") && (month >= 6 && month <= 9)) return "Monsoon";
  if (seasons.includes("Post-Monsoon") && (month >= 10 && month <= 11)) return "Post-Monsoon";
  if (seasons.includes("Long Rains") && (month >= 3 && month <= 5)) return "Long Rains";
  if (seasons.includes("Short Rains") && (month >= 10 && month <= 12)) return "Short Rains";

  if (isSouthern) {
    if (month === 12 || month <= 2) return "Summer";
    if (month >= 3 && month <= 5) return "Fall";
    if (month >= 6 && month <= 8) return "Winter";
    if (month >= 9 && month <= 11) return "Spring";
  } else {
    if (month === 12 || month <= 2) return "Winter";
    if (month >= 3 && month <= 5) return "Spring";
    if (month >= 6 && month <= 8) return "Summer";
    if (month >= 9 && month <= 11) return "Fall";
  }

  return "Unknown";
}

module.exports = detectSeason;
