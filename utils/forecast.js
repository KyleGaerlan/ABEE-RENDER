const fetch = require("node-fetch");
const FASTAPI_URL = process.env.FASTAPI_URL || "https://fast-api-service.onrender.com";

async function getForecast(series) {
  const res = await fetch(`${FASTAPI_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ series, horizon: 30 }),
  });

  if (!res.ok) {
    throw new Error(`Forecast API error: ${res.status}`);
  }

  return await res.json();
}

module.exports = { getForecast };
