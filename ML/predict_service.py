from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import numpy as np
import traceback
import math
from typing import List, Dict, Optional
from prophet import Prophet
from datetime import datetime, timedelta
import hashlib
import json


app = FastAPI(title="Forecast & Insights API", version="3.1")

# ------------------------
# 🌐 CORS Configuration
# ------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to dashboard domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------
# 📦 Data Models
# ------------------------
class Series(BaseModel):
    series: list   # list of {"ds": "...", "y": ...}
    horizon: int = 180
    freq: str = "D"
    growth: str = "linear"
    include_history: bool = True


class BatchForecast(BaseModel):
    datasets: Dict[str, Series]  # key -> Series


class TourPerformanceItem(BaseModel):
    tourId: str
    title: Optional[str] = None
    bookings: int
    revenue: float
    createdAt: Optional[str] = None


class InsightsRequest(BaseModel):
    tours: List[TourPerformanceItem]


# ======================================================
# 🧠 SIMPLE IN-MEMORY CACHE
# ======================================================
cache_store = {}
CACHE_EXPIRY_MINUTES = 60  # 1 hour

def make_cache_key(series, horizon):
    """Create a unique hash for the input dataset"""
    key_str = str(series) + str(horizon)
    return hashlib.md5(key_str.encode()).hexdigest()

def get_cached_forecast(series, horizon):
    key = make_cache_key(series, horizon)
    if key in cache_store:
        entry = cache_store[key]
        if datetime.now() - entry["timestamp"] < timedelta(minutes=CACHE_EXPIRY_MINUTES):
            print("⚡ Returning cached forecast result.")
            return entry["data"]
    return None

def set_cached_forecast(series, horizon, data):
    key = make_cache_key(series, horizon)
    cache_store[key] = {"timestamp": datetime.now(), "data": data}


# ------------------------
# 🔮 Forecast Function
# ------------------------
def run_forecast(data: Series) -> dict:
    df = pd.DataFrame(data.series)

    if df.empty or not {"ds", "y"}.issubset(df.columns):
        raise ValueError("Data must contain 'ds' and 'y' columns.")

    # ✅ Clean data
    df["ds"] = pd.to_datetime(df["ds"], errors="coerce").dt.tz_localize(None)
    df["y"] = pd.to_numeric(df["y"], errors="coerce")
    df = df.dropna(subset=["ds", "y"]).sort_values("ds").groupby("ds", as_index=False).mean()
    df = df[df["y"] >= 0]

    if len(df) < 5:
        raise ValueError("Not enough valid points (need at least 5).")

    # ✅ Add regressors for seasonal patterns
    df["month"] = df["ds"].dt.month
    df["day_of_week"] = df["ds"].dt.dayofweek

   # ✅ Build Prophet model (simpler and more flexible)
    model = Prophet(
        yearly_seasonality=True,
        weekly_seasonality=True,
        daily_seasonality=False,  # fewer data points benefit from simpler models
        changepoint_prior_scale=0.3,  # allow more flexible trend shifts
        seasonality_mode='additive'
    )

    # ✅ Include month and day_of_week as regressors to help capture seasonal effects
    model.add_regressor("month")
    model.add_regressor("day_of_week")


    model.fit(df)

    # ✅ Build future frame
    future = model.make_future_dataframe(periods=data.horizon)
    future["month"] = future["ds"].dt.month
    future["day_of_week"] = future["ds"].dt.dayofweek

    forecast = model.predict(future)

    # ✅ Metrics
    merged = pd.merge(df, forecast[["ds", "yhat"]], on="ds", how="inner")
    mape = float(np.mean(np.abs((merged["y"] - merged["yhat"]) / (merged["y"] + 1e-9))) * 100)
    rmse = float(np.sqrt(np.mean((merged["y"] - merged["yhat"]) ** 2)))

    # ✅ Seasonality
    seasonal_strength = np.std(forecast["yhat"]) / (np.mean(df["y"]) + 1e-9)
    if seasonal_strength > 0.4:
        seasonality_note = "🌋 Strong seasonality — clear recurring highs/lows each cycle."
    elif seasonal_strength > 0.2:
        seasonality_note = "🌦 Moderate seasonality — some predictable patterns."
    else:
        seasonality_note = "🌤 Weak seasonality — stable performance."

    # ✅ Trend detection
    start_val = float(df["y"].iloc[0])
    end_val = float(forecast["yhat"].iloc[-1])
    growth_rate = ((end_val - start_val) / (abs(start_val) + 1e-9)) * 100
    if growth_rate > 15:
        trend_note = f"📈 Upward trend (+{growth_rate:.1f}%) — demand is increasing."
    elif growth_rate < -10:
        trend_note = f"📉 Downward trend ({growth_rate:.1f}%) — decline detected."
    else:
        trend_note = f"➡️ Stable trend ({growth_rate:.1f}%) — steady performance."

    # ✅ Forecast output
    output = forecast[["ds", "yhat", "yhat_lower", "yhat_upper"]].tail(data.horizon)
    output = output.replace([np.inf, -np.inf], np.nan).fillna(0)

    # ✅ Accuracy badge
    if mape <= 5:
        accuracy = "💎 Excellent"
    elif mape <= 15:
        accuracy = "🟢 Good"
    elif mape <= 25:
        accuracy = "🟡 Fair"
    else:
        accuracy = "🔴 Poor"

    result = {
        "success": True,
        "forecast": output.to_dict(orient="records"),
        "mape": round(mape, 2),
        "rmse": round(rmse, 2),
        "accuracy": accuracy,
        "trend_note": trend_note,
        "seasonality_note": seasonality_note,
        "growth_rate": round(growth_rate, 2),
        "seasonality_strength": round(seasonal_strength, 3)
    }

    return result


# ------------------------
# 🔮 Single Forecast (with caching)
# ------------------------
@app.post("/predict")
async def predict(data: Series):
    try:
        cached = get_cached_forecast(data.series, data.horizon)
        if cached:
            return cached

        result = run_forecast(data)
        set_cached_forecast(data.series, data.horizon, result)
        print("✅ Forecast computed and cached.")
        return result

    except Exception as e:
        print("❌ Forecast error:", str(e))
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------
# 🔁 Batch Forecast
# ------------------------
@app.post("/batch-predict")
async def batch_predict(batch: BatchForecast):
    results = {}
    for key, series in batch.datasets.items():
        try:
            cached = get_cached_forecast(series.series, series.horizon)
            if cached:
                results[key] = cached
                continue

            forecast = run_forecast(series)
            set_cached_forecast(series.series, series.horizon, forecast)
            results[key] = forecast
        except Exception as e:
            results[key] = {"success": False, "error": str(e)}
    return results

@app.post("/insights")
async def insights(request: Request):
    try:
        # ✅ Step 1: Safely get raw JSON
        data = await request.json()
        print("📥 Raw insights payload received:")
        print(json.dumps(data, indent=2))

        # ✅ Step 2: Validate and extract tours
        tours = data.get("tours", [])
        if not tours:
            raise HTTPException(status_code=400, detail="No tours provided")

        # ✅ Step 3: Convert to DataFrame
        df = pd.DataFrame(tours)
        print("✅ DataFrame head:", df.head().to_dict(orient="records"))

        # ✅ Step 4: Compute composite score (popularity metric)
        df["score"] = (df["bookings"] * 0.6) + (df["revenue"] / df["revenue"].max() * 40)
        top_tours = df.sort_values("score", ascending=False).head(5)

        # ✅ Step 5: Emerging vs Declining tours
        median_bookings = df["bookings"].median()
        emerging = df[df["bookings"] > median_bookings * 1.3]
        declining = df[df["bookings"] < median_bookings * 0.6]

        # ✅ Step 6: Build recommendations list
        recs = []
        recs.append("🏆 Top Performing Tours:")
        for _, row in top_tours.iterrows():
            title = row["title"] or row["tourId"]
            recs.append(f" • {title} — ₱{row['revenue']:.2f}, {row['bookings']} bookings")

        if not emerging.empty:
            recs.append("\n🌱 Emerging Tours (rapid growth): " + ", ".join(emerging["title"].fillna(emerging["tourId"])))
        if not declining.empty:
            recs.append("\n⚠️ Underperforming Tours: " + ", ".join(declining["title"].fillna(declining["tourId"])))

        # ✅ Step 7: Summary for admin dashboard
        summary = {
            "total_tours": len(df),
            "median_bookings": float(median_bookings),
            "top_revenue_tours": top_tours[["tourId", "title", "revenue"]].to_dict(orient="records")
        }

        print("✅ Insights generated successfully.")
        return {"success": True, "recommendations": recs, "summary": summary}

    except Exception as e:
        print("❌ Insight error:", str(e))
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------
# 💡 Health Check
# ------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "library": "Prophet",
        "version": "3.1",
        "cache_items": len(cache_store),
        "cache_expiry_minutes": CACHE_EXPIRY_MINUTES,
        "endpoints": ["/predict", "/batch-predict", "/insights"]
    }
