from utils.data_fetcher import obtener_datos_indice_vivo
from utils.indicator_calculator import calcular_indicadores
import datetime
import ta

# ================== Estrategia Scalping-Hybrid ==================
def estrategia_scalping_hybrid(asset, temporalidad):
    # Estrategia combinada de Scalping y Hybrid
    df = obtener_datos_indice_vivo(asset, temporalidad)
    if df.empty or len(df) < 20:
        print(f"DataFrame insuficiente para el activo {asset} en temporalidad {temporalidad}")
        return {
            "strategy_name": "Scalping-Hybrid Mejorada",
            "asset": asset,
            "entry_point": None,
            "stop_loss": None,
            "take_profit": None,
            "win_rate": 0,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": "No se encontró oportunidad, probabilidad de éxito es del 0%"
        }

    # Calcular indicadores técnicos
    calcular_indicadores(df)

    # Calcular nuevos indicadores personalizados
    df['RSI'] = ta.momentum.rsi(df['close'], window=7)  # RSI más sensible (ventana de 7)
    df['MA_5'] = df['close'].rolling(window=3).mean()  # MA de 3 para scalping rápido
    df['MA_20'] = df['close'].rolling(window=10).mean()  # MA de 10 para tendencia
    df['ATR'] = ta.volatility.average_true_range(df['high'], df['low'], df['close'], window=14)  # ATR para volatilidad

    # Mostrar últimos valores de indicadores
    print(f"[DEBUG] Últimos valores de indicadores para {asset} (Temporalidad: {temporalidad}):")
    print(df[['close', 'MA_5', 'MA_20', 'RSI', 'ATR']].tail())

    # Condiciones de la estrategia
    rsi_sobreventa = df['RSI'].iloc[-1] < 30  # RSI en sobreventa
    rsi_sobrecompra = df['RSI'].iloc[-1] > 70  # RSI en sobrecompra
    cruce_ma_corto = df['MA_5'].iloc[-2] < df['MA_20'].iloc[-2] and df['MA_5'].iloc[-1] > df['MA_20'].iloc[-1]  # Cruce hacia arriba
    cruce_ma_largo = df['MA_5'].iloc[-2] > df['MA_20'].iloc[-2] and df['MA_5'].iloc[-1] < df['MA_20'].iloc[-1]  # Cruce hacia abajo

    # Condición de soporte/resistencia automático
    pivot_high = df['high'].rolling(window=5).max().iloc[-1]  # Resistencia reciente
    pivot_low = df['low'].rolling(window=5).min().iloc[-1]  # Soporte reciente
    soporte_cercano = df['low'].iloc[-1] > pivot_low
    resistencia_cercana = df['high'].iloc[-1] < pivot_high

    # Condiciones combinadas
    condiciones = [
        rsi_sobreventa or rsi_sobrecompra,
        cruce_ma_corto or cruce_ma_largo,
        soporte_cercano or resistencia_cercana
    ]
    condiciones_cumplidas = sum(condiciones)
    porcentaje_confirmacion = (condiciones_cumplidas / len(condiciones)) * 100

    # Lógica para determinar si se cumple alguna oportunidad
    if porcentaje_confirmacion >= 50:
        entry_point = df['close'].iloc[-1]
        atr = df['ATR'].iloc[-1]  # ATR para calcular SL y TP dinámicos
        stop_loss = entry_point - 1.5 * atr if "BOOM" in asset else entry_point + 1.5 * atr
        take_profit = entry_point + 2 * atr if "BOOM" in asset else entry_point - 2 * atr

        return {
            "strategy_name": "Scalping-Hybrid Mejorada",
            "asset": asset,
            "entry_point": entry_point,
            "stop_loss": stop_loss,
            "take_profit": take_profit,
            "win_rate": porcentaje_confirmacion,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": f"Posible entrada con un {porcentaje_confirmacion:.2f}% de confirmación"
        }
    else:
        return {
            "strategy_name": "Scalping-Hybrid Mejorada",
            "asset": asset,
            "entry_point": None,
            "stop_loss": None,
            "take_profit": None,
            "win_rate": porcentaje_confirmacion,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": f"No se encontró oportunidad, probabilidad de éxito es del {porcentaje_confirmacion:.2f}%"
        }
