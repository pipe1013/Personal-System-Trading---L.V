import pandas as pd
from ta.volatility import AverageTrueRange
from ta.momentum import RSIIndicator
from ta.trend import ADXIndicator

def calcular_indicadores(df):
    try:
        if len(df) >= 20:
            df['MA_5'] = df['close'].rolling(window=5).mean()
            df['MA_20'] = df['close'].rolling(window=20).mean()
            df['EMA_12'] = df['close'].ewm(span=12, adjust=False).mean()
            df['EMA_26'] = df['close'].ewm(span=26, adjust=False).mean()
            df['MACD'] = df['EMA_12'] - df['EMA_26']
            df['Signal'] = df['MACD'].ewm(span=9, adjust=False).mean()
            df['ATR'] = AverageTrueRange(df['high'], df['low'], df['close'], window=14).average_true_range()
            df['RSI'] = RSIIndicator(df['close'], window=14).rsi()
            df['ADX'] = ADXIndicator(df['high'], df['low'], df['close'], window=14).adx()
            print("[INFO] Indicadores calculados correctamente.")
        else:
            raise ValueError("No hay suficientes datos para calcular los indicadores técnicos.")
    except Exception as e:
        print(f"[ERROR] Error al calcular indicadores: {str(e)}")

def evaluar_efectividad_indicadores(df):
    try:
        # Lista de indicadores a evaluar
        indicadores = ['MA_5', 'MA_20', 'EMA_12', 'EMA_26', 'MACD', 'Signal', 'ATR', 'RSI', 'ADX']

        # Calcular la correlación de cada indicador con el precio de cierre
        correlaciones = {}
        for indicador in indicadores:
            if indicador in df.columns:
                correlacion = df['close'].corr(df[indicador])
                correlaciones[indicador] = correlacion

        # Ordenar los indicadores por su correlación
        correlaciones_ordenadas = sorted(correlaciones.items(), key=lambda x: abs(x[1]), reverse=True)

        # Log de correlaciones
        print("[INFO] Correlaciones entre indicadores y precio de cierre:")
        for indicador, correlacion in correlaciones_ordenadas:
            print(f"{indicador}: {correlacion:.2f}")

        return correlaciones_ordenadas

    except Exception as e:
        print(f"[ERROR] Error al evaluar la efectividad de los indicadores: {str(e)}")
        return []
