from utils.data_fetcher import obtener_datos_indice_vivo
from utils.indicator_calculator import calcular_indicadores, evaluar_efectividad_indicadores
from models.random_forest import entrenar_modelo_rf
import datetime

def check_combined_strategies(asset, temporalidad):
    df = obtener_datos_indice_vivo(asset, temporalidad)
    if df.empty or len(df) < 20:
        print(f"DataFrame insuficiente para el activo {asset} en temporalidad {temporalidad}")
        return None

    # Calcular indicadores
    calcular_indicadores(df)

    # Entrenar el modelo RandomForest para mejorar las predicciones
    modelo_rf = entrenar_modelo_rf(df)
    if modelo_rf is not None:
        df['predicted_close'] = modelo_rf.predict(df[['MA_5', 'MA_20', 'EMA_12', 'EMA_26', 'MACD', 'Signal', 'ATR', 'RSI', 'ADX']])
    else:
        print("[INFO] No se pudo entrenar el modelo RandomForest, se continúa sin predicciones basadas en ML.")

    # Evaluar efectividad de indicadores y seleccionar los mejores con correlación alta (>0.6)
    correlaciones = evaluar_efectividad_indicadores(df)
    indicadores_seleccionados = [indicador for indicador, correlacion in correlaciones if abs(correlacion) > 0.6]

    # Verificar si la selección es razonable; en caso contrario, variar la correlación mínima
    if len(indicadores_seleccionados) < 3:
        indicadores_seleccionados = [indicador for indicador, correlacion in correlaciones if abs(correlacion) > 0.5]

    print(f"[INFO] Indicadores seleccionados para la estrategia: {indicadores_seleccionados}")

    # Confirmación Multi-Temporalidad
    temporalidad_superior = temporalidad * 3  # Temporalidad superior (ej: si es 5m, usar 15m)
    df_superior = obtener_datos_indice_vivo(asset, temporalidad_superior)
    if df_superior.empty or len(df_superior) < 20:
        print(f"[INFO] No se pudo obtener la confirmación de temporalidad superior para el activo {asset}")
    else:
        calcular_indicadores(df_superior)
        if df_superior['MA_5'].iloc[-1] > df_superior['MA_20'].iloc[-1]:
            print("[INFO] Confirmación de temporalidad superior: Tendencia alcista.")
        else:
            print("[INFO] Confirmación de temporalidad superior: Tendencia bajista.")

    # Continuar con las condiciones combinadas y el cálculo de entradas
    condiciones = []

    # Estrategia de Cruce de Medias Móviles (Boom: Corto; Crash: Largo)
    if 'MA_5' in indicadores_seleccionados and 'MA_20' in indicadores_seleccionados:
        cruce_ma = df['MA_5'].iloc[-2] < df['MA_20'].iloc[-2] and df['MA_5'].iloc[-1] > df['MA_20'].iloc[-1]
        condiciones.append(cruce_ma)

    # Estrategia de Cruce MACD
    if 'MACD' in indicadores_seleccionados and 'Signal' in indicadores_seleccionados:
        macd_cruce = df['MACD'].iloc[-2] < df['Signal'].iloc[-2] and df['MACD'].iloc[-1] > df['Signal'].iloc[-1]
        condiciones.append(macd_cruce)

    # RSI en Zona de Sobreventa/Sobrecompra
    if 'RSI' in df.columns:
        rsi_sobreventa = df['RSI'].iloc[-1] < 30
        rsi_sobrecompra = df['RSI'].iloc[-1] > 70
        condiciones.append(rsi_sobreventa or rsi_sobrecompra)

    # Evaluar porcentaje de confirmación con umbral más estricto (75%)
    condiciones_cumplidas = sum(condiciones)
    porcentaje_confirmacion = (condiciones_cumplidas / len(condiciones)) * 100 if condiciones else 0

    if porcentaje_confirmacion >= 75:
        entry_point = df['close'].iloc[-1]
        atr_value = df['ATR'].iloc[-1] if 'ATR' in df.columns else 10

        stop_loss = entry_point + (atr_value * 1.5) if "CRASH" in asset else entry_point - (atr_value * 1.5)
        take_profit = entry_point - (atr_value * 3) if "CRASH" in asset else entry_point + (atr_value * 3)

        return {
            "strategy_name": "Estrategia Combinada",
            "asset": asset,
            "entry_point": entry_point,
            "ATR": atr_value,
            "stop_loss": stop_loss,
            "take_profit": take_profit,
            "win_rate": porcentaje_confirmacion,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": f"Posible entrada con un {porcentaje_confirmacion:.2f}% de confirmación"
        }
    else:
        return {
            "strategy_name": "Estrategia Combinada",
            "asset": asset,
            "entry_point": None,
            "stop_loss": None,
            "take_profit": None,
            "win_rate": porcentaje_confirmacion,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": f"No se encontró oportunidad, probabilidad de éxito es del {porcentaje_confirmacion:.2f}%"
        }
