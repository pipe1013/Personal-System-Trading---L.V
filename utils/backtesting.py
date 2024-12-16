import pandas as pd
import numpy as np
import datetime

def ejecutar_backtesting(activo, temporalidad, df):
    try:
        capital = 10000  # Capital inicial
        posiciones = []
        operaciones = []
        spread = 0.5  # Costo fijo del spread (en puntos)
        comision = 1.0  # Comisión fija por operación
        max_slippage = 0.2  # Máximo slippage en puntos (puede variar)

        for index, row in df.iterrows():
            # Ejecutar la estrategia combinada para obtener la posible entrada
            from strategies.combined import check_combined_strategies
            resultado = check_combined_strategies(activo, temporalidad)
            if resultado and resultado['entry_point']:
                entry_price = resultado['entry_point']
                atr_value = resultado['ATR']

                # Aplicar spread al precio de entrada
                entry_price += spread if "BOOM" in activo else -spread

                # Introducir slippage de manera aleatoria dentro del máximo definido
                slippage = np.random.uniform(0, max_slippage)
                if "CRASH" in activo:
                    entry_price += slippage
                else:
                    entry_price -= slippage

                # Lógica para determinar Take Profit y Stop Loss
                if "CRASH" in activo:
                    take_profit = entry_price - abs(atr_value * 3)
                    stop_loss = entry_price + abs(atr_value * 1.5)
                else:
                    take_profit = entry_price + abs(atr_value * 3)
                    stop_loss = entry_price - abs(atr_value * 1.5)

                # Determinar si se alcanza el stop loss o take profit
                if "CRASH" in activo:
                    if row['low'] <= take_profit:
                        ganancia = (entry_price - take_profit) * 1 - comision
                        posiciones.append(ganancia)
                        operaciones.append({
                            'Iteración': index,
                            'Tipo': 'Ganancia',
                            'Precio de Entrada': entry_price,
                            'Take Profit': take_profit,
                            'Resultado': ganancia,
                            'Puntaje': take_profit
                        })
                    elif row['high'] >= stop_loss:
                        perdida = (stop_loss - entry_price) * 1 + comision
                        posiciones.append(-perdida)
                        operaciones.append({
                            'Iteración': index,
                            'Tipo': 'Pérdida',
                            'Precio de Entrada': entry_price,
                            'Stop Loss': stop_loss,
                            'Resultado': -perdida,
                            'Puntaje': stop_loss
                        })
                else:
                    if row['high'] >= take_profit:
                        ganancia = (take_profit - entry_price) * 1 - comision
                        posiciones.append(ganancia)
                        operaciones.append({
                            'Iteración': index,
                            'Tipo': 'Ganancia',
                            'Precio de Entrada': entry_price,
                            'Take Profit': take_profit,
                            'Resultado': ganancia,
                            'Puntaje': take_profit
                        })
                    elif row['low'] <= stop_loss:
                        perdida = (entry_price - stop_loss) * 1 + comision
                        posiciones.append(-perdida)
                        operaciones.append({
                            'Iteración': index,
                            'Tipo': 'Pérdida',
                            'Precio de Entrada': entry_price,
                            'Stop Loss': stop_loss,
                            'Resultado': -perdida,
                            'Puntaje': stop_loss
                        })

        # Métricas clave del backtesting
        total_ganancia = sum(posiciones)
        ratio_sharpe = np.mean(posiciones) / np.std(posiciones) if np.std(posiciones) != 0 else 0
        drawdown_max = min(posiciones) if posiciones else 0

        print(f"[INFO] Backtesting completado. Total Ganancia: {total_ganancia}, Ratio de Sharpe: {ratio_sharpe}, Drawdown Máximo: {drawdown_max}")

        # Crear DataFrame para registrar todas las operaciones
        df_operaciones = pd.DataFrame(operaciones)

        # Guardar en un archivo Excel
        excel_path = f"backtesting_result_{activo}_{temporalidad}.xlsx"
        df_operaciones.to_excel(excel_path, index=False)

        resultados_backtesting = {
            "total_ganancia": total_ganancia,
            "ratio_sharpe": ratio_sharpe,
            "drawdown_max": drawdown_max,
            "excel_path": excel_path
        }

        return resultados_backtesting

    except Exception as e:
        print(f"[ERROR] Error durante el backtesting: {str(e)}")
        return {"error": f"Hubo un error al ejecutar el backtesting: {str(e)}"}
