import websocket
import json
import pandas as pd
import datetime
import time

def obtener_datos_indice_vivo(symbol, granularity):
    try:
        # Calcular el rango temporal con base en la granularity seleccionada
        fecha_atras = int((datetime.datetime.now() - datetime.timedelta(days=90 if granularity > 5 else 7)).timestamp())

        ws = websocket.create_connection("wss://ws.binaryws.com/websockets/v3?app_id=64422")
        request_data = {
            "ticks_history": symbol,
            "adjust_start_time": 1,
            "count": 2000,
            "end": "latest",
            "start": fecha_atras,
            "style": "candles",
            "granularity": granularity * 60
        }
        ws.send(json.dumps(request_data))
        response = ws.recv()
        data = json.loads(response)
        ws.close()

        if 'candles' in data:
            df = pd.DataFrame(data['candles'])
            # Convertir la columna de tiempo a un formato legible solo si se encuentra la columna 'epoch'
            if 'epoch' in df.columns:
                df['time'] = pd.to_datetime(df['epoch'], unit='s')

            # Verificar si la columna 'volume' está presente antes de incluirla
            columns = ['time', 'open', 'high', 'low', 'close']
            if 'volume' in df.columns:
                columns.append('volume')

            df = df[columns]
            # Filtrar filas para eliminar duplicados y garantizar datos consistentes
            df.drop_duplicates(subset=['time'], keep='last', inplace=True)
            return df
        else:
            print(f"[INFO] No se encontraron datos de velas para {symbol}")
            return pd.DataFrame()
    except websocket.WebSocketException as e:
        print(f"[ERROR] WebSocket error al obtener datos del índice {symbol}: {str(e)}")
        time.sleep(5)
        return obtener_datos_indice_vivo(symbol, granularity)
    except Exception as e:
        print(f"[ERROR] Error al obtener datos del índice {symbol}: {str(e)}")
        return pd.DataFrame()