from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score

def entrenar_modelo_rf(df):
    try:
        # Seleccionar características para el modelo y eliminar nulos
        features = df[['MA_5', 'MA_20', 'EMA_12', 'EMA_26', 'MACD', 'Signal', 'ATR', 'RSI', 'ADX']].dropna()
        target = df['close'].dropna()

        # Alinear el índice de las características y del objetivo para garantizar que ambos tengan la misma longitud
        common_index = features.index.intersection(target.index)
        features = features.loc[common_index]
        target = target.loc[common_index]

        # Verificar si los datos son suficientes para entrenar
        if features.empty or target.empty or len(features) < 20:
            print("[INFO] Datos insuficientes para entrenar el modelo RandomForest.")
            return None

        # División de datos de entrenamiento y prueba
        X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.2, random_state=42)

        # Entrenar el modelo RandomForestRegressor
        modelo_rf = RandomForestRegressor(n_estimators=100, random_state=42)
        modelo_rf.fit(X_train, y_train)

        # Evaluar el modelo
        y_pred = modelo_rf.predict(X_test)
        mse = mean_squared_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)

        print(f"[INFO] Modelo RandomForest entrenado. MSE: {mse}, R2: {r2}")
        return modelo_rf

    except Exception as e:
        print(f"[ERROR] Error al entrenar el modelo RandomForest: {str(e)}")
        return None
