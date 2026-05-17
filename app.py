from flask import Flask, render_template, request, jsonify
from utils.header_checker import SecurityHeaderChecker

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url', '').strip()
    
    if not url:
        return render_template('index.html', error='Por favor ingresa una URL')
    
    # Analizar cabeceras
    result = SecurityHeaderChecker.check_headers(url)
    
    if 'error' in result:
        return render_template('index.html', error=result['message'])
    
    return render_template('resultados.html', result=result)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL requerida'}), 400
    
    result = SecurityHeaderChecker.check_headers(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)