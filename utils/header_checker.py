import requests
from urllib.parse import urlparse

class SecurityHeaderChecker:
    HEADER_RULES = {
        'Content-Security-Policy': {
            'required': True,
            'severity': 'high',
            'good_values': ['default-src', 'script-src', 'unsafe-inline'],
            'recommendation': 'Implementa CSP: default-src https:; script-src https: "unsafe-inline"'
        },
        'X-Frame-Options': {
            'required': True,
            'severity': 'high',
            'good_values': ['DENY', 'SAMEORIGIN'],
            'recommendation': 'Configurar X-Frame-Options: DENY o SAMEORIGIN'
        },
        'Strict-Transport-Security': {
            'required': True,
            'severity': 'medium',
            'good_values': ['max-age=', 'includeSubDomains'],
            'recommendation': 'Implementar HSTS con max-age=31536000; includeSubDomains'
        },
        'X-Content-Type-Options': {
            'required': True,
            'severity': 'medium',
            'good_values': ['nosniff'],
            'recommendation': 'Configurar X-Content-Type-Options: nosniff'
        },
        'Referrer-Policy': {
            'required': False,
            'severity': 'low',
            'good_values': ['strict-origin', 'strict-origin-when-cross-origin'],
            'recommendation': 'Configurar Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'required': False,
            'severity': 'low',
            'good_values': ['geolocation=()', 'camera=()', 'microphone=()'],
            'recommendation': 'Configurar Permissions-Policy para restringir APIs sensibles'
        }
    }
    
    @staticmethod
    def check_headers(url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            response = requests.get(url, timeout=10, verify=True, allow_redirects=True)
            headers = response.headers

            result = {
                'url': url,
                'status_code': response.status_code,
                'final_url': response.url,
                'headers_analyzed': [],
                'summary': {
                    'high_risk': 0,
                    'medium_risk': 0,
                    'low_risk': 0,
                    'total_score': 100
                }
            }
            
            for header_name, rules in SecurityHeaderChecker.HEADER_RULES.items():
                header_value = headers.get(header_name, None)
                
                analysis = SecurityHeaderChecker._analyze_header(
                    header_name, 
                    header_value, 
                    rules
                )
                
                result['headers_analyzed'].append(analysis)
                
                if not analysis['is_secure']:
                    if rules['severity'] == 'high':
                        result['summary']['high_risk'] += 1
                        result['summary']['total_score'] -= 25
                    elif rules['severity'] == 'medium':
                        result['summary']['medium_risk'] += 1
                        result['summary']['total_score'] -= 15
                    else:
                        result['summary']['low_risk'] += 1
                        result['summary']['total_score'] -= 5
            
            result['summary']['total_score'] = max(0, result['summary']['total_score'])
            
            if result['summary']['total_score'] >= 80:
                result['overall_risk'] = 'Bajo 🟢'
                result['risk_class'] = 'low-risk'
            elif result['summary']['total_score'] >= 50:
                result['overall_risk'] = 'Medio 🟡'
                result['risk_class'] = 'medium-risk'
            else:
                result['overall_risk'] = 'Alto 🔴'
                result['risk_class'] = 'high-risk'
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                'error': True,
                'message': f'Error al analizar la URL: {str(e)}',
                'url': url
            }
    
    @staticmethod
    def _analyze_header(name, value, rules):
        """Analiza una cabecera individual"""
        
        analysis = {
            'name': name,
            'present': value is not None,
            'value': value if value else 'No configurada',
            'severity': rules['severity'],
            'is_secure': False,
            'recommendation': rules['recommendation']
        }
        
        if not analysis['present']:
            if rules['required']:
                analysis['is_secure'] = False
                analysis['status'] = '❌ Crítico'
                analysis['message'] = 'Cabecera no encontrada'
            else:
                analysis['is_secure'] = True
                analysis['status'] = '⚠️ Opcional'
                analysis['message'] = 'Cabecera opcional no implementada'
        else:
            value_lower = value.lower()
            is_good = any(good_val.lower() in value_lower 
                         for good_val in rules['good_values'])
            
            if is_good:
                analysis['is_secure'] = True
                analysis['status'] = '✅ Correcto'
                analysis['message'] = 'Configuración correcta de seguridad'
            else:
                analysis['is_secure'] = False
                analysis['status'] = '⚠️ Riesgo'
                analysis['message'] = f'Valor actual: {value}'
        
        return analysis