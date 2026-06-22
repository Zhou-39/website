from flask import Flask, request, session, redirect, jsonify, render_template, g, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import string
import secrets
import re
from datetime import datetime, timedelta
import requests
import docker
import threading
import time
import os
import socket
from urllib.parse import urlparse, urljoin
import ipaddress

# ========== 应用初始化 ==========

def generate_random_string(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for i in range(length))

app = Flask(__name__)
app.secret_key = generate_random_string(100)

# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////var/website/share/share.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 会话配置
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=6)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Docker 配置
docker_client = docker.from_env()

# IDE 服务地址
IDE_SERVICE_URL = "http://127.0.0.1:8001"

# 主域名配置
MAIN_DOMAIN = "share.free-hub.cn"
BASE_DOMAIN = "free-hub.cn"

# 初始化数据库
db = SQLAlchemy(app)

# 初始化登录管理
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'


# ========== 数据库模型 ==========

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True, nullable=False)
    nickname = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(30), nullable=False)
    level = db.Column(db.Integer, default=0)
    status = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)
    
    subdomains = db.relationship('Subdomain', backref='owner', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', foreign_keys='Report.reporter_id', backref='reporter', lazy=True)
    port_forwards = db.relationship('PortForward', backref='owner', lazy=True, cascade='all, delete-orphan')


class Subdomain(db.Model):
    __tablename__ = 'subdomains'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    subdomain = db.Column(db.String(63), unique=True, nullable=False, index=True)
    full_domain = db.Column(db.String(100), nullable=False)
    
    target_domain = db.Column(db.String(255), nullable=False)
    target_type = db.Column(db.String(20), default='domain')
    proxy_mode = db.Column(db.String(20), default='server')  # 'server', 'iframe', 'redirect'
    
    site_name = db.Column(db.String(100))
    site_description = db.Column(db.Text)
    site_icon = db.Column(db.String(500))
    
    status = db.Column(db.String(20), default='active')
    report_count = db.Column(db.Integer, default=0)
    is_banned = db.Column(db.Boolean, default=False)
    banned_reason = db.Column(db.String(200))
    banned_at = db.Column(db.DateTime)
    
    view_count = db.Column(db.Integer, default=0)
    like_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'subdomain': self.subdomain,
            'full_domain': self.full_domain,
            'target_domain': self.target_domain,
            'target_type': self.target_type,
            'proxy_mode': self.proxy_mode,
            'site_name': self.site_name or self.subdomain,
            'site_description': self.site_description,
            'status': self.status,
            'is_banned': self.is_banned,
            'report_count': self.report_count,
            'view_count': self.view_count,
            'like_count': self.like_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'owner': {
                'user_id': self.owner.user_id,
                'nickname': self.owner.nickname,
                'level': self.owner.level
            } if self.owner else None
        }


class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    subdomain_id = db.Column(db.Integer, db.ForeignKey('subdomains.id'), nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    reason = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.now)
    reviewed_at = db.Column(db.DateTime)
    
    subdomain = db.relationship('Subdomain', backref='reports')


class VisitLog(db.Model):
    __tablename__ = 'visit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    subdomain_id = db.Column(db.Integer, db.ForeignKey('subdomains.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    referer = db.Column(db.String(500))
    visited_at = db.Column(db.DateTime, default=datetime.now)


class PortForward(db.Model):
    __tablename__ = 'port_forwards'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    project_name = db.Column(db.String(100), nullable=False)
    subdomain = db.Column(db.String(100), unique=True, nullable=False, index=True)
    full_domain = db.Column(db.String(150), nullable=False)
    container_port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='active')
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    def to_dict(self):
        return {
            'id': self.id,
            'project_name': self.project_name,
            'subdomain': self.subdomain,
            'full_domain': self.full_domain,
            'container_port': self.container_port,
            'status': self.status,
            'is_banned': self.is_banned,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'access_url': f'https://{self.full_domain}'
        }


# ========== SSRF 防护函数 ==========

def is_internal_ip(hostname):
    """检测域名/IP是否为内网地址"""
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # 所有私有IP段
        private_networks = [
            '10.0.0.0/8',        # A类私有地址
            '172.16.0.0/12',     # B类私有地址 (覆盖 172.16.0.0 - 172.31.255.255)
            '192.168.0.0/16',    # C类私有地址
            '127.0.0.0/8',       # 本地回环
            '169.254.0.0/16',    # 链路本地地址（AWS元数据等）
            '0.0.0.0/8',         # 无效地址
            '224.0.0.0/4',       # 组播地址
            '240.0.0.0/4',       # 保留地址
            '255.255.255.255/32' # 广播地址
        ]
        
        for network in private_networks:
            if ip_obj in ipaddress.ip_network(network, strict=False):
                return True
        
        # Docker 常见网段（可选，因为 172.16.0.0/12 已经覆盖）
        docker_networks = [
            '172.17.0.0/16',
            '172.18.0.0/16',
            '172.19.0.0/16',
            '172.20.0.0/14',
        ]
        for network in docker_networks:
            if ip_obj in ipaddress.ip_network(network):
                return True
        
        return False
        
    except socket.gaierror:
        # DNS 解析失败，保守处理，拒绝访问
        return True


def is_dangerous_port(port):
    """检查端口是否为高危端口"""
    dangerous_ports = {
        22, 23, 25, 53, 69, 111, 135, 137, 139, 161, 389, 445, 512, 513, 514, 873,
        1080, 1099, 1433, 1521, 2049, 2181, 2375, 2376, 2379, 2380, 3306, 3389,
        4000, 4369, 5000, 5432, 5672, 5900, 5984, 6379, 7001, 8000, 8080, 8081,
        8090, 8443, 8888, 9000, 9092, 9200, 9300, 11211, 15672, 27017, 27018, 50000
    }
    return port in dangerous_ports


def validate_target_safe(target_url):
    """完整的安全验证：协议、域名、端口、内网IP"""
    try:
        parsed = urlparse(target_url)
        
        # 1. 协议检查
        if parsed.scheme not in ['http', 'https']:
            return False, "仅支持 http 和 https 协议"
        
        # 2. 端口检查
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == 'https' else 80
        
        if is_dangerous_port(port):
            return False, f"端口 {port} 被禁止访问，请使用其他端口"
        
        # 3. 内网IP检查
        hostname = parsed.hostname
        if not hostname:
            return False, "无效的主机名"
        
        if is_internal_ip(hostname):
            return False, f"禁止访问内网地址，不支持解析到内网的域名"
        
        return True, "验证通过"
        
    except Exception as e:
        return False, f"URL 验证失败: {str(e)}"


# ========== 辅助函数 ==========

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def is_main_domain():
    """检查当前请求是否来自主域名"""
    host = request.headers.get('Host', '').split(':')[0]
    return host == MAIN_DOMAIN


def get_subdomain_from_host():
    """从 Host 头中提取子域名"""
    host = request.headers.get('Host', '').split(':')[0]
    if host.endswith(f'.{MAIN_DOMAIN}') and host != MAIN_DOMAIN:
        return host.replace(f'.{MAIN_DOMAIN}', '')
    return None


def sync_user_from_main(user_info):
    user = User.query.filter_by(user_id=user_info['user_id']).first()
    if user:
        user.nickname = user_info.get('nickname', user.nickname)
        user.email = user_info.get('email', user.email)
        user.level = user_info.get('level', user.level)
        user.last_login = datetime.now()
    else:
        user = User(
            user_id=user_info['user_id'],
            nickname=user_info.get('nickname', ''),
            email=user_info.get('email', ''),
            level=user_info.get('level', 0),
            created_at=datetime.now(),
            last_login=datetime.now()
        )
        db.session.add(user)
    db.session.commit()
    return user


def validate_subdomain(subdomain):
    if not subdomain:
        return False
    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', subdomain):
        return False
    reserved = ['www', 'api', 'admin', 'login', 'logout', 'register', 'static', 'media', 'assets', 'dashboard', 'share']
    if subdomain in reserved:
        return False
    return True


def validate_target_domain(domain):
    if not domain:
        return False
    if not domain.startswith(('http://', 'https://')):
        return False
    if len(domain) > 255:
        return False
    return True


def find_container_by_user_and_project(user_nickname, project_name):
    """根据用户名和项目名查找容器（统一使用小写）"""
    try:
        containers = docker_client.containers.list(all=True)
        
        user_clean = re.sub(r'[^a-zA-Z0-9-]', '', user_nickname).lower()
        project_clean = re.sub(r'[^a-zA-Z0-9-]', '', project_name).lower()
        target_name = f"ide_{user_clean}_{project_clean}"
        
        print(f"[DEBUG] 查找容器: {target_name}")
        
        for container in containers:
            if container.name.lower() == target_name:
                print(f"[DEBUG] 找到容器: {container.name}, 状态: {container.status}")
                return container
        
        for container in containers:
            if 'ide' in container.name and user_clean in container.name.lower() and project_clean in container.name.lower():
                print(f"[DEBUG] 模糊匹配到容器: {container.name}")
                return container
        
        return None
        
    except Exception as e:
        print(f"[DEBUG] 查找容器失败: {e}")
        return None


def get_container_ip(container):
    """获取容器 IP"""
    try:
        container.reload()
        inspect_data = docker_client.api.inspect_container(container.id)
        networks = inspect_data.get('NetworkSettings', {}).get('Networks', {})
        
        for net_name, net_config in networks.items():
            ip = net_config.get('IPAddress')
            if ip:
                print(f"[DEBUG] 容器 {container.name} IP: {ip}")
                return ip
        
        ip = inspect_data.get('NetworkSettings', {}).get('IPAddress')
        if ip:
            return ip
        
        return '172.17.0.2'
    except Exception as e:
        print(f"获取容器 IP 失败: {e}")
        return '172.17.0.2'


def proxy_to_target(site, path):
    """服务端代理到目标网站，支持所有路径"""
    # SSRF 防护：在每次代理前验证目标地址
    safe, err_msg = validate_target_safe(site.target_domain)
    if not safe:
        return render_template('error.html', error=f'目标网站验证失败: {err_msg}'), 403
    
    base_url = site.target_domain.rstrip('/')
    full_path = '/' + path if path else '/'
    if request.query_string:
        full_path += '?' + request.query_string.decode()
    target_url = base_url + full_path
    
    print(f"[PROXY] {site.subdomain} -> {target_url}")
    
    # 准备转发的请求头
    headers = {}
    for key, value in request.headers.items():
        key_lower = key.lower()
        if key_lower not in ['host', 'content-length', 'connection']:
            headers[key] = value
    
    # 设置正确的 Host 头
    parsed = urlparse(site.target_domain)
    headers['Host'] = parsed.netloc
    headers['X-Forwarded-For'] = request.remote_addr
    headers['X-Forwarded-Proto'] = 'https'
    headers['X-Forwarded-Host'] = request.host
    headers['X-Real-IP'] = request.remote_addr
    
    try:
        # 转发请求
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            timeout=30,
            allow_redirects=False,
            stream=True
        )
        
        # 处理重定向：将目标域名替换回子域名
        if resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get('Location', '')
            if location:
                parsed_target = urlparse(site.target_domain)
                if parsed_target.netloc in location:
                    location = location.replace(parsed_target.netloc, f"{site.subdomain}.{MAIN_DOMAIN}")
                elif location.startswith('/'):
                    location = f"https://{site.subdomain}.{MAIN_DOMAIN}{location}"
                elif not location.startswith('http'):
                    location = urljoin(target_url, location)
                    if parsed_target.netloc in location:
                        location = location.replace(parsed_target.netloc, f"{site.subdomain}.{MAIN_DOMAIN}")
                
                response_headers = [(key, value) for key, value in resp.raw.headers.items() 
                                   if key.lower() not in ['content-length', 'transfer-encoding']]
                response_headers = [(k, v if k.lower() != 'location' else location) for k, v in response_headers]
                return resp.content, resp.status_code, response_headers
        
        # 过滤响应头
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = []
        for key, value in resp.raw.headers.items():
            key_lower = key.lower()
            if key_lower not in excluded_headers:
                # 移除安全限制头，避免被目标网站拦截
                if key_lower in ['x-frame-options', 'content-security-policy']:
                    continue
                response_headers.append((key, value))
        
        # 添加跨域头
        response_headers.append(('Access-Control-Allow-Origin', '*'))
        response_headers.append(('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS'))
        response_headers.append(('Access-Control-Allow-Headers', 'Content-Type, Authorization'))
        
        return resp.content, resp.status_code, response_headers
        
    except requests.exceptions.Timeout:
        return render_template('error.html', error='代理超时，目标网站响应过慢'), 504
    except requests.exceptions.ConnectionError as e:
        return render_template('error.html', error=f'无法连接到目标网站: {str(e)}'), 502
    except Exception as e:
        print(f"[PROXY ERROR] {e}")
        return render_template('error.html', error=f'代理错误: {str(e)}'), 500


def handle_subdomain_request(path):
    """处理子域名请求（非主域名）"""
    subdomain = get_subdomain_from_host()
    
    if not subdomain:
        return render_template('error.html', error='无效的域名'), 400
    
    # 先检查是否是端口转发
    port_forward = PortForward.query.filter_by(
        subdomain=subdomain, 
        status='active', 
        is_banned=False
    ).first()
    
    if port_forward:
        return handle_port_forward_request(path, port_forward)
    
    # 再检查普通子域名
    site = Subdomain.query.filter_by(
        subdomain=subdomain, 
        status='active', 
        is_banned=False
    ).first()
    
    if not site:
        return render_template('error.html', error=f'网站 "{subdomain}" 不存在或已被封禁'), 404
    
    # 更新访问计数
    site.view_count = (site.view_count or 0) + 1
    db.session.commit()
    
    # 根据代理模式处理
    if site.proxy_mode == 'redirect':
        target_url = site.target_domain.rstrip('/') + '/' + path if path else site.target_domain
        if request.query_string:
            target_url += '?' + request.query_string.decode()
        return redirect(target_url)
    elif site.proxy_mode == 'iframe':
        return render_template('proxy.html', site=site, path=path)
    else:  # server mode (default)
        return proxy_to_target(site, path)


def handle_port_forward_request(path, forward):
    """处理端口转发请求"""
    if forward.status != 'active':
        return render_template('error.html', error='端口转发已失效'), 404
    
    user = User.query.filter_by(user_id=forward.user_id).first()
    if not user:
        return render_template('error.html', error='用户不存在'), 404
    
    container = find_container_by_user_and_project(user.nickname, forward.project_name)
    
    if not container or container.status != 'running':
        forward.status = 'stopped'
        db.session.commit()
        return render_template('error.html', error='容器已停止，端口转发已自动禁用。请重新启动项目后重新创建转发。'), 404
    
    # 处理 OPTIONS 预检请求
    if request.method == 'OPTIONS':
        response = make_response('')
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Max-Age'] = '86400'
        return response
    
    # 代理请求到容器
    full_path = '/' + path if path else '/'
    if request.query_string:
        full_path += '?' + request.query_string.decode()
    
    container_ip = get_container_ip(container)
    target_url = f"http://{container_ip}:{forward.container_port}{full_path}"
    print(f"[PORT_FORWARD] {forward.subdomain} -> {target_url}")
    
    # 转发请求头
    forward_headers = {}
    for k, v in request.headers.items():
        if k.lower() not in ['host', 'content-length', 'connection', 'origin', 'referer']:
            forward_headers[k] = v
    
    forward_headers['X-Forwarded-For'] = request.remote_addr
    forward_headers['X-Forwarded-Proto'] = 'https'
    forward_headers['X-Forwarded-Host'] = request.host
    forward_headers['X-Real-IP'] = request.remote_addr
    
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=request.get_data(),
            timeout=120,
            stream=True,
            allow_redirects=False
        )
        
        # 构建响应
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = []
        
        for name, value in resp.raw.headers.items():
            if name.lower() not in excluded_headers:
                response_headers.append((name, value))
        
        # 添加 CORS 头
        response_headers.append(('Access-Control-Allow-Origin', '*'))
        response_headers.append(('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS'))
        response_headers.append(('Access-Control-Allow-Headers', 'Content-Type, Authorization'))
        response_headers.append(('Access-Control-Allow-Credentials', 'true'))
        
        return resp.content, resp.status_code, response_headers
        
    except requests.exceptions.Timeout:
        return render_template('error.html', error='代理超时'), 504
    except requests.exceptions.ConnectionError as e:
        return render_template('error.html', error=f'无法连接到容器端口 {forward.container_port}: {str(e)}'), 502
    except Exception as e:
        return render_template('error.html', error=f'代理错误: {str(e)}'), 500


# ========== 子域名检测中间件 ==========

@app.before_request
def detect_subdomain():
    """在请求前检测是否为子域名，并缓存相关信息"""
    g.is_main = is_main_domain()
    g.subdomain = get_subdomain_from_host()


# ========== 主域名路由（只对 share.free-hub.cn 生效） ==========

@app.route('/')
def index():
    """主页 - 只在主域名生效"""
    if not is_main_domain():
        return handle_subdomain_request('')
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    search = request.args.get('search', '')
    
    query = Subdomain.query.filter_by(status='active', is_banned=False)
    
    if search:
        query = query.filter(
            Subdomain.site_name.contains(search) |
            Subdomain.site_description.contains(search) |
            Subdomain.subdomain.contains(search)
        )
    
    sort = request.args.get('sort', 'latest')
    if sort == 'popular':
        query = query.order_by(Subdomain.view_count.desc())
    elif sort == 'likes':
        query = query.order_by(Subdomain.like_count.desc())
    else:
        query = query.order_by(Subdomain.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'data': [s.to_dict() for s in pagination.items],
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        })
    
    return render_template('index.html', websites=pagination.items, pagination=pagination, search=search, sort=sort)


@app.route('/site/<subdomain>')
def view_site(subdomain):
    """网站详情页 - 只在主域名生效"""
    if not is_main_domain():
        return handle_subdomain_request(f'site/{subdomain}')
    
    site = Subdomain.query.filter_by(subdomain=subdomain, status='active', is_banned=False).first_or_404()
    return render_template('site_detail.html', site=site)


@app.route('/go')
def go_to_subdomain():
    """跳转到子域名 - 只在主域名生效"""
    if not is_main_domain():
        return handle_subdomain_request('go')
    
    subdomain = request.args.get('subdomain')
    if not subdomain:
        return render_template('error.html', error='缺少子域名参数'), 400
    
    site = Subdomain.query.filter_by(subdomain=subdomain, status='active', is_banned=False).first()
    if not site:
        return render_template('error.html', error=f'子域名 "{subdomain}" 不存在或已被封禁'), 404

    site.view_count = (site.view_count or 0) + 1
    db.session.commit()
    
    target_url = f'https://{subdomain}.{MAIN_DOMAIN}'
    return render_template('redirect.html', subdomain=subdomain, target_url=target_url, site=site)


@app.route('/login', methods=['GET'])
def login_page():
    """登录页 - 只在主域名生效"""
    if not is_main_domain():
        return handle_subdomain_request('login')
    
    if current_user.is_authenticated:
        return redirect('/dashboard')
    
    error = request.args.get('error', '')
    main_site_url = 'https://free-hub.cn'
    share_login_url = f'{main_site_url}/user/api/auth/share-login?share_url=https://{MAIN_DOMAIN}'
    return render_template('login.html', error=error, login_url=share_login_url)


@app.route('/logout')
@login_required
def logout():
    """登出 - 只在主域名生效"""
    if not is_main_domain():
        return handle_subdomain_request('logout')
    
    logout_user()
    session.clear()
    return redirect('/login?message=已登出')


@app.route('/dashboard')
@login_required
def dashboard():
    """仪表板 - 只在主域名生效"""
    if not is_main_domain():
        return handle_subdomain_request('dashboard')
    
    return render_template('dashboard.html', user=current_user)


# ========== 通配路由：处理所有子域名请求 ==========

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def catch_all(path):
    """捕获所有请求，根据域名决定处理方式"""
    if is_main_domain():
        # 主域名下，如果 path 不为空，返回 404
        if path:
            return render_template('error.html', error='页面不存在'), 404
        return index()
    
    # 子域名：处理代理请求
    return handle_subdomain_request(path)


# ========== API 路由（仅主域名） ==========

@app.route('/api/auth/callback', methods=['GET'])
def auth_callback():
    """认证回调 - 仅主域名"""
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    token = request.args.get('token')
    if not token:
        return redirect('/login?error=missing_token')
    
    try:
        resp = requests.post(
            'https://free-hub.cn/user/api/auth/verify',
            json={'token': token, 'service': 'share'},
            timeout=10,
            verify=True
        )
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get('success'):
                user_info = data.get('user_info', {})
                user = sync_user_from_main(user_info)
                login_user(user)
                session.permanent = True
                return redirect('/dashboard')
            else:
                return redirect(f'/login?error={data.get("error", "验证失败")}')
        else:
            return redirect(f'/login?error=验证服务返回{resp.status_code}')
    except Exception as e:
        print(f"验证令牌失败: {e}")
        return redirect('/login?error=连接主站失败')


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """认证状态 - 仅主域名"""
    if not is_main_domain():
        return jsonify({'authenticated': False, 'user': None})
    
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': {
                'user_id': current_user.user_id,
                'nickname': current_user.nickname,
                'email': current_user.email,
                'level': current_user.level
            }
        })
    return jsonify({'authenticated': False, 'user': None})


# ========== 子域名管理 API（仅主域名） ==========

@app.route('/api/subdomains/check', methods=['GET'])
def check_subdomain():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    subdomain = request.args.get('subdomain', '').strip().lower()
    if not subdomain:
        return jsonify({'success': False, 'error': '缺少子域名参数'}), 400
    
    if not validate_subdomain(subdomain):
        return jsonify({'success': False, 'available': False, 'error': '子域名格式无效'}), 400
    
    existing = Subdomain.query.filter_by(subdomain=subdomain).first()
    if existing:
        return jsonify({'success': False, 'available': False, 'error': '该子域名已被注册'}), 409
    
    return jsonify({'success': True, 'available': True})


@app.route('/api/subdomains', methods=['GET'])
@login_required
def list_subdomains():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    subdomains = Subdomain.query.filter_by(user_id=current_user.user_id).all()
    return jsonify({'success': True, 'data': [s.to_dict() for s in subdomains]})


@app.route('/api/subdomains', methods=['POST'])
@login_required
def register_subdomain():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    data = request.get_json()
    
    subdomain = data.get('subdomain', '').strip().lower()
    target_domain = data.get('target_domain', '').strip()
    site_name = data.get('site_name', '').strip()
    site_description = data.get('site_description', '').strip()
    proxy_mode = data.get('proxy_mode', 'server')
    
    if not subdomain or not target_domain:
        return jsonify({'success': False, 'error': '子域名和目标域名不能为空'}), 400
    
    if not validate_subdomain(subdomain):
        return jsonify({'success': False, 'error': '子域名格式无效'}), 400
    
    if not validate_target_domain(target_domain):
        return jsonify({'success': False, 'error': '目标域名必须以 http:// 或 https:// 开头'}), 400
    
    # SSRF 防护验证
    safe, err_msg = validate_target_safe(target_domain)
    if not safe:
        return jsonify({'success': False, 'error': err_msg}), 400
    
    # 额外的 URL 格式验证
    try:
        parsed = urlparse(target_domain)
        if not parsed.netloc:
            return jsonify({'success': False, 'error': '无效的URL格式'}), 400
    except Exception:
        return jsonify({'success': False, 'error': '无效的URL格式'}), 400
    
    if proxy_mode not in ['server', 'iframe', 'redirect']:
        proxy_mode = 'server'
    
    existing = Subdomain.query.filter_by(subdomain=subdomain).first()
    if existing:
        return jsonify({'success': False, 'error': '该子域名已被注册'}), 409
    
    full_domain = f"{subdomain}.{MAIN_DOMAIN}"
    new_subdomain = Subdomain(
        user_id=current_user.user_id,
        subdomain=subdomain,
        full_domain=full_domain,
        target_domain=target_domain,
        target_type='domain',
        proxy_mode=proxy_mode,
        site_name=site_name or subdomain,
        site_description=site_description,
        status='active',
        created_at=datetime.now()
    )
    
    db.session.add(new_subdomain)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '子域名注册成功', 'data': new_subdomain.to_dict()})


@app.route('/api/subdomains/<int:subdomain_id>', methods=['PUT'])
@login_required
def update_subdomain(subdomain_id):
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    subdomain = Subdomain.query.filter_by(id=subdomain_id, user_id=current_user.user_id).first()
    if not subdomain:
        return jsonify({'success': False, 'error': '子域名不存在'}), 404
    
    data = request.get_json()
    
    if 'site_name' in data:
        subdomain.site_name = data['site_name'][:100]
    if 'site_description' in data:
        subdomain.site_description = data['site_description'][:500]
    if 'target_domain' in data and validate_target_domain(data['target_domain']):
        # SSRF 防护验证
        safe, err_msg = validate_target_safe(data['target_domain'])
        if not safe:
            return jsonify({'success': False, 'error': err_msg}), 400
        subdomain.target_domain = data['target_domain']
    if 'proxy_mode' in data and data['proxy_mode'] in ['server', 'iframe', 'redirect']:
        subdomain.proxy_mode = data['proxy_mode']
    
    subdomain.updated_at = datetime.now()
    db.session.commit()
    
    return jsonify({'success': True, 'message': '更新成功', 'data': subdomain.to_dict()})


@app.route('/api/subdomains/<int:subdomain_id>', methods=['DELETE'])
@login_required
def delete_subdomain(subdomain_id):
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    subdomain = Subdomain.query.filter_by(id=subdomain_id, user_id=current_user.user_id).first()
    if not subdomain:
        return jsonify({'success': False, 'error': '子域名不存在'}), 404
    
    db.session.delete(subdomain)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '子域名已删除'})


@app.route('/api/subdomains/<int:subdomain_id>/status', methods=['PUT'])
@login_required
def toggle_subdomain_status(subdomain_id):
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    subdomain = Subdomain.query.filter_by(id=subdomain_id, user_id=current_user.user_id).first()
    if not subdomain:
        return jsonify({'success': False, 'error': '子域名不存在'}), 404
    
    data = request.get_json()
    status = data.get('status', 'active')
    subdomain.status = 'active' if status == 'active' else 'disabled'
    subdomain.updated_at = datetime.now()
    db.session.commit()
    
    return jsonify({'success': True, 'message': '状态已更新', 'status': subdomain.status})


@app.route('/api/subdomains/<int:subdomain_id>/like', methods=['POST'])
def like_subdomain(subdomain_id):
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    subdomain = Subdomain.query.get(subdomain_id)
    if not subdomain:
        return jsonify({'success': False, 'error': '子域名不存在'}), 404
    
    subdomain.like_count = (subdomain.like_count or 0) + 1
    db.session.commit()
    
    return jsonify({'success': True, 'like_count': subdomain.like_count})


@app.route('/api/subdomains/<int:subdomain_id>/stats', methods=['GET'])
def subdomain_stats(subdomain_id):
    subdomain = Subdomain.query.get(subdomain_id)
    if not subdomain:
        return jsonify({'success': False, 'error': '子域名不存在'}), 404
    
    return jsonify({
        'success': True,
        'data': {
            'view_count': subdomain.view_count or 0,
            'like_count': subdomain.like_count or 0,
            'report_count': subdomain.report_count or 0,
            'is_banned': subdomain.is_banned
        }
    })


# ========== 端口转发 API（仅主域名） ==========

@app.route('/api/user/projects', methods=['GET'])
@login_required
def get_user_projects():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    try:
        resp = requests.get(
            f"{IDE_SERVICE_URL}/api/user/projects",
            headers={'X-Username': current_user.nickname},
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            return jsonify({'success': True, 'projects': data.get('projects', [])})
    except Exception as e:
        print(f"获取项目列表失败: {e}")
    
    return jsonify({'success': True, 'projects': []})


@app.route('/api/port-forwards', methods=['GET'])
@login_required
def list_port_forwards():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    forwards = PortForward.query.filter_by(user_id=current_user.user_id).all()
    return jsonify({'success': True, 'data': [f.to_dict() for f in forwards]})


@app.route('/api/port-forwards', methods=['POST'])
@login_required
def create_port_forward():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    data = request.get_json()
    
    project_name = data.get('project_name', '').strip()
    container_port = data.get('port')
    
    if not project_name:
        return jsonify({'success': False, 'error': '项目名称不能为空'}), 400
    
    if not container_port:
        return jsonify({'success': False, 'error': '端口号不能为空'}), 400
    
    try:
        container_port = int(container_port)
        if container_port < 1 or container_port > 65535:
            raise ValueError
    except ValueError:
        return jsonify({'success': False, 'error': '端口号必须在 1-65535 之间'}), 400
    
    existing = PortForward.query.filter_by(
        user_id=current_user.user_id,
        project_name=project_name,
        container_port=container_port,
        status='active'
    ).first()
    
    if existing:
        return jsonify({
            'success': False, 
            'error': f'已存在活跃的转发: https://{existing.subdomain}.{MAIN_DOMAIN}'
        }), 409
    
    container = find_container_by_user_and_project(current_user.nickname, project_name)
    if not container:
        return jsonify({'success': False, 'error': '容器不存在，请先在 IDE 中打开项目'}), 400
    
    if container.status != 'running':
        return jsonify({'success': False, 'error': '容器未运行，请先在 IDE 中启动容器'}), 400
    
    nickname_clean = re.sub(r'[^a-zA-Z0-9-]', '', current_user.nickname).lower()
    project_clean = re.sub(r'[^a-zA-Z0-9-]', '', project_name).lower()
    base_subdomain = f"{nickname_clean}-{project_clean}-{container_port}"
    
    subdomain = base_subdomain
    counter = 1
    while PortForward.query.filter_by(subdomain=subdomain).first():
        subdomain = f"{base_subdomain}-{counter}"
        counter += 1
    
    full_domain = f"{subdomain}.{MAIN_DOMAIN}"
    
    new_forward = PortForward(
        user_id=current_user.user_id,
        project_name=project_name,
        subdomain=subdomain,
        full_domain=full_domain,
        container_port=container_port,
        status='active',
        created_at=datetime.now()
    )
    
    db.session.add(new_forward)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'端口转发已创建',
        'data': new_forward.to_dict()
    })


@app.route('/api/port-forwards/<int:forward_id>', methods=['DELETE'])
@login_required
def delete_port_forward(forward_id):
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    forward = PortForward.query.filter_by(id=forward_id, user_id=current_user.user_id).first()
    if not forward:
        return jsonify({'success': False, 'error': '转发记录不存在'}), 404
    
    db.session.delete(forward)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '已删除'})


@app.route('/api/port-forwards/check', methods=['POST'])
@login_required
def check_container_port():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    try:
        data = request.get_json()
        print(f"[DEBUG] check_container_port 收到: {data}")
        
        if not data:
            return jsonify({'success': False, 'error': '请求体为空'}), 400
        
        project_name = data.get('project_name', '').strip()
        port = data.get('port')
        
        if not project_name:
            return jsonify({'success': False, 'error': '项目名称不能为空'}), 400
        
        if port is None:
            return jsonify({'success': False, 'error': '缺少端口参数'}), 400
        
        try:
            port = int(port)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': '端口号必须是数字'}), 400
        
        if port < 1 or port > 65535:
            return jsonify({'success': False, 'error': '端口号必须在 1-65535 之间'}), 400
        
        container = find_container_by_user_and_project(current_user.nickname, project_name)
        print(f"[DEBUG] 获取到的容器: {container}")
        
        if not container:
            return jsonify({'success': False, 'error': '容器不存在，请先在 IDE 中打开项目'}), 400
        
        container.reload()
        if container.status != 'running':
            return jsonify({'success': False, 'error': '容器未运行，请先在 IDE 中启动容器'}), 400
        
        container_ip = get_container_ip(container)
        print(f"[DEBUG] 容器 IP: {container_ip}")
        
        if not container_ip:
            return jsonify({'success': False, 'error': '无法获取容器 IP，请检查网络配置'}), 400
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((container_ip, port))
        sock.close()
        
        if result == 0:
            print(f"[DEBUG] 端口 {port} 连接成功")
            return jsonify({'success': True, 'listening': True, 'message': f'端口 {port} 正在监听'})
        else:
            print(f"[DEBUG] 端口 {port} 连接失败: {result}")
            return jsonify({'success': True, 'listening': False, 'message': f'端口 {port} 未检测到监听服务，请先启动 Web 应用'})
            
    except Exception as e:
        print(f"[ERROR] check_container_port 异常: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/port-forwards/cleanup', methods=['POST'])
@login_required
def manual_cleanup():
    if not is_main_domain():
        return jsonify({'success': False, 'error': 'Invalid domain'}), 400
    
    forwards = PortForward.query.filter_by(user_id=current_user.user_id, status='active').all()
    
    cleaned = 0
    for forward in forwards:
        container = find_container_by_user_and_project(current_user.nickname, forward.project_name)
        if not container or container.status != 'running':
            forward.status = 'stopped'
            cleaned += 1
    
    if cleaned > 0:
        db.session.commit()
    
    return jsonify({
        'success': True,
        'cleaned': cleaned,
        'message': f'已清理 {cleaned} 个无效转发'
    })


# ========== 容器事件回调 API ==========

@app.route('/api/container/destroyed', methods=['POST'])
def on_container_destroyed():
    """接收容器销毁的通知，自动清理相关转发"""
    data = request.get_json()
    username = data.get('username')
    project_name = data.get('project_name')
    
    if not username or not project_name:
        return jsonify({'success': False, 'error': '缺少参数'}), 400
    
    try:
        user = User.query.filter_by(nickname=username).first()
        if not user:
            return jsonify({'success': False, 'error': '用户不存在'}), 404
        
        forwards = PortForward.query.filter_by(
            user_id=user.user_id,
            project_name=project_name,
            status='active'
        ).all()
        
        for forward in forwards:
            forward.status = 'stopped'
            forward.updated_at = datetime.now()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'cleaned': len(forwards),
            'message': f'已清理 {len(forwards)} 个端口转发'
        })
        
    except Exception as e:
        print(f"清理转发失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 举报 API ==========

@app.route('/api/report/reasons', methods=['GET'])
def get_report_reasons():
    reasons = [
        {'code': 'spam', 'name': '垃圾广告', 'description': '包含广告、推广等内容'},
        {'code': 'porn', 'name': '色情低俗', 'description': '包含色情、低俗内容'},
        {'code': 'illegal', 'name': '违法信息', 'description': '包含违法信息'},
        {'code': 'malware', 'name': '恶意软件', 'description': '包含病毒、恶意代码'},
        {'code': 'phishing', 'name': '钓鱼网站', 'description': '仿冒、诈骗网站'},
        {'code': 'copyright', 'name': '侵犯版权', 'description': '侵犯他人版权'},
        {'code': 'other', 'name': '其他', 'description': '其他违规内容'}
    ]
    return jsonify({'success': True, 'data': reasons})


@app.route('/api/report', methods=['POST'])
def submit_report():
    data = request.get_json()
    subdomain_id = data.get('subdomain_id')
    reason = data.get('reason', '').strip()
    description = data.get('description', '').strip()
    
    if not subdomain_id or not reason:
        return jsonify({'success': False, 'error': '参数不完整'}), 400
    
    subdomain = Subdomain.query.get(subdomain_id)
    if not subdomain:
        return jsonify({'success': False, 'error': '网站不存在'}), 404
    
    if current_user.is_authenticated and subdomain.user_id == current_user.user_id:
        return jsonify({'success': False, 'error': '不能举报自己的网站'}), 400
    
    reporter_id = current_user.user_id if current_user.is_authenticated else None
    
    existing = Report.query.filter_by(
        subdomain_id=subdomain_id,
        reporter_id=reporter_id,
        status='pending'
    ).first()
    
    if existing:
        return jsonify({'success': False, 'error': '您已举报过该网站，请等待审核'}), 400
    
    report = Report(
        subdomain_id=subdomain_id,
        reporter_id=reporter_id,
        reason=reason,
        description=description,
        status='pending',
        created_at=datetime.now()
    )
    
    db.session.add(report)
    subdomain.report_count = (subdomain.report_count or 0) + 1
    db.session.commit()
    
    if subdomain.report_count >= 3:
        subdomain.is_banned = True
        subdomain.status = 'banned'
        subdomain.banned_at = datetime.now()
        subdomain.banned_reason = '累计收到3次举报，已自动封禁'
        db.session.commit()
        return jsonify({'success': True, 'message': '举报已提交。该网站已收到3次举报，已被自动封禁处理。', 'banned': True})
    
    return jsonify({'success': True, 'message': '举报已提交，我们会尽快处理'})


# ========== 公开 API ==========

@app.route('/api/sites')
def api_list_sites():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = Subdomain.query.filter_by(status='active', is_banned=False)
    pagination = query.order_by(Subdomain.created_at.desc()).paginate(page=page, per_page=per_page)
    
    return jsonify({
        'success': True,
        'data': [s.to_dict() for s in pagination.items],
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'has_next': pagination.has_next
    })


@app.route('/api/site/by-subdomain')
def api_get_site_by_subdomain():
    subdomain = request.args.get('subdomain')
    if not subdomain:
        return jsonify({'success': False, 'error': '缺少子域名参数'}), 400
    
    site = Subdomain.query.filter_by(subdomain=subdomain, status='active', is_banned=False).first()
    if not site:
        return jsonify({'success': False, 'error': '子域名不存在'}), 404
    
    site.view_count += 1
    db.session.commit()
    
    return jsonify({
        'success': True,
        'data': {
            'subdomain': site.subdomain,
            'full_domain': site.full_domain,
            'target_url': site.target_domain,
            'site_name': site.site_name,
            'site_description': site.site_description
        }
    })


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'share'})


# ========== 定时清理线程 ==========

def auto_cleanup_invalid_forwards():
    """定时清理无效的端口转发"""
    while True:
        time.sleep(300)
        try:
            with app.app_context():
                forwards = PortForward.query.filter_by(status='active').all()
                cleaned = 0
                for forward in forwards:
                    user = User.query.filter_by(user_id=forward.user_id).first()
                    if user:
                        container = find_container_by_user_and_project(user.nickname, forward.project_name)
                        if not container or container.status != 'running':
                            forward.status = 'stopped'
                            cleaned += 1
                    else:
                        forward.status = 'stopped'
                        cleaned += 1
                if cleaned > 0:
                    db.session.commit()
                    print(f"[自动清理] 已清理 {cleaned} 个无效转发")
        except Exception as e:
            print(f"[自动清理] 错误: {e}")


_cleanup_thread_started = False

def start_cleanup_thread():
    global _cleanup_thread_started
    if not _cleanup_thread_started:
        _cleanup_thread_started = True
        thread = threading.Thread(target=auto_cleanup_invalid_forwards, daemon=True)
        thread.start()
        print("自动清理线程已启动")


# ========== 初始化数据库 ==========
_init_lock = threading.Lock()
_db_initialized = False

def init_db_once():
    global _db_initialized
    if _db_initialized:
        return
    with _init_lock:
        if not _db_initialized:
            with app.app_context():
                db.create_all()
                print("Share 服务数据库初始化完成")
                _db_initialized = True


@app.before_request
def before_request():
    init_db_once()


if __name__ == '__main__':
    init_db_once()
    start_cleanup_thread()
    app.run(host='0.0.0.0', port=8002, debug=False)
    