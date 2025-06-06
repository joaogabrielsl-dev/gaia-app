from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import os
import base64
import io
from PIL import Image

app = Flask(__name__)

# Configuração do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///gaia.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

db = SQLAlchemy(app)

# Modelos
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(120), nullable=False)
    nome = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False) 
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    
    problemas_criados = db.relationship('Problema', foreign_keys='Problema.criador_id', backref='criador')
    problemas_candidatados = db.relationship('Problema', foreign_keys='Problema.candidato_id', backref='candidato')

class Problema(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    foto = db.Column(db.LargeBinary, nullable=False)
    localizacao = db.Column(db.String(255), nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    descricao = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Aberto')
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    
    criador_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    candidato_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)
    data_candidatura = db.Column(db.DateTime, nullable=True)
    
    solucao = db.relationship('Solucao', backref='problema', uselist=False)
    
    def prazo_expirado(self):
        if self.data_candidatura and self.status == 'Em andamento':
            return datetime.utcnow() > (self.data_candidatura + timedelta(days=2))
        return False
    
    def foto_base64(self):
        if self.foto:
            return base64.b64encode(self.foto).decode('utf-8')
        return None

class Solucao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    problema_id = db.Column(db.Integer, db.ForeignKey('problema.id'), nullable=False)
    foto_depois = db.Column(db.LargeBinary, nullable=False)
    data_postagem = db.Column(db.DateTime, default=datetime.utcnow)
    aprovado = db.Column(db.Boolean, default=False)
    
    def foto_base64(self):
        if self.foto_depois:
            return base64.b64encode(self.foto_depois).decode('utf-8')
        return None

# Decorator para login obrigatório
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa fazer login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Função para verificar prazos
def verificar_prazos_expirados():
    problemas_expirados = Problema.query.filter(
        Problema.status == 'Em andamento',
        Problema.data_candidatura < datetime.utcnow() - timedelta(days=2)
    ).all()
    
    for problema in problemas_expirados:
        problema.status = 'Aberto'
        problema.candidato_id = None
        problema.data_candidatura = None
    
    if problemas_expirados:
        db.session.commit()

@app.template_global()
def timedelta_days(days):
    return timedelta(days=days)

@app.template_global()
def now():
    return datetime.utcnow()

def recriar_banco():
    """Função para recriar o banco quando houver mudanças no modelo"""
    db.drop_all()
    db.create_all()
    print("Banco de dados recriado com sucesso!")

# Rotas
@app.route('/')
def home():
    verificar_prazos_expirados()
    problemas_abertos = Problema.query.filter_by(status='Aberto').order_by(Problema.data_criacao.desc()).all()
    return render_template('home.html', problemas=problemas_abertos)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        
        usuario = Usuario.query.filter_by(email=email).first()
        
        if usuario and check_password_hash(usuario.senha, senha):
            session['user_id'] = usuario.id
            session['user_nome'] = usuario.nome
            session['user_email'] = usuario.email
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email ou senha incorretos!', 'error')
    
    return render_template('login.html')

# Atualizar a rota de cadastro no app.py
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        cpf = request.form['cpf']
        email = request.form['email']
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']
        
        # Validações
        if not nome or not cpf or not email or not senha:
            flash('Todos os campos são obrigatórios!', 'error')
            return render_template('cadastro.html')
        
        if senha != confirmar_senha:
            flash('As senhas não coincidem!', 'error')
            return render_template('cadastro.html')
        
        # Validar CPF (formato básico)
        cpf_limpo = ''.join(filter(str.isdigit, cpf))
        if len(cpf_limpo) != 11:
            flash('CPF deve ter 11 dígitos!', 'error')
            return render_template('cadastro.html')
        
        if Usuario.query.filter_by(email=email).first():
            flash('Este email já está cadastrado!', 'error')
            return render_template('cadastro.html')
            
        if Usuario.query.filter_by(cpf=cpf_limpo).first():
            flash('Este CPF já está cadastrado!', 'error')
            return render_template('cadastro.html')
        
        # Criar usuário
        usuario = Usuario(
            nome=nome,
            cpf=cpf_limpo,
            email=email,
            senha=generate_password_hash(senha)
        )
        
        db.session.add(usuario)
        db.session.commit()
        
        flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))
    
    return render_template('cadastro.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso!', 'info')
    return redirect(url_for('home'))

@app.route('/nova-solicitacao', methods=['GET', 'POST'])
@login_required
def nova_solicitacao():
    if request.method == 'POST':
        if 'foto' not in request.files:
            flash('Foto é obrigatória!', 'error')
            return redirect(request.url)
        
        foto = request.files['foto']
        localizacao = request.form['localizacao']
        descricao = request.form['descricao']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        if foto.filename == '':
            flash('Nenhuma foto selecionada!', 'error')
            return redirect(request.url)
        
        if not localizacao or not descricao:
            flash('Localização e descrição são obrigatórias!', 'error')
            return redirect(request.url)
        
        try:
            img = Image.open(foto.stream)
            img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
            
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', quality=85)
            img_data = img_bytes.getvalue()
            
        except Exception as e:
            flash('Erro ao processar imagem. Verifique se é um arquivo válido.', 'error')
            return redirect(request.url)
        
        problema = Problema(
            foto=img_data,
            localizacao=localizacao,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None,
            descricao=descricao,
            criador_id=session['user_id']
        )
        
        db.session.add(problema)
        db.session.commit()
        
        flash('Solicitação criada com sucesso!', 'success')
        return redirect(url_for('home'))
    
    return render_template('nova_solicitacao.html')

@app.route('/candidatar-se/<int:problema_id>', methods=['POST'])
@login_required
def candidatar_se(problema_id):
    problema = Problema.query.get_or_404(problema_id)
    
    if problema.status != 'Aberto':
        flash('Este problema não está mais disponível!', 'error')
        return redirect(url_for('home'))
    
    if problema.criador_id == session['user_id']:
        flash('Você não pode se candidatar ao seu próprio problema!', 'error')
        return redirect(url_for('home'))
    
    problema.status = 'Em andamento'
    problema.candidato_id = session['user_id']
    problema.data_candidatura = datetime.utcnow()
    
    db.session.commit()
    
    flash('Candidatura realizada com sucesso! Você tem 2 dias para resolver o problema.', 'success')
    return redirect(url_for('home'))

@app.route('/minhas-solicitacoes')
@login_required
def minhas_solicitacoes():
    problemas = Problema.query.filter_by(criador_id=session['user_id']).order_by(Problema.data_criacao.desc()).all()
    return render_template('minhas_solicitacoes.html', problemas=problemas)

@app.route('/minhas-solucoes')
@login_required
def minhas_solucoes():
    problemas = Problema.query.filter_by(candidato_id=session['user_id']).order_by(Problema.data_candidatura.desc()).all()
    return render_template('minhas_solucoes.html', problemas=problemas)

# Adicionar ao app.py
@app.route('/postar-solucao/<int:problema_id>', methods=['GET', 'POST'])
@login_required
def postar_solucao(problema_id):
    problema = Problema.query.get_or_404(problema_id)
    
    # Verificar se o usuário é o candidato
    if problema.candidato_id != session['user_id']:
        flash('Você não tem permissão para postar solução neste problema.', 'error')
        return redirect(url_for('minhas_solucoes'))
    
    # Verificar se o problema está em andamento
    if problema.status != 'Em andamento':
        flash('Este problema não está mais em andamento.', 'error')
        return redirect(url_for('minhas_solucoes'))
    
    if request.method == 'POST':
        if 'foto_depois' not in request.files:
            flash('Foto da solução é obrigatória!', 'error')
            return redirect(request.url)
        
        foto_depois = request.files['foto_depois']
        
        if foto_depois.filename == '':
            flash('Nenhuma foto selecionada!', 'error')
            return redirect(request.url)
        
        try:
            img = Image.open(foto_depois.stream)
            img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
            
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', quality=85)
            img_data = img_bytes.getvalue()
            
        except Exception as e:
            flash('Erro ao processar imagem. Verifique se é um arquivo válido.', 'error')
            return redirect(request.url)
        
        # Criar ou atualizar solução
        if problema.solucao:
            problema.solucao.foto_depois = img_data
            problema.solucao.data_postagem = datetime.utcnow()
            problema.solucao.aprovado = False
        else:
            solucao = Solucao(
                problema_id=problema.id,
                foto_depois=img_data
            )
            db.session.add(solucao)
        
        db.session.commit()
        
        flash('Solução postada com sucesso! Aguardando aprovação do criador.', 'success')
        return redirect(url_for('minhas_solucoes'))
    
    return render_template('postar_solucao.html', problema=problema)

@app.route('/aprovar-solucao/<int:problema_id>')
@login_required
def aprovar_solucao(problema_id):
    problema = Problema.query.get_or_404(problema_id)
    
    if problema.criador_id != session['user_id']:
        flash('Você não tem permissão para aprovar esta solução.', 'error')
        return redirect(url_for('minhas_solicitacoes'))
    
    if not problema.solucao:
        flash('Não há solução postada para este problema.', 'error')
        return redirect(url_for('minhas_solicitacoes'))
    
    return render_template('aprovar_solucao.html', problema=problema)

@app.route('/confirmar-aprovacao/<int:problema_id>', methods=['POST'])
@login_required
def confirmar_aprovacao(problema_id):
    problema = Problema.query.get_or_404(problema_id)
    
    if problema.criador_id != session['user_id']:
        flash('Você não tem permissão para aprovar esta solução.', 'error')
        return redirect(url_for('minhas_solicitacoes'))
    
    acao = request.form.get('acao')
    
    if acao == 'aprovar':
        problema.solucao.aprovado = True
        problema.status = 'Resolvido'
        db.session.commit()
        flash('Solução aprovada! Problema marcado como resolvido.', 'success')
    elif acao == 'rejeitar':
        db.session.delete(problema.solucao)
        
        problema.status = 'Aberto'
        problema.candidato_id = None
        problema.data_candidatura = None
        
        db.session.commit()
        flash('Solução rejeitada. O problema voltou para aberto e está disponível para novos candidatos.', 'warning')
    
    return redirect(url_for('minhas_solicitacoes'))


@app.route('/deletar-solicitacao/<int:problema_id>', methods=['POST'])
@login_required
def deletar_solicitacao(problema_id):
    problema = Problema.query.get_or_404(problema_id)
    
    if problema.criador_id != session['user_id']:
        flash('Você não tem permissão para deletar esta solicitação.', 'error')
        return redirect(url_for('minhas_solicitacoes'))
    
    if problema.status != 'Aberto':
        flash('Só é possível deletar solicitações que estejam em Aberto.', 'warning')
        return redirect(url_for('minhas_solicitacoes'))
    
    if problema.solucao:
        db.session.delete(problema.solucao)
    
    db.session.delete(problema)
    db.session.commit()
    
    flash('Solicitação deletada com sucesso.', 'success')
    return redirect(url_for('minhas_solicitacoes'))

if __name__ == '__main__':
    with app.app_context():
        #recriar_banco()
        db.create_all()
    app.run(debug=True)
